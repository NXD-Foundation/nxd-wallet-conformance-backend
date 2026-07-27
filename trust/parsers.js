import xmlCrypto from "xml-crypto";
import xpathModule from "xpath";
import { derToPem, certificateFingerprint } from "./crypto.js";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

const xpath = xpathModule;

const LOTL_TYPE = "http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists";

function asArray(value) {
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

function firstMultilang(value) {
  return asArray(value)[0]?.value || asArray(value)[0]?.uriValue || null;
}

function certValues(identity) {
  return asArray(identity?.X509Certificates).map((item) => item?.val).filter(Boolean);
}

function fingerprintValues(identity) {
  return certValues(identity).map((value) => {
    try {
      return certificateFingerprint(derToPem(Buffer.from(value, "base64")));
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function parseJsonScheme(info) {
  const issue = Date.parse(info?.ListIssueDateTime || "");
  const next = Date.parse(info?.NextUpdate || "");
  if (!Number.isFinite(issue) || !Number.isFinite(next)) {
    throw new TrustListError("JSON list has invalid issue or next-update time", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  return {
    version: info.LoTEVersionIdentifier ?? info.TSLVersionIdentifier,
    sequence: info.LoTESequenceNumber ?? info.TSLSequenceNumber,
    type: info.LoTEType ?? info.TSLType,
    issueTime: new Date(issue).toISOString(),
    nextUpdate: new Date(next).toISOString(),
    operator: firstMultilang(info.SchemeOperatorName),
  };
}

export function parseJsonDocument(unsigned, { listType = null } = {}) {
  const lote = unsigned?.LoTE;
  const info = lote?.ListAndSchemeInformation;
  if (!info) throw new TrustListError("JSON document lacks ListAndSchemeInformation", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  const scheme = parseJsonScheme(info);
  const pointers = asArray(info.PointersToOtherLoTE).map((pointer) => ({
    url: pointer.LoTELocation,
    mimeType: pointer.LoTEQualifiers?.[0]?.MimeType || "application/json",
    listTypeUri: pointer.LoTEQualifiers?.[0]?.LoTEType || null,
    anchorCertificates: certValues(pointer.ServiceDigitalIdentities?.[0]),
  })).filter((pointer) => pointer.url);
  const entities = asArray(lote.TrustedEntitiesList).map((entity) => {
    const entityInfo = entity.TrustedEntityInformation || {};
    const entityId = firstMultilang(entityInfo.TEName) || firstMultilang(entityInfo.EntityName) || entityInfo.EntityIdentifier || null;
    const services = asArray(entity.TrustedEntityServices).map((service) => {
      const serviceInfo = service.ServiceInformation || service;
      const identity = serviceInfo.ServiceDigitalIdentity || {};
      const certificates = fingerprintValues(identity);
      const certificatePems = certValues(identity).map((value) => derToPem(Buffer.from(value, "base64")));
      return {
        name: firstMultilang(serviceInfo.ServiceName),
        type: serviceInfo.ServiceTypeIdentifier || null,
        status: serviceInfo.ServiceStatus || null,
        certificates,
        certificatePems,
      };
    });
    return { id: entityId, name: entityId, services };
  });
  return { format: "json", listType, scheme, pointers, entities, raw: unsigned };
}

function textAt(node, name) {
  return xpath.select(`.//*[local-name(.)='${name}']`, node)[0]?.textContent?.trim() || null;
}

function nodesAt(node, name) {
  return xpath.select(`.//*[local-name(.)='${name}']`, node);
}

export function parseXmlDocument(document, { listType = null } = {}) {
  const info = xpath.select("//*[local-name(.)='SchemeInformation']", document)[0];
  const issueValue = textAt(info, "ListIssueDateTime");
  const nextValue = textAt(info, "NextUpdate");
  const issue = Date.parse(issueValue || "");
  const next = Date.parse(nextValue || "");
  if (!info || !Number.isFinite(issue) || !Number.isFinite(next)) {
    throw new TrustListError("XML list has invalid scheme information or dates", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  const root = document.documentElement;
  const scheme = {
    version: textAt(info, "TSLVersionIdentifier") || textAt(info, "LoTEVersionIdentifier"),
    sequence: Number(textAt(info, "TSLSequenceNumber") || textAt(info, "LoTESequenceNumber")),
    type: textAt(info, "TSLType") || textAt(info, "LoTEType"),
    issueTime: new Date(issue).toISOString(),
    nextUpdate: new Date(next).toISOString(),
    operator: textAt(info, "Name"),
  };
  const pointers = nodesAt(root, "OtherTSLPointer").concat(nodesAt(root, "OtherLoTEPointer")).map((pointer) => ({
    url: textAt(pointer, "TSLLocation") || textAt(pointer, "LoTELocation") || textAt(pointer, "URI"),
    mimeType: textAt(pointer, "MimeType") || "application/xml",
    listTypeUri: textAt(pointer, "TSLType") || textAt(pointer, "LoTEType"),
    anchorCertificates: nodesAt(pointer, "X509Certificate").map((node) => node.textContent.trim()).filter(Boolean),
  })).filter((pointer) => pointer.url);
  const serviceNodes = nodesAt(root, "TSPService");
  const entities = serviceNodes.map((service) => ({
    id: textAt(service, "TSPName") || textAt(service, "Name"),
    name: textAt(service, "TSPName") || textAt(service, "Name"),
    services: [{
      name: textAt(service, "ServiceName") || textAt(service, "Name"),
      type: textAt(service, "ServiceTypeIdentifier"),
      status: textAt(service, "ServiceStatus"),
      certificates: nodesAt(service, "X509Certificate").map((node) => {
        try {
          return certificateFingerprint(derToPem(Buffer.from(node.textContent.trim(), "base64")));
        } catch {
          return null;
        }
      }).filter(Boolean),
      certificatePems: nodesAt(service, "X509Certificate").map((node) => derToPem(Buffer.from(node.textContent.trim(), "base64"))),
    }],
  }));
  return { format: "xml", listType, scheme, pointers, entities, raw: root.toString() };
}

export function validateListShape(parsed, { expectedType = null, expectedProfile = null, isLoTL = false } = {}) {
  if (!parsed?.scheme?.sequence || !parsed.scheme.issueTime || !parsed.scheme.nextUpdate) {
    throw new TrustListError("List is missing required scheme metadata", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  if (isLoTL && parsed.scheme.type !== LOTL_TYPE && parsed.format === "json") {
    throw new TrustListError("JSON document is not a WE BUILD LoTL", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  if (!isLoTL && expectedProfile?.profile !== "ts119612-national-tsl" && parsed.scheme.type !== expectedProfile?.referenceUri) {
    throw new TrustListError("Referenced LoTE type does not match the requested WP4 list type", TRUST_REASON_CODES.LIST_PROFILE_INVALID, {
      expected: expectedProfile?.referenceUri,
      actual: parsed.scheme.type,
    });
  }
  if (!isLoTL && expectedProfile?.profile === "ts119612-national-tsl" && parsed.scheme.type !== "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric") {
    throw new TrustListError("Referenced national Trusted List has an unexpected TSL type", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  if (!isLoTL && !parsed.entities.length && !parsed.pointers.length) {
    throw new TrustListError("Referenced list contains no entities or pointers", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  if (expectedType && !parsed.format) {
    throw new TrustListError(`List type ${expectedType} is invalid`, TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  return parsed;
}
