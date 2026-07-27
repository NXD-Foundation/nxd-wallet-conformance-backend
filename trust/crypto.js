import { createHash, createPublicKey, X509Certificate } from "node:crypto";
import { compactVerify } from "jose";
import { DOMParser } from "@xmldom/xmldom";
import xmlCrypto from "xml-crypto";
import xpathModule from "xpath";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

const { SignedXml } = xmlCrypto;
const xpath = xpathModule;

export function base64urlDecode(value) {
  return Buffer.from(value, "base64url");
}

export function stableJsonStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableJsonStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJsonStringify(value[key])}`).join(",")}}`;
  }
  if (typeof value === "string") {
    return JSON.stringify(value).replace(/[^\x00-\x7F]/g, (character) => {
      const codePoint = character.codePointAt(0);
      if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, "0")}`;
      const high = ((codePoint - 0x10000) >> 10) + 0xd800;
      const low = ((codePoint - 0x10000) & 0x3ff) + 0xdc00;
      return `\\u${high.toString(16)}\\u${low.toString(16)}`;
    });
  }
  return JSON.stringify(value);
}

export function derToPem(der) {
  const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g)?.join("\n") || "";
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

export function certificateFingerprint(certPem) {
  const cert = new X509Certificate(certPem);
  return createHash("sha256").update(cert.raw).digest("hex").toLowerCase();
}

export function certificateFromX5c(x5c) {
  if (!Array.isArray(x5c) || typeof x5c[0] !== "string") {
    throw new TrustListError("Signed document does not contain an X.509 certificate", TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  return derToPem(Buffer.from(x5c[0], "base64"));
}

export function assertCertificateAllowed(certPem, allowedFingerprints, reasonCode = TRUST_REASON_CODES.BOOTSTRAP_UNTRUSTED) {
  const fingerprint = certificateFingerprint(certPem);
  if (!allowedFingerprints?.map((x) => x.toLowerCase()).includes(fingerprint)) {
    throw new TrustListError("Signing certificate is not authorized by the trust profile", reasonCode, { fingerprint });
  }
  return fingerprint;
}

export async function verifyJadesJson(document, { allowedFingerprints = [], algorithms = ["RS256", "ES256"] } = {}) {
  const signature = document?.signature;
  if (!signature?.protected || !signature?.signature) {
    throw new TrustListError("JAdES signature is missing or malformed", TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  let header;
  try {
    header = JSON.parse(base64urlDecode(signature.protected).toString("utf8"));
  } catch (error) {
    throw new TrustListError(`JAdES protected header is invalid: ${error.message}`, TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  const certPem = certificateFromX5c(header.x5c);
  const fingerprint = assertCertificateAllowed(certPem, allowedFingerprints);
  if (!algorithms.includes(header.alg)) {
    throw new TrustListError(`JAdES algorithm is not allowed: ${header.alg}`, TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  const unsigned = { ...document };
  delete unsigned.signature;
  const payload = Buffer.from(stableJsonStringify(unsigned));
  const compact = `${signature.protected}.${payload.toString("base64url")}.${signature.signature}`;
  try {
    await compactVerify(compact, createPublicKey(certPem), { algorithms });
  } catch (error) {
    throw new TrustListError(`JAdES signature verification failed: ${error.message}`, TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  return { unsigned, signer: { certPem, fingerprint, algorithm: header.alg } };
}

function firstText(node, localName) {
  const found = xpath.select(`.//*[local-name(.)='${localName}']`, node);
  return found[0]?.textContent?.trim() || null;
}

export function verifyXadesXml(xmlBytes, { allowedFingerprints = [], publicCertPem = null } = {}) {
  const xml = Buffer.from(xmlBytes).toString("utf8");
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const signatures = xpath.select("//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc);
  if (!signatures.length) {
    throw new TrustListError("XML signature is missing", TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  const embedded = firstText(signatures[0], "X509Certificate");
  const certPem = publicCertPem || (embedded ? derToPem(Buffer.from(embedded, "base64")) : null);
  if (!certPem) {
    throw new TrustListError("XML signature does not contain a certificate", TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  const fingerprint = assertCertificateAllowed(certPem, allowedFingerprints);
  const verifier = new SignedXml({ publicCert: certPem, getCertFromKeyInfo: () => null });
  try {
    verifier.loadSignature(signatures[0]);
    if (!verifier.checkSignature(xml)) {
      throw new Error("XML signature check returned false");
    }
  } catch (error) {
    throw new TrustListError(`XAdES/XML signature verification failed: ${error.message}`, TRUST_REASON_CODES.LIST_SIGNATURE_INVALID);
  }
  return { document: doc, signer: { certPem, fingerprint, algorithm: "XMLDSig-RSA-SHA256" } };
}
