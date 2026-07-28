import { fetchDocument } from "./fetch.js";
import { verifyJadesJson, verifyXadesXml, certificateFingerprint, derToPem } from "./crypto.js";
import { parseJsonDocument, parseXmlDocument, validateListShape } from "./parsers.js";
import { listTypeProfile } from "./profile.js";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

function isJson(document) {
  const text = document.bytes.toString("utf8").trim();
  return document.contentType.includes("json") || text.startsWith("{");
}

function formatUrl(profile, format) {
  return profile.lotl?.[`${format}Url`] || profile.lotl?.[format];
}

function freshness(parsed, now, profile) {
  const nowMs = now.getTime();
  const issue = Date.parse(parsed.scheme.issueTime);
  const next = Date.parse(parsed.scheme.nextUpdate);
  if (nowMs < issue - profile.freshness.clockSkewSeconds * 1000) {
    throw new TrustListError("List is not yet valid", TRUST_REASON_CODES.LIST_NOT_YET_VALID);
  }
  if (nowMs > next + profile.freshness.maxStaleSeconds * 1000) {
    throw new TrustListError("List is stale", TRUST_REASON_CODES.LIST_STALE, { nextUpdate: parsed.scheme.nextUpdate });
  }
}

async function loadOne({ document, profile, format, allowedFingerprints, listType, isLoTL }) {
  let verified;
  if (format === "json") {
    verified = await verifyJadesJson(JSON.parse(document.bytes.toString("utf8")), {
      allowedFingerprints,
      algorithms: profile.algorithms.jades,
      allowEmbeddedCertificate: isLoTL && profile.network.allowEmbeddedX5cBootstrapForTests === true,
    });
  } else {
    verified = verifyXadesXml(document.bytes, { allowedFingerprints });
  }
  const parsed = format === "json"
    ? parseJsonDocument(verified.unsigned, { listType })
    : parseXmlDocument(verified.document, { listType });
  validateListShape(parsed, { expectedType: listType, expectedProfile: profile.listTypes[listType], isLoTL });
  return { ...parsed, source: { url: document.url, format }, signer: verified.signer };
}

async function loadByFormat({ profile, format, fetchImpl, clock, listType = null, isLoTL = false, allowedFingerprints }) {
  const url = isLoTL ? formatUrl(profile, format) : null;
  const document = await fetchDocument(url, { fetchImpl, timeoutMs: profile.network.timeoutMs, maxBytes: profile.network.maxBytes, allowInsecureHttp: profile.network.allowInsecureHttp === true, allowedHosts: profile.network.allowedHosts || null, allowPrivateAddresses: profile.network.allowPrivateAddresses === true });
  if ((format === "json") !== isJson(document)) {
    throw new TrustListError(`Expected ${format} document but received another format`, TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  const parsed = await loadOne({ document, profile, format, allowedFingerprints, listType, isLoTL });
  freshness(parsed, clock(), profile);
  return parsed;
}

export function pointersForType(pointers, typeProfile, format) {
  const matches = pointers.filter((pointer) => pointer.listTypeUri === typeProfile.referenceUri);
  const formatMatches = matches.filter((pointer) => pointer.mimeType.includes(format));
  const candidates = formatMatches.length ? formatMatches : matches;
  if (!candidates.length) return null;

  if (typeProfile.pointerUrl) {
    const selected = candidates.filter((pointer) => pointer.url === typeProfile.pointerUrl);
    if (selected.length === 1) return selected;
    throw new TrustListError(
      "Configured trust-list pointer URL is missing or ambiguous",
      TRUST_REASON_CODES.POINTER_NOT_FOUND,
      { referenceUri: typeProfile.referenceUri, pointerUrl: typeProfile.pointerUrl },
    );
  }

  return candidates;
}

// Compatibility helper for callers that intentionally require exactly one
// pointer. Trust resolution itself must use pointersForType() so every LoTL
// publisher can be evaluated independently.
export function pointerForType(pointers, typeProfile, format) {
  const candidates = pointersForType(pointers, typeProfile, format);
  if (!candidates) return null;
  if (candidates.length > 1) {
    throw new TrustListError(
      "Multiple trust-list pointers match this role; use pointersForType to evaluate all authenticated candidates",
      TRUST_REASON_CODES.LIST_PROFILE_INVALID,
      { referenceUri: typeProfile.referenceUri, candidates: candidates.map((pointer) => pointer.url) },
    );
  }
  return candidates[0];
}

export async function loadTrustSnapshot({ profile, fetchImpl = globalThis.fetch, clock = () => new Date(), format = profile.formats.preferred, listTypes = Object.keys(profile.listTypes) } = {}) {
  const formats = [format, profile.formats.fallback].filter(Boolean);
  let lotl;
  let firstError;
  for (const selectedFormat of formats) {
    try {
      lotl = await loadByFormat({
        profile,
        format: selectedFormat,
        fetchImpl,
        clock,
        isLoTL: true,
        allowedFingerprints: profile.bootstrap.loTLSignerFingerprints,
      });
      break;
    } catch (error) {
      firstError ||= error;
      if (error.reasonCode !== TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE) break;
    }
  }
  if (!lotl) throw firstError;
  const lists = {};
  const listFailures = {};
  for (const listType of listTypes) {
    const typeProfile = listTypeProfile(profile, listType);
    const pointers = pointersForType(lotl.pointers, typeProfile, lotl.format);
    if (!pointers) continue;
    lists[listType] = [];
    listFailures[listType] = [];
    for (const pointer of pointers) {
      try {
        const allowed = pointer.anchorCertificates.map((value) => {
          if (value.includes("BEGIN CERTIFICATE")) return certificateFingerprint(value);
          return certificateFingerprint(derToPem(Buffer.from(value, "base64")));
        });
        const source = await fetchDocument(pointer.url, { fetchImpl, timeoutMs: profile.network.timeoutMs, maxBytes: profile.network.maxBytes, allowInsecureHttp: profile.network.allowInsecureHttp === true, allowedHosts: profile.network.allowedHosts || null, allowPrivateAddresses: profile.network.allowPrivateAddresses === true });
        const selectedFormat = isJson(source) ? "json" : "xml";
        const parsed = await loadOne({ document: source, profile, format: selectedFormat, allowedFingerprints: allowed.length ? allowed : typeProfile.signerFingerprints, listType });
        freshness(parsed, clock(), profile);
        lists[listType].push(parsed);
      } catch (error) {
        const reasonCode = error instanceof TrustListError && error.reasonCode === TRUST_REASON_CODES.LIST_SIGNATURE_INVALID
          ? TRUST_REASON_CODES.REFERENCED_LIST_SIGNATURE_INVALID
          : error.reasonCode || TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE;
        listFailures[listType].push({ url: pointer.url, reasonCode, message: error.message });
      }
    }
  }
  return { profile, profileId: profile.id, format: lotl.format, lotl, lists, listFailures, loadedAt: clock().toISOString() };
}
