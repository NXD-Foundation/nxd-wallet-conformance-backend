import { decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { derToPem } from "../trust/crypto.js";

function fail(message) { throw new Error(`WRPRC: ${message}`); }
function object(value) {
  if (typeof value === "string") { try { return JSON.parse(value); } catch { fail("invalid JSON metadata"); } }
  return value || {};
}
function intendedUseIdentifier(value) { return value?.intendedUseIdentifier ?? value?.intendedUseId ?? value?.intended_use_id; }
function id(value) { return intendedUseIdentifier(value) ?? value?.id; }
function service(value) { return value?.serviceId ?? value?.serviceIdentifier ?? value?.service_id ?? value?.service_identifier; }
function checkId(actual, expected, label) {
  if (actual !== undefined && expected !== undefined && actual !== expected) fail(`${label} mismatch`);
}

// Flat ETSI certificates do not necessarily carry service/intended-use IDs.
// The caller must bind those certificates using the saved issuance response.
export function resolveRegistrationIntendedUse(registration, { intendedUseId, serviceId } = {}) {
  checkId(service(registration), serviceId, "service");
  const uses = registration?.intendedUse ?? registration?.intendedUses;
  let selected = registration;
  if (uses !== undefined) {
    if (!Array.isArray(uses) || uses.length === 0) fail("missing intended use");
    const matches = intendedUseId === undefined ? uses : uses.filter((use) => id(use) === intendedUseId);
    if (matches.length !== 1) fail("intended use is missing or ambiguous");
    [selected] = matches;
  }
  checkId(uses === undefined ? intendedUseIdentifier(selected) : id(selected), intendedUseId, "intended use");
  checkId(service(selected), serviceId, "service");
  if (!Array.isArray(selected?.credentials) || selected.credentials.length === 0) fail("credential scope is not declared");
  return selected;
}

function claimPath(claim) {
  let path = claim?.path;
  if (typeof path === "string") { try { path = JSON.parse(path); } catch { fail("invalid claim path"); } }
  if (!Array.isArray(path) || path.length === 0 || path.some((part) => part !== null && typeof part !== "string" && !(Number.isInteger(part) && part >= 0))) fail("invalid claim path");
  return JSON.stringify(path);
}
function credentialCovered(requested, registered) {
  if (!requested?.format || requested.format !== registered?.format) return false;
  const queryMeta = object(requested.meta);
  const allowedMeta = object(registered.meta);
  // Every allowed request alternative must be registered; a first-item match
  // cannot authorize a second, unregistered VCT or certificate policy.
  const keys = requested.format === "mso_mdoc" ? ["doctype_value"]
    : requested.format === "dc+sd-jwt" ? ["vct_values"]
      : requested.format === "https://cloudsignatureconsortium.org/2025/x509" ? ["certificatePolicies"] : [];
  if (keys.length === 0) return false;
  for (const key of keys) {
    const values = Array.isArray(queryMeta[key]) ? queryMeta[key] : [queryMeta[key]].filter(Boolean);
    const allowed = Array.isArray(allowedMeta[key]) ? allowedMeta[key] : [allowedMeta[key]].filter(Boolean);
    if (!values.length || values.some((value) => !allowed.includes(value))) return false;
  }
  const claims = requested.claims;
  if (claims === undefined && requested.format !== "https://cloudsignatureconsortium.org/2025/x509") return false;
  if (claims !== undefined && (!Array.isArray(claims) || !claims.length)) return false;
  const registeredClaims = registered.claims ?? registered.claim ?? [];
  if (!Array.isArray(registeredClaims)) return false;
  const paths = new Set(registeredClaims.map(claimPath));
  return (claims || []).every((claim) => paths.has(claimPath(claim)));
}

export function assertQueryScope(query, intendedUse) {
  if (!Array.isArray(query?.credentials) || !query.credentials.length) fail("non-empty DCQL credentials required");
  if (!Array.isArray(intendedUse?.credentials) || !intendedUse.credentials.length) fail("credential scope is not declared");
  if (!query.credentials.every((credential) => intendedUse.credentials.some((registered) => credentialCovered(credential, registered)))) fail("query exceeds intended-use credential or claim scope");
  return true;
}

export function encodeRegistrationCertificate(token) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) fail("compact signed JWT required");
  return Buffer.from(token, "utf8").toString("base64url");
}
export function decodeRegistrationCertificate(data) {
  if (typeof data !== "string" || !/^[A-Za-z0-9_-]+$/.test(data)) fail("base64url certificate required");
  const token = Buffer.from(data, "base64url").toString("utf8");
  if (encodeRegistrationCertificate(token) !== data) fail("non-canonical certificate encoding");
  return token;
}

export async function verifyWrprc(token, { entityId, intendedUseId, serviceId, checkTrust, currentDate } = {}) {
  encodeRegistrationCertificate(token);
  if (!entityId || typeof checkTrust !== "function") fail("entity identity and trust callback required");
  const header = decodeProtectedHeader(token);
  if (header.typ !== "rc-wrp+jwt" || !["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA"].includes(header.alg)) fail("unsupported certificate type or algorithm");
  if (!Array.isArray(header.x5c) || !header.x5c.length || header.x5c.some((cert) => typeof cert !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(cert))) fail("signing certificate chain required");
  const certificateChain = header.x5c.map((cert) => derToPem(Buffer.from(cert, "base64")));
  const { payload } = await jwtVerify(token, await importX509(certificateChain[0], header.alg), { algorithms: [header.alg], requiredClaims: ["exp", "sub"], currentDate });
  if (payload.sub !== entityId) fail("subject does not match WRPAC");
  if (!Array.isArray(payload.entitlements) || !payload.entitlements.includes("https://uri.etsi.org/19475/Entitlement/Service_Provider")) fail("Service Provider entitlement required");
  const trustDecision = await checkTrust({ certificatePem: certificateChain[0], certificateChain, role: "wrprc-provider", operation: "verify-registration-certificate" });
  if (!trustDecision?.trusted) fail("registration signing chain is not trusted");
  const intendedUse = resolveRegistrationIntendedUse(payload, { intendedUseId, serviceId });
  return { payload, header, intendedUse, trustDecision };
}

function languageValues(values) {
  return (values || []).flat().map((entry) => ({ lang: entry.lang, value: entry.value ?? entry.content })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
export function assertRegistrarDataset(dataset, { registration, intendedUse, entityId, intendedUseId, serviceId } = {}) {
  if (!dataset || typeof dataset !== "object" || Array.isArray(dataset)) fail("registrar dataset required");
  if (dataset.identifier !== entityId || registration?.sub !== entityId) fail("registrar dataset identity mismatch");
  if (!intendedUseId || dataset.intendedUseIdentifier !== intendedUseId) fail("registrar dataset intended use mismatch");
  checkId(service(dataset), serviceId, "registrar dataset service");
  if (!dataset.registryURI || !Array.isArray(dataset.srvDescription) || !dataset.srvDescription.length) fail("registrar dataset description and registry URI required");
  const registry = registration.registry_uri ?? registration.registryURI;
  if (registry && registry !== dataset.registryURI) fail("registrar dataset registry URI mismatch");
  const description = registration.srv_description ?? registration.srvDescription;
  if (description && JSON.stringify(languageValues(description)) !== JSON.stringify(languageValues(dataset.srvDescription))) fail("registrar dataset service description mismatch");
  const privacy = intendedUse?.privacy_policy ?? intendedUse?.privacyPolicy ?? registration?.privacy_policy ?? registration?.privacyPolicy;
  const urls = typeof privacy === "string" ? [privacy] : (privacy || []).map((entry) => entry.url);
  try {
    const policy = new URL(dataset.policyURI);
    if (!["http:", "https:"].includes(policy.protocol) || policy.username || policy.password) fail("invalid registrar dataset privacy policy URL");
  } catch { fail("invalid registrar dataset privacy policy URL"); }
  // Raidiam can omit privacy_policy from the signed WRPRC. In that case the
  // policy must come from the authenticated registration response retained by
  // provisioning; a present signed policy must always agree with the dataset.
  if (privacy !== undefined && !urls.includes(dataset.policyURI)) fail("registrar dataset privacy policy mismatch");
  const purpose = intendedUse?.purpose ?? registration?.purpose;
  if (!Array.isArray(purpose) || !purpose.length || JSON.stringify(languageValues(purpose)) !== JSON.stringify(languageValues(dataset.purpose))) fail("registrar dataset purpose mismatch");
  if (dataset.credentials) assertQueryScope({ credentials: dataset.credentials }, intendedUse);
  return true;
}
