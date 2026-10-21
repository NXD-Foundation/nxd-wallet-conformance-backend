import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { X509Certificate } from "node:crypto";
import { decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { walletRedisClient } from "./cache.js";
import { makeSessionLogger } from "./logger.js";
import { createWalletContext } from "../../../utils/sessionContext.js";
import {
  checkAccessCertificateTrust,
  checkVerifierCredentialTrust,
  isTrustFrameworkSession,
} from "../../../utils/trustFrameworkPolicy.js";
import { validateVerifierAttestationTrust } from "../../../utils/cs02TrustPolicy.js";
import { certificateFromX5c, certificatesFromX5c } from "../../../trust/crypto.js";
import { assertQueryScope, assertRegistrarDataset, decodeRegistrationCertificate, resolveRegistrationIntendedUse, verifyWrprc } from "../../../utils/wrprc.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DEFAULT_ROLE_MAP_PATH = path.join(ROOT, "data/trust-role-map.json");
const ISSUER_PROVIDER_ROLES = [
  "pid-provider",
  "pub-eaa-provider",
  "eaa-provider",
  "qeaa-provider",
  "ebwoid-provider",
];
let roleMapPromise = null;
let testSessionStorage = null;

export function setWalletTrustSessionStorageForTests(storage = null) {
  testSessionStorage = storage;
}

async function getSessionValue(key) {
  return testSessionStorage ? testSessionStorage.get(key) : walletRedisClient.get(key);
}

async function setSessionValue(key, ttl, value) {
  if (testSessionStorage) return testSessionStorage.set(key, value, ttl);
  return walletRedisClient.setEx(key, ttl, value);
}

export class WalletTrustError extends Error {
  constructor(message, decision = null) {
    super(message);
    this.name = "WalletTrustError";
    this.decision = decision;
    this.errorCode = decision?.reasonCode || "TRUST_EVALUATION_INDETERMINATE";
  }
}

export async function loadWalletTrustSession(sessionId) {
  if (!sessionId) return null;
  const raw = await getSessionValue(`wallet:test-session:${sessionId}`);
  return raw ? JSON.parse(raw) : null;
}

export async function recordWalletTrustDecision(sessionId, decision, operation) {
  if (!sessionId || !decision) return;
  const key = `wallet:test-session:${sessionId}`;
  const raw = await getSessionValue(key);
  if (!raw) return;
  const current = JSON.parse(raw);
  const enriched = { ...decision, operation, evaluatedAt: new Date().toISOString() };
  const next = createWalletContext({
    sessionContext: current.sessionContext,
    id: sessionId,
    flow: current.sessionContext?.flow || current.flow,
    status: current.status,
    trustPolicy: current.trustPolicy,
  }).withTrustDecision(enriched).toSession({
    ...current,
    trustDecision: enriched,
    trustDecisions: [...(current.trustDecisions || []), enriched],
  });
  await setSessionValue(key, Number(process.env.WALLET_TEST_SESSION_TTL || 86400), JSON.stringify(next));
  try { makeSessionLogger(sessionId)("[TRUST] wallet decision", { operation, trusted: decision.trusted, reasonCode: decision.reasonCode, state: decision.state }); } catch {}
}

export async function isWalletTrustEnabled(sessionId) {
  const session = await loadWalletTrustSession(sessionId);
  return { session, enabled: isTrustFrameworkSession(session) };
}

async function roleMap() {
  roleMapPromise ||= fs.readFile(process.env.WALLET_TRUST_ROLE_MAP_PATH || DEFAULT_ROLE_MAP_PATH, "utf8")
    .then(JSON.parse)
    .then((value) => value?.credentialTypes || {});
  return roleMapPromise;
}

export async function resolveIssuerRole({ vct = null, doctype = null } = {}) {
  const map = await roleMap();
  return map[vct || doctype] || null;
}

export function credentialTypeFromJwtVcPayload(payload = {}) {
  const candidates = [payload?.vct, payload?.credential_type, payload?.vc?.type]
    .flatMap((value) => Array.isArray(value) ? value : [value])
    .filter((value) => typeof value === "string" && value.length > 0);
  return candidates.find((value) => value !== "VerifiableCredential") || candidates[0] || null;
}

function scopeOmission({ scopeEvidence = null, credentialType = null, operation }) {
  if (Array.isArray(scopeEvidence?.credentialTypes) && scopeEvidence.credentialTypes.length > 0) return null;
  return {
    code: "TRUST_SCOPE_NOT_DECLARED",
    operation,
    credentialType,
    message: "Trusted provider registration/list does not declare credential or claim scope; accepted for test-infrastructure interoperability",
  };
}

function withScopeOmission(decision, omission) {
  if (!omission) return decision;
  return { ...decision, evidence: { ...(decision?.evidence || {}), scopeOmission: omission } };
}

function logScopeOmission(sessionId, omission) {
  if (!sessionId || !omission) return;
  try { makeSessionLogger(sessionId)("[TRUST] scope omission accepted", omission); } catch {}
}

export function x5cEvidence(header) {
  if (!Array.isArray(header?.x5c) || header.x5c.length === 0) return null;
  return { certificatePem: certificateFromX5c(header.x5c), certificateChain: certificatesFromX5c(header.x5c) };
}

export async function enforceIssuedCredentialTrust({ sessionId, payload, header, format, vct, doctype, scopeEvidence = null, trustEvidenceBound = true }) {
  const { session, enabled } = await isWalletTrustEnabled(sessionId);
  if (!enabled) return null;
  if (!trustEvidenceBound) {
    const decision = {
      trusted: false,
      state: "not_trusted",
      reasonCode: "CREDENTIAL_SIGNATURE_UNVERIFIED",
      evidence: { operation: "wallet-store-credential", format, vct, doctype, credentialSignatureVerified: false, trustEvidenceBound: false },
    };
    await recordWalletTrustDecision(sessionId, decision, "wallet-store-credential");
    throw new WalletTrustError("Trust-enabled credential storage requires the presented x5c certificate to verify the issuer signature", decision);
  }
  const evidence = x5cEvidence(header);
  if (!evidence) {
    const decision = { trusted: false, state: "not_trusted", reasonCode: "ANCHOR_MISMATCH", evidence: { operation: "wallet-store-credential", format, vct, doctype, role: null } };
    await recordWalletTrustDecision(sessionId, decision, "wallet-store-credential");
    throw new WalletTrustError("Credential issuer does not provide trusted role/certificate evidence", decision);
  }
  const mappedRole = await resolveIssuerRole({ vct, doctype });
  // The map is only a lookup hint for this test infrastructure. It must not
  // become an undeclared local authorization policy when the TL/Registrar has
  // not published credential scope.
  const candidateRoles = mappedRole
    ? [mappedRole, ...ISSUER_PROVIDER_ROLES.filter((role) => role !== mappedRole)]
    : ISSUER_PROVIDER_ROLES;
  let decision = null;
  for (const role of candidateRoles) {
    const candidate = await checkVerifierCredentialTrust({
      session, payload, certificatePem: evidence.certificatePem, certificateChain: evidence.certificateChain,
      format, vct, doctype, role, scopeEvidence, operation: "wallet-store-credential",
    });
    decision ||= candidate;
    if (candidate?.trusted) {
      decision = candidate;
      break;
    }
  }
  const omission = scopeOmission({
    scopeEvidence,
    credentialType: vct || doctype,
    operation: "wallet-store-credential",
  });
  decision = withScopeOmission(decision, omission);
  await recordWalletTrustDecision(sessionId, decision, "wallet-store-credential");
  if (!decision?.trusted) throw new WalletTrustError(`Credential issuer trust rejected: ${decision?.reasonCode || "TRUST_EVALUATION_INDETERMINATE"}`, decision);
  logScopeOmission(sessionId, omission);
  return decision;
}

function entityIdentifier(certificatePem) {
  const subject = new X509Certificate(certificatePem).subject.split("\n").map((value) => value.trim());
  return subject.find((value) => /^(organizationIdentifier|serialNumber)=/i.test(value))?.replace(/^[^=]+=/, "") || null;
}

export function assertVerifierCertificateBinding({ clientId, certificatePem, entityId }) {
  if (!entityId) {
    throw new WalletTrustError("Verifier WRPAC is missing an entity identifier required for WRPRC binding");
  }
  if (!clientId.startsWith("x509_san_dns:")) return;
  const host = clientId.slice("x509_san_dns:".length);
  if (!host || new X509Certificate(certificatePem).checkHost(host) == null) {
    throw new WalletTrustError("Verifier WRPAC SAN does not match x509_san_dns client_id");
  }
}

export async function assertVerifierAttestationBinding({ clientId, requestHeader }) {
  if (!clientId.startsWith("verifier_attestation:")) return null;
  const attestation = await validateVerifierAttestationTrust(requestHeader, clientId);
  const expectedSubject = clientId.slice("verifier_attestation:".length);
  if (!attestation.structureValid || attestation.parsedPayload?.sub !== expectedSubject) {
    throw new WalletTrustError("Verifier attestation JWT is malformed or not bound to verifier_attestation client_id");
  }
  return attestation;
}

export function credentialMatchesRequest(registered, requested) {
  try { return assertQueryScope({ credentials: [requested] }, { credentials: [registered] }); }
  catch { return false; }
}

// A selected intended use is required: never union authorization from different purposes.
export function registrationCredentials(registration, intendedUseId) {
  try { return resolveRegistrationIntendedUse(registration, { intendedUseId }).credentials; }
  catch { return []; }
}

export function authorizeVerifierRegistrationScope({ registration, requested, intendedUseId }) {
  try {
    assertQueryScope({ credentials: requested }, resolveRegistrationIntendedUse(registration, { intendedUseId }));
    return { authorized: true, scopeOmission: null };
  } catch { return { authorized: false, scopeOmission: null }; }
}

export function parseVerifierInfo(verifierInfo) {
  if (!Array.isArray(verifierInfo)) throw new WalletTrustError("verifier_info must be an array containing a registrar dataset and registration certificate");
  const datasets = verifierInfo.filter((entry) => entry?.format === "registrar_dataset");
  const certificates = verifierInfo.filter((entry) => entry?.format === "registration_cert");
  if (datasets.length !== 1 || certificates.length !== 1) throw new WalletTrustError("verifier_info requires exactly one registrar dataset and registration certificate");
  const dataset = datasets[0].data;
  if (!dataset || typeof dataset !== "object" || Array.isArray(dataset) || !dataset.intendedUseIdentifier) throw new WalletTrustError("Registrar dataset must identify the selected intended use");
  return { dataset, token: decodeRegistrationCertificate(certificates[0].data) };
}

async function verifyRegistrationCertificate(registrationCert, session, expectedEntityId) {
  if (typeof registrationCert !== "string") throw new WalletTrustError("Verifier registration certificate is missing");
  const header = decodeProtectedHeader(registrationCert);
  const evidence = x5cEvidence(header);
  if (!evidence) throw new WalletTrustError("Verifier registration certificate has no x5c");
  const decision = await checkAccessCertificateTrust({
    session,
    certificatePem: evidence.certificatePem,
    certificateChain: evidence.certificateChain,
    role: "wrprc-provider",
    operation: "wallet-verify-wrprc",
  });
  if (!decision?.trusted) throw new WalletTrustError(`Verifier registration certificate trust rejected: ${decision?.reasonCode || "TRUST_EVALUATION_INDETERMINATE"}`, decision);
  const verified = await jwtVerify(registrationCert, await importX509(evidence.certificatePem, header.alg || "ES256"));
  const payload = verified.payload;
  if (expectedEntityId && payload.sub !== expectedEntityId) throw new WalletTrustError("Verifier registration certificate entity does not match WRPAC");
  return { payload, decision };
}

function attestationTypesFromRegistration(payload) {
  return (payload?.provides_attestations || payload?.providesAttestations || [])
    .flatMap((entry) => {
      const meta = typeof entry?.meta === "string" ? JSON.parse(entry.meta) : (entry?.meta || {});
      return meta.vct_values || [meta.vct, meta.doctype, meta.doctype_value].filter(Boolean);
    });
}

export async function resolveIssuerScopeEvidence({ sessionId, issuerMetadata }) {
  const { session, enabled } = await isWalletTrustEnabled(sessionId);
  if (!enabled) return null;
  const registrationCert = issuerMetadata?.registration_certificate || issuerMetadata?.registration_cert;
  if (!registrationCert) return null;
  const { payload, decision } = await verifyRegistrationCertificate(registrationCert, session, issuerMetadata?.credential_issuer || null);
  await recordWalletTrustDecision(sessionId, decision, "wallet-verify-issuer-registration");
  return {
    verified: true,
    registrar: payload.iss || null,
    credentialTypes: attestationTypesFromRegistration(payload),
  };
}

export async function enforceVerifierPresentationTrust({ sessionId, requestHeader, requestPayload, trustEvidenceBound = true }) {
  const { session, enabled } = await isWalletTrustEnabled(sessionId);
  if (!enabled) return null;
  const clientId = String(requestPayload?.client_id || "");
  if (!clientId.startsWith("x509_hash:") && !clientId.startsWith("x509_san_dns:") && !clientId.startsWith("verifier_attestation:")) {
    const decision = { trusted: true, state: "not_applicable", reasonCode: "DID_TRUST_NOT_IMPLEMENTED", evidence: { clientId } };
    await recordWalletTrustDecision(sessionId, decision, "wallet-verify-verifier");
    return decision;
  }
  if (!trustEvidenceBound) {
    throw new WalletTrustError("Trust-enabled verifier requests require the presented WRPAC x5c certificate to verify the authorization request");
  }
  const requested = requestPayload?.dcql_query?.credentials;
  if (!Array.isArray(requested) || requested.length === 0) {
    throw new WalletTrustError(
      "Trust-enabled verifier requests must include non-empty dcql_query.credentials; presentation_definition and unscoped requests are not supported",
    );
  }
  const evidence = x5cEvidence(requestHeader);
  if (!evidence) throw new WalletTrustError("Verifier request has no WRPAC x5c");
  const entityId = entityIdentifier(evidence.certificatePem);
  await assertVerifierAttestationBinding({ clientId, requestHeader });
  assertVerifierCertificateBinding({ clientId, certificatePem: evidence.certificatePem, entityId });
  const accessDecision = await checkAccessCertificateTrust({
    session,
    certificatePem: evidence.certificatePem,
    certificateChain: evidence.certificateChain,
    role: "wrpac-provider",
    entityId,
    operation: "wallet-verify-wrpac",
  });
  await recordWalletTrustDecision(sessionId, accessDecision, "wallet-verify-wrpac");
  if (!accessDecision?.trusted) throw new WalletTrustError(`Verifier access certificate trust rejected: ${accessDecision?.reasonCode || "TRUST_EVALUATION_INDETERMINATE"}`, accessDecision);
  try {
    const { dataset, token } = parseVerifierInfo(requestPayload?.verifier_info);
    const intendedUseId = dataset.intendedUseIdentifier;
    const serviceId = dataset.serviceId || dataset.serviceIdentifier || dataset.service_id;
    const accessServiceId = new X509Certificate(evidence.certificatePem).subject.match(/(?:^|\n)OU\s*=\s*([^\n]+)/)?.[1]?.trim();
    if (serviceId && accessServiceId && serviceId !== accessServiceId) throw new WalletTrustError("Registrar dataset service does not match WRPAC");
    const { payload: registration, intendedUse, trustDecision } = await verifyWrprc(token, {
      entityId, intendedUseId, serviceId,
      checkTrust: (material) => checkAccessCertificateTrust({ ...material, session, operation: "wallet-verify-wrprc" }),
    });
    assertRegistrarDataset(dataset, { registration, intendedUse, entityId, intendedUseId, serviceId });
    assertQueryScope(requestPayload.dcql_query, intendedUse);
    await recordWalletTrustDecision(sessionId, trustDecision, "wallet-verify-wrprc");
    return trustDecision;
  } catch (error) {
    const decision = { trusted: false, state: "not_trusted", reasonCode: "VERIFIER_REGISTRATION_INVALID", evidence: { entityId, message: error.message } };
    await recordWalletTrustDecision(sessionId, decision, "wallet-verify-wrprc");
    throw new WalletTrustError(error.message, decision);
  }
}
