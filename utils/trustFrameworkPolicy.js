import { decodeJwt, decodeProtectedHeader } from "jose";
import { certificateFingerprint, certificateFromX5c, certificatesFromX5c } from "../trust/crypto.js";
import { createTrustResolver } from "../trust/resolver.js";
import { loadTrustProfile } from "../trust/profile.js";
import { loadTrustSnapshot } from "../trust/loader.js";
import { X509Certificate } from "node:crypto";
import fs from "node:fs/promises";
import { sessionTrustPolicy } from "./sessionContext.js";

const WEBUILD_PROFILE = "webuild-wp4-pilot";
let testResolver = null;
let runtimeResolverPromise = null;

export function normalizeTrustFrameworkFlag(value) {
  return value === true || value === "true";
}

export function trustFrameworkSessionProps(input = {}) {
  if (!normalizeTrustFrameworkFlag(input.trustFramework ?? input.trust_framework)) return {};
  return { trustPolicy: { mode: "webuild", profile: WEBUILD_PROFILE } };
}

export function isTrustFrameworkSession(session) {
  const trustPolicy = sessionTrustPolicy(session);
  return trustPolicy?.mode === "webuild" && typeof trustPolicy?.profile === "string";
}

export function resolveVerifierCredentialContext({ format, vct = null, doctype = null } = {}) {
  const context = String(vct || doctype || "").toLowerCase();
  if (context.includes("pid")) return { role: "pid-provider", credentialType: "pid" };
  if (context.includes("qeaa")) return { role: "qeaa-provider", credentialType: "qeaa" };
  if (context.includes("pub-eaa") || context.includes("pubeaa")) {
    return { role: "pub-eaa-provider", credentialType: "pub-eaa" };
  }
  if (context.includes("eaa")) return { role: "eaa-provider", credentialType: "eaa" };
  return { role: null, credentialType: format === "mso_mdoc" ? "mdoc" : "unknown" };
}

export function setTrustResolverForTests(resolver) {
  testResolver = resolver;
}

export function clearTrustResolverForTests() {
  testResolver = null;
  runtimeResolverPromise = null;
}

async function runtimeTrustResolver() {
  if (testResolver) return testResolver;
  runtimeResolverPromise ||= (async () => {
    const profile = await loadTrustProfile(process.env.TRUST_PROFILE_PATH || "data/trust/webuild-wp4-pilot.json");
    if (process.env.TRUST_LOTL_SIGNER_FINGERPRINTS) {
      profile.bootstrap.loTLSignerFingerprints = process.env.TRUST_LOTL_SIGNER_FINGERPRINTS.split(",").map((value) => value.trim()).filter(Boolean);
    }
    if (process.env.TRUST_ALLOW_EMBEDDED_LOTL_X5C === "true") {
      profile.bootstrap.loTLSignerFingerprints = [];
      profile.network.allowEmbeddedX5cBootstrapForTests = true;
      console.warn("[TRUST] UNSAFE test-only LoTL bootstrap enabled: trusting embedded x5c");
    }
    return createTrustResolver({
      profile,
      snapshotProvider: ({ profile: selectedProfile, request }) => loadTrustSnapshot({ profile: selectedProfile, listTypes: [request.role] }),
    });
  })();
  return runtimeResolverPromise;
}

export async function checkWalletProviderTrust({ session, attestationJwt = null, payload = null, header = null, operation = "verify-wia" }) {
  if (!isTrustFrameworkSession(session)) return null;
  const trustPolicy = sessionTrustPolicy(session);
  try {
    const resolvedPayload = payload || (attestationJwt ? decodeJwt(attestationJwt) : null);
    const resolvedHeader = header || (attestationJwt ? decodeProtectedHeader(attestationJwt) : null);
    if (!resolvedPayload || !resolvedHeader?.x5c?.length) {
      return {
        trusted: false,
        state: "not_trusted",
        reasonCode: "ANCHOR_MISMATCH",
        evidence: { role: "wallet-provider", operation, issuer: resolvedPayload?.iss || null, trustPolicy },
      };
    }
    const certPem = certificateFromX5c(resolvedHeader.x5c);
    const resolver = await runtimeTrustResolver();
    return resolver.resolve({
      framework: trustPolicy.profile,
      role: "wallet-provider",
      operation,
      presentedIdentity: {
        issuer: resolvedPayload.iss || null,
        entityId: resolvedPayload.iss || null,
        certificateFingerprint: certificateFingerprint(certPem),
        certificateChain: certificatesFromX5c(resolvedHeader.x5c),
      },
      credentialContext: { attestationType: operation },
      policy: { requireRevocation: false },
    });
  } catch (error) {
    return {
      trusted: false,
      state: "indeterminate",
      reasonCode: "TRUST_EVALUATION_INDETERMINATE",
      evidence: { role: "wallet-provider", operation, trustPolicy, error: error.message },
    };
  }
}

export async function checkVerifierCredentialTrust({
  session,
  payload,
  header = null,
  certificatePem = null,
  format = "dc+sd-jwt",
  vct = null,
  doctype = null,
  operation = "verify-credential",
} = {}) {
  if (!isTrustFrameworkSession(session)) return null;
  const trustPolicy = sessionTrustPolicy(session);
  const context = resolveVerifierCredentialContext({ format, vct, doctype });
  if (!context.role) {
    return {
      trusted: false,
      state: "not_trusted",
      reasonCode: "UNSUPPORTED_ROLE",
      evidence: {
        role: null,
        operation,
        format,
        vct,
        doctype,
        trustPolicy,
        error: "No WP4 provider role mapping exists for this credential context",
      },
    };
  }
  try {
    const certificate = certificatePem || (header?.x5c?.length ? certificateFromX5c(header.x5c) : null);
    const certificateChain = header?.x5c?.length ? certificatesFromX5c(header.x5c) : certificate ? [certificate] : [];
    let certificateSubject = null;
    if (certificate) {
      try {
        certificateSubject = new X509Certificate(certificate).subject
          .split("\n")
          .map((part) => part.trim())
          .find((part) => part.startsWith("CN="))
          ?.slice(3) || null;
      } catch {}
    }
    const issuer = payload?.iss || certificateSubject;
    if (!issuer || !certificate) {
      return {
        trusted: false,
        state: "not_trusted",
        reasonCode: "ANCHOR_MISMATCH",
        evidence: {
          role: context.role,
          operation,
          format,
          vct,
          doctype,
          issuer: issuer || null,
          hasX5c: !!certificate,
          trustPolicy,
        },
      };
    }
    const resolver = await runtimeTrustResolver();
    return resolver.resolve({
      framework: trustPolicy.profile,
      role: context.role,
      operation,
      presentedIdentity: {
        issuer,
        entityId: issuer,
        certificateFingerprint: certificateFingerprint(certificate),
        certificateChain,
      },
      credentialContext: {
        format,
        vct,
        doctype,
      },
      policy: { requireRevocation: false },
    });
  } catch (error) {
    return {
      trusted: false,
      state: "indeterminate",
      reasonCode: "TRUST_EVALUATION_INDETERMINATE",
      evidence: {
        role: context.role,
        operation,
        format,
        vct,
        doctype,
        trustPolicy,
        error: error.message,
      },
    };
  }
}

export async function checkAccessCertificateTrust({
  session,
  certificatePem,
  entityId = null,
  role = "wrpac-provider",
  operation = "verify-access-certificate",
} = {}) {
  if (!isTrustFrameworkSession(session)) return null;
  const trustPolicy = sessionTrustPolicy(session);
  if (!certificatePem) {
    return {
      trusted: false,
      state: "not_trusted",
      reasonCode: "ANCHOR_MISMATCH",
      evidence: { role, operation, entityId, trustPolicy, error: "Access certificate is missing" },
    };
  }
  try {
    const resolver = await runtimeTrustResolver();
    return resolver.resolve({
      framework: trustPolicy.profile,
      role,
      operation,
      presentedIdentity: {
        entityId,
        certificateFingerprint: certificateFingerprint(certificatePem),
        certificateChain: [certificatePem],
      },
      credentialContext: { certificateType: role },
      policy: { requireRevocation: false },
    });
  } catch (error) {
    return {
      trusted: false,
      state: "indeterminate",
      reasonCode: "TRUST_EVALUATION_INDETERMINATE",
      evidence: { role, operation, entityId, trustPolicy, error: error.message },
    };
  }
}

export async function loadConfiguredAccessCertificate(role = "wrprc-provider", env = process.env) {
  const path = role === "wrprc-provider" ? env.TRUST_WRPRC_CERT_PATH : env.TRUST_WRPAC_CERT_PATH;
  if (!path) return null;
  return fs.readFile(path, "utf8");
}

export async function recordVerifierTrustDecision({ session, decision, store, sessionKey, sessionId, slog }) {
  if (!session || !decision) return;
  session.trustDecision = {
    trusted: decision.trusted,
    state: decision.state,
    reasonCode: decision.reasonCode,
    evidence: decision.evidence,
    evaluatedAt: new Date().toISOString(),
  };
  await store(sessionKey, session);
  try { slog?.("[TRUST] Verifier credential trust decision", session.trustDecision); } catch {}
  void sessionId;
}

export async function recordTrustDecision({ session, decision, store, sessionKey, sessionId, slog }) {
  if (!session || !decision) return;
  session.trustDecision = {
    trusted: decision.trusted,
    state: decision.state,
    reasonCode: decision.reasonCode,
    evidence: decision.evidence,
    evaluatedAt: new Date().toISOString(),
  };
  await store(sessionKey, session);
  try { slog?.("[TRUST] Wallet Provider trust decision", session.trustDecision); } catch {}
  void sessionId;
}

export async function recordTrustFailure({ session, store, sessionKey, sessionId, slog, operation, error }) {
  await recordTrustDecision({
    session,
    store,
    sessionKey,
    sessionId,
    slog,
    decision: {
      trusted: false,
      state: "indeterminate",
      reasonCode: "TRUST_EVALUATION_INDETERMINATE",
      evidence: {
        role: "wallet-provider",
        operation,
        error,
        trustPolicy: session?.trustPolicy,
      },
    },
  });
}
