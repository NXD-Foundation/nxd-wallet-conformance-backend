import { decodeSdJwtSync, getClaimsSync } from "@sd-jwt/decode";
import { digest } from "@sd-jwt/crypto-nodejs";
import { resolveDeferredPollIntervalMs } from "./deferredIssuance.js";
import { createDpopNonceState } from "./dpopNonce.js";
import { requestWithResourceDpop, requestCredentialNonce } from "./dpopIssuanceTransport.js";
import { isWebuildCs01Profile } from "./profile.js";
import {
  assertDpopBoundTokenReceived,
  assertAccessTokenCnfMatchesDpop,
  buildResourceRequestHeaders,
} from "./dpopBinding.js";
import {
  buildCredentialProofRequest,
  buildCredentialProofBindingContext,
  buildDeferredCredentialPollRequest,
  toKeyBindingMaterial,
} from "./credentialProofBinding.js";
import { pollDeferredCredentialIssuance } from "./deferredIssuance.js";
import { createAttestationChallengeState } from "./attestationChallenge.js";
import { resolveCredentialRequestTargets } from "./scopeResolution.js";
import { describeIssuanceRefreshTokenMetadata } from "./cs01Conformance.js";

export function buildReissuanceBinding({
  profile,
  refreshToken,
  dpopBinding,
  walletClientId,
  apiBase,
  issuerMeta,
  tokenEndpoint,
  authorizationServerIssuer,
  keyPath,
  trustSessionId = null,
  configurationId = null,
}) {
  if (!isWebuildCs01Profile(profile) || typeof refreshToken !== "string" || !refreshToken) {
    return null;
  }
  if (!dpopBinding?.privateJwk || !dpopBinding?.publicJwk) {
    return null;
  }
  return {
    refreshToken,
    privateJwk: dpopBinding.privateJwk,
    publicJwk: dpopBinding.publicJwk,
    nonceState: dpopBinding.nonceState
      ? JSON.parse(JSON.stringify(dpopBinding.nonceState))
      : createDpopNonceState(),
    walletClientId,
    apiBase,
    issuerMeta,
    tokenEndpoint,
    authorizationServerIssuer,
    keyPath: keyPath || null,
    trustSessionId,
    configurationId,
  };
}

export function extractReissuanceCredentialToken(envelope) {
  if (typeof envelope === "string") return envelope;
  return envelope?.credential || envelope?.credentials?.[0]?.credential || null;
}

function parseSdJwtPayload(envelope) {
  const token = extractReissuanceCredentialToken(envelope);
  if (typeof token !== "string" || !token.includes("~")) return null;
  try {
    const decoded = decodeSdJwtSync(token, digest);
    return getClaimsSync(decoded.jwt.payload, decoded.disclosures, digest);
  } catch {
    return null;
  }
}

/** Retry temporary refusal with a bounded delay; grant/client/proof errors remain terminal. */
export async function requestWithReissuanceBackoff(send, {
  pollTimeoutMs = 30000, pollIntervalMs, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  now = Date.now, maxAttempts = 3,
} = {}) {
  const started = now();
  const interval = resolveDeferredPollIntervalMs(null, pollIntervalMs);
  for (let attempt = 0; ; attempt++) {
    const response = await send();
    if (response.ok || response.status === 202) return response;
    let body = {};
    try { body = JSON.parse(response.bodyText ?? await response.clone().text()); } catch {}
    const terminal = ["invalid_grant", "invalid_client", "invalid_request", "invalid_dpop_proof", "invalid_proof", "invalid_token"];
    const retryable = !terminal.includes(body.error) &&
      (response.status === 429 || response.status >= 500 || body.error === "credential_request_denied" || body.error === "temporarily_unavailable");
    const retryAfter = Number(response.headers?.get("Retry-After"));
    const delay = Math.max(interval * 2 ** attempt, Number.isFinite(retryAfter) ? retryAfter * 1000 : 0);
    if (!retryable || attempt + 1 >= maxAttempts || now() - started + delay >= pollTimeoutMs) return response;
    await sleep(delay);
  }
}

export function diffCredentialAttributes(previousToken, nextToken) {
  const prev = parseSdJwtPayload(previousToken);
  const next = parseSdJwtPayload(nextToken);
  if (!prev || !next) {
    return { comparable: false, changes: [] };
  }
  const ignore = new Set(["iat", "exp", "nbf", "cnf", "_sd", "_sd_alg"]);
  const keys = new Set([...Object.keys(prev), ...Object.keys(next)]);
  const changes = [];
  for (const key of keys) {
    if (ignore.has(key)) continue;
    const a = prev[key];
    const b = next[key];
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      changes.push({ key, previous: a, next: b });
    }
  }
  return { comparable: true, changes };
}

export async function runRefreshTokenReissuance({
  profile,
  binding,
  configurationId,
  attestationChallengeState = createAttestationChallengeState(),
  httpPostFormWithAttestationNonceRetry,
  httpPostJson,
  fetchImpl,
  validateAndStoreCredential,
  persistReissuanceBinding = async () => {},
  buildCredentialProofRequest: buildProof = buildCredentialProofRequest,
  retryOptions = {},
  pollDeferredCredentialIssuance: pollDeferred = pollDeferredCredentialIssuance,
  pollTimeoutMs,
  pollIntervalMs,
  logSessionId,
  log = () => {},
  previousCredentialEnvelope = null,
}) {
  if (binding?.configurationId && binding.configurationId !== configurationId) {
    throw new Error("reissuance_error: credential configuration does not match the original issuance");
  }
  if (!binding?.refreshToken) {
    const error = new Error("reissuance_error: no refresh token binding for this credential");
    error.errorCode = "reauthorization_required";
    throw error;
  }

  const dpopBinding = {
    privateJwk: binding.privateJwk,
    publicJwk: binding.publicJwk,
    nonceState: binding.nonceState || createDpopNonceState(),
  };
  dpopBinding.nonceState.authorizationServer = binding.authorizationServerIssuer;
  dpopBinding.nonceState.resourceServer = binding.issuerMeta?.credential_issuer || binding.apiBase;

  const tokenRes = await requestWithReissuanceBackoff(() => httpPostFormWithAttestationNonceRetry({
    url: binding.tokenEndpoint,
    params: {
      grant_type: "refresh_token",
      refresh_token: binding.refreshToken,
    },
    logSessionId,
    profile,
    keyPath: binding.keyPath,
    clientId: binding.walletClientId,
    endpointAudience: binding.tokenEndpoint,
    authorizationServerIssuer: binding.authorizationServerIssuer,
    stage: "refresh token request",
    challengeState: attestationChallengeState,
    dpopKeyPair: dpopBinding,
    nonceState: dpopBinding.nonceState,
  }), { pollTimeoutMs, pollIntervalMs, ...retryOptions });

  const tokenText = tokenRes.bodyText ?? (await tokenRes.text().catch(() => ""));
  if (!tokenRes.ok) {
    let err = {};
    try {
      err = JSON.parse(tokenText);
    } catch {}
    if (err.error === "invalid_grant") {
      const error = new Error(`reissuance_error: ${tokenText || err.error_description || "invalid_grant"}`);
      error.errorCode = "reauthorization_required";
      throw error;
    }
    throw new Error(`token_error ${tokenRes.status}: ${tokenText}`);
  }

  let tokenBody;
  try {
    tokenBody = JSON.parse(tokenText);
  } catch (e) {
    throw new Error(`token_error: invalid JSON response - ${e?.message}`);
  }

  const accessToken = tokenBody.access_token;
  assertDpopBoundTokenReceived(profile, tokenBody, accessToken);
  await assertAccessTokenCnfMatchesDpop(profile, accessToken, dpopBinding.publicJwk);

  const nextBinding = buildReissuanceBinding({
    profile, refreshToken: tokenBody.refresh_token, dpopBinding,
    walletClientId: binding.walletClientId, apiBase: binding.apiBase,
    issuerMeta: binding.issuerMeta, tokenEndpoint: binding.tokenEndpoint,
    authorizationServerIssuer: binding.authorizationServerIssuer, keyPath: binding.keyPath,
    trustSessionId: binding.trustSessionId, configurationId,
  });
  if (!nextBinding) throw new Error("token_error: rotated refresh_token is required for re-issuance");
  nextBinding.trustPolicy = binding.trustPolicy;
  await persistReissuanceBinding(nextBinding);
  Object.assign(binding, nextBinding);

  let c_nonce = tokenBody.c_nonce;
  let c_nonce_expires_in = tokenBody.c_nonce_expires_in;
  const issuerMeta = binding.issuerMeta;
  const apiBase = binding.apiBase;

  if (!c_nonce && issuerMeta.nonce_endpoint) {
    const nonceRes = await requestCredentialNonce({
      url: issuerMeta.nonce_endpoint,
      binding: dpopBinding,
      log,
      send: (proof) => httpPostJson(issuerMeta.nonce_endpoint, {}, logSessionId, proof ? { DPoP: proof } : {}),
    });
    if (!nonceRes.ok) {
      throw new Error(`nonce_error ${nonceRes.status}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
    c_nonce_expires_in = nonceJson.c_nonce_expires_in;
  } else if (!c_nonce) {
    throw new Error("nonce_error: issuer did not provide c_nonce and no nonce_endpoint is available");
  }

  const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
  const credentialTarget = resolveCredentialRequestTargets({ configurationId, tokenResponse: tokenBody })[0];
  let proofBundle;
  let credentialAttempts = 0;
  const credRes = await requestWithReissuanceBackoff(async () => {
    // A refusal may follow proof/nonce consumption. Rebuild both the proof and KA
    // for each back-off attempt; DPoP nonce retries within an attempt keep the body.
    if (credentialAttempts++ > 0 && issuerMeta.nonce_endpoint) {
      const nonceRes = await requestCredentialNonce({
        url: issuerMeta.nonce_endpoint, binding: dpopBinding, log,
        send: proof => httpPostJson(issuerMeta.nonce_endpoint, {}, logSessionId, proof ? { DPoP: proof } : {}),
      });
      if (!nonceRes.ok) throw new Error(`nonce_error ${nonceRes.status}`);
      const nonceJson = await nonceRes.json();
      c_nonce = nonceJson.c_nonce;
      c_nonce_expires_in = nonceJson.c_nonce_expires_in;
    }
    proofBundle = await buildProof({
      profile, keyPath: binding.keyPath, issuerMeta, apiBase, configurationId,
      credentialIdentifier: credentialTarget.credential_identifier,
      cNonce: c_nonce, credentialEndpoint, clientId: binding.walletClientId,
    });
    const credReqBody = JSON.stringify(proofBundle.credentialRequest);
    return requestWithResourceDpop({
      url: credentialEndpoint, binding: dpopBinding, profile, tokenBody, accessToken, log,
      send: proof => fetchImpl(credentialEndpoint, {
        method: "POST", body: credReqBody,
        headers: { "content-type": "application/json", ...buildResourceRequestHeaders(accessToken, proof, tokenBody) },
      }),
    });
  }, { pollTimeoutMs, pollIntervalMs, ...retryOptions });

  const responseText = await credRes.text().catch(() => "");
  let credBody;
  if (credRes.status === 202) {
    credBody = JSON.parse(responseText);
    const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
    credBody = await pollDeferred({
      transactionId: credBody.transaction_id,
      issuerIntervalSeconds: credBody.interval,
      pollTimeoutMs,
      pollIntervalMs,
      deferredEndpoint,
      buildPollRequest: () =>
        buildDeferredCredentialPollRequest({
          profile,
          dpopBinding,
          tokenBody,
          accessToken,
          subjectKey: proofBundle.subjectKey,
          deferredEndpoint,
          transactionId: credBody.transaction_id,
        }),
      httpPostJson,
      logSessionId,
      sleep: retryOptions.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms))),
      log,
    });
  } else if (!credRes.ok) {
    throw new Error(`credential_error ${credRes.status}: ${responseText}`);
  } else {
    credBody = JSON.parse(responseText);
  }

  nextBinding.nonceState = JSON.parse(JSON.stringify(dpopBinding.nonceState));
  const proofBinding = buildCredentialProofBindingContext({
    profile,
    subjectKey: proofBundle.subjectKey,
    dpopBinding,
    tokenBody,
    accessToken,
    keyAttestation: proofBundle.keyAttestation,
  });

  await validateAndStoreCredential({
    configurationId,
    credential: credBody,
    issuerMeta,
    apiBase,
    keyBinding: toKeyBindingMaterial(proofBundle.subjectKey),
    metadata: {
      configurationId,
      c_nonce,
      c_nonce_expires_in,
      proofBinding,
      reissuanceBinding: nextBinding,
      refreshToken: describeIssuanceRefreshTokenMetadata(tokenBody),
    },
    authorizationServerMeta: issuerMeta._authorizationServerMeta,
  }, logSessionId);

  const attributeDiff = diffCredentialAttributes(
    previousCredentialEnvelope,
    credBody,
  );

  return {
    credential: credBody,
    issuanceContext: {
      configurationId,
      grantRoute: "refresh_token",
      refreshToken: describeIssuanceRefreshTokenMetadata(tokenBody),
      attributeDiff,
    },
  };
}
