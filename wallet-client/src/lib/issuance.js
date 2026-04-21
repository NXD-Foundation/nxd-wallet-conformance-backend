import { storeWalletCredentialByType } from "./cache.js";
import {
  extractNotificationId,
  resolveNotificationEndpoint,
  postCredentialAcceptedNotification,
} from "./credentialNotification.js";
import {
  getNextPollDelayMs,
  resolveDeferredPollResult,
  formatDeferredTerminalError,
} from "./deferredIssuancePoll.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function selectProofSigningAlg(issuerMeta, configurationId) {
  const supportedAlgs =
    issuerMeta?.proof_types_supported?.jwt?.proof_signing_alg_values_supported ||
    issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.jwt?.proof_signing_alg_values_supported ||
    [];
  const preferredOrder = ["ES256", "ES384", "ES512", "EdDSA"];
  return (Array.isArray(supportedAlgs) && supportedAlgs.length)
    ? (preferredOrder.find((alg) => supportedAlgs.includes(alg)) || supportedAlgs[0])
    : "ES256";
}

export async function buildKeyPairs({
  keyPaths,
  selectedAlg,
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
}) {
  const keyPairs = [];
  for (const keyPath of keyPaths) {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, selectedAlg);
    keyPairs.push({
      privateJwk,
      publicJwk,
      didJwk: generateDidJwkFromPrivateJwk(publicJwk),
    });
  }
  return keyPairs;
}

export async function notifyCredentialAcceptedIfNeeded({
  credentialResponse,
  issuerMeta,
  apiBase,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
}) {
  const notificationId = extractNotificationId(credentialResponse);
  const notificationEndpoint = resolveNotificationEndpoint(issuerMeta, apiBase);
  if (!notificationId || !accessToken) return;
  await postCredentialAcceptedNotification({
    notificationEndpoint,
    notificationId,
    accessToken,
    tokenBody,
    dpopPrivateJwk,
    dpopPublicJwk,
  });
}

export async function storeIssuedCredentials(configurationId, credentialResponse, keyPairs, metadataBase = {}) {
  const notificationId = extractNotificationId(credentialResponse);
  const metadata = {
    ...metadataBase,
    ...(notificationId ? { notification_id: notificationId } : {}),
  };
  const entries = Array.isArray(credentialResponse?.credentials)
    ? credentialResponse.credentials
    : null;

  if (entries && entries.length > 1) {
    await storeWalletCredentialByType(configurationId, {
      multi: true,
      entries: entries.map((item, index) => ({
        credential: typeof item?.credential === "string" ? { credential: item.credential } : item,
        keyBinding: {
          privateJwk: keyPairs[index].privateJwk,
          publicJwk: keyPairs[index].publicJwk,
          didJwk: keyPairs[index].didJwk,
        },
        metadata: { ...metadata, attestedKeyIndex: index },
      })),
      metadata,
    });
    return;
  }

  await storeWalletCredentialByType(configurationId, {
    credential: credentialResponse,
    keyBinding: {
      privateJwk: keyPairs[0].privateJwk,
      publicJwk: keyPairs[0].publicJwk,
      didJwk: keyPairs[0].didJwk,
    },
    metadata,
  });
}

export async function exchangeToken({
  tokenEndpoint,
  tokenPayload,
  authorizationServerIssuer,
  ensureOrCreateEcKeyPair,
  createDPoP,
  resolveAttestationForEndpoint,
  shouldRetryTokenExchangeAfterRotatingWalletProviderKey,
  rotateWalletProviderKeyPair,
  postForm,
  deviceKeyPath,
  log,
  logPrefix,
}) {
  let dpopPrivateJwk = null;
  let dpopPublicJwk = null;
  let tokenBody = null;
  let lastTokenResponseText = "";

  for (let attempt = 0; attempt < 2; attempt++) {
    let dpopJwt = null;
    let oauthClientAttestationHeaders = {};
    let clientAssertionJwt = null;

    try {
      const dpopKeys = await ensureOrCreateEcKeyPair(deviceKeyPath, "ES256");
      dpopPrivateJwk = dpopKeys.privateJwk;
      dpopPublicJwk = dpopKeys.publicJwk;
      dpopJwt = await createDPoP({
        privateJwk: dpopPrivateJwk,
        publicJwk: dpopPublicJwk,
        htu: tokenEndpoint,
        htm: "POST",
        alg: "ES256",
      });
      log?.(`${logPrefix} DPoP generated`, { hasDPoP: true });
    } catch (error) {
      log?.(`${logPrefix} DPoP generation failed`, { error: error?.message });
    }

    try {
      const attestation = await resolveAttestationForEndpoint({
        endpointAudience: tokenEndpoint,
        authorizationServerIssuer,
      });
      clientAssertionJwt = attestation.clientAssertionJwt;
      oauthClientAttestationHeaders = attestation.oauthHeaders;
      log?.(`${logPrefix} OAuth client attestation`, { hasClientAssertion: !!clientAssertionJwt });
    } catch (error) {
      log?.(`${logPrefix} attestation failed`, { error: error?.message });
    }

    const response = await postForm(
      tokenEndpoint,
      {
        ...tokenPayload,
        ...(clientAssertionJwt
          ? {
              client_assertion: clientAssertionJwt,
              client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            }
          : {}),
      },
      dpopJwt,
      oauthClientAttestationHeaders,
    );
    lastTokenResponseText = await response.text().catch(() => "");
    if (response.ok) {
      tokenBody = JSON.parse(lastTokenResponseText);
      return { tokenBody, dpopPrivateJwk, dpopPublicJwk };
    }

    let errorBody = {};
    try {
      errorBody = JSON.parse(lastTokenResponseText);
    } catch {}

    if (
      attempt === 0 &&
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey(response.status, errorBody)
    ) {
      try {
        const didRotate = await rotateWalletProviderKeyPair();
        if (didRotate) {
          log?.(`${logPrefix} token retry after WP key rotation`);
          continue;
        }
      } catch (error) {
        log?.(`${logPrefix} WP rotation failed`, { error: error?.message });
      }
    }

    throw new Error(`token_error ${response.status}: ${JSON.stringify(errorBody)}`);
  }

  throw new Error(`token_error: invalid JSON response - ${lastTokenResponseText}`);
}

export async function fetchCredentialNonce({
  tokenBody,
  nonceEndpoint,
  accessToken,
  postJson,
}) {
  let c_nonce = tokenBody?.c_nonce;
  let c_nonce_expires_in = tokenBody?.c_nonce_expires_in;
  if (c_nonce) {
    return { c_nonce, c_nonce_expires_in };
  }
  if (!nonceEndpoint) {
    throw new Error("nonce_error: issuer did not provide c_nonce and no nonce_endpoint is available");
  }
  const response = await postJson(
    nonceEndpoint,
    {},
    null,
    accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  );
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    let errorBody = {};
    try {
      errorBody = JSON.parse(text);
    } catch {}
    throw new Error(`nonce_error ${response.status}: ${JSON.stringify(errorBody)}`);
  }
  const nonceBody = await response.json();
  c_nonce = nonceBody.c_nonce;
  c_nonce_expires_in = nonceBody.c_nonce_expires_in;
  if (!c_nonce) {
    throw new Error("nonce_error: issuer nonce endpoint did not return c_nonce");
  }
  return { c_nonce, c_nonce_expires_in };
}

export async function buildCredentialRequest({
  configurationId,
  tokenBody,
  proofMode,
  credentialEndpoint,
  audience,
  c_nonce,
  keyPairs,
  selectedAlg,
  buildCredentialRequestProofs,
  buildCredentialRequestSelector,
  prepareCredentialResponseEncryption,
}) {
  const { proofs, proofJwt } = await buildCredentialRequestProofs({
    proofMode,
    credentialEndpoint,
    aud: audience,
    c_nonce,
    keyPairs,
    selectedAlg,
  });
  const credentialResponseEncCtx = await prepareCredentialResponseEncryption();
  const credentialRequest = {
    ...buildCredentialRequestSelector(configurationId, tokenBody),
    proofs,
    ...(credentialResponseEncCtx
      ? { credential_response_encryption: credentialResponseEncCtx.credential_response_encryption }
      : {}),
  };
  return {
    credentialRequest,
    proofJwt,
    credentialResponseDecryptionKey: credentialResponseEncCtx?.privateKey || null,
  };
}

export async function postCredentialRequest({
  credentialEndpoint,
  credentialRequest,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
  isDpopBoundAccessToken,
  computeAthForDpop,
  createDPoP,
  fetchImpl,
  parseCredentialResponsePayload,
}) {
  let credentialDpopJwt = null;
  if (
    accessToken &&
    dpopPrivateJwk &&
    dpopPublicJwk &&
    isDpopBoundAccessToken(tokenBody, accessToken)
  ) {
    credentialDpopJwt = await createDPoP({
      privateJwk: dpopPrivateJwk,
      publicJwk: dpopPublicJwk,
      htu: credentialEndpoint,
      htm: "POST",
      ath: computeAthForDpop(accessToken),
      alg: "ES256",
    });
  }

  const response = await fetchImpl(credentialEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`,
      ...(credentialDpopJwt ? { DPoP: credentialDpopJwt } : {}),
    },
    body: JSON.stringify(credentialRequest),
  });

  const responseText = await response.text().catch(() => "");
  const contentType = response.headers.get("content-type") || "";

  if (!response.ok && response.status !== 202) {
    let errorBody = {};
    try {
      errorBody = JSON.parse(responseText);
    } catch {
      errorBody = { error: "invalid_response", error_description: responseText };
    }
    throw new Error(`credential_error ${response.status}: ${JSON.stringify(errorBody)}`);
  }

  const body = await parseCredentialResponsePayload(responseText, contentType);
  if (!body || typeof body !== "object") {
    throw new Error(
      response.status === 202
        ? `credential_error ${response.status}: invalid response (expected JSON inside JWE or plain JSON)`
        : "credential_error: invalid JSON response",
    );
  }

  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body,
    credentialDpopJwt,
  };
}

export async function pollDeferredCredential({
  deferredEndpoint,
  transactionId,
  initialInterval,
  pollTimeoutMs,
  pollIntervalMs,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
  isDpopBoundAccessToken,
  computeAthForDpop,
  createDPoP,
  postJson,
  parseCredentialResponsePayload,
}) {
  const start = Date.now();
  const timeout = pollTimeoutMs ?? 30000;
  let nextDelayMs = getNextPollDelayMs(initialInterval, pollIntervalMs);

  while (Date.now() - start < timeout) {
    await sleep(nextDelayMs);

    let deferredDpopJwt = null;
    if (
      accessToken &&
      dpopPrivateJwk &&
      dpopPublicJwk &&
      isDpopBoundAccessToken(tokenBody, accessToken)
    ) {
      deferredDpopJwt = await createDPoP({
        privateJwk: dpopPrivateJwk,
        publicJwk: dpopPublicJwk,
        htu: deferredEndpoint,
        htm: "POST",
        ath: computeAthForDpop(accessToken),
        alg: "ES256",
      });
    }

    const response = await postJson(
      deferredEndpoint,
      { transaction_id: transactionId },
      deferredDpopJwt,
      { Authorization: `Bearer ${accessToken}` },
    );
    const responseText = await response.text().catch(() => "");
    const contentType = response.headers.get("content-type") || "";

    if (response.ok) {
      const body = await parseCredentialResponsePayload(responseText, contentType);
      if (!body || typeof body !== "object") {
        throw new Error("credential_error: invalid deferred credential response");
      }
      return body;
    }

    const outcome = await resolveDeferredPollResult({
      status: response.status,
      ok: false,
      contentType,
      responseText,
      decryptionPrivateKey: null,
    });

    if (outcome.kind === "success") {
      return outcome.body;
    }
    if (outcome.kind === "pending") {
      nextDelayMs = getNextPollDelayMs(outcome.interval, pollIntervalMs);
      continue;
    }
    throw new Error(formatDeferredTerminalError(outcome));
  }

  throw new Error("timeout: Deferred issuance timed out");
}
