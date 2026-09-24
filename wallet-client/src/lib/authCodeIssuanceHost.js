import fetch from "node-fetch";
import { createAuthorizationCodeIssuance } from "./authorizationCodeIssuance.js";
import { createWalletUnitAttestationClientAuth } from "./walletUnitAttestation.js";
import {
  createAttestationChallengeState,
  fetchAttestationChallenge,
  shouldRetryWithAttestationChallenge,
} from "./attestationChallenge.js";
import {
  buildCredentialProofRequest,
  buildCredentialProofBindingContext,
  buildDeferredCredentialPollRequest,
  toKeyBindingMaterial,
} from "./credentialProofBinding.js";
import { pollDeferredCredentialIssuance } from "./deferredIssuance.js";
import {
  createResourceRequestDpopProof,
  buildResourceRequestHeaders,
} from "./dpopBinding.js";

export function createAuthCodeIssuanceHost(deps) {
  const {
    discoverAuthorizationServerMetadata,
    httpPostForm,
    httpPostJson,
    validateAndStoreCredential,
    sleep,
  } = deps;

function wrapIssuanceResult(credential, issuanceContext) {
  if (credential && typeof credential === "object" && !Array.isArray(credential)) {
    return { ...credential, issuanceContext };
  }
  return { credential, issuanceContext };
}

function resolveAuthorizationServerBase(issuerMeta, apiBase, authorizationServer) {
  const authorizationServers = Array.isArray(issuerMeta.authorization_servers)
    ? issuerMeta.authorization_servers
    : issuerMeta.authorization_server
      ? [issuerMeta.authorization_server]
      : [];

  if (authorizationServers.length > 0) {
    if (authorizationServer) {
      if (!authorizationServers.includes(authorizationServer)) {
        throw new Error(
          "invalid_authorization_server: grant authorization_server must match one of the values in authorization_servers array",
        );
      }
      return authorizationServer;
    }
    return authorizationServers[0];
  }

  if (authorizationServer) {
    throw new Error(
      "invalid_authorization_server: grant authorization_server MUST NOT be used when authorization_servers parameter is omitted",
    );
  }
  return issuerMeta.credential_issuer || apiBase;
}

async function initializeAttestationChallengeState(asMeta) {
  const state = createAttestationChallengeState();
  if (asMeta?.challenge_endpoint) {
    const challenge = await fetchAttestationChallenge(asMeta.challenge_endpoint);
    state.set(challenge);
  }
  return state;
}

async function createAttestationHeadersForRequest({
  profile,
  keyPath,
  clientId,
  endpointAudience,
  authorizationServerIssuer,
  stage,
  challengeState,
  cnfKeyPair = null,
}) {
  const attestation = await createWalletUnitAttestationClientAuth({
    profile,
    keyPath,
    clientId,
    endpointAudience,
    authorizationServerIssuer,
    stage,
    challenge: challengeState?.consume() ?? null,
    cnfKeyPair,
  });
  return attestation.headers;
}

async function httpPostFormWithAttestationChallengeRetry({
  url,
  params,
  logSessionId,
  dpopHeader = null,
  profile,
  keyPath,
  clientId,
  endpointAudience,
  authorizationServerIssuer,
  stage,
  challengeState,
  cnfKeyPair = null,
}) {
  const buildHeaders = () =>
    createAttestationHeadersForRequest({
      profile,
      keyPath,
      clientId,
      endpointAudience,
      authorizationServerIssuer,
      stage,
      challengeState,
      cnfKeyPair,
    });

  let headers = await buildHeaders();
  let res = await httpPostForm(url, params, logSessionId, dpopHeader, headers);
  challengeState?.updateFromResponse(res.headers);

  const responseText = typeof res.bodyText === "string" ? res.bodyText : await res.clone().text().catch(() => "");
  const { shouldRetry, challenge } = shouldRetryWithAttestationChallenge(res, responseText);
  if (shouldRetry && challenge) {
    challengeState?.set(challenge);
    headers = await buildHeaders();
    res = await httpPostForm(url, params, logSessionId, dpopHeader, headers);
    challengeState?.updateFromResponse(res.headers);
  }

  return res;
}

async function issueCredentialTargets({
  targets,
  profile,
  keyPath,
  issuerMeta,
  apiBase,
  credentialEndpoint,
  cNonce,
  cNonceExpiresIn,
  dpopBinding,
  tokenBody,
  accessToken,
  pollTimeoutMs,
  pollIntervalMs,
  authorizationServerMeta,
  metadata,
  clientId,
  anonymousAccess = false,
}, logSessionId) {
  const credentials = [];
  const proofBindings = [];
  for (const target of targets) {
    const proofBundle = await buildCredentialProofRequest({
      profile,
      keyPath,
      issuerMeta,
      apiBase,
      configurationId: target.credential_configuration_id,
      credentialIdentifier: target.credential_identifier,
      cNonce,
      credentialEndpoint,
      clientId,
      anonymousAccess,
    });
    const credentialDpop = await createResourceRequestDpopProof({
      binding: dpopBinding,
      tokenBody,
      accessToken,
      htu: credentialEndpoint,
      profile,
      stage: "credential request",
    });
    const response = await fetch(credentialEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildResourceRequestHeaders(accessToken, credentialDpop, tokenBody),
      },
      body: JSON.stringify(proofBundle.credentialRequest),
    });
    const text = await response.text().catch(() => "");
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch {}
    if (!response.ok) {
      throw new Error(`credential_error ${response.status}: ${JSON.stringify(body || { error: "invalid_response", error_description: text })}`);
    }
    if (response.status === 202) {
      const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
      body = await pollDeferredCredentialIssuance({
        transactionId: body?.transaction_id,
        issuerIntervalSeconds: body?.interval,
        pollTimeoutMs,
        pollIntervalMs,
        deferredEndpoint,
        buildPollRequest: () => buildDeferredCredentialPollRequest({
          profile,
          dpopBinding,
          tokenBody,
          accessToken,
          subjectKey: proofBundle.subjectKey,
          deferredEndpoint,
          transactionId: body?.transaction_id,
        }),
        httpPostJson,
        logSessionId,
        sleep,
      });
    }
    await validateAndStoreCredential({
      configurationId: target.credential_configuration_id,
      credential: body,
      issuerMeta,
      apiBase,
      keyBinding: toKeyBindingMaterial(proofBundle.subjectKey),
      metadata: { ...metadata, c_nonce: cNonce, c_nonce_expires_in: cNonceExpiresIn },
      authorizationServerMeta,
    }, logSessionId);
    credentials.push(body);
    proofBindings.push(buildCredentialProofBindingContext({
      profile,
      subjectKey: proofBundle.subjectKey,
      dpopBinding,
      tokenBody,
      accessToken,
      keyAttestation: proofBundle.keyAttestation,
    }));
  }
  return { credentials, proofBindings };
}

  let authCodeIssuanceInstance = null;

  function getAuthCodeIssuance() {
    if (!authCodeIssuanceInstance) {
      authCodeIssuanceInstance = createAuthorizationCodeIssuance({
        discoverAuthorizationServerMetadata,
        httpPostFormWithAttestationChallengeRetry,
        httpPostJson,
        validateAndStoreCredential,
        issueCredentialTargets,
        wrapIssuanceResult,
        sleep,
        fetchImpl: fetch,
      });
    }
    return authCodeIssuanceInstance;
  }

  return { getAuthCodeIssuance };
}
