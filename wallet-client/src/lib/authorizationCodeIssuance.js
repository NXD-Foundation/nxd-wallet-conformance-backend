import fetch from "node-fetch";
import { createPkcePair } from "./crypto.js";
import {
  isWebuildCs01Profile,
  isParMandatory,
  assertParEndpointAvailable,
  assertParResponse,
  assertNoDirectAuthorizationFallback,
} from "./profile.js";
import {
  assertAuthorizationDetailsSupportForCredentialRequest,
  resolveCredentialScope,
  resolveCredentialRequestTargets,
} from "./scopeResolution.js";
import {
  createTokenRequestDpopBinding,
  createResourceRequestDpopProof,
  buildResourceRequestHeaders,
  assertDpopBoundTokenReceived,
  assertAccessTokenCnfMatchesWia,
} from "./dpopBinding.js";
import {
  describeAttestationConfiguration,
  createLegacyBodyClientAssertionJwt,
  allowsLegacyBodyClientAssertion,
} from "./walletUnitAttestation.js";
import {
  buildCredentialProofRequest,
  buildCredentialProofBindingContext,
  buildDeferredCredentialPollRequest,
  toKeyBindingMaterial,
} from "./credentialProofBinding.js";
import { pollDeferredCredentialIssuance } from "./deferredIssuance.js";
import {
  createAttestationChallengeState,
  fetchAttestationChallenge,
} from "./attestationChallenge.js";
import { isOpenId4VpDeepLink, OPENID4VP_CS02_URI } from "./openid4vpUri.js";
import { makeSessionLogger } from "./logger.js";
import { resolveAuthHandoffTtlSeconds } from "./authHandoffConfig.js";

function logFlowError(slog, label, error, extra = {}) {
  try {
    console.error(label, error?.message || error);
    slog(label, {
      error: error?.message || String(error),
      errorCode: error?.errorCode || error?.name || undefined,
      stack: error?.stack,
      ...extra,
    });
  } catch {}
}

function runGuardedSync(slog, label, fn, extra = {}) {
  try {
    return fn();
  } catch (error) {
    logFlowError(slog, label, error, extra);
    throw error;
  }
}

async function runGuardedAsync(slog, label, fn, extra = {}) {
  try {
    return await fn();
  } catch (error) {
    logFlowError(slog, label, error, extra);
    throw error;
  }
}

function randomState() {
  return Math.random().toString(36).slice(2);
}

function safeParseJson(str) {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

function deriveAuthorizationServerIssuer(endpoint, fallback) {
  if (fallback) return fallback;
  if (!endpoint) return undefined;
  try {
    return new URL(endpoint).origin;
  } catch {
    return endpoint;
  }
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

export function serializePendingContext(prepared) {
  return {
    profile: prepared.profile,
    walletClientId: prepared.walletClientId,
    apiBase: prepared.apiBase,
    issuerMeta: prepared.issuerMeta,
    offerConfig: prepared.offerConfig,
    configurationId: prepared.configurationId,
    issuerState: prepared.issuerState,
    authorizationServer: prepared.authorizationServer,
    keyPath: prepared.keyPath,
    pollTimeoutMs: prepared.pollTimeoutMs,
    pollIntervalMs: prepared.pollIntervalMs,
    codeVerifier: prepared.codeVerifier,
    state: prepared.state,
    redirectUri: prepared.redirectUri,
    tokenEndpoint: prepared.tokenEndpoint,
    authorizationServerIssuer: prepared.authorizationServerIssuer,
    usedPar: prepared.usedPar,
    parExpiresIn: prepared.parExpiresIn,
    scopeResolution: prepared.scopeResolution,
    issuanceContext: prepared.issuanceContext,
    attestationChallenge: prepared.attestationChallengeState?.current ?? null,
  };
}

export function deserializePendingContext(raw) {
  if (!raw || typeof raw !== "object") {
    throw new Error("invalid_pending_context");
  }
  const attestationChallengeState = createAttestationChallengeState(raw.attestationChallenge);
  return {
    ...raw,
    attestationChallengeState,
  };
}

export function createAuthorizationCodeIssuance(deps) {
  const {
    discoverAuthorizationServerMetadata,
    httpPostFormWithAttestationChallengeRetry,
    httpPostJson,
    validateAndStoreCredential,
    issueCredentialTargets,
    wrapIssuanceResult,
    sleep,
    fetchImpl = fetch,
  } = deps;

  async function prepareAuthorization(
    {
      profile,
      walletClientId,
      apiBase,
      issuerMeta,
      offerConfig = null,
      configurationId,
      issuerState,
      authorizationServer,
      keyPath,
      pollTimeoutMs,
      pollIntervalMs,
      redirectUri = OPENID4VP_CS02_URI,
    },
    logSessionId,
  ) {
    const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
    try {
      slog("[codeflow] prepare start", {
        configurationId,
        profile,
        cs01Mode: isWebuildCs01Profile(profile),
        walletClientId,
        redirectUri,
      });
    } catch {}

    let authorizeEndpoint = issuerMeta.authorization_endpoint || null;
    let tokenEndpointFromAS = null;
    let parEndpoint = null;
    let requirePushedAuthorizationRequests = false;
    let authorizationServerIssuer = issuerMeta.credential_issuer || apiBase;
    const asBase = resolveAuthorizationServerBase(issuerMeta, apiBase, authorizationServer);

    let authorizationServerMetaForScope = null;
    let attestationChallengeState = createAttestationChallengeState();
    const issuerMetaWorking = { ...issuerMeta };
    try {
      const asMeta = await discoverAuthorizationServerMetadata(asBase, logSessionId, fetchImpl, {
        grant: "authorization_code",
      });
      authorizationServerMetaForScope = asMeta;
      authorizeEndpoint = authorizeEndpoint || asMeta.authorization_endpoint;
      tokenEndpointFromAS = asMeta.token_endpoint || null;
      parEndpoint = asMeta.pushed_authorization_request_endpoint || null;
      requirePushedAuthorizationRequests = asMeta.require_pushed_authorization_requests === true;
      authorizationServerIssuer = asMeta.issuer || asBase || authorizationServerIssuer;
      attestationChallengeState = await initializeAttestationChallengeState(asMeta);
      if (!tokenEndpointFromAS) {
        throw new Error("token_endpoint_required: authorization server metadata must include 'token_endpoint'");
      }
      issuerMetaWorking._authorizationServerMeta = asMeta;
    } catch (e) {
      logFlowError(slog, "[codeflow] AS metadata discovery failed", e);
      throw e;
    }

    const authorizeUrl = new URL(authorizeEndpoint || `${apiBase}/authorize`);
    const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
    const state = randomState();

    const scopeResolution = runGuardedSync(
      slog,
      "[codeflow] scope resolution failed",
      () =>
        resolveCredentialScope({
          profile,
          configurationId,
          issuerMeta: issuerMetaWorking,
          offerConfig,
          scopesSupported: authorizationServerMetaForScope?.scopes_supported ?? null,
        }),
      {
        configurationId,
        scopesSupported: authorizationServerMetaForScope?.scopes_supported ?? null,
      },
    );

    runGuardedSync(
      slog,
      "[codeflow] authorization_details support validation failed",
      () =>
        assertAuthorizationDetailsSupportForCredentialRequest({
          configurationId,
          issuerMeta: issuerMetaWorking,
          offerConfig,
          authorizationServerMeta: authorizationServerMetaForScope,
        }),
      {
        configurationId,
        authorizationDetailsTypesSupported:
          authorizationServerMetaForScope?.authorization_details_types_supported ?? null,
      },
    );

    const authzDetails = [
      {
        type: "openid_credential",
        credential_configuration_id: configurationId,
        ...(issuerMetaWorking?.credential_issuer
          ? { locations: [issuerMetaWorking.credential_issuer] }
          : {}),
      },
    ];
    const authzParams = {
      response_type: "code",
      ...(issuerState ? { issuer_state: issuerState } : {}),
      state,
      client_id: walletClientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      scope: scopeResolution.scope,
      authorization_details: JSON.stringify(authzDetails),
    };
    const attestationConfiguration = describeAttestationConfiguration(profile);
    const issuanceContext = {
      configurationId,
      scope: scopeResolution.scope,
      scopeSource: scopeResolution.source,
      attestation: attestationConfiguration,
      attestationChallenge: attestationChallengeState.current,
    };

    const parRequired = isParMandatory(profile, requirePushedAuthorizationRequests);
    runGuardedSync(
      slog,
      "[codeflow] PAR endpoint unavailable",
      () => assertParEndpointAvailable(profile, parEndpoint, { asRequiresPar: requirePushedAuthorizationRequests }),
      { parEndpoint, parRequired },
    );

    let finalAuthorizeUrl = authorizeUrl.toString();
    let usedPar = false;
    let parExpiresIn = null;
    if (parEndpoint) {
      try {
        let legacyParBodyClientAssertionJwt = null;
        if (allowsLegacyBodyClientAssertion(profile)) {
          try {
            legacyParBodyClientAssertionJwt = await createLegacyBodyClientAssertionJwt({
              keyPath,
              audience: parEndpoint,
            });
          } catch (legacyAssertionError) {
            console.warn(
              "[codeflow][par] Failed to generate legacy body client_assertion:",
              legacyAssertionError?.message,
            );
          }
        }
        const parParams = {
          ...authzParams,
          ...(legacyParBodyClientAssertionJwt
            ? {
                client_assertion: legacyParBodyClientAssertionJwt,
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              }
            : {}),
        };
        const parRes = await httpPostFormWithAttestationChallengeRetry({
          url: parEndpoint,
          params: parParams,
          logSessionId,
          profile,
          keyPath,
          clientId: authzParams.client_id,
          endpointAudience: parEndpoint,
          authorizationServerIssuer,
          stage: "PAR",
          challengeState: attestationChallengeState,
        });
        if (parRes.ok) {
          const parBody = parRes.parsedBody || (await parRes.json().catch(() => ({})));
          const requestUri = parBody.request_uri;
          parExpiresIn = parBody.expires_in ?? null;
          assertParResponse(profile, {
            ok: true,
            status: parRes.status,
            requestUri,
            asRequiresPar: requirePushedAuthorizationRequests,
          });
          if (requestUri) {
            const url = new URL(authorizeEndpoint || `${apiBase}/authorize`);
            url.searchParams.set("client_id", authzParams.client_id);
            url.searchParams.set("request_uri", requestUri);
            finalAuthorizeUrl = url.toString();
            usedPar = true;
          }
        } else {
          const text = await parRes.text().catch(() => "");
          assertParResponse(profile, {
            ok: false,
            status: parRes.status,
            requestUri: null,
            asRequiresPar: requirePushedAuthorizationRequests,
            responseBody: text,
          });
        }
      } catch (e) {
        if (parRequired) {
          throw e;
        }
      }
    }

    runGuardedSync(
      slog,
      "[codeflow] direct authorization fallback rejected",
      () => assertNoDirectAuthorizationFallback(profile, usedPar),
      { usedPar, parRequired },
    );
    if (!usedPar) {
      Object.entries(authzParams).forEach(([k, v]) => authorizeUrl.searchParams.set(k, v));
      finalAuthorizeUrl = authorizeUrl.toString();
    }

    const tokenEndpoint = issuerMetaWorking.token_endpoint || tokenEndpointFromAS || null;
    if (!tokenEndpoint) {
      throw new Error(
        "token_endpoint_required: unable to determine token_endpoint from authorization server metadata",
      );
    }

    const ttlSeconds = resolveAuthHandoffTtlSeconds(process.env, parExpiresIn);
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

    try {
      slog("[codeflow] prepare complete", { authorizationUrl: finalAuthorizeUrl, state, expiresAt });
    } catch {}

    const prepared = {
      profile,
      walletClientId,
      apiBase,
      issuerMeta: issuerMetaWorking,
      offerConfig,
      configurationId,
      issuerState,
      authorizationServer,
      keyPath,
      pollTimeoutMs,
      pollIntervalMs,
      codeVerifier,
      state,
      redirectUri,
      authorizationUrl: finalAuthorizeUrl,
      tokenEndpoint,
      authorizationServerIssuer,
      usedPar,
      parExpiresIn,
      scopeResolution,
      issuanceContext,
      attestationChallengeState,
      expiresAt,
      ttlSeconds,
    };

    return prepared;
  }

  async function fetchAuthorizationCodeBlocking(prepared, logSessionId) {
    const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});
    const authRes = await fetchImpl(prepared.authorizationUrl, { redirect: "manual" });
    prepared.attestationChallengeState.updateFromResponse(authRes.headers);
    prepared.issuanceContext.attestationChallenge = prepared.attestationChallengeState.current;

    let redirectUrl = authRes.headers.get("location");
    if (!redirectUrl) {
      const bodyText = await authRes.text().catch(() => "");
      const redirectPayload = safeParseJson(bodyText);
      if (redirectPayload?.redirect_uri) redirectUrl = redirectPayload.redirect_uri;
      else if (isOpenId4VpDeepLink(bodyText)) redirectUrl = bodyText;
    }

    if (!redirectUrl) {
      throw new Error(`authorize_error ${authRes.status}: No redirect URL found`);
    }

    const redirect = new URL(redirectUrl);
    const code = redirect.searchParams.get("code");
    if (!code) {
      const error = new Error("invalid_response: Authorization code missing");
      logFlowError(slog, "[codeflow] authorization code missing", error, { redirectUrl });
      throw error;
    }

    const returnedState = redirect.searchParams.get("state");
    if (returnedState && returnedState !== prepared.state) {
      throw new Error("invalid_state: authorization response state mismatch");
    }

    return code;
  }

  async function completeAuthorization(pendingInput, { code, state: callbackState, iss }, logSessionId) {
    const pending =
      pendingInput?.attestationChallengeState != null
        ? pendingInput
        : deserializePendingContext(pendingInput);
    const slog = logSessionId ? makeSessionLogger(logSessionId) : (() => {});

    if (callbackState && callbackState !== pending.state) {
      throw new Error("invalid_state: callback state does not match pending authorization");
    }
    if (iss && pending.authorizationServerIssuer) {
      try {
        const expected = new URL(pending.authorizationServerIssuer);
        const actual = new URL(iss);
        if (expected.origin !== actual.origin) {
          throw new Error("invalid_issuer: callback iss does not match expected authorization server");
        }
      } catch (e) {
        if (e.message?.startsWith("invalid_issuer")) throw e;
        if (
          String(pending.authorizationServerIssuer).replace(/\/$/, "") !==
          String(iss).replace(/\/$/, "")
        ) {
          throw new Error("invalid_issuer: callback iss does not match expected authorization server");
        }
      }
    }

    const {
      profile,
      walletClientId,
      apiBase,
      issuerMeta,
      configurationId,
      keyPath,
      pollTimeoutMs,
      pollIntervalMs,
      codeVerifier,
      redirectUri,
      tokenEndpoint,
      authorizationServerIssuer,
      scopeResolution,
    } = pending;

    let issuanceContext = { ...pending.issuanceContext };
    const attestationChallengeState = pending.attestationChallengeState;

    const dpopBinding = await createTokenRequestDpopBinding({
      keyPath,
      tokenEndpoint,
      profile,
    });
    const { dpopJwt } = dpopBinding;

    let legacyTokenBodyClientAssertionJwt = null;
    if (allowsLegacyBodyClientAssertion(profile)) {
      try {
        legacyTokenBodyClientAssertionJwt = await createLegacyBodyClientAssertionJwt({
          keyPath,
          audience: tokenEndpoint,
        });
      } catch (legacyAssertionError) {
        console.warn(
          "[codeflow] Failed to generate legacy body client_assertion:",
          legacyAssertionError?.message,
        );
      }
    }

    const tokenAuthzDetails = [
      {
        type: "openid_credential",
        credential_configuration_id: configurationId,
        ...(issuerMeta?.credential_issuer ? { locations: [issuerMeta.credential_issuer] } : {}),
      },
    ];
    const tokenRes = await httpPostFormWithAttestationChallengeRetry({
      url: tokenEndpoint,
      params: {
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
        client_id: walletClientId,
        redirect_uri: redirectUri,
        authorization_details: JSON.stringify(tokenAuthzDetails),
        ...(legacyTokenBodyClientAssertionJwt
          ? {
              client_assertion: legacyTokenBodyClientAssertionJwt,
              client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            }
          : {}),
      },
      logSessionId,
      dpopHeader: dpopJwt,
      profile,
      keyPath,
      clientId: walletClientId,
      endpointAudience: tokenEndpoint,
      authorizationServerIssuer: deriveAuthorizationServerIssuer(
        tokenEndpoint,
        authorizationServerIssuer,
      ),
      stage: "token request",
      challengeState: attestationChallengeState,
      cnfKeyPair: dpopBinding,
    });

    if (!tokenRes.ok) {
      const text = await tokenRes.text().catch(() => "");
      let err = {};
      try {
        err = JSON.parse(text);
      } catch {}
      throw new Error(`token_error ${tokenRes.status}: ${JSON.stringify(err)}`);
    }

    let tokenBody;
    try {
      tokenBody = await tokenRes.json();
      attestationChallengeState.updateFromResponse(tokenRes.headers);
      issuanceContext.attestationChallenge = attestationChallengeState.current;
    } catch (e) {
      throw new Error(`token_error: invalid JSON response - ${e?.message}`);
    }

    const accessToken = tokenBody.access_token;
    runGuardedSync(slog, "[codeflow] DPoP-bound token validation failed", () =>
      assertDpopBoundTokenReceived(profile, tokenBody, accessToken),
    );
    await runGuardedAsync(slog, "[codeflow] access token cnf validation failed", () =>
      assertAccessTokenCnfMatchesWia(profile, accessToken, dpopBinding.publicJwk),
    );

    let c_nonce = tokenBody.c_nonce;
    const credentialRequestTargets = runGuardedSync(
      slog,
      "[codeflow] credential selector resolution failed",
      () => resolveCredentialRequestTargets({ configurationId, tokenResponse: tokenBody }),
      { configurationId },
    );
    issuanceContext.credentialSelection = {
      ...(issuanceContext.credentialSelection || {}),
      targets: credentialRequestTargets,
    };
    let c_nonce_expires_in = tokenBody.c_nonce_expires_in;

    if (c_nonce) {
      // use token c_nonce
    } else if (issuerMeta.nonce_endpoint) {
      const nonceEndpoint = issuerMeta.nonce_endpoint;
      const nonceRes = await httpPostJson(nonceEndpoint, {}, logSessionId);
      if (!nonceRes.ok) {
        const text = await nonceRes.text().catch(() => "");
        let err = {};
        try {
          err = JSON.parse(text);
        } catch {}
        throw new Error(`nonce_error ${nonceRes.status}: ${JSON.stringify(err)}`);
      }
      const nonceJson = await nonceRes.json();
      c_nonce = nonceJson.c_nonce;
      c_nonce_expires_in = nonceJson.c_nonce_expires_in;
    } else {
      throw new Error("nonce_error: issuer did not provide c_nonce and no nonce_endpoint is available");
    }

    if (credentialRequestTargets.length > 1) {
      const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
      const multiple = await issueCredentialTargets(
        {
          targets: credentialRequestTargets,
          profile,
          keyPath,
          issuerMeta,
          apiBase,
          credentialEndpoint,
          cNonce: c_nonce,
          cNonceExpiresIn: c_nonce_expires_in,
          dpopBinding,
          tokenBody,
          accessToken,
          pollTimeoutMs,
          pollIntervalMs,
          authorizationServerMeta: issuerMeta._authorizationServerMeta,
          metadata: {
            configurationId,
            scope: scopeResolution.scope,
            scopeSource: scopeResolution.source,
            proofBinding: null,
          },
        },
        logSessionId,
      );
      issuanceContext.proofBinding = multiple.proofBindings[0];
      return {
        credential: multiple.credentials[0],
        credentials: multiple.credentials,
        issuanceContext,
      };
    }

    const credentialEndpoint = issuerMeta.credential_endpoint || `${apiBase}/credential`;
    const proofBundle = await runGuardedAsync(
      slog,
      "[codeflow] credential proof request failed",
      () =>
        buildCredentialProofRequest({
          profile,
          keyPath,
          issuerMeta,
          apiBase,
          configurationId,
          credentialIdentifier: credentialRequestTargets[0].credential_identifier,
          cNonce: c_nonce,
          credentialEndpoint,
        }),
      { configurationId, credentialEndpoint },
    );
    const { subjectKey, credentialRequest: credReq } = proofBundle;
    issuanceContext.proofBinding = buildCredentialProofBindingContext({
      profile,
      subjectKey,
      dpopBinding,
      tokenBody,
      accessToken,
      keyAttestation: proofBundle.keyAttestation,
    });

    const credentialDpopJwtCode = await createResourceRequestDpopProof({
      binding: dpopBinding,
      tokenBody,
      accessToken,
      htu: credentialEndpoint,
      profile,
      stage: "credential request",
    });
    const credReqBody = JSON.stringify(credReq);
    const credHeadersCode = {
      "content-type": "application/json",
      ...buildResourceRequestHeaders(accessToken, credentialDpopJwtCode, tokenBody),
    };
    const credRes = await fetchImpl(credentialEndpoint, {
      method: "POST",
      headers: credHeadersCode,
      body: credReqBody,
    });

    const responseText = await credRes.text().catch(() => "");

    if (credRes.status === 202) {
      let credBody;
      try {
        credBody = JSON.parse(responseText);
      } catch (e) {
        throw new Error(`credential_error ${credRes.status}: invalid JSON response`);
      }
      const { transaction_id, interval: issuerInterval } = credBody;
      const deferredEndpoint = issuerMeta.credential_deferred_endpoint || `${apiBase}/credential_deferred`;
      const defBody = await pollDeferredCredentialIssuance({
        transactionId: transaction_id,
        issuerIntervalSeconds: issuerInterval,
        pollTimeoutMs,
        pollIntervalMs,
        deferredEndpoint,
        buildPollRequest: () =>
          buildDeferredCredentialPollRequest({
            profile,
            dpopBinding,
            tokenBody,
            accessToken,
            subjectKey,
            deferredEndpoint,
            transactionId: transaction_id,
          }),
        httpPostJson,
        logSessionId,
        sleep,
        log: (msg, data) => {
          try {
            slog(`[codeflow] ${msg}`, data);
          } catch {}
        },
      });
      await validateAndStoreCredential(
        {
          configurationId,
          credential: defBody,
          issuerMeta,
          apiBase,
          keyBinding: toKeyBindingMaterial(subjectKey),
          metadata: {
            configurationId,
            scope: scopeResolution.scope,
            scopeSource: scopeResolution.source,
            c_nonce,
            c_nonce_expires_in,
            proofBinding: issuanceContext.proofBinding,
          },
          authorizationServerMeta: issuerMeta._authorizationServerMeta,
        },
        logSessionId,
      );
      return wrapIssuanceResult(defBody, issuanceContext);
    }

    if (!credRes.ok) {
      let err = {};
      try {
        err = JSON.parse(responseText);
      } catch {
        err = { error: "invalid_response", error_description: responseText };
      }
      throw new Error(`credential_error ${credRes.status}: ${JSON.stringify(err)}`);
    }

    let credBody;
    try {
      credBody = JSON.parse(responseText);
    } catch (e) {
      throw new Error(`credential_error: invalid JSON response - ${e?.message}`);
    }

    await validateAndStoreCredential(
      {
        configurationId,
        credential: credBody,
        issuerMeta,
        apiBase,
        keyBinding: toKeyBindingMaterial(subjectKey),
        metadata: {
          configurationId,
          scope: scopeResolution.scope,
          scopeSource: scopeResolution.source,
          c_nonce,
          c_nonce_expires_in,
          proofBinding: issuanceContext.proofBinding,
        },
        authorizationServerMeta: issuerMeta._authorizationServerMeta,
      },
      logSessionId,
    );
    return wrapIssuanceResult(credBody, issuanceContext);
  }

  async function runAuthorizationCodeIssuance(args, logSessionId) {
    const prepared = await prepareAuthorization(args, logSessionId);
    const code = await fetchAuthorizationCodeBlocking(prepared, logSessionId);
    return completeAuthorization(prepared, { code, state: prepared.state }, logSessionId);
  }

  return {
    prepareAuthorization,
    completeAuthorization,
    fetchAuthorizationCodeBlocking,
    runAuthorizationCodeIssuance,
  };
}
