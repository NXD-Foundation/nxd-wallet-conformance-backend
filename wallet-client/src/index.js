#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import fetch from "node-fetch";
import {
  generateDidJwkFromPrivateJwk,
  ensureOrCreateEcKeyPair,
  createDPoP,
} from "./lib/crypto.js";
import { storeWalletCredentialByType } from "./lib/cache.js";
import { resolveAttestationForEndpoint } from "./lib/walletProviderIdentity.js";
import { resolveAttestDeviceKeyPaths } from "./lib/deviceKeyPaths.js";
import { buildCredentialRequestProofs } from "./lib/credentialRequestProofs.js";
import { normalizeCredentialOfferDeepLink } from "./lib/credentialOfferScheme.js";
import {
  extractNotificationId,
  resolveNotificationEndpoint,
  postCredentialAcceptedNotification,
} from "./lib/credentialNotification.js";
import {
  isDpopBoundAccessToken,
  computeAthForDpop,
  deriveAuthorizationServerIssuer,
  buildPreAuthorizedCodeTokenFormParams,
  buildCliTokenEndpointHeaders,
  buildCredentialRequestSelector,
} from "../utils/tokenUtils.js";
import {
  getNextPollDelayMs,
  resolveDeferredPollResult,
  formatDeferredTerminalError,
} from "./lib/deferredIssuancePoll.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function notifyCredentialAcceptedIfNeeded({
  credentialResponse,
  apiBase,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
}) {
  const notificationId = extractNotificationId(credentialResponse);
  const notificationEndpoint = resolveNotificationEndpoint(undefined, apiBase);
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

async function storeIssuedCredentialsFromCli(configurationId, credBody, keyPairs, metadataBase) {
  const notificationId = extractNotificationId(credBody);
  const baseMeta = {
    ...metadataBase,
    ...(notificationId ? { notification_id: notificationId } : {}),
  };
  const n = Array.isArray(credBody?.credentials) ? credBody.credentials.length : 0;
  if (n > 1) {
    await storeWalletCredentialByType(configurationId, {
      multi: true,
      entries: credBody.credentials.map((item, i) => ({
        credential: typeof item?.credential === "string" ? { credential: item.credential } : item,
        keyBinding: {
          privateJwk: keyPairs[i].privateJwk,
          publicJwk: keyPairs[i].publicJwk,
          didJwk: keyPairs[i].didJwk,
        },
        metadata: { ...baseMeta, attestedKeyIndex: i },
      })),
      metadata: baseMeta,
    });
  } else {
    await storeWalletCredentialByType(configurationId, {
      credential: credBody,
      keyBinding: {
        privateJwk: keyPairs[0].privateJwk,
        publicJwk: keyPairs[0].publicJwk,
        didJwk: keyPairs[0].didJwk,
      },
      metadata: baseMeta,
    });
  }
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option("issuer", { type: "string", default: "http://localhost:3000" })
    .option("offer", {
      type: "string",
      describe: "credential offer deep link (openid-credential-offer, haip, haip-vci, eu-eaa-offer)",
    })
    .option("fetch-offer", { type: "string", describe: "issuer path to fetch an offer, e.g. /offer-no-code" })
    .option("credential", { type: "string", describe: "credential_configuration_id to request" })
    .option("key", {
      type: "string",
      describe: "device-bound proof/DPoP key (EC P-256 JWK file); default: data/device-key.json",
    })
    .option("proof-mode", {
      type: "string",
      choices: ["jwt", "attestation"],
      default: "jwt",
      describe: "VCI credential request: proofs.jwt (default) or proofs.attestation (WUA only)",
    })
    .option("attest-keys", {
      type: "number",
      default: 1,
      describe: "number of device keys in WUA attested_keys (1–32); proof JWT uses first key",
    })
    .option("poll-interval", { type: "number", default: 2000 })
    .option("poll-timeout", { type: "number", default: 30000 })
    .strict()
    .help()
    .parse();

  const issuerBase = argv.issuer.replace(/\/$/, "");

  const deepLink = argv.offer || (await getOfferDeepLink(issuerBase, argv["fetch-offer"], argv.credential));
  if (!deepLink) {
    console.error("No offer provided or fetched.");
    process.exit(1);
  }

  const offerConfig = await resolveOfferConfig(deepLink);
  const {
    credential_issuer,
    credential_configuration_ids: offerConfigIds,
    credentials: legacyCredentialIds,
    grants,
  } = offerConfig;

  const normalizedConfigIds = Array.isArray(offerConfigIds) && offerConfigIds.length > 0
    ? offerConfigIds
    : Array.isArray(legacyCredentialIds)
      ? legacyCredentialIds
      : legacyCredentialIds && typeof legacyCredentialIds === "object"
        ? Object.keys(legacyCredentialIds)
        : [];

  const configurationId = argv.credential || normalizedConfigIds?.[0];
  if (!configurationId) {
    console.error("No credential_configuration_id available in offer; use --credential");
    process.exit(1);
  }

  const apiBase = (credential_issuer || issuerBase).replace(/\/$/, "");
  const attestKeyCount = argv["attest-keys"];
  if (!Number.isInteger(attestKeyCount) || attestKeyCount < 1 || attestKeyCount > 32) {
    console.error("--attest-keys must be an integer from 1 to 32");
    process.exit(1);
  }
  const attestPaths = resolveAttestDeviceKeyPaths(argv.key, attestKeyCount);
  const deviceKeyPath = attestPaths[0];
  const proofMode = argv["proof-mode"] || "jwt";

  const preAuthGrant = grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  if (!preAuthGrant) {
    console.error("Only pre-authorized_code is supported in this client.");
    process.exit(1);
  }

  const preAuthorizedCode = preAuthGrant["pre-authorized_code"]; // sessionId
  const txCode = preAuthGrant?.tx_code ? await promptTxCode(preAuthGrant.tx_code) : undefined;

  const tokenEndpoint = `${apiBase}/token_endpoint`;
  const authorizationDetails = configurationId ? [{
    type: "openid_credential",
    credential_configuration_id: configurationId,
    ...(credential_issuer ? { locations: [credential_issuer] } : {}),
  }] : undefined;
  
  // Generate DPoP (Demonstrating Proof-of-Possession) for token request
  let dpopJwt = null;
  let dpopPrivateJwk = null;
  let dpopPublicJwk = null;
  try {
    const dpopKeys = await ensureOrCreateEcKeyPair(deviceKeyPath, "ES256");
    dpopPrivateJwk = dpopKeys.privateJwk;
    dpopPublicJwk = dpopKeys.publicJwk;
    dpopJwt = await createDPoP({
      privateJwk: dpopPrivateJwk,
      publicJwk: dpopPublicJwk,
      htu: tokenEndpoint,
      htm: "POST",
      alg: "ES256"
    });
  } catch (dpopError) {
    // RFC001 §7.4 / RFC 9449: DPoP is mandatory at the token endpoint; the issuer
    // will reject the exchange with 400 invalid_dpop_proof if this header is missing.
    console.warn("Failed to generate DPoP (token exchange will be rejected by the issuer):", dpopError?.message);
  }
  
  const authorizationServerIssuer = deriveAuthorizationServerIssuer(
    tokenEndpoint,
    credential_issuer || apiBase,
  );
  let wiaJwt = null;
  let oauthClientAttestationHeaders = {};
  try {
    const att = await resolveAttestationForEndpoint({
      endpointAudience: tokenEndpoint,
      authorizationServerIssuer,
    });
    wiaJwt = att.clientAssertionJwt;
    oauthClientAttestationHeaders = att.oauthHeaders;
  } catch (attError) {
    console.warn("Failed to resolve OAuth client attestation:", attError?.message);
  }

  const tokenForm = buildPreAuthorizedCodeTokenFormParams({
    preAuthorizedCode,
    txCode,
    authorizationDetails,
    clientAssertion: wiaJwt || undefined,
  });
  const tokenHeaders = buildCliTokenEndpointHeaders({
    dpopJwt,
    oauthClientAttestation: oauthClientAttestationHeaders["OAuth-Client-Attestation"],
    oauthClientAttestationPop: oauthClientAttestationHeaders["OAuth-Client-Attestation-PoP"],
  });
  const tokenRes = await fetch(tokenEndpoint, {
    method: "POST",
    headers: tokenHeaders,
    body: tokenForm.toString(),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.json().catch(() => ({}));
    throw new Error(`Token error ${tokenRes.status}: ${JSON.stringify(err)}`);
  }
  const tokenBody = await tokenRes.json();
  const accessToken = tokenBody.access_token;
  let c_nonce = tokenBody.c_nonce;
  let c_nonce_expires_in = tokenBody.c_nonce_expires_in;

  if (!c_nonce) {
    const nonceEndpoint = `${apiBase}/nonce`;
    const nonceRes = await httpPostJson(nonceEndpoint, {}, null, {
      Authorization: `Bearer ${accessToken}`,
    });
    if (!nonceRes.ok) {
      const err = await nonceRes.json().catch(() => ({}));
      throw new Error(`Nonce error ${nonceRes.status}: ${JSON.stringify(err)}`);
    }
    const nonceJson = await nonceRes.json();
    c_nonce = nonceJson.c_nonce;
    c_nonce_expires_in = nonceJson.c_nonce_expires_in;
  }

  if (!c_nonce) {
    throw new Error("Issuer did not provide c_nonce; cannot complete proof-of-possession flow.");
  }

  const keyPairs = [];
  for (const p of attestPaths) {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(p, "ES256");
    keyPairs.push({ privateJwk, publicJwk, didJwk: generateDidJwkFromPrivateJwk(publicJwk) });
  }

  const credentialEndpoint = `${apiBase}/credential`;
  const { proofs: proofsSection } = await buildCredentialRequestProofs({
    proofMode,
    credentialEndpoint,
    aud: credential_issuer || issuerBase,
    c_nonce,
    keyPairs,
    selectedAlg: "ES256",
  });

  const credReq = {
    ...buildCredentialRequestSelector(configurationId, tokenBody),
    proofs: proofsSection,
  };

  // DPoP on /credential is required only for DPoP-bound access tokens (RFC 9449).
  let credentialDpopJwt = null;
  try {
    if (
      accessToken &&
      dpopPrivateJwk &&
      dpopPublicJwk &&
      isDpopBoundAccessToken(tokenBody, accessToken)
    ) {
      const ath = computeAthForDpop(accessToken);
      credentialDpopJwt = await createDPoP({
        privateJwk: dpopPrivateJwk,
        publicJwk: dpopPublicJwk,
        htu: credentialEndpoint,
        htm: "POST",
        ath,
        alg: "ES256"
      });
    }
  } catch (dpopError) {
    console.warn("Failed to generate DPoP for credential request:", dpopError?.message);
  }

  const credHeaders = {
    "content-type": "application/json",
    authorization: `Bearer ${accessToken}`,
  };
  if (credentialDpopJwt) {
    credHeaders["DPoP"] = credentialDpopJwt;
  }

  const credRes = await fetch(credentialEndpoint, {
    method: "POST",
    headers: credHeaders,
    body: JSON.stringify(credReq),
  });

  if (credRes.status === 202) {
    const deferredAccept = await credRes.json();
    const { transaction_id, interval: initialInterval } = deferredAccept;
    const deferredUrl = `${apiBase}/credential_deferred`;
    const start = Date.now();
    const clientPollMs = argv["poll-interval"];
    let nextDelayMs = getNextPollDelayMs(initialInterval, clientPollMs);
    while (Date.now() - start < argv["poll-timeout"]) {
      await sleep(nextDelayMs);
      let deferredDpopJwt = null;
      try {
        if (
          accessToken &&
          dpopPrivateJwk &&
          dpopPublicJwk &&
          isDpopBoundAccessToken(tokenBody, accessToken)
        ) {
          deferredDpopJwt = await createDPoP({
            privateJwk: dpopPrivateJwk,
            publicJwk: dpopPublicJwk,
            htu: deferredUrl,
            htm: "POST",
            ath: computeAthForDpop(accessToken),
            alg: "ES256",
          });
        }
      } catch (dpopDefErr) {
        console.warn("Failed to generate DPoP for deferred poll:", dpopDefErr?.message);
      }
      const defRes = await httpPostJson(
        deferredUrl,
        { transaction_id },
        deferredDpopJwt,
        { Authorization: `Bearer ${accessToken}` },
      );
      const defText = await defRes.text().catch(() => "");
      const defCt = defRes.headers.get("content-type") || "";
      const outcome = await resolveDeferredPollResult({
        status: defRes.status,
        ok: defRes.ok,
        contentType: defCt,
        responseText: defText,
        decryptionPrivateKey: null,
      });
      if (outcome.kind === "success") {
        const body = outcome.body;
        await notifyCredentialAcceptedIfNeeded({
          credentialResponse: body,
          apiBase,
          accessToken,
          tokenBody,
          dpopPrivateJwk,
          dpopPublicJwk,
        });
        await storeIssuedCredentialsFromCli(configurationId, body, keyPairs, {
          configurationId,
          c_nonce,
          c_nonce_expires_in,
          credential_issuer: credential_issuer || apiBase,
        });
        console.log(JSON.stringify(body, null, 2));
        return;
      }
      if (outcome.kind === "pending") {
        nextDelayMs = getNextPollDelayMs(outcome.interval, clientPollMs);
        continue;
      }
      throw new Error(formatDeferredTerminalError(outcome));
    }
    throw new Error("Deferred issuance timed out");
  }

  if (!credRes.ok) {
    const err = await credRes.json().catch(() => ({}));
    throw new Error(`Credential error ${credRes.status}: ${JSON.stringify(err)}`);
  }

  const credBody = await credRes.json();
  await notifyCredentialAcceptedIfNeeded({
    credentialResponse: credBody,
    apiBase,
    accessToken,
    tokenBody,
    dpopPrivateJwk,
    dpopPublicJwk,
  });
  await storeIssuedCredentialsFromCli(configurationId, credBody, keyPairs, {
    configurationId,
    c_nonce,
    c_nonce_expires_in,
    credential_issuer: credential_issuer || apiBase,
  });
  console.log(JSON.stringify(credBody, null, 2));
}

async function getOfferDeepLink(issuerBase, path, credentialType) {
  if (!path) return undefined;
  const url = new URL(issuerBase + path);
  if (credentialType) url.searchParams.set("type", credentialType);
  const res = await fetch(url.toString());
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Fetch-offer error ${res.status}: ${JSON.stringify(err)}`);
  }
  const body = await res.json();
  return body.deepLink;
}

async function resolveOfferConfig(deepLink) {
  const url = new URL(normalizeCredentialOfferDeepLink(deepLink));
  if (url.protocol !== "openid-credential-offer:") {
    throw new Error("Unsupported offer scheme");
  }
  const inlineOffer = url.searchParams.get("credential_offer");
  if (inlineOffer) {
    return parseCredentialOfferParam(inlineOffer);
  }
  const encoded = url.searchParams.get("credential_offer_uri");
  if (!encoded) throw new Error("Missing credential_offer_uri in offer");
  const offerUri = decodeURIComponent(encoded);
  const res = await fetch(offerUri);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`Offer-config error ${res.status}: ${JSON.stringify(err)}`);
  }
  return res.json();
}

function parseCredentialOfferParam(value) {
  const attempts = new Set([value]);
  try {
    attempts.add(decodeURIComponent(value));
  } catch {
    // ignore decode errors
  }

  for (const attempt of attempts) {
    try {
      return JSON.parse(attempt);
    } catch {
      // not plain JSON, try base64url
      try {
        const decoded = Buffer.from(attempt, "base64url").toString("utf8");
        return JSON.parse(decoded);
      } catch {
        // continue trying other attempts
      }
    }
  }
  throw new Error("Unable to parse credential_offer parameter");
}

async function promptTxCode(cfg) {
  // Non-interactive default: generate a dummy numeric code if required; issuer enforces non-empty tx_code only (no value check).
  if (cfg?.input_mode === "numeric" && typeof cfg?.length === "number") {
    return "".padStart(cfg.length, "1");
  }
  return undefined;
}

async function httpPostJson(url, body, dpopHeader = null, extraHeaders = {}) {
  const headers = { "content-type": "application/json", ...extraHeaders };
  if (dpopHeader) {
    headers["DPoP"] = dpopHeader;
  }
  return fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body || {}),
  });
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});


