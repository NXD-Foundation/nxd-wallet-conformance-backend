#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import fetch from "node-fetch";
import {
  generateDidJwkFromPrivateJwk,
  ensureOrCreateEcKeyPair,
  createDPoP,
} from "./lib/crypto.js";
import { resolveAttestationForEndpoint } from "./lib/walletProviderIdentity.js";
import { resolveAttestDeviceKeyPaths } from "./lib/deviceKeyPaths.js";
import { buildCredentialRequestProofs } from "./lib/credentialRequestProofs.js";
import { normalizeCredentialOfferDeepLink } from "./lib/credentialOfferScheme.js";
import {
  exchangeToken,
  fetchCredentialNonce,
  buildCredentialRequest,
  postCredentialRequest,
  pollDeferredCredential,
  notifyCredentialAcceptedIfNeeded,
  storeIssuedCredentials,
  buildKeyPairs,
} from "./lib/issuance.js";
import {
  isDpopBoundAccessToken,
  computeAthForDpop,
  deriveAuthorizationServerIssuer,
  buildPreAuthorizedCodeTokenFormParams,
  buildCliTokenEndpointHeaders,
  buildCredentialRequestSelector,
} from "../utils/tokenUtils.js";

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
    .option("poll-interval", {
      type: "number",
      describe: "optional deferred issuance poll interval override in milliseconds",
    })
    .option("poll-timeout", {
      type: "number",
      describe: "optional deferred issuance timeout override in milliseconds",
    })
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
  let dpopPrivateJwk = null;
  let dpopPublicJwk = null;
  const authorizationServerIssuer = deriveAuthorizationServerIssuer(
    tokenEndpoint,
    credential_issuer || apiBase,
  );
  const tokenExchange = await exchangeToken({
      tokenEndpoint,
      tokenPayload: Object.fromEntries(buildPreAuthorizedCodeTokenFormParams({
        preAuthorizedCode,
        txCode,
        authorizationDetails,
      }).entries()),
      authorizationServerIssuer,
      ensureOrCreateEcKeyPair,
      createDPoP,
      resolveAttestationForEndpoint,
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey: () => false,
      rotateWalletProviderKeyPair: async () => false,
      postForm: async (url, params, dpopHeader, extraHeaders = {}) => {
        const form = new URLSearchParams();
        Object.entries(params).forEach(([key, value]) => {
          if (typeof value !== "undefined") form.append(key, value);
        });
        const headers = buildCliTokenEndpointHeaders({
          dpopJwt: dpopHeader,
          oauthClientAttestation: extraHeaders["OAuth-Client-Attestation"],
          oauthClientAttestationPop: extraHeaders["OAuth-Client-Attestation-PoP"],
        });
        return fetch(url, {
          method: "POST",
          headers,
          body: form.toString(),
        });
      },
      deviceKeyPath,
    });
  const tokenBody = tokenExchange.tokenBody;
  dpopPrivateJwk = tokenExchange.dpopPrivateJwk;
  dpopPublicJwk = tokenExchange.dpopPublicJwk;
  const accessToken = tokenBody.access_token;
  const { c_nonce, c_nonce_expires_in } = await fetchCredentialNonce({
    tokenBody,
    nonceEndpoint: `${apiBase}/nonce`,
    accessToken,
    postJson: httpPostJson,
  });

  const keyPairs = await buildKeyPairs({
    keyPaths: attestPaths,
    selectedAlg: "ES256",
    ensureOrCreateEcKeyPair,
    generateDidJwkFromPrivateJwk,
  });

  const credentialEndpoint = `${apiBase}/credential`;
  const { credentialRequest: credReq } = await buildCredentialRequest({
    configurationId,
    tokenBody,
    proofMode,
    credentialEndpoint,
    audience: credential_issuer || issuerBase,
    c_nonce,
    keyPairs,
    selectedAlg: "ES256",
    buildCredentialRequestProofs,
    buildCredentialRequestSelector,
    prepareCredentialResponseEncryption: async () => null,
  });

  const { body: initialCredentialBody, status: credentialStatus } = await postCredentialRequest({
    credentialEndpoint,
    credentialRequest: credReq,
    accessToken,
    tokenBody,
    dpopPrivateJwk,
    dpopPublicJwk,
    isDpopBoundAccessToken,
    computeAthForDpop,
    createDPoP,
    fetchImpl: fetch,
    parseCredentialResponsePayload: async (responseText, contentType) => {
      if (!contentType.includes("json")) return null;
      return responseText ? JSON.parse(responseText) : {};
    },
  });

  const credBody = credentialStatus === 202
    ? await pollDeferredCredential({
        deferredEndpoint: `${apiBase}/credential_deferred`,
        transactionId: initialCredentialBody.transaction_id,
        initialInterval: initialCredentialBody.interval,
        pollTimeoutMs: argv["poll-timeout"],
        pollIntervalMs: argv["poll-interval"],
        accessToken,
        tokenBody,
        dpopPrivateJwk,
        dpopPublicJwk,
        isDpopBoundAccessToken,
        computeAthForDpop,
        createDPoP,
        postJson: httpPostJson,
        parseCredentialResponsePayload: async (responseText, contentType) => {
          if (!contentType.includes("json")) return null;
          return responseText ? JSON.parse(responseText) : {};
        },
      })
    : initialCredentialBody;

  await notifyCredentialAcceptedIfNeeded({
    credentialResponse: credBody,
    issuerMeta: undefined,
    apiBase,
    accessToken,
    tokenBody,
    dpopPrivateJwk,
    dpopPublicJwk,
  });
  await storeIssuedCredentials(configurationId, credBody, keyPairs, {
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
