import fs from "fs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { error } from "console";
import {generateNonce} from "../utils/cryptoUtils.js"

export function buildAccessToken(issuerURL, privateKey) {
  const payload = {
    iss: issuerURL,
    sub: "user123", // This should be the authenticated user's identifier
    aud: issuerURL, // The identifier of your resource server
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
    iat: Math.floor(Date.now() / 1000), // Current time
    scope: "openid",
  };
  // Sign the JWT
  const token = jwt.sign(payload, privateKey, { algorithm: "ES256" });

  //   console.log(token);
  return token;
}

export function generateRefreshToken(length = 64) {
  return crypto.randomBytes(length).toString("hex");
}

export function buildIdToken(issuerURL, privateKey) {
  const payload = {
    iss: issuerURL,
    sub: "user123",
    aud: "https://self-issued.me/v2", // The client ID of the application making the authentication request
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expiration time (1 hour from now)
    iat: Math.floor(Date.now() / 1000), // Token issued at time
    auth_time: Math.floor(Date.now() / 1000) - 60 * 5, // Assume the user authenticated 5 minutes ago
    // Optional claims
    nonce: "nonceValue", // If using implicit flow or authorization code flow with PKCE
    // Add other claims as necessary
  };

  // Sign the token
  const idToken = jwt.sign(payload, privateKey, {
    algorithm: "ES256", // Ensure the algorithm matches the key and your authorization server configuration
    // You can add a "kid" (key ID) here if your private key has one
  });

  //   console.log("Generated ID Token:", idToken);
  return idToken;
}

export function buildVPbyValue(
  client_id,
  presentation_definition_uri,
  client_id_scheme,
  client_metadata,
  response_uri,
  state,
  response_type = "vp_token",
  nonce,
  response_mode = "direct_post",
  dcql_query = null
) {
  // Validate response_mode
  const allowedResponseModes = ["direct_post", "direct_post.jwt"];
  if (!allowedResponseModes.includes(response_mode)) {
    throw new Error(`Invalid response_mode. Must be one of: ${allowedResponseModes.join(", ")}`);
  }

  if (!nonce) nonce = generateNonce(16);
  if (!state) state = generateNonce(16);

  let vpRequest = "openid4vp://?";
  vpRequest += `client_id=${encodeURIComponent(client_id)}`;
  vpRequest += `&client_id_scheme=${encodeURIComponent(client_id_scheme)}`;
  vpRequest += `&response_type=${encodeURIComponent(response_type)}`;
  vpRequest += `&response_mode=${encodeURIComponent(response_mode)}`;
  vpRequest += `&response_uri=${encodeURIComponent(response_uri)}`;
  vpRequest += `&nonce=${encodeURIComponent(nonce)}`;
  vpRequest += `&state=${encodeURIComponent(state)}`;

  if (presentation_definition_uri) {
    vpRequest += `&presentation_definition_uri=${encodeURIComponent(presentation_definition_uri)}`;
  }

  // Handle client_metadata (object)
  if (client_metadata && typeof client_metadata === 'object') {
    vpRequest += `&client_metadata=${encodeURIComponent(JSON.stringify(client_metadata))}`;
  }

  if (dcql_query) {
    vpRequest += `&dcql_query=${encodeURIComponent(JSON.stringify(dcql_query))}`;
  }

  return vpRequest;
}


// export function buildVPbyReference(
//   client_id,
//   presentation_definition_uri,
//   client_id_scheme = "redirect_uri",
//   client_metadata_uri,
//   redirect_uri,
//   state = "af0ifjsldkj",
//   response_type = "vp_token"
// ) {
//   if (client_id_scheme == "redirect_uri") {
//     throw new Error("redirect_uri is not supportted for VP by reference");
//   } else {
//     if (response_type == "id_token") {
//       // state, client_id, redirect_uri, response_type, response_mode, scope, nonce, request_uri

//       let result =
//         "openid4vp://?client_id=" +
//         encodeURIComponent(client_id) +
//         "&response_type=" +
//         response_type;
//       "&response_mode=direct_post" +
//         "&response_uri=" +
//         encodeURIComponent(redirect_uri) +
//         "&client_id_scheme=" +
//         client_id_scheme +
//         "&client_metadata_uri=" +
//         encodeURIComponent(client_metadata_uri) +
//         "&nonce=n0S6_WzA2Mj" +
//         "&state=" +
//         state  
//       return result;
//     } else {
//       let result =
//         "openid4vp://?client_id=" +
//         encodeURIComponent(client_id) +
//         "&response_type=" +
//         response_type;
//       "&response_mode=direct_post" +
//         "&response_uri=" +
//         encodeURIComponent(redirect_uri) +
//         "&presentation_definition_uri=" +
//         encodeURIComponent(presentation_definition_uri) +
//         "&client_id_scheme=" +
//         client_id_scheme +
//         "&client_metadata_uri=" +
//         encodeURIComponent(client_metadata_uri) +
//         "&nonce=n0S6_WzA2Mj" +
//         "&state=" +
//         state;
//       return result;
//     }
//   }
// }

/**
 * Base64url (no padding) of SHA-256(access token), for DPoP `ath` claim (RFC 9449).
 */
export function computeAthForDpop(accessToken) {
  const hash = crypto.createHash("sha256").update(accessToken, "utf8").digest();
  return hash
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Whether the token response / access token is DPoP sender-constrained (RFC 9449).
 * Uses token_type when present; for JWT access tokens, also detects cnf.jkt.
 */
export function isDpopBoundAccessToken(tokenBody, accessToken) {
  const tt = tokenBody?.token_type;
  if (typeof tt === "string" && tt.toLowerCase() === "dpop") {
    return true;
  }
  if (typeof accessToken !== "string" || !accessToken) {
    return false;
  }
  const parts = accessToken.split(".");
  if (parts.length < 2) {
    return false;
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return !!(payload?.cnf?.jkt && typeof payload.cnf.jkt === "string");
  } catch {
    return false;
  }
}

/**
 * Authorization Server issuer URL for OAuth Client Attestation PoP `aud`
 * (matches wallet-client server `deriveAuthorizationServerIssuer`).
 */
export function deriveAuthorizationServerIssuer(endpoint, fallback) {
  if (fallback) return fallback;
  if (!endpoint) return undefined;
  try {
    return new URL(endpoint).origin;
  } catch {
    return endpoint;
  }
}

/**
 * Pre-authorized code grant token request body as `application/x-www-form-urlencoded`
 * (OAuth 2.0 token endpoint; OIDC4VCI).
 */
export function buildPreAuthorizedCodeTokenFormParams({
  preAuthorizedCode,
  txCode,
  authorizationDetails,
  clientAssertion,
  clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
}) {
  const form = new URLSearchParams();
  form.set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code");
  form.set("pre-authorized_code", preAuthorizedCode);
  if (txCode !== undefined && txCode !== null && txCode !== "") {
    form.set("tx_code", String(txCode));
  }
  if (authorizationDetails !== undefined && authorizationDetails !== null) {
    const ad =
      typeof authorizationDetails === "string"
        ? authorizationDetails
        : JSON.stringify(authorizationDetails);
    form.set("authorization_details", ad);
  }
  if (clientAssertion) {
    form.set("client_assertion", clientAssertion);
    form.set("client_assertion_type", clientAssertionType);
  }
  return form;
}

/**
 * Headers for CLI token endpoint POST (form body + DPoP + OAuth Client Attestation).
 */
export function buildCliTokenEndpointHeaders({
  dpopJwt,
  oauthClientAttestation,
  oauthClientAttestationPop,
}) {
  const headers = {
    "content-type": "application/x-www-form-urlencoded",
  };
  if (dpopJwt) {
    headers["DPoP"] = dpopJwt;
  }
  if (oauthClientAttestation) {
    headers["OAuth-Client-Attestation"] = oauthClientAttestation;
  }
  if (oauthClientAttestationPop) {
    headers["OAuth-Client-Attestation-PoP"] = oauthClientAttestationPop;
  }
  return headers;
}

/**
 * Token response may include `authorization_details` with `credential_identifiers` (OIDC4VCI / RFC001 §6.2.7).
 * Returns the first non-empty string from any detail's `credential_identifiers` array.
 */
export function extractFirstCredentialIdentifierFromTokenResponse(tokenBody) {
  if (!tokenBody || typeof tokenBody !== "object") return undefined;
  let details = tokenBody.authorization_details;
  if (details == null) return undefined;
  if (typeof details === "string") {
    try {
      details = JSON.parse(details);
    } catch {
      return undefined;
    }
  }
  if (!Array.isArray(details)) return undefined;
  for (const d of details) {
    if (!d || typeof d !== "object") continue;
    const ids = d.credential_identifiers;
    if (!Array.isArray(ids) || ids.length === 0) continue;
    for (const x of ids) {
      if (typeof x === "string" && x.length > 0) return x;
    }
  }
  return undefined;
}

/**
 * `/credential` request body: use `credential_identifier` when the token response carried identifiers;
 * otherwise `credential_configuration_id` from the offer flow.
 */
export function buildCredentialRequestSelector(configurationId, tokenBody) {
  const cid = extractFirstCredentialIdentifierFromTokenResponse(tokenBody);
  if (cid) return { credential_identifier: cid };
  return { credential_configuration_id: configurationId };
}
