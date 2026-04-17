import express from "express";
import fs from "fs";
import * as jose from "jose";
import { pemToJWK } from "../utils/cryptoUtils.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";
import { PROXY_PATH } from "../utils/routeUtils.js";
import { buildIssuerInfo } from "../utils/issuerInfo.js";
const metadataRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
const issuerMetadataSigningKey = fs.readFileSync(
  "./x509EC/ec_private_pkcs8.key",
  "utf-8",
);
const issuerMetadataSigningCertPem = fs.readFileSync(
  "./x509EC/client_certificate.crt",
  "utf-8",
);
const issuerMetadataSigningX5c = [pemToBase64Der(issuerMetadataSigningCertPem)];

const issuerConfig = JSON.parse(
  fs.readFileSync("./data/issuer-config.json", "utf-8")
);
const oauthConfig = JSON.parse(
  fs.readFileSync("./data/oauth-config.json", "utf-8")
);

// Load defaultSigningKid from issuer-config.json, similar to credGenerationUtils.js
let issuerConfigValues = {};
try {
  const issuerConfigRaw = fs.readFileSync("./data/issuer-config.json", "utf-8");
  issuerConfigValues = JSON.parse(issuerConfigRaw);
} catch (err) {
  console.warn("Could not load ./data/issuer-config.json for defaultSigningKid in metadataroutes, using defaults.", err);
}
const defaultSigningKid = issuerConfigValues.default_signing_kid || "aegean#authentication-key";

const jwks = pemToJWK(publicKeyPem, "public");

// RFC001 §7.7 SHALL 8 / ETSI TS 119 472-3: build the `issuer_info` metadata
// parameter once at module load. We intentionally do not fail module init if
// the registration certificate is missing — the metadata response simply
// omits `issuer_info` when no material is available.
let issuerInfoPromise = buildIssuerInfo().catch((err) => {
  console.warn("[issuer_info] Failed to build issuer_info:", err?.message);
  return null;
});

function clientWantsSignedMetadata(req) {
  const accept = String(req.headers.accept || "").toLowerCase();
  return accept.includes("application/jwt");
}

async function signMetadataPayload(payload, typ) {
  const importedKey = await jose.importPKCS8(issuerMetadataSigningKey, "ES256");
  return await new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ,
      x5c: issuerMetadataSigningX5c,
    })
    .sign(importedKey);
}


/**
 * Credential Issuer metadata
 */

metadataRouter.get(
  [
    "/.well-known/openid-credential-issuer",
    "/.well-known/openid-credential-issuer/:suffix(*)",
    "/openid-credential-issuer/:suffix(*)",
  ],
  async (req, res) => {
    const rawSuffix = req.params?.suffix || "";
    const normalizedSuffix = rawSuffix.replace(/^\/+/, "");

    // If the suffix matches PROXY_PATH, don't add it again since SERVER_URL already includes it
    const issuerBase = (normalizedSuffix && normalizedSuffix !== PROXY_PATH) ? `${serverURL}/${normalizedSuffix}` : serverURL;

    issuerConfig.credential_issuer = issuerBase;
    issuerConfig.authorization_servers = [serverURL];
    issuerConfig.credential_endpoint = issuerBase + "/credential";
    issuerConfig.deferred_credential_endpoint = issuerBase + "/credential_deferred";
    issuerConfig.nonce_endpoint = issuerBase + "/nonce";
    issuerConfig.notification_endpoint = issuerBase + "/notification";

    // OID4VCI §11.2: if credential_response_encryption is advertised,
    // credential_request_encryption MUST also be present (EUDI wallet library enforces this).
    if (issuerConfig.credential_response_encryption && !issuerConfig.credential_request_encryption) {
      const encJwk = { ...jwks, kid: `${defaultSigningKid}-agreement`, use: "enc", alg: "ECDH-ES" };
      issuerConfig.credential_request_encryption = {
        jwks: { keys: [encJwk] },
        enc_values_supported: issuerConfig.credential_response_encryption.enc_values_supported || ["A256GCM"],
        encryption_required: false,
      };
    }

    // OID4VCI 1.0 (draft-14+) removed `batch_credential_endpoint` from the issuer
    // metadata. RFC001 is constrained to OID4VCI 1.0, so we MUST NOT advertise it —
    // strip it from the outgoing metadata regardless of what `data/issuer-config.json`
    // contains. Batch/multi-credential issuance is performed against the standard
    // `POST /credential` endpoint using `proofs.jwt[]`.
    if (Object.prototype.hasOwnProperty.call(issuerConfig, "batch_credential_endpoint")) {
      delete issuerConfig.batch_credential_endpoint;
    }

    // RFC001 §7.7 SHALL 8 — attach `issuer_info` (registration certificate +
    // registrar-provided registration information) when available.
    const issuerInfo = await issuerInfoPromise;
    if (issuerInfo) {
      issuerConfig.issuer_info = issuerInfo;
    } else if (Object.prototype.hasOwnProperty.call(issuerConfig, "issuer_info")) {
      delete issuerConfig.issuer_info;
    }

    if (clientWantsSignedMetadata(req)) {
      const signedMetadata = await signMetadataPayload(
        issuerConfig,
        "openid-credential-issuer-metadata+jwt",
      );
      return res.type("application/jwt").send(signedMetadata);
    }

    res.type("application/json").send(issuerConfig);
  }
);

/**
 * Authorization Server Metadata
 */
metadataRouter.get(
  [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/openid-configuration/:suffix(*)",
    "/oauth-authorization-server/rfc-issuer", //this is required in case the issuer is behind a reverse proxy: see https://www.rfc-editor.org/rfc/rfc8414.html
  ],
  async (req, res) => {
    oauthConfig.issuer = serverURL;
    oauthConfig.authorization_endpoint = serverURL + "/authorize";
    oauthConfig.pushed_authorization_request_endpoint = serverURL + "/par";
    oauthConfig.token_endpoint = serverURL + "/token_endpoint";
    oauthConfig.jwks_uri = serverURL + "/jwks";
    res.type("application/json").send(oauthConfig);
  }
);




metadataRouter.get(["/", "/jwks"], (req, res) => {
  res.json({
    keys: [
      { ...jwks, kid: defaultSigningKid, use: "sig" },
      { ...jwks, kid: `${defaultSigningKid}-agreement`, use: "keyAgreement" },
    ],
  });
});


/*
*If the iss value contains a path component, any terminating / MUST 
be removed before inserting /.well-known/ and the well-known URI suffix between the host component and the path component.
*/
metadataRouter.get(
  ["/.well-known/jwt-vc-issuer", "/.well-known/jwt-vc-issuer/rfc-issuer", "/jwt-vc-issuer/rfc-issuer"  ],
  
  /*
  issuer:  REQUIRED. The Issuer identifier, which MUST be identical to the iss value in the JWT. 
  jwks_uri: OPTIONAL. URL string referencing the Issuer's JSON Web Key (JWK) Set [RFC7517] 
document which contains the Issuer's public keys. The value of this field MUST point to a valid JWK Set document.
  jwks : OPTIONAL. Issuer's JSON Web Key Set [RFC7517] document value, 
which contains the Issuer's public keys. The value of this field MUST be a JSON object containing a valid JWK Set.
  */
  
  async (req, res) => {
    const metadata ={
      issuer: serverURL,
      jwks : {
        keys: [
          { ...jwks, kid: defaultSigningKid, use: "sig" },
          { ...jwks, kid: `${defaultSigningKid}-agreement`, use: "keyAgreement" },
        ]
      }

    }

    res.type("application/json").send(metadata);
  }
);



export default metadataRouter;
