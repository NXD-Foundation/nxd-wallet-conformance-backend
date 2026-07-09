import express from "express";
import fs from "fs";
import { pemToJWK } from "../utils/cryptoUtils.js";
import { PROXY_PATH } from "../utils/routeUtils.js";
import { buildStrictCs02ClientMetadata } from "../utils/cs02TrustPolicy.js";
const metadataRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

const issuerConfig = JSON.parse(
  fs.readFileSync("./data/issuer-config.json", "utf-8")
);
const oauthConfig = JSON.parse(
  fs.readFileSync("./data/oauth-config.json", "utf-8")
);

function loadVerifierClientMetadata() {
  return JSON.parse(fs.readFileSync("./data/verifier-config.json", "utf-8"));
}

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

    if (issuerConfig.batch_credential_endpoint) {
      console.warn("Warning: batch_credential_endpoint is part of issuerConfig but removed from spec draft -14. Consider removing from data/issuer-config.json");
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

metadataRouter.get(["/client-metadata", "/client-metadata/cs02"], (req, res) => {
  const broadMetadata = loadVerifierClientMetadata();
  const strictCs02 =
    req.path.endsWith("/cs02") ||
    String(req.query.profile || "").toLowerCase() === "cs02" ||
    String(req.query.profile || "").toLowerCase() === "we-build-cs02";
  const responseMode =
    typeof req.query.response_mode === "string" && req.query.response_mode
      ? req.query.response_mode
      : "direct_post";
  const metadata = strictCs02
    ? buildStrictCs02ClientMetadata(broadMetadata, responseMode)
    : broadMetadata;
  res.type("application/json").send(metadata);
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

metadataRouter.get(
  ["/.well-known/vct/:vct(*)", "/vct/:vct(*)"],
  async (req, res) => {
    const requestedVct = decodeURIComponent(req.params.vct || "");
    const supported = issuerConfig.credential_configurations_supported || {};
    const configEntry =
      supported[requestedVct] ||
      Object.values(supported).find((entry) => entry?.vct === requestedVct);

    if (!configEntry) {
      return res.status(404).json({ error: "Unknown vct" });
    }

    const metadata = {
      vct: configEntry.vct || requestedVct,
      name:
        configEntry.credential_metadata?.display?.[0]?.name ||
        configEntry.vct ||
        requestedVct,
      description:
        configEntry.credential_metadata?.display?.[0]?.name ||
        "TS12 SCA attestation",
    };

    if (configEntry.category) {
      metadata.category = configEntry.category;
    }
    if (configEntry.transaction_data_types) {
      metadata.transaction_data_types = configEntry.transaction_data_types;
    }

    res.type("application/json").send(metadata);
  },
);



export default metadataRouter;
