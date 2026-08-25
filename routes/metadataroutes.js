import express from "express";
import fs from "fs";
import { pemToJWK } from "../utils/cryptoUtils.js";
import {
  PROXY_PATH,
  SERVER_URL,
  buildOpenIdVerifierMetadataDocument,
  buildRfc002VerifierMetadataDocument,
  getPublicIssuerBaseUrl,
} from "../utils/routeUtils.js";
import { signCredentialIssuerMetadataFromConfiguredP12 } from "../utils/issuerMetadataSigning.js";
const metadataRouter = express.Router();

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
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

// The Android EUDI reference wallet deserializes every advertised credential
// configuration before it selects the one in the offer. Keep experimental
// formats in issuer-config.json for local work, but do not publish formats the
// wallet cannot parse: one unsupported entry breaks discovery entirely.
const WALLET_SUPPORTED_CREDENTIAL_FORMATS = new Set([
  "dc+sd-jwt",
  "jwt_vc_json",
  "mso_mdoc",
]);

// Wallet Demo build 39 uses openid4vci 0.12.1. That release rejects the
// complete issuer metadata document when any cryptographically-bound
// configuration advertises just one of `jwt` or `attestation`. Do not let an
// unrelated, narrower configuration (currently `room_key_credential`) make a
// valid offered credential undiscoverable.
function hasWalletCompatibleProofTypes(configuration) {
  const proofTypes = Object.keys(configuration?.proof_types_supported || {});
  return proofTypes.length === 0 ||
    (proofTypes.includes("jwt") && proofTypes.includes("attestation"));
}

function buildPublishedIssuerMetadata(config) {
  const credential_configurations_supported = Object.fromEntries(
    Object.entries(config.credential_configurations_supported || {}).filter(
      ([, value]) =>
        WALLET_SUPPORTED_CREDENTIAL_FORMATS.has(value?.format) &&
        hasWalletCompatibleProofTypes(value),
    ),
  );

  return { ...config, credential_configurations_supported };
}

// Do not retain the key used for credential-request encryption at module load
// time. Besides avoiding a stale key after certificate/key rotation, this makes
// the advertised JWK a direct export of the PEM currently used by the issuer.
function getCredentialRequestEncryptionJwk() {
  return pemToJWK(fs.readFileSync("./public-key.pem", "utf-8"), "public");
}

function clientWantsSignedMetadata(req) {
  const accept = String(req.headers.accept || "").toLowerCase();
  return accept.includes("application/jwt");
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
    // Keep the metadata identifier identical to the identifier in credential
    // offers.  The latter is built from SERVER_URL, so deriving this value
    // from a request Host header can make a locally-opened offer resolve a
    // different signed issuer identifier than the wallet expects.
    const serverURL = SERVER_URL;
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
      const encJwk = {
        ...getCredentialRequestEncryptionJwk(),
        kid: `${defaultSigningKid}-agreement`,
        use: "enc",
        alg: "ECDH-ES",
      };
      issuerConfig.credential_request_encryption = {
        jwks: { keys: [encJwk] },
        alg_values_supported: ["ECDH-ES"],
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

    const publishedIssuerMetadata = buildPublishedIssuerMetadata(issuerConfig);

    if (clientWantsSignedMetadata(req)) {
      try {
        const signedMetadata = await signCredentialIssuerMetadataFromConfiguredP12(publishedIssuerMetadata);
        return res.type("application/jwt").send(signedMetadata);
      } catch (error) {
        console.error("Unable to produce signed Credential Issuer metadata:", error.message);
        return res.status(503).json({
          error: "temporarily_unavailable",
          error_description: "Signed Credential Issuer metadata is unavailable",
        });
      }
    }

    res.type("application/json").send(publishedIssuerMetadata);
  }
);

/**
 * OpenID Verifier metadata (RFC002 §8.4)
 */
metadataRouter.get("/.well-known/openid-verifier-metadata", (req, res) => {
  try {
    const serverURL = SERVER_URL;
    const doc = buildOpenIdVerifierMetadataDocument({ serverURL });
    res.type("application/json").json(doc);
  } catch (err) {
    console.error("[openid-verifier-metadata]", err?.message || err);
    res.status(500).type("application/json").json({
      error: "server_error",
      error_description: err?.message || "Failed to build verifier metadata",
    });
  }
});

metadataRouter.get("/client-metadata/rfc002", (req, res) => {
  try {
    const serverURL = SERVER_URL;
    res.type("application/json").json(
      buildRfc002VerifierMetadataDocument({ serverURL }),
    );
  } catch (err) {
    res.status(500).type("application/json").json({
      error: "server_error",
      error_description: err?.message || "Failed to build RFC002 verifier metadata",
    });
  }
});

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
    const serverURL = getPublicIssuerBaseUrl(req);
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
    const serverURL = getPublicIssuerBaseUrl(req);
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
