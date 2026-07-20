import crypto from "crypto";
import { execSync } from "child_process";
import jwt from "jsonwebtoken";
import * as jose from "jose";
import base64url from "base64url";
import { error } from "console";
import fs from "fs";
import path from "path";
import { generateRefreshToken } from "./tokenUtils.js";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import fetch from "node-fetch";
import {
  resolveVerifierCs02Options,
  validateCs02JarGenerationInput,
  validateCs02TransactionDataEntries,
  applyCs02JarTimestamps,
  validateCs02SignedJar,
  filterClientMetadataForCs02,
  resolveCs02JarSigningPolicy,
  validateVerifierAttestationForRequestGeneration,
  validateX509SanDnsTrustForRequestGeneration,
  Cs02VerifierRequestError,
} from "./cs02VerifierRequest.js";
import { buildStrictCs02ClientMetadata } from "./cs02TrustPolicy.js";
import { isStrictCs02Base64Url } from "./cs02Encoding.js";
import { resolveCs07VerifierOrigin } from "./cs07DcApi.js";

/**
 * Extract certificate chain from a PEM file (fullchain or single cert)
 * Returns an array of base64-encoded certificates (without PEM headers)
 * @param {string} certPem - Certificate in PEM format (can contain multiple certs)
 * @returns {string[]} Array of base64-encoded certificates
 */
function extractCertificateChain(certPem) {
  // Split by certificate boundaries
  const certMatches = certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
  );

  if (!certMatches || certMatches.length === 0) {
    throw new Error("No certificates found in PEM data");
  }

  // Extract base64 content from each certificate
  return certMatches.map((cert) => {
    return cert
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "");
  });
}

/**
 * Load certificate chain and private key from WE-BUILD Verifier P12 file.
 * Uses openssl for reliable extraction (node-forge may fail on some p12 formats).
 * Used for x509 and dc_api flows.
 * @returns {{ privateKeyPkcs8: string, certChain: string[] }}
 */
const DEFAULT_VERIFIER_CA_PEMS = [
  path.resolve(process.cwd(), "certs", "pidissuerca02_eu.pem"),
];

function resolveVerifierCaPemPaths() {
  const raw = process.env.WEBUILD_X5C_CA_PEM;
  if (!raw) return DEFAULT_VERIFIER_CA_PEMS;
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => (path.isAbsolute(entry) ? entry : path.resolve(process.cwd(), entry)));
}

function appendCaCertsIfNeeded(certChain, caPemPaths = resolveVerifierCaPemPaths()) {
  if (!Array.isArray(certChain) || certChain.length !== 1) {
    return certChain;
  }

  const seen = new Set(certChain);
  const missingOrInvalid = [];

  for (const pemPath of caPemPaths) {
    if (!fs.existsSync(pemPath)) {
      missingOrInvalid.push(`${pemPath} (missing)`);
      continue;
    }

    try {
      const pem = fs.readFileSync(pemPath, "utf8");
      const certs = extractCertificateChain(pem);
      for (const derB64 of certs) {
        if (!seen.has(derB64)) {
          certChain.push(derB64);
          seen.add(derB64);
        }
      }
    } catch (error) {
      missingOrInvalid.push(`${pemPath} (${error.message})`);
    }
  }

  if (certChain.length > 1) {
    return certChain;
  }

  const allowLeafOnly = /^true$/i.test(process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY || "");
  const reason = missingOrInvalid.length > 0
    ? missingOrInvalid.join(", ")
    : "no CA certificates were appended";
  const message = `WE-BUILD verifier x5c CA chain is unavailable: ${reason}`;

  if (!allowLeafOnly) {
    throw new Error(`${message}. Add certs/pidissuerca02_eu.pem or set WEBUILD_X5C_CA_PEM.`);
  }

  console.warn(`${message}. Continuing with leaf-only x5c because WEBUILD_X5C_ALLOW_LEAF_ONLY=true.`);
  return certChain;
}

function loadVerifierP12() {
  const p12Path = path.resolve(process.cwd(), "certs", "WE-BUILD-Verifier.p12");
  const passphrase = process.env.WEBUILD_P12_PASSWORD || "webuild";

  if (!fs.existsSync(p12Path)) {
    throw new Error(
      `WE-BUILD Verifier P12 not found at ${p12Path}. Place the p12 file in ./certs/`
    );
  }

  try {
    const envWithPass = { ...process.env, WEBUILD_P12_PASS: passphrase };
    const certPem = execSync(
      `openssl pkcs12 -in "${p12Path}" -nokeys -passin env:WEBUILD_P12_PASS`,
      { encoding: "utf8", maxBuffer: 64 * 1024, env: envWithPass }
    );
    const privateKeyPem = execSync(
      `openssl pkcs12 -in "${p12Path}" -nodes -nocerts -passin env:WEBUILD_P12_PASS`,
      { encoding: "utf8", maxBuffer: 64 * 1024, env: envWithPass }
    );
    const certChain = appendCaCertsIfNeeded(extractCertificateChain(certPem));
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const privateKeyPkcs8 = privateKey.export({
      type: "pkcs8",
      format: "pem",
    });
    return { privateKeyPkcs8, certChain };
  } catch (err) {
    throw new Error(
      `Failed to extract cert/key from P12: ${err.message}. Ensure openssl is installed.`
    );
  }
}

export function pemToJWK(pem, keyType) {
  let key;
  let jwk;

  if (keyType === "private") {
    key = crypto.createPrivateKey(pem);
    // Export JWK including the private key parameter (`d`)
    jwk = key.export({ format: "jwk" }); // This includes x, y, and d for EC keys
  } else {
    key = crypto.createPublicKey(pem);
    // Export JWK with only public components
    jwk = key.export({ format: "jwk" }); // This includes x and y for EC keys
  }

  // Optionally, set or adjust JWK properties if necessary
  jwk.kty = "EC"; // Key Type
  jwk.crv = "P-256"; //"P-384"; // Curve (adjust as necessary based on your actual curve)

  return jwk;
}

/** PEM-wrap a single DER certificate (base64 body, no headers). */
export function derBase64ToPemCert(b64) {
  const body = String(b64).replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/**
 * Public JWK from the first certificate in an x5c chain (OID4VCI JWT proof header).
 * @param {string[]} x5c - Array of base64-encoded DER certificates
 * @param {string} [alg] - JWS alg hint for jose.importX509 (e.g. ES256)
 */
export async function jwkFromX5cFirstCert(x5c, alg = "ES256") {
  if (!Array.isArray(x5c) || x5c.length === 0 || !x5c[0]) {
    throw new Error("x5c must be a non-empty array of base64-encoded certificates");
  }
  const pem = derBase64ToPemCert(x5c[0]);
  const key = await jose.importX509(pem, alg);
  return jose.exportJWK(key);
}

export function generateNonce(length = 12) {
  return crypto.randomBytes(length).toString("hex");
}

export function parseDidJwk(did) {
  if (!did || !did.startsWith("did:jwk:")) {
    throw new Error("Identifier is not a did:jwk");
  }

  const didWithoutFragment = did
    .replace(/%23.*$/i, "")
    .split("#")[0];
  const jwkPart = didWithoutFragment.substring("did:jwk:".length);
  return JSON.parse(Buffer.from(jwkPart, "base64url").toString("utf8"));
}

export function buildVpRequestJSON(
  state,
  nonce,
  client_id,
  response_uri,
  presentation_definition,
  jwk,
  serverURL,
  privateKey
) {
  /*
      client_id	Verifier identifier for .e.g URI / DID. This value must be present in sub field of the verifiable presentation JWT
      response_type	The value must be vp_token
      scope	Optional value, details are specified in [Section 3.1.1](#3.1.1-scope-parameter-usage)
      response_uri	This should be present when the response_mode is direct_post.
      response_mode	The value must be direct_post
      state	The client uses an opaque value to maintain the state between the request and callback.
      nonce	Securely bin verifiable presentations provided by the wallet to a particular transaction
      presentation_definition	The verifier requires proof. It must conform to the DIF Presentation Exchange specification [4].
*/

  /**
 Location: https://client.example.org/universal-link?
    response_type=vp_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &client_id_scheme=redirect_uri
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &presentation_definition=...
    &nonce=n-0S6_WzA2Mj
    &client_metadata=%7B%22vp_formats%22:%7B%22jwt_vp%22:%
    7B%22alg%22:%5B%22EdDSA%22,%22ES256K%22%5D%7D,%22ldp
    _vp%22:%7B%22proof_type%22:%5B%22Ed25519Signature201
    8%22%5D%7D%7D%7D
 * 
 */

  let jwtPayload = {
    response_type: "vp_token",
    client_id: client_id,
    client_id_scheme: "redirect_uri",
    presentation_definition: presentation_definition,
    redirect_uri: response_uri,
    // response_mode: "direct_post",
    nonce: "n-0S6_WzA2Mj",
    state: "af0ifjsldkj",
    client_metadata: {
      vp_formats: {
        "vc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "ES384"],
          "kb-jwt_alg_values": ["ES256", "ES384"],
        },
        ldp_vp: {
          proof_type: ["Ed25519Signature2018"],
        },
      },
      // Add any additional required metadata here
    },

    // response_uri: response_uri, //TODO Note: If the Client Identifier scheme redirect_uri is used in conjunction with the Response Mode direct_post, and the response_uri parameter is present, the client_id value MUST be equal to the response_uri value
  };

  // const header = {
  //   alg: "ES256",
  //   kid: `aegean#authentication-key`, //this kid needs to be resolvable from the did.json endpoint
  // };

  // const token = jwt.sign(jwtPayload, privateKey, {
  //   algorithm: "ES256",
  //   noTimestamp: true,
  //   header,
  // });
  return jwtPayload;
}

// Generate a test VA-JWT for development/testing purposes
// NOTE: In production, VA-JWT should be obtained from a trusted third-party issuer
// This self-signed implementation is for testing only and violates the spec requirement
// that VA-JWTs must be issued by a trusted party separate from the verifier
async function generateTestVAJWT(subject) {
  const now = Math.floor(Date.now() / 1000);

  // Load the x509 private key to create a self-signed VA-JWT
  // NOTE: This violates the spec - VA-JWT should be signed by a trusted issuer's key
  const privateKeyPem = fs.readFileSync(
    "./x509/client_private_pkcs8.key",
    "utf8"
  );
  const publicKey = crypto.createPublicKey(privateKeyPem);
  const jwk = publicKey.export({ format: "jwk" });

  const vaHeader = {
    alg: "RS256",
    typ: "verifier-attestation+jwt",
  };

  const vaPayload = {
    iss: "https://dss.aegean.gr", // Self-issued for testing
    sub: subject,
    exp: now + 3600, // 1 hour
    iat: now,
    cnf: { jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } }, // Public key for proof-of-possession
  };

  const vaJwt = await new jose.SignJWT(vaPayload)
    .setProtectedHeader(vaHeader)
    .sign(await jose.importPKCS8(privateKeyPem, "RS256"));

  return vaJwt;
}

export async function buildVpRequestJWT(
  client_id,
  redirect_uri,
  presentation_definition,
  privateKey = null, // Only used for verifier_attestation scheme proof-of-possession
  client_metadata = {},
  kid = null, // Default to an empty object,
  serverURL,
  response_type = "vp_token",
  nonce,
  dcql_query = null,
  transaction_data = null,
  response_mode = "direct_post", // Add response_mode parameter with default
  audience = "https://self-issued.me/v2", // New audience parameter
  wallet_nonce = null,
  wallet_metadata = null,
  va_jwt = null, // Optional Verifier Attestation JWT for verifier_attestation scheme
  state = null, // Add state parameter (last param to match test ordering)
  jar_alg = null, // Optional JAR signature algorithm override (e.g., 'ES256') for x509 schemes
  cs07DcApi = false,
  cs07VerifierOrigin = null,
) {
  const cs02Options = resolveVerifierCs02Options(process.env);
  const cs07Origin = cs07DcApi
    ? (cs07VerifierOrigin || resolveCs07VerifierOrigin({ serverURL }))
    : null;
  if (cs07DcApi && response_mode !== "dc_api.jwt") {
    throw new Cs02VerifierRequestError(
      'CS-07 DC API requests must use response_mode "dc_api.jwt"',
      "invalid_request",
    );
  }
  const signingPolicy = resolveCs02JarSigningPolicy({
    client_id,
    jar_alg,
    response_mode,
    options: cs02Options,
  });

  validateCs02JarGenerationInput({
    client_id,
    response_uri: cs07DcApi ? null : redirect_uri,
    presentation_definition,
    dcql_query,
    response_mode,
    response_type,
    transaction_data,
    options: cs02Options,
  });

  if (!nonce) nonce = generateNonce(16);
  if (!isStrictCs02Base64Url(nonce)) {
    throw new Cs02VerifierRequestError(
      "CS-02 nonce must be a non-empty base64url string",
      "invalid_request",
    );
  }
  if (!state && !cs07DcApi) {
    // State is REQUIRED for direct_post modes per OpenID4VP spec
    // Generate only if not provided to maintain backwards compatibility with tests
    state = generateNonce(16);
    console.warn(
      "WARNING: state parameter not provided to buildVpRequestJWT, generating random state. This should be explicitly provided."
    );
  }

  // Validate response_mode
  const allowedResponseModes = [
    "direct_post",
    "direct_post.jwt",
    "dc_api.jwt",
    "dc_api",
  ];
  if (!allowedResponseModes.includes(response_mode)) {
    throw new Error(
      `Invalid response_mode. Must be one of: ${allowedResponseModes.join(
        ", "
      )}`
    );
  }

  // Note: encryption metadata should be provided in client_metadata from verifier-config.json
  // for direct_post.jwt (encrypted response). Per OpenID4VP 5.1.2.4.2.2,
  // encrypted_response_enc_values_supported MUST be absent when using direct_post (non-JWT) response mode.
  let clientMetadataForPayload = client_metadata;
  if (cs02Options.strict) {
    clientMetadataForPayload = buildStrictCs02ClientMetadata(
      client_metadata,
      response_mode,
      { allowCs03CredentialFormat: cs02Options.allowCs03CredentialFormat },
    );
  }
  if (response_mode === "direct_post" && clientMetadataForPayload && typeof clientMetadataForPayload === "object") {
    const {
      encrypted_response_alg_values_supported,
      encrypted_response_enc_values_supported,
      authorization_encrypted_response_alg,
      authorization_encrypted_response_enc,
      ...rest
    } = clientMetadataForPayload;
    clientMetadataForPayload = rest;
  }

  // Determine client scheme and effective identifier
  const schemeSeparatorIdx = client_id.indexOf(":");
  const schemePrefix =
    schemeSeparatorIdx > 0 ? client_id.substring(0, schemeSeparatorIdx) : null;
  const isRedirectUriScheme = schemePrefix === "redirect_uri";
  const isDecentralizedIdScheme = schemePrefix === "decentralized_identifier";
  const effectiveClientId = signingPolicy.effectiveClientId;

  // Construct the JWT payload
  let jwtPayload = {
    response_type: response_type,
    response_mode: response_mode,
    client_id: client_id,

    nonce: nonce,
    ...(cs07DcApi ? {} : { state }),
    // For redirect_uri scheme, client_metadata MUST be omitted (wallet discovers metadata)
    ...(isRedirectUriScheme ? {} : { client_metadata: clientMetadataForPayload }),
    // NOTE: Per OpenID4VP, wallets MUST ignore an iss claim in the authorization request.
    // To avoid confusion for implementers, we intentionally omit iss here.
    ...(cs07DcApi ? {} : { aud: audience }),
  };

  // Add response_uri for all response modes that require it
  if (!cs07DcApi && (
    response_mode === "direct_post" ||
    response_mode === "direct_post.jwt" ||
    response_mode === "dc_api.jwt" ||
    response_mode === "dc_api"
  )) {
    jwtPayload.response_uri = redirect_uri;
  }

  if (!cs07DcApi) {
    jwtPayload.aud = "https://self-issued.me/v2"; // Digital Credentials API audience
  }

  // Add required timestamp claims for Digital Credentials API
  if (cs07DcApi) {
    jwtPayload.expected_origins = [cs07Origin];
  }

  applyCs02JarTimestamps(jwtPayload, response_mode);

  // console.log("wallet_nonce", wallet_nonce);
  if (wallet_nonce) jwtPayload.wallet_nonce = wallet_nonce;

  // CS-02 requests use DCQL only. Compatibility mode may still emit legacy PEX requests.
  if (presentation_definition && cs02Options.strict) {
    throw new Error(
      "Presentation Exchange (presentation_definition) is not supported; use dcql_query per OpenID4VP 1.0"
    );
  }

  // Add dcql_query if provided (required in place of PEX)
  if (dcql_query) {
    jwtPayload.dcql_query = dcql_query;
  } else if (presentation_definition) {
    jwtPayload.presentation_definition = presentation_definition;
  }

  // Add transaction_data if provided
  if (transaction_data) {
    validateCs02TransactionDataEntries(transaction_data, dcql_query, cs02Options);
    jwtPayload.transaction_data = transaction_data;
  }

  let signedJwt;

  if (response_mode === "dc_api.jwt" || response_mode === "dc_api") {
    // Use WE-BUILD Verifier P12 certificate for Digital Credentials API
    const { privateKeyPkcs8, certChain } = loadVerifierP12();

    const header = {
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      x5c: certChain,
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKeyPkcs8, "ES256"));
  } else if (
    effectiveClientId.startsWith("x509_san_dns:") ||
    effectiveClientId.startsWith("x509_san_uri:")
  ) {
    const useEs256 =
      signingPolicy.forceEs256 ||
      (typeof jar_alg === "string" && jar_alg.toUpperCase() === "ES256");

    let certChain;
    if (useEs256) {
      const p12 = loadVerifierP12();
      privateKey = p12.privateKeyPkcs8;
      certChain = appendCaCertsIfNeeded([...p12.certChain]);
      await validateX509SanDnsTrustForRequestGeneration(client_id, { x5c: certChain });
    } else {
      if (cs02Options.strict) {
        throw new Cs02VerifierRequestError(
          "CS-02 x509_san_dns requests must use ES256/P-256 signing",
          "invalid_request",
        );
      }
      privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
      const certificate = fs.readFileSync("./x509/client_certificate.crt", "utf8");
      const certBase64 = certificate
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(/\s+/g, "");
      certChain = [certBase64];
    }

    const header = {
      alg: useEs256 ? "ES256" : "RS256",
      typ: "oauth-authz-req+jwt",
      x5c: certChain,
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, useEs256 ? "ES256" : "RS256"));
  } else if (effectiveClientId.startsWith("x509_hash:")) {
    if (cs02Options.strict) {
      throw new Cs02VerifierRequestError(
        "x509_hash client identifier scheme is not supported in CS-02 mode",
        "invalid_client",
      );
    }
    const useEs256 =
      signingPolicy.forceEs256 ||
      (typeof jar_alg === "string" && jar_alg.toUpperCase() === "ES256");

    let certChain;
    if (useEs256) {
      const p12 = loadVerifierP12();
      privateKey = p12.privateKeyPkcs8;
      certChain = p12.certChain;
    } else {
      privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
      const certificate = fs.readFileSync("./x509/client_certificate.crt", "utf8");
      const certBase64 = certificate
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(/\s+/g, "");
      certChain = [certBase64];
    }
    
    // For x509_hash, we need the leaf certificate (first in chain) for hash calculation
    const leafCertBase64 = certChain[0];
    const certDer = Buffer.from(leafCertBase64, "base64");
    const hash = crypto.createHash("sha256").update(certDer).digest();
    const hashB64Url = base64url.encode(hash);
    const expectedClientId = `x509_hash:${hashB64Url}`;
    if (client_id !== expectedClientId) {
      throw new Error(
        `x509_hash client_id mismatch: expected ${expectedClientId} but got ${client_id}`
      );
    }

    const header = {
      alg: useEs256 ? "ES256" : "RS256",
      typ: "oauth-authz-req+jwt",
      x5c: certChain,
    };

    signedJwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, useEs256 ? "ES256" : "RS256"));
  } else if (effectiveClientId.startsWith("did:")) {
    // Check if this is a did:jwk identifier
    if (effectiveClientId.startsWith("did:jwk:")) {
      // Load private key from file for DID JWK
      const didJwkPrivateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );

      const header = {
        alg: "ES256",
        typ: "oauth-authz-req+jwt",
        kid: kid, // This will be in the format did:jwk:<base64url-encoded-jwk>#0
      };

      signedJwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(await jose.importPKCS8(didJwkPrivateKey, "ES256"));
    } else if (effectiveClientId.startsWith("did:web:")) {
      // Handle did:web case - load private key from file
      const didWebPrivateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );

      const signingKey = {
        kty: "EC",
        x: "ijVgOGHvwHSeV1Z2iLF9pQLQAw7KcHF3VIjThhvVtBQ",
        y: "SfFShWAUGEnNx24V2b5G1jrhJNHmMwtgROBOi9OKJLc",
        crv: "P-256",
        use: "sig",
        kid: kid,
      };

      // Convert the private key to a KeyLike object
      const privateKeyObj = await jose.importPKCS8(
        didWebPrivateKey,
        signingKey.alg || "ES256"
      );

      // JWT header
      const header = {
        alg: signingKey.alg || "ES256",
        typ: "oauth-authz-req+jwt",
        kid: kid,
      };

      signedJwt = await new jose.SignJWT(jwtPayload)
        .setProtectedHeader(header)
        .sign(privateKeyObj);
    } else {
      throw new Error("Unsupported DID method: " + client_id);
    }
  } else {
    // For redirect_uri scheme, unsigned JAR is allowed; still sign with default if private key available
    if (isRedirectUriScheme) {
      if (cs02Options.strict) {
        throw new Cs02VerifierRequestError(
          "CS-02 mode forbids unsigned redirect_uri authorization requests",
          "invalid_client",
        );
      }
      const header = {
        alg: "none",
        typ: "oauth-authz-req+jwt",
      };
      // Produce unsecured JWT (JWS with alg=none) if signing key not applicable
      signedJwt = `${base64url.encode(
        JSON.stringify(header)
      )}.${base64url.encode(JSON.stringify(jwtPayload))}.`;
    } else if (schemePrefix === "verifier_attestation") {
      const nonPrefixedId = client_id.substring("verifier_attestation:".length);
      if (!va_jwt) {
        va_jwt = await generateTestVAJWT(nonPrefixedId);
      }

      const parts = va_jwt.split(".");
      let vaPayload;
      try {
        vaPayload = JSON.parse(base64url.decode(parts[1]));
      } catch (e) {
        throw new Error("Invalid VA-JWT payload format");
      }

      if (vaPayload.sub !== nonPrefixedId) {
        throw new Error("VA-JWT sub does not match non-prefixed client_id");
      }

      await validateVerifierAttestationForRequestGeneration({ jwt: va_jwt }, client_id);

      const useEs256 = signingPolicy.forceEs256;
      let header;
      if (useEs256) {
        const p12 = loadVerifierP12();
        privateKey = p12.privateKeyPkcs8;
        const certChain = appendCaCertsIfNeeded([...p12.certChain]);
        header = {
          alg: "ES256",
          typ: "oauth-authz-req+jwt",
          x5c: certChain,
          jwt: va_jwt,
        };
        signedJwt = await new jose.SignJWT(jwtPayload)
          .setProtectedHeader(header)
          .sign(await jose.importPKCS8(privateKey, "ES256"));
      } else {
        privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
        const certificate = fs.readFileSync("./x509/client_certificate.crt", "utf8");
        const certBase64 = certificate
          .replace("-----BEGIN CERTIFICATE-----", "")
          .replace("-----END CERTIFICATE-----", "")
          .replace(/\s+/g, "");

        header = {
          alg: "RS256",
          typ: "oauth-authz-req+jwt",
          x5c: [certBase64],
          jwt: va_jwt,
        };

        signedJwt = await new jose.SignJWT(jwtPayload)
          .setProtectedHeader(header)
          .sign(await jose.importPKCS8(privateKey, "RS256"));
      }
    } else {
      throw new Error(
        "not supported client_id scheme for client_id:" + client_id
      );
    }
  }

  validateCs02SignedJar(signedJwt, cs02Options);

  // If wallet_metadata with jwks is provided, encrypt the request object
  if (wallet_metadata && wallet_metadata.jwks) {
    console.log(
      "Encrypting request object using wallet's public key from wallet_metadata."
    );

    const jwks = wallet_metadata.jwks;
    // Find a key suitable for encryption
    const encryptionKey = jwks.keys.find(
      (k) => k.use === "enc" || k.use === undefined
    );
    if (!encryptionKey) {
      throw new Error(
        "No suitable encryption key found in wallet_metadata.jwks"
      );
    }
    const publicKey = await jose.importJWK(encryptionKey);

    const alg =
      wallet_metadata.authorization_encryption_alg_values_supported?.[0] ||
      "ECDH-ES+A256KW";
    const enc =
      wallet_metadata.authorization_encryption_enc_values_supported?.[0] ||
      "A256GCM";

    const encryptedRequest = await new jose.CompactEncrypt(
      new TextEncoder().encode(signedJwt)
    )
      .setProtectedHeader({ alg: alg, enc: enc, typ: "oauth-authz-req+jwt" })
      .encrypt(publicKey);

    return encryptedRequest;
  }

  return signedJwt;
}

export async function buildPaymentVpRequestJWT(
  client_id,
  redirect_uri,
  presentation_definition,
  privateKey = "",
  client_metadata = {},
  kid = null, // Default to an empty object,
  serverURL,
  response_type = "vp_token",

  merchant,
  currency,
  value,
  isRecurring,
  start_date,
  expiry_date,
  frequency,
  credential_ids
) {
  const nonce = generateNonce(16);
  const state = generateNonce(16);

  const transactionData = {
    type: "payment_data", // REQUIRED. The string that identifies the type of transaction data.
    credential_ids: [credential_ids], // REQUIRED. An array of strings, each referencing a Credential requested by the Verifier that can be used to authorize this transaction.
    transaction_data_hashes_alg: ["sha-256"], //OPTIONAL. An array of strings, each representing a hash algorithm identifier.
    payment_data: {
      payee: merchant,
      currency_amount: {
        currency: currency,
        value: value,
      },
    },
  };
  const base64EncodedTxData = Buffer.from(
    JSON.stringify(transactionData)
  ).toString("base64");

  // Construct the JWT payload
  let jwtPayload = {
    transaction_data: [base64EncodedTxData],
    response_type: response_type,
    response_mode: "direct_post",
    client_id: client_id, // this should match the dns record in the certificate (dss.aegean.gr)
    response_uri: redirect_uri,
    nonce: nonce,
    state: state,
    client_metadata: client_metadata, //
    // NOTE: Per OpenID4VP, wallets MUST ignore an iss claim in the authorization request.
    // To avoid confusion for implementers, we intentionally omit iss here.
    aud: "https://self-issued.me/v2",
    scope: "openid",
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 1, // Token expiration time (1 days)
  };

  if (isRecurring) {
    jwtPayload.payment_data.recurring_schedule = {
      // OPTIONAL. If present, it indicates a recurring payment with the following details:
      start_date: start_date,
      expiry_date: expiry_date,
      frequency: frequency,
    };
  }

  if (presentation_definition) {
    jwtPayload.presentation_definition = presentation_definition;
  }

  if (client_id.startsWith("x509_san_dns:")) {
    privateKey = fs.readFileSync("./x509/client_private_pkcs8.key", "utf8");
    // For RSA certificates: Use only leaf certificate
    const certificate = fs.readFileSync("./x509/client_certificate.crt", "utf8");
    const certBase64 = certificate
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "");

    const header = {
      alg: "RS256",
      typ: "oauth-authz-req+jwt",
      x5c: [certBase64],
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(await jose.importPKCS8(privateKey, "RS256"));

    return { jwt, base64EncodedTxData, nonce, state };
  } else if (client_id.startsWith("did:")) {
    //TODO NOT COMPLETED SHOULD RETURN txDATA HASH
    const signingKey = {
      kty: "EC",
      x: "ijVgOGHvwHSeV1Z2iLF9pQLQAw7KcHF3VIjThhvVtBQ",
      y: "SfFShWAUGEnNx24V2b5G1jrhJNHmMwtgROBOi9OKJLc",
      crv: "P-256",
      use: "sig",
      kid: kid,
    };

    // Convert the private key to a KeyLike object
    const privateKeyObj = await jose.importPKCS8(
      privateKey,
      signingKey.alg || "ES256"
    );

    const jwtPayload = {
      response_type: response_type,
      response_mode: "direct_post",
      client_id: client_id, // DID the did of the verifier!!!!!!
      redirect_uri: redirect_uri,
      nonce: nonce,
      state: state,
      client_metadata: client_metadata,
    };
    if (presentation_definition) {
      jwtPayload.presentation_definition = presentation_definition;
    }
    if (response_type.indexOf("id_token") >= 0) {
      jwtPayload["id_token_type"] = "subject_signed";
      jwtPayload["scope"] = "openid";
    }

    // JWT header
    const header = {
      alg: signingKey.alg || "ES256",
      typ: "oauth-authz-req+jwt",
      kid: kid,
    };

    const jwt = await new jose.SignJWT(jwtPayload)
      .setProtectedHeader(header)
      .sign(privateKeyObj);

    return jwt;

    // Conditional signing based on client_id_scheme
  } else {
    throw new Error(
      "not supported client_id scheme for client_id:" + client_id
    );
  }
}

export async function jarOAutTokenResponse(
  generatedAccessToken,
  authorization_details,
  id_token = null
) {
  // these need to be singed by the same key/alg and keyId
  // exposed in the /jwks endpoint of the OAUTH server

  const privateKeyPem = fs.readFileSync("./private-key-pkcs8.pem", "utf-8");
  const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
  const signingKey = pemToJWK(publicKeyPem, "public");

  // Convert the private key to a KeyLike object
  const privateKeyObj = await jose.importPKCS8(
    privateKeyPem,
    signingKey.alg || "ES256"
  );

  const jwtPayload = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: "bearer",
    expires_in: 86400,
    // id_token: buildIdToken(serverURL, privateKey),
    c_nonce: generateNonce(),
    c_nonce_expires_in: 86400,
  };
  if (id_token) {
    jwtPayload.id_token = id_token;
  }
  if (authorization_details) {
    jwtPayload.authorization_details = authorizatiton_details;
  }

  // JWT header
  const header = {
    alg: signingKey.alg || "ES256",
    typ: "oauth-authz-req+jwt",
    kid: "aegean#authentication-key", //kid,
  };

  const jwt = await new jose.SignJWT(jwtPayload)
    .setProtectedHeader(header)
    .sign(privateKeyObj);

  return {
    access_token: jwt,
    token_type: "bearer",
    expires_in: jwtPayload.expires_in,
  };

  return jwt;
}

export async function decryptJWE(jweToken, privateKeyPEM, mode) {
  try {
    const privateKey = crypto.createPrivateKey(privateKeyPEM);

    // Decrypt the JWE using the private key
    const decryptedPayload = await jose.jwtDecrypt(jweToken, privateKey);

    if (mode === "direct_post.jwt") {
      // OpenID4VP 1.0 Section 8.3 defines a JWE whose plaintext is the
      // Authorization Response JSON object. EncryptJWT exposes it as payload.
      if (decryptedPayload.payload && typeof decryptedPayload.payload === "object") {
        return decryptedPayload.payload;
      }
      throw new Error("Encrypted direct_post.jwt response has no JSON payload");
    } else if (mode === "dc_api.jwt") {
      // For HAIP dc_api.jwt, return the full decrypted payload
      // The calling code will handle extracting the VP token
      return decryptedPayload.payload;
    } else {
      // For other modes (legacy), parse and return disclosures
      // console.log(decryptedPayload);
      let presentation_submission =
        decryptedPayload.payload.presentation_submission;
      let disclosures = parseVP(decryptedPayload.payload.vp_token);
      // console.log(`diclosures in the VP found`);
      // console.log(disclosures);
      return disclosures;
    }
  } catch (error) {
    console.error("Error decrypting JWE:", error.message);
    throw error;
  }
}

export async function base64UrlEncodeSha256(codeVerifier) {
  // Convert the code verifier string to an ArrayBuffer with ASCII encoding
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);

  // Calculate the SHA-256 hash of the ArrayBuffer
  const hashBuffer = await crypto.subtle.digest("sha-256", data);

  // Convert the ArrayBuffer to a Uint8Array
  const hashArray = new Uint8Array(hashBuffer);

  // Convert the bytes to a Base64 string
  const base64String = btoa(String.fromCharCode.apply(null, hashArray));

  // Convert Base64 to Base64URL by replacing '+' with '-', '/' with '_', and stripping '='
  const base64UrlString = base64String
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return base64UrlString;
}

function parseVP(vp_token) {
  // Check if vp_token is a string
  if (typeof vp_token !== "string") {
    throw new Error(
      `parseVP expects a string, but received: ${typeof vp_token}`
    );
  }

  let vpPartsArray = vp_token.split(".");
  let disclosuresPart = vpPartsArray[2]; //this is the actual sd-jdt from the vpToken

  let disclosuresArray = disclosuresPart.split("~").slice(1, -1); //get all elements apart form the first and last one
  // console.log(disclosuresArray);
  let decodedDisclosuresArray = disclosuresArray.map((element) => {
    return base64urlDecode(element);
  });
  return decodedDisclosuresArray;
}

const base64urlDecode = (input) => {
  // Convert base64url to base64 by adding padding characters
  const base64 = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");
  // Decode base64
  const utf8String = atob(base64);
  // Convert UTF-8 string to byte array
  const bytes = new Uint8Array(utf8String.length);
  for (let i = 0; i < utf8String.length; i++) {
    bytes[i] = utf8String.charCodeAt(i);
  }
  let decodedString = new TextDecoder().decode(bytes);
  return JSON.parse(decodedString);
};

export async function didKeyToJwks(did) {
  if (did.startsWith("did:key:")) {
    const keyDidResolver = getResolver();
    const didResolver = new Resolver(keyDidResolver);

    const resolutionResult = await didResolver.resolve(did);
    const didDocument = resolutionResult.didDocument;
    if (!didDocument || !didDocument.verificationMethod) {
      console.error("Invalid DID Document for:", did);
      throw new Error("Invalid DID Document structure.");
    }
    const jwks = {
      keys: didDocument.verificationMethod.map((vm) => {
        const jwk = vm.publicKeyJwk;
        jwk.kid = vm.id;
        return jwk;
      }),
    };
    return jwks;
  } else if (did.startsWith("did:web:")) {
    // Handling did:web
    try {
      const [didPart] = did.split("#"); // we don't need the fragment for fetching did.json

      let didUrlPart = didPart.substring("did:web:".length);
      didUrlPart = decodeURIComponent(didUrlPart);

      const didParts = didUrlPart.split(":");
      const domain = didParts.shift();
      const path = didParts.join("/");

      let didDocUrl;
      if (path) {
        didDocUrl = `https://${domain}/${path}/did.json`;
      } else {
        didDocUrl = `https://${domain}/.well-known/did.json`;
      }

      const response = await fetch(didDocUrl);
      if (!response.ok) {
        throw new Error(`Failed to fetch DID document: ${response.statusText}`);
      }
      const didDocument = await response.json();

      if (!didDocument || !didDocument.verificationMethod) {
        // Handle cases where the document is empty or doesn't have verification methods
        console.error("Invalid DID Document for:", did);
        throw new Error("Invalid DID Document structure.");
      }

      const jwks = {
        keys: didDocument.verificationMethod.map((vm) => {
          const jwk = vm.publicKeyJwk;
          jwk.kid = vm.id;
          return jwk;
        }),
      };
      return jwks;
    } catch (e) {
      console.error("Error resolving did:web", e);
      throw e;
    }
  } else if (did.startsWith("did:jwk:")) {
    try {
      const jwk = parseDidJwk(did);
      return { keys: [jwk] };
    } catch (e) {
      console.error("Error parsing did:jwk", e);
      throw e;
    }
  }
  return null;
}
export async function fetchWalletMetadata(metadataUrl) {
  if (!metadataUrl) {
    console.log("No wallet metadata URL provided, skipping fetch.");
    return null;
  }
  try {
    const response = await fetch(metadataUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch wallet metadata: ${response.statusText}`
      );
    }
    const metadata = await response.json();
    console.log("Fetched wallet metadata:", metadata);
    return metadata;
  } catch (error) {
    console.error("Error fetching wallet metadata:", error);
    throw error;
  }
}
