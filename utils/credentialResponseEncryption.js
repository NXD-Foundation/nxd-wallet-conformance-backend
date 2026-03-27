import * as jose from "jose";
import { createPrivateKey, createPublicKey } from "crypto";

/**
 * OID4VCI 1.0 — credential_response_encryption (§8.2, §11.2.3).
 * Encrypted success responses use compact JWE; plaintext is UTF-8 JSON of the credential response object.
 */

export const INVALID_ENCRYPTION_PARAMETERS = "invalid_encryption_parameters";
const SPEC_REFS = {
  VCI_CREDENTIAL_REQUEST: "OpenID4VCI 1.0 §8.2",
  VCI_CREDENTIAL_RESPONSE_ENCRYPTION: "OpenID4VCI 1.0 §11.2.3",
  JWE_COMPACT: "RFC 7516",
};

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  if (present.length === 0) return message;
  return `${message}. See ${present.join(" and ")}.`;
}

export function encryptionParametersError(message) {
  const err = new Error(message);
  err.errorCode = INVALID_ENCRYPTION_PARAMETERS;
  return err;
}

/**
 * @param {object} issuerConfig — full issuer metadata / issuer-config.json root
 */
export function getCredentialResponseEncryptionMetadata(issuerConfig) {
  return issuerConfig?.credential_response_encryption ?? null;
}

/**
 * Validates credential_response_encryption against issuer metadata.
 * @throws Error with err.errorCode === INVALID_ENCRYPTION_PARAMETERS when invalid
 */
export function validateCredentialResponseEncryptionParams(cre, issuerMeta) {
  if (!cre || typeof cre !== "object") {
    throw encryptionParametersError(
      withSpecRef(
        "credential_response_encryption must be an object with jwk and enc",
        SPEC_REFS.VCI_CREDENTIAL_REQUEST,
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  const { jwk, enc, zip } = cre;

  if (!jwk || typeof jwk !== "object") {
    throw encryptionParametersError(
      withSpecRef(
        "credential_response_encryption.jwk is required",
        SPEC_REFS.VCI_CREDENTIAL_REQUEST,
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  if (typeof enc !== "string" || !enc.trim()) {
    throw encryptionParametersError(
      withSpecRef(
        "credential_response_encryption.enc is required",
        SPEC_REFS.VCI_CREDENTIAL_REQUEST,
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  if (typeof jwk.alg !== "string" || !jwk.alg.trim()) {
    throw encryptionParametersError(
      withSpecRef(
        "credential_response_encryption.jwk.alg is required",
        SPEC_REFS.VCI_CREDENTIAL_REQUEST,
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  if (!issuerMeta) {
    throw encryptionParametersError(
      withSpecRef(
        "Issuer does not advertise credential_response_encryption support",
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  const algSupported = issuerMeta.alg_values_supported;
  const encSupported = issuerMeta.enc_values_supported;
  if (!Array.isArray(algSupported) || !algSupported.includes(jwk.alg)) {
    throw encryptionParametersError(
      withSpecRef(
        "Unsupported credential response encryption algorithm",
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }
  if (!Array.isArray(encSupported) || !encSupported.includes(enc)) {
    throw encryptionParametersError(
      withSpecRef(
        "Unsupported credential response content encryption algorithm",
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  if (zip !== undefined && zip !== null) {
    const zipSupported = issuerMeta.zip_values_supported;
    if (!Array.isArray(zipSupported) || !zipSupported.includes(zip)) {
      throw encryptionParametersError(
        withSpecRef(
          "Unsupported credential response compression algorithm",
          SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
        )
      );
    }
  }
}

/**
 * encryption_required + presence of credential_response_encryption
 */
export function validateCredentialResponseEncryptionForRequest(requestBody, issuerConfig) {
  const meta = getCredentialResponseEncryptionMetadata(issuerConfig);
  const cre = requestBody?.credential_response_encryption;

  if (meta?.encryption_required === true && !cre) {
    throw encryptionParametersError(
      withSpecRef(
        "Credential response encryption is required but credential_response_encryption is missing",
        SPEC_REFS.VCI_CREDENTIAL_RESPONSE_ENCRYPTION
      )
    );
  }

  if (!cre) return;

  validateCredentialResponseEncryptionParams(cre, meta);
}

/**
 * Encrypts credential response JSON object as compact JWE (OID4VCI §11.2.3).
 * @param {object} payloadObject — e.g. { credentials: [...], notification_id } or { transaction_id, interval }
 */
export async function encryptCredentialResponseToJwe(payloadObject, cre, issuerConfig) {
  const meta = getCredentialResponseEncryptionMetadata(issuerConfig);
  validateCredentialResponseEncryptionParams(cre, meta);

  const { jwk, enc, zip } = cre;
  const publicKey = await jose.importJWK(jwk, jwk.alg);

  let plaintext = new TextEncoder().encode(JSON.stringify(payloadObject));
  if (zip === "DEF") {
    const { deflateRawSync } = await import("zlib");
    plaintext = deflateRawSync(Buffer.from(plaintext));
  }

  const header = {
    alg: jwk.alg,
    enc,
    typ: "JWT",
  };
  if (jwk.kid) header.kid = jwk.kid;

  return new jose.CompactEncrypt(plaintext).setProtectedHeader(header).encrypt(publicKey);
}

async function tryImportRsaPrivate(privateKeyPem) {
  try {
    return await jose.importPKCS8(privateKeyPem, "RSA-OAEP-256");
  } catch {
    try {
      return await jose.importPKCS8(privateKeyPem, "RSA-OAEP");
    } catch {
      return null;
    }
  }
}

async function getKeyDiagnostics(privateKeyPem) {
  const diagnostics = {
    pemHeader: privateKeyPem?.split("\n")?.[0] ?? null,
  };

  try {
    const keyObject = createPrivateKey(privateKeyPem);
    const publicKeyObject = createPublicKey(keyObject);
    const publicJwk = await jose.exportJWK(publicKeyObject);
    diagnostics.loadedKey = {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
      y: publicJwk.y,
      n: publicJwk.n,
      e: publicJwk.e,
      thumbprint: await jose.calculateJwkThumbprint(publicJwk),
    };
    return diagnostics;
  } catch (ecError) {
    diagnostics.ecImportError = {
      name: ecError?.name,
      code: ecError?.code,
      message: ecError?.message,
    };
  }

  try {
    const rsaKey = await tryImportRsaPrivate(privateKeyPem);
    if (!rsaKey) {
      diagnostics.rsaImportError = {
        message: "PKCS8 RSA import returned null",
      };
      return diagnostics;
    }
    const publicJwk = await jose.exportJWK(rsaKey);
    diagnostics.loadedKey = {
      kty: publicJwk.kty,
      n: publicJwk.n,
      e: publicJwk.e,
      thumbprint: await jose.calculateJwkThumbprint(publicJwk),
    };
  } catch (rsaError) {
    diagnostics.rsaImportError = {
      name: rsaError?.name,
      code: rsaError?.code,
      message: rsaError?.message,
    };
  }

  return diagnostics;
}

async function getJweDiagnostics(jweCompact) {
  try {
    const protectedHeader = jose.decodeProtectedHeader(jweCompact.trim());
    const recipientJwk = protectedHeader?.jwk ?? null;
    return {
      alg: protectedHeader?.alg ?? null,
      enc: protectedHeader?.enc ?? null,
      kid: protectedHeader?.kid ?? null,
      typ: protectedHeader?.typ ?? null,
      epk: protectedHeader?.epk
        ? {
            kty: protectedHeader.epk.kty,
            crv: protectedHeader.epk.crv,
            x: protectedHeader.epk.x,
            y: protectedHeader.epk.y,
          }
        : null,
      recipientJwk: recipientJwk
        ? {
            kty: recipientJwk.kty,
            crv: recipientJwk.crv,
            kid: recipientJwk.kid,
            x: recipientJwk.x,
            y: recipientJwk.y,
            n: recipientJwk.n,
            e: recipientJwk.e,
            alg: recipientJwk.alg,
            thumbprint: await jose.calculateJwkThumbprint(recipientJwk),
          }
        : null,
    };
  } catch (error) {
    return {
      protectedHeaderDecodeError: {
        name: error?.name,
        code: error?.code,
        message: error?.message,
      },
    };
  }
}

/**
 * Decrypts a credential request sent as compact JWE (wallet encrypts to issuer public key).
 * @param {string} jweCompact
 * @param {string} privateKeyPem — issuer EC private key PEM (SEC1 or PKCS8)
 */
export async function decryptCredentialRequestJwe(jweCompact, privateKeyPem) {
  const parts = jweCompact.trim().split(".");
  if (parts.length !== 5) {
    throw encryptionParametersError(
      withSpecRef(
        "Invalid encrypted credential request JWE",
        SPEC_REFS.VCI_CREDENTIAL_REQUEST,
        SPEC_REFS.JWE_COMPACT
      )
    );
  }

  try {
    const jweDiagnostics = await getJweDiagnostics(jweCompact);
    const keyDiagnostics = await getKeyDiagnostics(privateKeyPem);
    console.info("[credential_request_decryption] attempting decrypt", {
      jwe: jweDiagnostics,
      key: keyDiagnostics,
    });

    let plaintext;
    try {
      // createPrivateKey handles both SEC1 (BEGIN EC PRIVATE KEY) and PKCS8 (BEGIN PRIVATE KEY)
      const keyObject = createPrivateKey(privateKeyPem);
      ({ plaintext } = await jose.compactDecrypt(jweCompact.trim(), keyObject));
      console.info("[credential_request_decryption] decrypted with native key object", {
        alg: jweDiagnostics.alg,
        enc: jweDiagnostics.enc,
        kid: jweDiagnostics.kid,
        loadedKeyThumbprint: keyDiagnostics.loadedKey?.thumbprint ?? null,
        recipientKeyThumbprint: jweDiagnostics.recipientJwk?.thumbprint ?? null,
      });
    } catch {
      const rsaKey = await tryImportRsaPrivate(privateKeyPem);
      if (!rsaKey) {
        throw encryptionParametersError(
          withSpecRef(
            "Failed to decrypt credential request JWE",
            SPEC_REFS.VCI_CREDENTIAL_REQUEST,
            SPEC_REFS.JWE_COMPACT
          )
        );
      }
      ({ plaintext } = await jose.compactDecrypt(jweCompact.trim(), rsaKey));
      console.info("[credential_request_decryption] decrypted with imported RSA key", {
        alg: jweDiagnostics.alg,
        enc: jweDiagnostics.enc,
        kid: jweDiagnostics.kid,
        loadedKeyThumbprint: keyDiagnostics.loadedKey?.thumbprint ?? null,
        recipientKeyThumbprint: jweDiagnostics.recipientJwk?.thumbprint ?? null,
      });
    }

    try {
      return JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
      throw encryptionParametersError(
        withSpecRef(
          "Decrypted credential request is not valid JSON",
          SPEC_REFS.VCI_CREDENTIAL_REQUEST
        )
      );
    }
  } catch (e) {
    console.error("[credential_request_decryption] decrypt failed", {
      jwe: await getJweDiagnostics(jweCompact),
      key: await getKeyDiagnostics(privateKeyPem),
      error: {
        name: e?.name,
        code: e?.code,
        message: e?.message,
        stack: e?.stack,
      },
    });
    if (e.errorCode === INVALID_ENCRYPTION_PARAMETERS) throw e;
    throw encryptionParametersError(
      withSpecRef(
        "Failed to decrypt credential request JWE",
        SPEC_REFS.VCI_CREDENTIAL_REQUEST,
        SPEC_REFS.JWE_COMPACT
      )
    );
  }
}
