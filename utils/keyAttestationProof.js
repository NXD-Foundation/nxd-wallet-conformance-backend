/**
 * OID4VCI key-attestation proof (proofs.attestation) — parsing, verification hooks, and holder binding.
 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D.1
 *
 * EUDI note: in the current issuance profile the array element is the Wallet Unit Attestation (WUA),
 * a JWT signed by the Wallet Provider (not PoP of the attested key in this request). PID/EAA issuers
 * should ultimately trust the WP via the Trusted List; see isKeyAttestationTrustedByIssuer and
 * routeUtils.isWuaWalletProviderTrustedByPolicy for the policy hook (both stubbed until trust framework).
 */

import jwt from "jsonwebtoken";
import * as jose from "jose";

/** Match sharedIssuanceFlows ERROR_MESSAGES.INVALID_PROOF_* strings for consistent error handling */
const INVALID_PROOF = "No proof information found";
const INVALID_PROOF_MALFORMED = "Proof JWT is malformed or missing algorithm.";
const INVALID_PROOF_ALGORITHM = "Proof JWT uses an unsupported algorithm";
const INVALID_PROOF_PUBLIC_KEY = "Public key for proof verification not found in JWT header.";
const INVALID_PROOF_SIGNATURE = "Proof JWT signature verification failed";
const KEY_ATTESTATION_SPEC_REF =
  "OpenID4VCI 1.0 Appendix D.1";
const HAIP_KEY_ATTESTATION_SPEC_REF = "HAIP 1.0 §4.5.1";

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  if (present.length === 0) return message;
  return `${message}${message.endsWith(".") ? "" : "."} See ${present.join(" and ")}.`;
}

export const KEY_ATTESTATION_JWT_TYP = "key-attestation+jwt";

/**
 * Conformance-style parsing: proofs.attestation MUST be a JSON array containing exactly one JWT string.
 * @param {unknown} proofValue - requestBody.proofs.attestation
 * @param {string} [specRef]
 * @returns {string} compact JWT
 */
export function parseProofAttestationJwtFromCredentialProofs(proofValue, specRef = "") {
  if (!Array.isArray(proofValue)) {
    throw new Error(
      `${INVALID_PROOF}: proofs.attestation must be a JSON array of JWT strings. Received: ${typeof proofValue}, expected: array${specRef ? `. See ${specRef}` : ""}`
    );
  }
  if (proofValue.length === 0) {
    throw new Error(
      `${INVALID_PROOF}: proofs.attestation array must not be empty${specRef ? `. See ${specRef}` : ""}`
    );
  }
  if (proofValue.length !== 1) {
    throw new Error(
      `${INVALID_PROOF}: Expected exactly one JWT in proofs.attestation. Received: ${proofValue.length} element(s)${specRef ? `. See ${specRef}` : ""}`
    );
  }
  const s = proofValue[0];
  if (typeof s !== "string" || !s.trim()) {
    throw new Error(
      `${INVALID_PROOF}: proofs.attestation[0] must be a non-empty JWT string${specRef ? `. See ${specRef}` : ""}`
    );
  }
  return s.trim();
}

/**
 * Policy gate after cryptographic verification of the key-attestation JWT (often WUA in EUDI).
 * Stub: always true. Plug in Wallet Provider / Trusted List checks on payload.iss here, analogous to
 * isWuaWalletProviderTrustedByPolicy in routeUtils.js for the same WUA when carried as key_attestation.
 * @returns {boolean}
 */
export function isKeyAttestationTrustedByIssuer(_decodedHeader, _decodedPayload, _issuerConfig) {
  return true;
}

/**
 * Verification key for the key-attestation JWT signature.
 * Prefers issuer-configured JWKS; falls back to header.jwk only when no JWKS is configured (dev / transitional).
 * @param {{ header?: object }} decodedComplete - jwt.decode(..., { complete: true })
 * @param {object} issuerConfig - full issuer metadata object (optional key_attestation_jwks)
 * @returns {object} public JWK
 */
export function resolveKeyAttestationVerificationJwk(decodedComplete, issuerConfig) {
  const header = decodedComplete?.header;
  const jwks = issuerConfig?.key_attestation_jwks;
  if (jwks?.keys?.length) {
    const kid = header?.kid;
    if (kid) {
      const match = jwks.keys.find((k) => k.kid === kid);
      if (match) return match;
    }
    return jwks.keys[0];
  }
  if (header?.jwk) return header.jwk;
  throw new Error(
    withSpecRef(
      `${INVALID_PROOF_PUBLIC_KEY} Key attestation: configure issuer key_attestation_jwks or provide header.jwk for signature verification.`,
      KEY_ATTESTATION_SPEC_REF,
      HAIP_KEY_ATTESTATION_SPEC_REF
    )
  );
}

/**
 * Cryptographic verification of the key-attestation JWT (after trust policy allows proceeding).
 * @param {string} proofAttestationJwt
 * @param {object} verificationJwk - public JWK
 * @returns {Promise<object>} verified JWT payload
 */
export async function verifyKeyAttestationJwtSignature(proofAttestationJwt, verificationJwk) {
  const complete = jwt.decode(proofAttestationJwt, { complete: true });
  const alg = complete?.header?.alg;
  if (!alg) {
    throw new Error(
      withSpecRef(
        `${INVALID_PROOF_MALFORMED} Key attestation: missing alg in JWT header${complete?.header ? "" : " or unreadable JWT"}.`,
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  try {
    const key = await jose.importJWK(verificationJwk, alg);
    const { payload } = await jose.jwtVerify(proofAttestationJwt, key, { algorithms: [alg] });
    return payload;
  } catch (err) {
    const msg = err?.message || String(err);
    if (/signature|verification|invalid/i.test(msg)) {
      throw new Error(
        withSpecRef(
          `${INVALID_PROOF_SIGNATURE}: Key attestation JWT ${msg}`,
          KEY_ATTESTATION_SPEC_REF,
          HAIP_KEY_ATTESTATION_SPEC_REF
        )
      );
    }
    throw new Error(
      withSpecRef(
        `${INVALID_PROOF_MALFORMED}: Key attestation JWT ${msg}`,
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
}

/**
 * @param {object} header - decoded JWT header
 * @param {object} credConfig - credential_configurations_supported[id]
 * @param {string} [specRef]
 */
export function validateKeyAttestationHeaderForCredentialConfig(header, credConfig, specRef = "") {
  if (!header || typeof header !== "object") {
    throw new Error(`${INVALID_PROOF_MALFORMED} Key attestation: missing header${specRef ? `. See ${specRef}` : ""}`);
  }
  const typ = header.typ;
  if (typ !== KEY_ATTESTATION_JWT_TYP) {
    throw new Error(
      `${INVALID_PROOF_MALFORMED} Key attestation: invalid typ. Received: '${typ ?? "missing"}', expected: '${KEY_ATTESTATION_JWT_TYP}'${specRef ? `. See ${specRef}` : ""}`
    );
  }
  const supported =
    credConfig?.proof_types_supported?.attestation?.proof_signing_alg_values_supported || ["ES256"];
  if (!supported.includes(header.alg)) {
    throw new Error(
      `${INVALID_PROOF_ALGORITHM} Key attestation: '${header.alg}', expected: one of [${supported.join(", ")}]${specRef ? `. See ${specRef}` : ""}`
    );
  }
}

/**
 * Validates attestation claims and returns attested_keys (non-empty JWK array).
 * @param {object} payload - verified JWT payload
 * @param {string} [specRef]
 * @returns {object[]} attested_keys
 */
export function validateAttestationClaimsAndExtractAttestedKeys(payload, specRef = "") {
  if (!payload || typeof payload !== "object") {
    throw new Error(`${INVALID_PROOF_MALFORMED} Key attestation: empty payload${specRef ? `. See ${specRef}` : ""}`);
  }
  const keys = payload.attested_keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error(
      `${INVALID_PROOF_MALFORMED} Key attestation: attested_keys must be a non-empty array${specRef ? `. See ${specRef}` : ""}`
    );
  }
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (!k || typeof k !== "object" || !k.kty) {
      throw new Error(
        `${INVALID_PROOF_MALFORMED} Key attestation: attested_keys[${i}] must be a JWK object with kty${specRef ? `. See ${specRef}` : ""}`
      );
    }
  }
  return keys;
}

/**
 * Holder binding for attestation proofs: cnf from attested key material (first attested key).
 * Multiple keys in attested_keys: issuance returns one credential bound to the first key (same pattern as single credential response).
 * @param {object[]} attestedKeys
 * @returns {{ jwk: object }}
 */
export function buildCredentialBindingCnfFromAttestedKeys(attestedKeys) {
  const jwk = attestedKeys[0];
  return { jwk };
}

/**
 * Full key-attestation path: header/alg, trust stub, signature verify, claims, cnf.
 * Caller should validate nonce from an unverified decode before calling this.
 * @param {string} proofAttestationJwt
 * @param {object} credConfig
 * @param {object} issuerConfig
 * @param {string} [specRef]
 */
export async function verifyKeyAttestationProofChain(
  proofAttestationJwt,
  credConfig,
  issuerConfig,
  specRef = ""
) {
  const decodedComplete = jwt.decode(proofAttestationJwt, { complete: true });
  if (!decodedComplete?.header) {
    throw new Error(`${INVALID_PROOF_MALFORMED} Key attestation: could not decode JWT${specRef ? `. See ${specRef}` : ""}`);
  }

  validateKeyAttestationHeaderForCredentialConfig(decodedComplete.header, credConfig, specRef);

  // Wallet Provider trust (Trusted List / iss policy) — stub true; see isKeyAttestationTrustedByIssuer JSDoc.
  if (!isKeyAttestationTrustedByIssuer(decodedComplete.header, decodedComplete.payload, issuerConfig)) {
    throw new Error(
      withSpecRef(
        `${INVALID_PROOF_SIGNATURE}: Key attestation is not trusted by issuer policy`,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }

  const verificationJwk = resolveKeyAttestationVerificationJwk(decodedComplete, issuerConfig);
  const payload = await verifyKeyAttestationJwtSignature(proofAttestationJwt, verificationJwk);
  const attestedKeys = validateAttestationClaimsAndExtractAttestedKeys(payload, specRef);
  const cnf = buildCredentialBindingCnfFromAttestedKeys(attestedKeys);

  return { payload, attestedKeys, cnf };
}
