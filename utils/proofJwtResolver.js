import { Buffer } from "buffer";
import { didKeyToJwks, jwkFromX5cFirstCert, parseDidJwk } from "./cryptoUtils.js";
import { ProofJwtHeaderValidator } from "./proofJwtHeaderUtils.js";
import { logInfo } from "../services/cacheServiceRedis.js";

const DEFAULT_MESSAGES = {
  INVALID_PROOF_PUBLIC_KEY:
    "Public key for proof verification not found in JWT header.",
  INVALID_PROOF: "No proof information found",
};

/**
 * Resolve DID Web public key (verificationMethod) for a proof JWT kid.
 */
export async function resolveDidWebPublicKey(didWeb, sessionId = null) {
  try {
    const [did, keyFragment] = didWeb.split("#");
    if (!keyFragment) {
      throw new Error(
        `kid does not contain a key identifier fragment. Received: '${didWeb}' (no #fragment), expected: format like 'did:web:example.com#key-1'`
      );
    }

    let didUrlPart = did.substring("did:web:".length);
    didUrlPart = decodeURIComponent(didUrlPart);

    const didParts = didUrlPart.split(":");
    const domain = didParts.shift();
    const path = didParts.join("/");

    const didDocUrl = path
      ? `https://${domain}/${path}/did.json`
      : `https://${domain}/.well-known/did.json`;

    if (sessionId) {
      logInfo(sessionId, "Resolving did:web public key", {
        didWeb,
        didDocUrl,
        domain,
        path,
      }).catch(() => {});
    }

    const response = await fetch(didDocUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch DID document. Received: HTTP ${response.status} from ${didDocUrl}, expected: HTTP 200`
      );
    }

    const didDocument = await response.json();
    if (!didDocument) {
      throw new Error(
        `Failed to parse DID document. Received: null/undefined from ${didDocUrl}, expected: valid DID document JSON`
      );
    }

    const verificationMethod = didDocument.verificationMethod?.find(
      (vm) =>
        vm.id === didWeb ||
        (didDocument.id && didDocument.id + vm.id === didWeb)
    );

    if (!verificationMethod?.publicKeyJwk) {
      const availableIds =
        didDocument.verificationMethod?.map((vm) => vm.id).join(", ") || "none";
      throw new Error(
        `Public key not found in DID document. Received: verificationMethod with id '${didWeb}' ${verificationMethod ? "but no publicKeyJwk" : "not found"}, expected: verificationMethod with id '${didWeb}' containing publicKeyJwk. Available verificationMethod ids: [${availableIds}]`
      );
    }

    return verificationMethod.publicKeyJwk;
  } catch (error) {
    console.error(`Error resolving did:web. Received kid: ${didWeb}, error:`, error);
    throw new Error(
      `Failed to resolve public key from proof JWT kid (did:web). Received kid: ${didWeb}, error: ${error.message}`
    );
  }
}

/**
 * Resolve holder public JWK from OID4VCI proof JWT protected header (jwk, x5c, did:* kid).
 *
 * @param {object} decodedProofHeader - JWT protected header object
 * @param {{ sessionId?: string | null, messages?: typeof DEFAULT_MESSAGES, specRefVciProof?: string }} [options]
 * @returns {Promise<object>} JWK (public)
 */
export async function resolveProofJwtPublicJwk(decodedProofHeader, options = {}) {
  const sessionId = options.sessionId ?? null;
  const messages = { ...DEFAULT_MESSAGES, ...options.messages };
  const specRefVciProof = options.specRefVciProof ?? "";

  ProofJwtHeaderValidator.assertX5cExclusiveWithKidOrJwk(decodedProofHeader, {
    invalidProofMessage: messages.INVALID_PROOF,
    specRef: specRefVciProof,
  });

  const hasX5c =
    Array.isArray(decodedProofHeader.x5c) && decodedProofHeader.x5c.length > 0;

  if (decodedProofHeader.jwk) {
    return decodedProofHeader.jwk;
  }

  if (hasX5c) {
    try {
      return await jwkFromX5cFirstCert(
        decodedProofHeader.x5c,
        decodedProofHeader.alg || "ES256"
      );
    } catch (error) {
      console.error("Error resolving x5c to JWK:", error);
      throw new Error(
        `Failed to resolve public key from proof JWT x5c. error: ${error.message}`
      );
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:key:")) {
    try {
      const jwks = await didKeyToJwks(decodedProofHeader.kid);
      if (jwks?.keys?.length > 0) {
        return jwks.keys[0];
      }
      const received = jwks?.keys
        ? `JWKS with ${jwks.keys.length} keys`
        : "null/undefined JWKS";
      throw new Error(
        `Failed to resolve did:key to JWK. Received: ${received}, expected: JWKS with at least 1 key`
      );
    } catch (error) {
      console.error(
        `Error resolving did:key to JWK. Received kid: ${decodedProofHeader.kid}, error:`,
        error
      );
      throw new Error(
        `Failed to resolve public key from proof JWT kid (did:key). Received kid: ${decodedProofHeader.kid}, error: ${error.message}`
      );
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:jwk:")) {
    try {
      return parseDidJwk(decodedProofHeader.kid);
    } catch (error) {
      console.error(
        `Error resolving did:jwk to JWK. Received kid: ${decodedProofHeader.kid}, error:`,
        error
      );
      throw new Error(
        `Failed to resolve public key from proof JWT kid (did:jwk). Received kid: ${decodedProofHeader.kid}, error: ${error.message}`
      );
    }
  }

  if (decodedProofHeader.kid?.startsWith("did:web:")) {
    return await resolveDidWebPublicKey(decodedProofHeader.kid, sessionId);
  }

  const received = decodedProofHeader.kid
    ? `kid: ${decodedProofHeader.kid}`
    : "no kid in header";
  const hasJwk = decodedProofHeader.jwk ? "has jwk" : "no jwk";
  throw new Error(
    `${messages.INVALID_PROOF_PUBLIC_KEY} Received: ${received}, ${hasJwk}. Expected: kid starting with did:key:, did:jwk:, or did:web:, jwk in header, or x5c certificate chain`
  );
}
