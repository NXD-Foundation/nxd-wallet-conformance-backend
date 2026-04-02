import fs from "fs";
import { createPublicKey } from "crypto";
import { pemToJWK } from "./cryptoUtils.js";

const DID_PRIVATE_PKCS8 = "./didjwks/did_private_pkcs8.key";
const DID_PUBLIC_SPKI = "./didjwks/did_public.pem";

/**
 * PEM key material served in did:web DID documents and did:jwk-derived identifiers
 * (see routes/didweb.js, routes/didJwkRoutes.js). SD-JWT signing for those modes MUST
 * use this pair so header `kid` resolves to the same key that produced the signature.
 */
export function loadDidIssuerPems() {
  return {
    privatePem: fs.readFileSync(DID_PRIVATE_PKCS8, "utf8"),
    publicPem: fs.readFileSync(DID_PUBLIC_SPKI, "utf8"),
  };
}

export function getIssuerJwkPairAlignedWithDidDocument() {
  const { privatePem, publicPem } = loadDidIssuerPems();
  return {
    privateJwk: pemToJWK(privatePem, "private"),
    publicJwk: pemToJWK(publicPem, "public"),
  };
}

/**
 * Public JWK for did:jwk issuer DID — same derivation as routes/didJwkRoutes.js
 * (createPublicKey(privatePkcs8).export({ format: "jwk" })).
 */
export function getIssuerPublicJwkForDidJwkDid() {
  const { privatePem } = loadDidIssuerPems();
  return createPublicKey(privatePem).export({ format: "jwk" });
}

export function computeDidJwkIssuerDidAndKidFromDidKeys() {
  const publicJwkForSigning = getIssuerPublicJwkForDidJwkDid();
  const did = `did:jwk:${Buffer.from(JSON.stringify(publicJwkForSigning)).toString("base64url")}`;
  const kid = `${did}#0`;
  return { did, kid, publicJwk: publicJwkForSigning };
}
