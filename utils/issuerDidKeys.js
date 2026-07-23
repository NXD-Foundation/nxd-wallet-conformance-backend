import fs from "fs";
import { createPublicKey } from "crypto";
import { pemToJWK } from "./cryptoUtils.js";
import { KEY_MATERIAL_PATHS } from "./keyMaterialPaths.js";

const DID_PRIVATE_PKCS8 = KEY_MATERIAL_PATHS.didPrivateKeyPkcs8;
const DID_PUBLIC_SPKI = KEY_MATERIAL_PATHS.didPublicKey;

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
