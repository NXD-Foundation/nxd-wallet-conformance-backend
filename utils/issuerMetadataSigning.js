import fs from "fs";
import * as jose from "jose";
import { pemToBase64Der } from "./sdjwtUtils.js";
import { KEY_MATERIAL_PATHS } from "./keyMaterialPaths.js";

/** RFC001 / aptitude tests use this typ (see metadataDiscovery.test.js). */
export const SIGNED_ISSUER_METADATA_TYP = "openid-credential-issuer-metadata+jwt";

function loadAptitudeIssuerMetadataSigningMaterial() {
  const privateKeyPkcs8 = fs.readFileSync(
    KEY_MATERIAL_PATHS.aptitudeX509EcPrivateKey,
    "utf-8",
  );
  const certPem = fs.readFileSync(
    KEY_MATERIAL_PATHS.aptitudeX509EcCertificate,
    "utf-8",
  );
  return {
    privateKeyPkcs8,
    certChain: [pemToBase64Der(certPem)],
  };
}

function requireEs256Material({ privateKeyPkcs8, certChain }) {
  if (typeof privateKeyPkcs8 !== "string" || !privateKeyPkcs8.includes("PRIVATE KEY")) {
    throw new Error("Issuer metadata signing material does not contain a PKCS#8 private key");
  }
  if (!Array.isArray(certChain) || certChain.length < 1 || certChain.some((cert) => !cert)) {
    throw new Error("Issuer metadata signing requires an x5c chain with a leaf certificate");
  }
}

/**
 * Produce OpenID4VCI signed Credential Issuer metadata for APTITUDE (RFC001 §7.7).
 */
export async function signCredentialIssuerMetadata(metadata, signingMaterial) {
  const issuer = metadata?.credential_issuer;
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new Error("Credential Issuer metadata must contain credential_issuer before signing");
  }
  requireEs256Material(signingMaterial);

  const { privateKeyPkcs8, certChain } = signingMaterial;
  const payload = {
    ...metadata,
    sub: issuer,
    iat: Math.floor(Date.now() / 1000),
  };

  return new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: SIGNED_ISSUER_METADATA_TYP,
      x5c: certChain,
    })
    .sign(await jose.importPKCS8(privateKeyPkcs8, "ES256"));
}

export async function signCredentialIssuerMetadataFromConfiguredMaterial(metadata) {
  return signCredentialIssuerMetadata(metadata, loadAptitudeIssuerMetadataSigningMaterial());
}
