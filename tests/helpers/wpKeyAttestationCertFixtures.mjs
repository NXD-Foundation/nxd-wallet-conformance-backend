/**
 * CA-signed leaf + anchor PEM for key-attestation x5c verification tests.
 */
import crypto from "node:crypto";
import { exportPKCS8, exportSPKI } from "jose";
import {
  X509CertificateGenerator,
  KeyUsageFlags,
  KeyUsagesExtension,
  BasicConstraintsExtension,
} from "@peculiar/x509";

const signingAlgorithm = { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" };

/**
 * @returns {Promise<{ caPem: string, leafPem: string, leafPrivateKey: CryptoKey, leafPublicKey: CryptoKey, x5c: string[], issuerConfigAnchors: string[] }>}
 */
export async function createWalletProviderKeyAttestationCertFixtures() {
  const caKeys = await crypto.subtle.generateKey(signingAlgorithm, true, ["sign", "verify"]);
  const leafKeys = await crypto.subtle.generateKey(signingAlgorithm, true, ["sign", "verify"]);

  const caCert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Test Wallet Provider CA",
    keys: caKeys,
    signingAlgorithm,
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.digitalSignature, true),
    ],
  });

  const leafCert = await X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "CN=Test Wallet Provider KA Signer",
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingKey: caKeys.privateKey,
    publicKey: leafKeys.publicKey,
    signingAlgorithm,
    extensions: [
      new BasicConstraintsExtension(false, -1, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
    ],
  });

  const caPem = caCert.toString("pem");
  const leafPem = leafCert.toString("pem");

  const derB64 = (pem) =>
    pem
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");

  return {
    caPem,
    leafPem,
    leafPrivateKey: leafKeys.privateKey,
    leafPublicKey: leafKeys.publicKey,
    leafPrivateKeyPem: await exportPKCS8(leafKeys.privateKey),
    leafPublicKeyPem: await exportSPKI(leafKeys.publicKey),
    x5c: [derB64(leafPem)],
    issuerConfigAnchors: [caPem],
  };
}

export function pemToX5cDerB64(pem) {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

/**
 * @param {object} params
 * @param {Awaited<ReturnType<typeof createWalletProviderKeyAttestationCertFixtures>>} params.fixtures
 * @param {object[]} params.attestedKeys
 * @param {object} [params.claims]
 */
export async function buildSignedKeyAttestationJwt({ fixtures, attestedKeys, claims = {} }) {
  const { SignJWT } = await import("jose");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: "https://wallet-provider.example",
    aud: "https://issuer.example/credential",
    iat: now,
    exp: now + 3600,
    jti: "ka-test-jti",
    key_storage: ["iso_18045_high"],
    user_authentication: ["iso_18045_high"],
    certification: "https://wallet-provider.example/certification",
    key_storage_status: {
      status: { status_list: { uri: "https://example.com/status", idx: 0 } },
      exp: now + 86400,
    },
    attested_keys: attestedKeys,
    ...claims,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "key-attestation+jwt",
      x5c: fixtures.x5c,
    })
    .sign(fixtures.leafPrivateKey);
}
