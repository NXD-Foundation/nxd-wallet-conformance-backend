/** Local development certificates do not establish issuer trust. Deployments must
 * configure signing material whose chain is accepted by their issuer. */
import fs from "node:fs";
import { createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { jwtVerify, decodeProtectedHeader } from "jose";
import { assertCertificateValidity, handleUnestablishedTrust } from "./trustPolicy.js";

const fixtureKey = fileURLToPath(new URL("../../x509EC/ec_private_pkcs8.key", import.meta.url));
const fixtureCert = fileURLToPath(new URL("../../x509EC/client_certificate.crt", import.meta.url));

export function loadWuaSigningMaterial(env = process.env) {
  const keyPath = env.WALLET_WUA_SIGNING_KEY_PATH?.trim();
  const certPath = env.WALLET_WUA_SIGNING_CERT_PATH?.trim();
  if (Boolean(keyPath) !== Boolean(certPath)) {
    throw new Error("WUA signing requires both WALLET_WUA_SIGNING_KEY_PATH and WALLET_WUA_SIGNING_CERT_PATH");
  }
  try {
    const privateKeyPem = fs.readFileSync(keyPath || fixtureKey, "utf8");
    const certPem = fs.readFileSync(certPath || fixtureCert, "utf8");
    const blocks = certPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (!blocks?.length) throw new Error("certificate chain contains no PEM certificates");
    const certificates = blocks.map((block) => new X509Certificate(block));
    const privateKey = createPrivateKey(privateKeyPem);
    if (privateKey.asymmetricKeyType !== "ec" || privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new Error("ES256 requires a P-256 private key");
    }
    const publicKey = createPublicKey(privateKey);
    if (!publicKey.export({ type: "spki", format: "der" }).equals(certificates[0].publicKey.export({ type: "spki", format: "der" }))) {
      throw new Error("private key does not match the first signing certificate");
    }
    return {
      privateKeyPem,
      publicJwk: publicKey.export({ format: "jwk" }),
      x5c: certificates.map((certificate) => certificate.raw.toString("base64")),
    };
  } catch (error) {
    throw new Error(`WUA signing material is unavailable or invalid: ${error.message}`);
  }
}

/** Checks signer possession only; issuer-side trust-chain validation is separate. */
export async function validateExternalWuaSignature(jwt) {
  try {
    const header = decodeProtectedHeader(jwt);
    if (header.typ !== "key-attestation+jwt" || header.alg !== "ES256" || !Array.isArray(header.x5c) || !header.x5c.length || header.jwk) {
      throw new Error("requires typ key-attestation+jwt, alg ES256 and x5c without jwk");
    }
    const certificates = header.x5c.map((entry) => new X509Certificate(Buffer.from(entry, "base64")));
    assertCertificateValidity(header.x5c);
    await jwtVerify(jwt, certificates[0].publicKey, { algorithms: ["ES256"] });
    handleUnestablishedTrust("External Wallet Provider attestation signer");
  } catch (error) {
    throw new Error(`External WUA certificate/signature is invalid: ${error.message}`);
  }
}
