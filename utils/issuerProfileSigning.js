import fs from "node:fs";
import crypto from "node:crypto";
import { getIssuerProfile } from "./issuerProfiles.js";

// Pilot placeholders are deliberately separate paths so that each certificate
// can be replaced without changing another profile's configuration.
export function loadProfileCredentialSigningMaterial(profileId, { certPath, keyPath } = {}) {
  if (!getIssuerProfile(profileId)) throw new Error(`Unknown issuer profile: ${profileId}`);
  const envPrefix = `ISSUER_${profileId.toUpperCase().replaceAll("-", "_")}`;
  const defaultCertificates = {
    pid: "certs/id-union-pid-certificate.pem",
    // Temporary pilot fallback: IdUnion has not issued a generic EAA leaf yet.
    eaa: "certs/id-union-pid-certificate.pem",
    "pub-eaa": "certs/idunion/idunon_pub_eaa.pem",
    qeaa: "certs/idunion/id_union_qeea_prov.pem",
  };
  const certificatePath = certPath || process.env[`${envPrefix}_CERT_PATH`] || defaultCertificates[profileId];
  const privateKeyPath = keyPath || process.env[`${envPrefix}_KEY_PATH`] || "certs/dev-i4mlab.aegean.gr.key.pem";
  if (!fs.existsSync(certificatePath) || !fs.existsSync(privateKeyPath)) throw new Error(`Issuer profile ${profileId} signing material unavailable`);
  const certificatePem = fs.readFileSync(certificatePath, "utf8");
  const privateKey = crypto.createPrivateKey(fs.readFileSync(privateKeyPath, "utf8"));
  const certificate = new crypto.X509Certificate(certificatePem);
  const publicKey = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  if (!publicKey.equals(certificate.publicKey.export({ type: "spki", format: "der" }))) throw new Error(`Issuer profile ${profileId} certificate and key do not match`);
  const chain = certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return { certificatePem, privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }), x5c: chain.map((pem) => new crypto.X509Certificate(pem).raw.toString("base64")) };
}
