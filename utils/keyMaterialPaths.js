/**
 * Canonical key and certificate paths used by the issuer, verifier, and
 * wallet-client fixtures. Keep protocol roles separate: the verifier's
 * response-encryption key is not the application's signing key.
 */
export const KEY_MATERIAL_PATHS = Object.freeze({
  applicationSigningPrivateKey: "./private-key.pem",
  applicationSigningPrivateKeyPkcs8: "./private-key-pkcs8.pem",
  applicationSigningPublicKey: "./public-key.pem",
  didPrivateKeyPkcs8: "./didjwks/did_private_pkcs8.key",
  didPublicKey: "./didjwks/did_public.pem",
  verifierEncryptionPrivateKey: "./x509EC/ec_private_pkcs8.key",
  verifierEncryptionCertificate: "./x509EC/client_certificate.crt",
  verifierSigningP12: "./certs/WE-BUILD-Verifier.p12",
  verifierSigningCa: "./certs/pidissuerca02_eu.pem",
});

export const DEPRECATED_KEY_MATERIAL_DIR = "./deprecated";
