/**
 * Canonical key and certificate paths for the APTITUDE issuer, verifier, and
 * wallet-client fixtures. Protocol roles stay separate: the verifier response-
 * encryption key is not the application signing key.
 */
export const KEY_MATERIAL_PATHS = Object.freeze({
  applicationSigningPrivateKey: "./private-key.pem",
  applicationSigningPrivateKeyPkcs8: "./private-key-pkcs8.pem",
  applicationSigningPublicKey: "./public-key.pem",
  didPrivateKeyPkcs8: "./didjwks/did_private_pkcs8.key",
  didPublicKey: "./didjwks/did_public.pem",
  /** APTITUDE x509EC fixture (RFC001 §10): issuer metadata JWS signing. */
  aptitudeX509EcPrivateKey: "./x509EC/ec_private_pkcs8.key",
  aptitudeX509EcCertificate: "./x509EC/client_certificate.crt",
  /** Verifier direct_post.jwt decryption (same x509EC pair in this repo). */
  verifierEncryptionPrivateKey: "./x509EC/ec_private_pkcs8.key",
  verifierEncryptionCertificate: "./x509EC/client_certificate.crt",
});

export const DEPRECATED_KEY_MATERIAL_DIR = "./deprecated";
