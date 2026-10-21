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
  verifierTrustWrpacCertificate: "./certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem",
  verifierTrustWrpacKey: "./certs/raidiam/4c3ecfb0-76ff-4eea-8e51-c8fac931e186-WRPAC.key",
  verifierTrustWrpacIssuingCa: "./certs/raidiam/eudi-sandbox-issuing-ca-g1.pem",
  trustFrameworkPidIssuerCertificate: "./certs/id-union-pid-certificate.pem",
});

export const DEPRECATED_KEY_MATERIAL_DIR = "./deprecated";
