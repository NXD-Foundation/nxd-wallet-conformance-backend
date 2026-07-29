import crypto from "crypto";
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { pemToBase64Der } from "./sdjwtUtils.js";

const DEFAULT_P12_PATH = path.resolve(process.cwd(), "certs", "WE-BUILD-Verifier.p12");
const DEFAULT_TRUST_ANCHOR_PATH = path.resolve(process.cwd(), "certs", "pidissuerca02_eu.pem");

function extractCertificates(pem) {
  const certificates = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!certificates?.length) throw new Error("Issuer signing P12 does not contain a certificate");
  return certificates;
}

function assertMatchingKeyAndTrustedLeaf(privateKeyPkcs8, leafCertificatePem, trustAnchorPem) {
  const privatePublicKey = crypto.createPublicKey(crypto.createPrivateKey(privateKeyPkcs8))
    .export({ type: "spki", format: "der" });
  const leaf = new crypto.X509Certificate(leafCertificatePem);
  const leafPublicKey = leaf.publicKey.export({ type: "spki", format: "der" });
  if (!privatePublicKey.equals(leafPublicKey)) {
    throw new Error("Issuer signing P12 private key does not match its leaf certificate");
  }

  const trustAnchor = new crypto.X509Certificate(trustAnchorPem);
  if (!leaf.checkIssued(trustAnchor) || !leaf.verify(trustAnchor.publicKey)) {
    throw new Error("Issuer signing leaf does not chain to the configured EUDI trust anchor");
  }
  if (Date.parse(leaf.validTo) <= Date.now()) {
    throw new Error(`Issuer signing leaf certificate is expired: ${leaf.validTo}`);
  }
}

/**
 * Load the EUDI pre-production issuer signing leaf from the Aptitude P12.
 * The PID Issuer CA is verified locally but deliberately excluded from x5c:
 * it is a trust anchor configured by the wallet, not a transmitted chain entry.
 */
export function loadAptitudeIssuerSigningMaterial({ p12Path, trustAnchorPath, passphrase } = {}) {
  const resolvedP12Path = p12Path
    ? path.resolve(process.cwd(), p12Path)
    : process.env.APTITUDE_ISSUER_SIGNING_P12_PATH || DEFAULT_P12_PATH;
  const resolvedTrustAnchorPath = trustAnchorPath
    ? path.resolve(process.cwd(), trustAnchorPath)
    : process.env.APTITUDE_ISSUER_TRUST_ANCHOR_PEM || DEFAULT_TRUST_ANCHOR_PATH;
  const effectivePassphrase = passphrase || process.env.WEBUILD_P12_PASSWORD || "webuild";

  if (!fs.existsSync(resolvedP12Path)) {
    throw new Error(`Aptitude issuer signing P12 not found at ${resolvedP12Path}`);
  }
  if (!fs.existsSync(resolvedTrustAnchorPath)) {
    throw new Error(`Aptitude issuer trust anchor not found at ${resolvedTrustAnchorPath}`);
  }

  const env = { ...process.env, APTITUDE_ISSUER_P12_PASSWORD: effectivePassphrase };
  let certificatesPem;
  let privateKeyPem;
  try {
    certificatesPem = execFileSync(
      "openssl",
      ["pkcs12", "-in", resolvedP12Path, "-nokeys", "-passin", "env:APTITUDE_ISSUER_P12_PASSWORD"],
      { encoding: "utf8", env },
    );
    privateKeyPem = execFileSync(
      "openssl",
      ["pkcs12", "-in", resolvedP12Path, "-nodes", "-nocerts", "-passin", "env:APTITUDE_ISSUER_P12_PASSWORD"],
      { encoding: "utf8", env },
    );
  } catch (error) {
    throw new Error(`Unable to load Aptitude issuer signing P12: ${error.message}`);
  }

  const [leafCertificatePem] = extractCertificates(certificatesPem);
  const privateKeyPkcs8 = crypto.createPrivateKey(privateKeyPem).export({ type: "pkcs8", format: "pem" });
  const trustAnchorPem = fs.readFileSync(resolvedTrustAnchorPath, "utf8");
  assertMatchingKeyAndTrustedLeaf(privateKeyPkcs8, leafCertificatePem, trustAnchorPem);

  return {
    privateKeyPkcs8,
    leafCertificatePem,
    certChain: [pemToBase64Der(leafCertificatePem)],
  };
}
