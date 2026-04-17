/**
 * RFC001 §5 / §7.7 SHALL 8 — ETSI TS 119 472-3 `issuer_info` metadata parameter.
 *
 * Builds a JSON object that transports the Issuer's registration material:
 *   - the registration certificate (PEM + base64 DER + parsed summary fields),
 *   - the registrar-provided registration information (legal name, country,
 *     registrar identifier, etc.).
 *
 * In deployments without an APTITUDE registrar, we self-sign the development
 * certificate at `x509EC/client_certificate.crt` and mark `self_registered:true`
 * in the registration dataset so wallets can distinguish pilot material from
 * production trust anchors.
 */
import fs from "fs";
import path from "path";
import { X509Certificate } from "@peculiar/x509";

const DEFAULT_CERT_PATH = path.join(
  process.cwd(),
  "x509EC",
  "client_certificate.crt",
);
const DEFAULT_REGISTRATION_PATH = path.join(
  process.cwd(),
  "data",
  "issuer-registration.json",
);

function stripPemToBase64Der(pem) {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}

function hex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function readRegistrationDataset(pathOverride) {
  const p = pathOverride || DEFAULT_REGISTRATION_PATH;
  if (!fs.existsSync(p)) return null;
  try {
    const raw = fs.readFileSync(p, "utf-8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      delete parsed._comment;
      return parsed;
    }
    return null;
  } catch (e) {
    console.warn(
      `[issuer_info] Failed to read registration dataset from ${p}: ${e.message}`,
    );
    return null;
  }
}

/**
 * Build an `issuer_info` object from the PEM certificate at `certPath` and the
 * registrar dataset at `registrationPath`. Returns `null` if the certificate
 * cannot be loaded (callers should then skip attaching `issuer_info`).
 *
 * @param {object} [options]
 * @param {string} [options.certPath] - Path to PEM certificate
 *   (default: `x509EC/client_certificate.crt`).
 * @param {string} [options.registrationPath] - Path to registrar dataset JSON
 *   (default: `data/issuer-registration.json`).
 * @returns {Promise<object|null>}
 */
export async function buildIssuerInfo({
  certPath = process.env.ISSUER_REGISTRATION_CERT_PATH || DEFAULT_CERT_PATH,
  registrationPath = process.env.ISSUER_REGISTRATION_INFO_PATH ||
    DEFAULT_REGISTRATION_PATH,
} = {}) {
  if (!fs.existsSync(certPath)) {
    console.warn(
      `[issuer_info] Registration certificate not found at ${certPath}; issuer_info will not be advertised.`,
    );
    return null;
  }

  let pem;
  try {
    pem = fs.readFileSync(certPath, "utf-8");
  } catch (e) {
    console.warn(
      `[issuer_info] Unable to read registration certificate ${certPath}: ${e.message}`,
    );
    return null;
  }

  let cert;
  try {
    cert = new X509Certificate(pem);
  } catch (e) {
    console.warn(
      `[issuer_info] Unable to parse registration certificate ${certPath}: ${e.message}`,
    );
    return null;
  }

  const registrationCertificateB64Der = stripPemToBase64Der(pem);

  let sha256Thumbprint = null;
  try {
    const raw = await cert.getThumbprint("SHA-256");
    sha256Thumbprint = hex(raw);
  } catch {
    // Some runtimes expose a sync thumbprint helper; fall back to null.
  }

  const registrationDataset = readRegistrationDataset(registrationPath) || {
    self_registered: true,
  };

  const issuerInfo = {
    registration_certificate: registrationCertificateB64Der,
    registration_certificate_pem: pem.trim(),
    registration_certificate_summary: {
      subject: cert.subject,
      issuer: cert.issuer,
      serial_number: cert.serialNumber,
      not_before: cert.notBefore.toISOString(),
      not_after: cert.notAfter.toISOString(),
      sha256_thumbprint: sha256Thumbprint,
      self_signed: cert.subject === cert.issuer,
    },
    registration_information: registrationDataset,
    profile: "ETSI TS 119 472-3 (APTITUDE RFC001 §7.7 SHALL 8)",
  };

  return issuerInfo;
}
