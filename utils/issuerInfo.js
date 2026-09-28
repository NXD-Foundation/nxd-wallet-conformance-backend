/**
 * RFC001 §7.7 SHALL 8 / ETSI TS 119 472-3 clause 4.2.3 `issuer_info`.
 *
 * `issuer_info` is an array of OpenID4VP `verifier_info`-shaped objects:
 * `{ format, data }`. This profile uses:
 *   - `format: "registration_cert"` — WRPRC / registration certificate (`data` string)
 *   - `format: "registrar_dataset"` — registrar JSON (`data` object with
 *     `identifier`, `srvDescription`, `registryURI`, `providesAttestations`)
 *
 * The active Aptitude issuer certificate may be provided directly by the
 * issuer-signing material loader, avoiding drift from the metadata JWS signer.
 */
import fs from "fs";
import path from "path";
import { X509Certificate } from "@peculiar/x509";

export const ISSUER_INFO_FORMAT_REGISTRATION_CERT = "registration_cert";
export const ISSUER_INFO_FORMAT_REGISTRAR_DATASET = "registrar_dataset";

const REQUIRED_REGISTRAR_DATASET_KEYS = [
  "identifier",
  "srvDescription",
  "registryURI",
  "providesAttestations",
];

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

const FALLBACK_REGISTRAR_DATASET = {
  identifier: "dev:rfc-issuer-v1",
  srvDescription: [
    {
      lang: "en",
      content:
        "APTITUDE RFC001 test issuer (self-registered development material)",
    },
  ],
  registryURI: "https://uaegean.gr",
  providesAttestations: [],
};

function stripPemToBase64Der(pem) {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}

function readRegistrationDataset(pathOverride) {
  const p = pathOverride || DEFAULT_REGISTRATION_PATH;
  if (!fs.existsSync(p)) return null;
  try {
    const raw = fs.readFileSync(p, "utf-8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
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

function warnIfRegistrarDatasetIncomplete(dataset) {
  const missing = REQUIRED_REGISTRAR_DATASET_KEYS.filter(
    (key) => dataset[key] == null,
  );
  if (missing.length > 0) {
    console.warn(
      `[issuer_info] registrar_dataset is missing ETSI TS 119 472-3 members: ${missing.join(", ")}`,
    );
  }
}

/**
 * Return the first `issuer_info` array element whose `format` matches.
 *
 * @param {unknown} issuerInfo
 * @param {string} format
 * @returns {object | undefined}
 */
export function pickIssuerInfoEntry(issuerInfo, format) {
  if (!Array.isArray(issuerInfo)) return undefined;
  return issuerInfo.find(
    (entry) => entry && typeof entry === "object" && entry.format === format,
  );
}

/**
 * Build the ETSI/RFC001 `issuer_info` array from the PEM certificate at
 * `certPath` and the registrar dataset at `registrationPath`. Returns `null`
 * if the certificate cannot be loaded (callers should then skip attaching
 * `issuer_info`).
 *
 * @param {object} [options]
 * @param {string} [options.certPath] - Path to PEM certificate.
 * @param {string} [options.certificatePem] - Active issuer leaf certificate.
 * @param {string} [options.registrationPath] - Path to registrar dataset JSON
 *   (default: `data/issuer-registration.json`).
 * @returns {Promise<object[]|null>}
 */
export async function buildIssuerInfo({
  certPath = process.env.ISSUER_REGISTRATION_CERT_PATH || DEFAULT_CERT_PATH,
  certificatePem,
  registrationPath = process.env.ISSUER_REGISTRATION_INFO_PATH ||
    DEFAULT_REGISTRATION_PATH,
} = {}) {
  if (!certificatePem && !fs.existsSync(certPath)) {
    console.warn(
      `[issuer_info] Registration certificate not found at ${certPath}; issuer_info will not be advertised.`,
    );
    return null;
  }

  let pem = certificatePem;
  try {
    if (!pem) pem = fs.readFileSync(certPath, "utf-8");
  } catch (e) {
    console.warn(
      `[issuer_info] Unable to read registration certificate ${certPath}: ${e.message}`,
    );
    return null;
  }

  try {
    // Validate the stand-in registration material is an X.509 certificate.
    // A production WRPRC is typically a JWT; this test service currently
    // publishes the issuer leaf certificate in `registration_cert.data`.
    new X509Certificate(pem);
  } catch (e) {
    console.warn(
      `[issuer_info] Unable to parse registration certificate ${certPath}: ${e.message}`,
    );
    return null;
  }

  const registrationCertificateB64Der = stripPemToBase64Der(pem);
  const registrationDataset =
    readRegistrationDataset(registrationPath) || FALLBACK_REGISTRAR_DATASET;
  warnIfRegistrarDatasetIncomplete(registrationDataset);

  return [
    {
      format: ISSUER_INFO_FORMAT_REGISTRATION_CERT,
      data: registrationCertificateB64Der,
    },
    {
      format: ISSUER_INFO_FORMAT_REGISTRAR_DATASET,
      data: registrationDataset,
    },
  ];
}
