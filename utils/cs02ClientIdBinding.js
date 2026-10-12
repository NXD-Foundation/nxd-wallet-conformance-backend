import { createHash, X509Certificate } from "node:crypto";
import base64url from "base64url";

export const X509_SAN_DNS_PREFIX = "x509_san_dns:";
export const X509_HASH_PREFIX = "x509_hash:";

export class Cs02ClientIdBindingError extends Error {
  constructor(message, errorCode = "invalid_client") {
    super(message);
    this.name = "Cs02ClientIdBindingError";
    this.errorCode = errorCode;
  }
}

export function parseX509SanDnsClientId(clientId) {
  if (typeof clientId !== "string" || !clientId.startsWith(X509_SAN_DNS_PREFIX)) {
    return null;
  }
  const dns = clientId.slice(X509_SAN_DNS_PREFIX.length).trim();
  return dns.length > 0 ? dns : null;
}

export function parseTrustedX509ClientIds(raw) {
  if (raw == null || raw === "") return [];
  return String(raw)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function isTrustedX509SanDnsClientId(clientId, trustedClientIds = []) {
  if (!clientId || !Array.isArray(trustedClientIds) || trustedClientIds.length === 0) {
    return false;
  }
  return trustedClientIds.includes(clientId);
}

export function parseDnsNamesFromSubjectAltName(subjectAltName) {
  if (!subjectAltName) return [];
  return String(subjectAltName)
    .split(",")
    .map((part) => part.trim())
    .filter((part) => /^DNS:/i.test(part))
    .map((part) => part.slice(4).trim())
    .filter((name) => name.length > 0 && !name.includes("*"));
}

export function dnsNamesFromCertificatePem(pem) {
  if (typeof pem !== "string" || pem.trim().length === 0) {
    throw new Cs02ClientIdBindingError(
      "x509_san_dns leaf certificate is missing",
      "invalid_client",
    );
  }
  try {
    const cert = new X509Certificate(pem);
    return parseDnsNamesFromSubjectAltName(cert.subjectAltName);
  } catch (error) {
    if (error instanceof Cs02ClientIdBindingError) throw error;
    throw new Cs02ClientIdBindingError(
      "Unable to read dNSName SAN entries from x509_san_dns leaf certificate",
      "invalid_client",
    );
  }
}

export function assertX509SanDnsResponseUriFqdn(
  clientId,
  responseUri,
  { trustedClientIds = [] } = {},
) {
  const dns = parseX509SanDnsClientId(clientId);
  if (!dns) {
    throw new Cs02ClientIdBindingError(
      "x509_san_dns client_id must include a DNS name after the prefix",
      "invalid_client",
    );
  }
  if (dns.includes("*")) {
    throw new Cs02ClientIdBindingError(
      "x509_san_dns client_id must not use a wildcard DNS name",
      "invalid_client",
    );
  }
  if (isTrustedX509SanDnsClientId(clientId, trustedClientIds)) {
    return { skipped: true, reason: "trusted_client_id", dns };
  }
  let parsed;
  try {
    parsed = new URL(responseUri);
  } catch {
    throw new Cs02ClientIdBindingError(
      "x509_san_dns response_uri must be an absolute URI",
      "invalid_request",
    );
  }
  const hostname = typeof parsed.hostname === "string" ? parsed.hostname : "";
  if (!hostname || hostname.toLowerCase() !== dns.toLowerCase()) {
    throw new Cs02ClientIdBindingError(
      `x509_san_dns response_uri FQDN "${hostname || ""}" must match client_id DNS name "${dns}"`,
      "invalid_client",
    );
  }
  return { skipped: false, dns, hostname };
}

export function parseX509HashClientId(clientId) {
  if (typeof clientId !== "string" || !clientId.startsWith(X509_HASH_PREFIX)) {
    return null;
  }
  const hash = clientId.slice(X509_HASH_PREFIX.length).trim();
  return hash.length > 0 ? hash : null;
}

export function computeX509HashClientIdFromLeafCertBase64(leafCertBase64) {
  if (typeof leafCertBase64 !== "string" || leafCertBase64.length === 0) {
    throw new Cs02ClientIdBindingError(
      "x509_hash leaf certificate is missing",
      "invalid_client",
    );
  }
  let certDer;
  try {
    certDer = Buffer.from(leafCertBase64, "base64");
  } catch {
    throw new Cs02ClientIdBindingError(
      "x509_hash leaf certificate is malformed",
      "invalid_client",
    );
  }
  if (certDer.length === 0) {
    throw new Cs02ClientIdBindingError(
      "x509_hash leaf certificate is malformed",
      "invalid_client",
    );
  }
  const hashB64Url = base64url.encode(createHash("sha256").update(certDer).digest());
  return `${X509_HASH_PREFIX}${hashB64Url}`;
}

export function assertX509HashLeafMatchesClientId(clientId, leafCertBase64) {
  const expectedHash = parseX509HashClientId(clientId);
  if (!expectedHash) {
    throw new Cs02ClientIdBindingError(
      "x509_hash client_id must include a base64url SHA-256 hash after the prefix",
      "invalid_client",
    );
  }
  const expectedClientId = computeX509HashClientIdFromLeafCertBase64(leafCertBase64);
  if (clientId !== expectedClientId) {
    throw new Cs02ClientIdBindingError(
      `x509_hash client_id mismatch: expected ${expectedClientId} but got ${clientId}`,
      "invalid_client",
    );
  }
  return { clientId: expectedClientId };
}

export function assertX509SanDnsLeafMatchesClientId(clientId, leafCertPem) {
  const dns = parseX509SanDnsClientId(clientId);
  if (!dns) {
    throw new Cs02ClientIdBindingError(
      "x509_san_dns client_id must include a DNS name after the prefix",
      "invalid_client",
    );
  }
  if (dns.includes("*")) {
    throw new Cs02ClientIdBindingError(
      "x509_san_dns client_id must not use a wildcard DNS name",
      "invalid_client",
    );
  }
  const dnsNames = dnsNamesFromCertificatePem(leafCertPem);
  const matched = dnsNames.some((name) => name.toLowerCase() === dns.toLowerCase());
  if (!matched) {
    throw new Cs02ClientIdBindingError(
      `x509_san_dns client_id DNS name "${dns}" is not a dNSName SAN of the JAR leaf certificate`,
      "invalid_client",
    );
  }
  return { dns, dnsNames };
}
