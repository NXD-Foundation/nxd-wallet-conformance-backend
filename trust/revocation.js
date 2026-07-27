import { X509Certificate as PeculiarX509Certificate, X509Crl, AuthorityInfoAccessExtension, CRLDistributionPointsExtension } from "@peculiar/x509";
import { X509Certificate } from "node:crypto";
import { fetchDocument } from "./fetch.js";
import { derToPem } from "./crypto.js";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

function crlUrls(certPem) {
  const certificate = new PeculiarX509Certificate(new X509Certificate(certPem).raw);
  const extension = certificate.getExtension(CRLDistributionPointsExtension);
  return (extension?.distributionPoints || []).flatMap((point) => point.distributionPoint?.fullName || [])
    .map((name) => String(name.value || name).replace(/^URI:/i, ""))
    .filter((url) => /^https?:\/\//i.test(url));
}

function caIssuerUrls(certPem) {
  const certificate = new PeculiarX509Certificate(new X509Certificate(certPem).raw);
  const extension = certificate.getExtension(AuthorityInfoAccessExtension);
  return (extension?.caIssuers || [])
    .map((name) => String(name.value || name).replace(/^URI:/i, ""))
    .filter((url) => /^https?:\/\//i.test(url));
}

function certificatePemFromDocument(document) {
  const text = document.bytes.toString("utf8").trim();
  return text.includes("BEGIN CERTIFICATE") ? text : derToPem(document.bytes);
}

async function resolveCrlIssuerCertificate({ certificatePem, issuerPem = null, fetchImpl, network }) {
  const leaf = new X509Certificate(certificatePem);
  const validIssuer = (candidatePem) => {
    try {
      const candidate = new X509Certificate(candidatePem);
      return leaf.checkIssued(candidate) && leaf.verify(candidate.publicKey);
    } catch { return false; }
  };
  if (issuerPem && validIssuer(issuerPem)) return issuerPem;
  // A self-signed trust-anchor leaf is its own issuer; a non-self-signed leaf
  // must never be used as its own CRL issuer.
  if (leaf.checkIssued(leaf) && leaf.verify(leaf.publicKey)) return certificatePem;
  for (const url of caIssuerUrls(certificatePem)) {
    try {
      const document = await fetchDocument(url, { fetchImpl, ...network });
      const candidatePem = certificatePemFromDocument(document);
      if (validIssuer(candidatePem)) return candidatePem;
    } catch {
      // Try each authenticated AIA candidate; the final error below is stable.
    }
  }
  throw new TrustListError("Certificate advertises a CRL but its issuer certificate is unavailable", TRUST_REASON_CODES.REVOCATION_UNKNOWN);
}

export function normalizeCrlTime(value) {
  const time = new Date(value);
  if (!Number.isFinite(time.getTime())) throw new Error("CRL has an invalid update time");
  return time;
}

/** Checks advertised CRLs only.  Certificates without a CRL DP are explicitly
 * reported as not-advertised rather than being silently mistaken for checked. */
export async function checkCertificateRevocation({ certificatePem, issuerPem, fetchImpl = globalThis.fetch, network = {}, evaluationTime = new Date() } = {}) {
  const urls = crlUrls(certificatePem);
  if (!urls.length) return { status: "not-advertised", urls: [] };
  const resolvedIssuerPem = await resolveCrlIssuerCertificate({ certificatePem, issuerPem, fetchImpl, network });
  const certificate = new PeculiarX509Certificate(new X509Certificate(certificatePem).raw);
  const issuer = new PeculiarX509Certificate(new X509Certificate(resolvedIssuerPem).raw);
  const evaluatedAt = new Date(evaluationTime);
  let lastError;
  for (const url of urls) {
    try {
      const document = await fetchDocument(url, { fetchImpl, ...network });
      const crl = new X509Crl(document.bytes);
      if (!(await crl.verify({ publicKey: issuer }))) throw new Error("CRL signature is invalid");
      const thisUpdate = normalizeCrlTime(crl.thisUpdate);
      const nextUpdate = crl.nextUpdate == null ? null : normalizeCrlTime(crl.nextUpdate);
      if (thisUpdate > evaluatedAt || (nextUpdate && nextUpdate < evaluatedAt)) throw new Error("CRL is not currently valid");
      if (crl.findRevoked(certificate)) {
        throw new TrustListError("Certificate is revoked", TRUST_REASON_CODES.CERTIFICATE_REVOKED, { url });
      }
      return { status: "good", url, thisUpdate: thisUpdate.toISOString(), nextUpdate: nextUpdate?.toISOString() || null };
    } catch (error) {
      if (error instanceof TrustListError && error.reasonCode === TRUST_REASON_CODES.CERTIFICATE_REVOKED) throw error;
      lastError = error;
    }
  }
  throw new TrustListError("Advertised CRL could not be validated", TRUST_REASON_CODES.REVOCATION_UNKNOWN, { urls, error: lastError?.message });
}
