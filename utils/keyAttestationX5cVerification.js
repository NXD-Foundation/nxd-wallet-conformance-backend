/**
 * Credential-request key attestation (WUA / Appendix D.1) verification under x5c + configured WP trust anchors.
 * @see HAIP 1.0 §4.5.1, RFC001 §7.5.1
 */

import { createHash, X509Certificate } from "node:crypto";
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate as PeculiarX509Certificate,
} from "@peculiar/x509";

const KEY_ATTESTATION_SPEC_REF = "OpenID4VCI 1.0 Appendix D.1";
const HAIP_KEY_ATTESTATION_SPEC_REF = "HAIP 1.0 §4.5.1";

export function withKeyAttestationSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  if (present.length === 0) return message;
  return `${message}${message.endsWith(".") ? "" : "."} See ${present.join(" and ")}.`;
}

function derToPem(der) {
  const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g)?.join("\n") || "";
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

export function certificateFingerprintFromPem(certPem) {
  const cert = new X509Certificate(certPem);
  return createHash("sha256").update(cert.raw).digest("hex").toLowerCase();
}

export function certificatesFromX5cHeader(x5c) {
  if (!Array.isArray(x5c) || !x5c.length || x5c.some((value) => typeof value !== "string")) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: x5c must be a non-empty array of base64-encoded DER certificates",
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  return x5c.map((value) => derToPem(Buffer.from(String(value).replace(/\s+/g, ""), "base64")));
}

function certificateAt(certPem, evaluationTime) {
  const certificate = new X509Certificate(certPem);
  const time = new Date(evaluationTime).getTime();
  if (time < Date.parse(certificate.validFrom) || time > Date.parse(certificate.validTo)) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: signing certificate is outside its validity period",
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  return certificate;
}

function hasDigitalSignatureKeyUsage(certPem) {
  const certificate = new PeculiarX509Certificate(new X509Certificate(certPem).raw);
  const keyUsage = certificate.getExtension(KeyUsagesExtension);
  return !!keyUsage && (keyUsage.usages & KeyUsageFlags.digitalSignature) === KeyUsageFlags.digitalSignature;
}

/** Whether subjectCert was issued by issuerCert (DN match + signature verifies). */
function certificateIssuedBy(subjectCert, issuerCert) {
  if (subjectCert.subject === subjectCert.issuer) {
    return false;
  }
  if (subjectCert.issuer !== issuerCert.subject) {
    return false;
  }
  try {
    return subjectCert.verify(issuerCert.publicKey);
  } catch {
    return false;
  }
}

/**
 * Validates leaf (+ optional intermediates in x5c) terminates at a configured anchor not carried in x5c.
 */
export function validateWalletProviderCertificatePath({
  certificateChain,
  anchorCertificates = [],
  evaluationTime = new Date(),
  requireDigitalSignature = true,
} = {}) {
  const chain = (certificateChain || []).map((pem) => ({ pem, cert: certificateAt(pem, evaluationTime) }));
  const anchors = (anchorCertificates || []).map((pem) => ({ pem, cert: certificateAt(pem, evaluationTime) }));
  if (!chain.length || !anchors.length) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: a signing certificate chain and issuer wallet_provider_trust_anchors are required",
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  const leaf = chain[0];
  if (leaf.cert.subject === leaf.cert.issuer) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: signing certificate must not be self-signed",
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  if (requireDigitalSignature && !hasDigitalSignatureKeyUsage(leaf.pem)) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: signing certificate is not permitted for digital signatures",
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }

  const anchorFingerprints = new Set(anchors.map((a) => certificateFingerprintFromPem(a.pem)));
  for (const entry of chain) {
    if (anchorFingerprints.has(certificateFingerprintFromPem(entry.pem))) {
      throw new Error(
        withKeyAttestationSpecRef(
          "Key attestation: trust anchor certificate must not appear in the x5c JOSE header",
          HAIP_KEY_ATTESTATION_SPEC_REF
        )
      );
    }
  }

  const candidates = [...chain.slice(1), ...anchors];
  let current = leaf;
  let subordinateCaCount = 0;
  const seen = new Set([certificateFingerprintFromPem(current.pem)]);
  for (;;) {
    const exactAnchor = anchors.find(
      (anchor) => certificateFingerprintFromPem(anchor.pem) === certificateFingerprintFromPem(current.pem)
    );
    if (exactAnchor) {
      return {
        leafPem: leaf.pem,
        chain: chain.map((entry) => entry.pem),
        anchorPem: exactAnchor.pem,
      };
    }
    const issuer = candidates.find((candidate) => {
      const fingerprint = certificateFingerprintFromPem(candidate.pem);
      return !seen.has(fingerprint) && certificateIssuedBy(current.cert, candidate.cert);
    });
    if (!issuer) {
      throw new Error(
        withKeyAttestationSpecRef(
          "Key attestation: certificate chain does not terminate at a configured Wallet Provider trust anchor",
          HAIP_KEY_ATTESTATION_SPEC_REF
        )
      );
    }
    seen.add(certificateFingerprintFromPem(issuer.pem));
    if (!issuer.cert.ca) {
      throw new Error(
        withKeyAttestationSpecRef(
          "Key attestation: certificate chain does not terminate at a configured Wallet Provider trust anchor",
          HAIP_KEY_ATTESTATION_SPEC_REF
        )
      );
    }
    // RFC 5280: count non-self-issued intermediate CAs below this issuer,
    // excluding the target signing certificate itself.
    if (current !== leaf && current.cert.ca && current.cert.subject !== current.cert.issuer) {
      subordinateCaCount += 1;
    }
    const constraints = new PeculiarX509Certificate(issuer.cert.raw)
      .getExtension(BasicConstraintsExtension);
    if (constraints?.pathLength != null && subordinateCaCount > constraints.pathLength) {
      throw new Error(
        withKeyAttestationSpecRef(
          "Key attestation: certificate chain exceeds CA pathLenConstraint",
          HAIP_KEY_ATTESTATION_SPEC_REF
        )
      );
    }
    current = issuer;
  }
}

export function getWalletProviderTrustAnchorPems(issuerConfig) {
  const raw = issuerConfig?.wallet_provider_trust_anchors;
  if (!Array.isArray(raw)) return [];
  return raw.filter((pem) => typeof pem === "string" && pem.includes("BEGIN CERTIFICATE"));
}

/**
 * Resolve JWK for key-attestation JWS verification (x5c leaf only).
 * @param {object} decodedHeader - JWT protected header
 * @param {object} issuerConfig - issuer metadata root
 * @returns {object} public JWK
 */
export function resolveKeyAttestationVerificationJwkFromX5c(decodedHeader, issuerConfig) {
  if (decodedHeader?.jwk) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: header.jwk is not accepted; use x5c with a CA-signed signing certificate",
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  const x5c = decodedHeader?.x5c;
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new Error(
      withKeyAttestationSpecRef(
        "Key attestation: protected header must include x5c with the Wallet Provider signing certificate",
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
  const chainPems = certificatesFromX5cHeader(x5c);
  const anchors = getWalletProviderTrustAnchorPems(issuerConfig);
  // Always reject malformed/expired certificates and invalid signing usage,
  // even when framework trust has not been established yet.
  for (const pem of chainPems) certificateAt(pem, new Date());
  if (!hasDigitalSignatureKeyUsage(chainPems[0])) {
    throw new Error("Key attestation: signing certificate is not permitted for digital signatures");
  }
  const mode = issuerConfig?.wallet_provider_trust_mode ?? process.env.WALLET_PROVIDER_TRUST_MODE ?? "warn";
  if (!["warn", "strict"].includes(mode)) throw new Error("Invalid WALLET_PROVIDER_TRUST_MODE; expected warn or strict");
  try {
    validateWalletProviderCertificatePath({
      certificateChain: chainPems,
      anchorCertificates: anchors,
    });
  } catch (error) {
    const unestablishedTrust = /wallet_provider_trust_anchors are required|must not be self-signed|does not terminate at a configured Wallet Provider trust anchor|trust anchor certificate must not appear/.test(error.message);
    if (mode === "strict" || !unestablishedTrust) throw error;
    console.warn(`[trust] Wallet Provider trust not established; continuing in warn mode: ${error.message}`);
  }
  try {
    const leafDer = Buffer.from(String(x5c[0]).replace(/\s+/g, ""), "base64");
    const cert = new X509Certificate(leafDer);
    return cert.publicKey.export({ format: "jwk" });
  } catch (e) {
    throw new Error(
      withKeyAttestationSpecRef(
        `Key attestation: x5c certificate parsing failed (${e?.message || e})`,
        KEY_ATTESTATION_SPEC_REF,
        HAIP_KEY_ATTESTATION_SPEC_REF
      )
    );
  }
}

/**
 * Wallet Provider trust policy for credential key attestation: x5c chain validated against configured anchors.
 */
export function isWalletProviderKeyAttestationTrustedByPolicy(decodedHeader, _decodedPayload, issuerConfig) {
  try {
    resolveKeyAttestationVerificationJwkFromX5c(decodedHeader, issuerConfig);
    return true;
  } catch {
    return false;
  }
}
