import fs from "fs";
import path from "path";
import crypto, { X509Certificate, createHash, createPublicKey, createVerify } from "crypto";
import fetch from "node-fetch";
import { validateCs03QesResponse } from "./routeUtils.js";

const CSC_QES_TYPE = "https://cloudsignatureconsortium.org/2025/qes";
const CS03_SAMPLE_DOCUMENT_PATH = path.join(process.cwd(), "data", "cs03-sample.pdf");

function strictBase64Decode(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("payload must be a non-empty base64 string");
  }

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error("payload is not valid base64");
  }

  return Buffer.from(value, "base64");
}

function decodeCs03TransactionDataEntry(entry) {
  if (typeof entry !== "string") return null;
  const decoded = JSON.parse(Buffer.from(entry, "base64url").toString("utf8"));
  if (decoded?.type !== CSC_QES_TYPE) return null;
  return decoded;
}

function toChecksum(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
}

function isLikelyPdf(bytes) {
  return Buffer.isBuffer(bytes) && bytes.subarray(0, 5).toString("ascii") === "%PDF-";
}

function hasEmbeddedPdfSignature(bytes) {
  const ascii = bytes.toString("latin1");
  return ascii.includes("/ByteRange") && ascii.includes("/Contents");
}

function buildCertificateSummary(certificatePem) {
  if (typeof certificatePem !== "string" || certificatePem.trim().length === 0) {
    return { present: false };
  }

  const parsed = new X509Certificate(certificatePem);
  return {
    present: true,
    subject: parsed.subject,
    issuer: parsed.issuer,
    fingerprint256: parsed.fingerprint256,
    validFrom: parsed.validFrom,
    validTo: parsed.validTo,
  };
}

async function resolveDocumentBytes(signatureRequest, options = {}) {
  if (typeof options.documentResolver === "function") {
    return options.documentResolver(signatureRequest);
  }

  if (!signatureRequest?.href) {
    throw new Error("signatureRequest.href is required");
  }

  if (signatureRequest.href.startsWith("data:")) {
    const match = signatureRequest.href.match(/^data:.*?;base64,(.+)$/);
    if (!match) {
      throw new Error("Only base64 data: URIs are supported for CS-03 validation");
    }
    return Buffer.from(match[1], "base64");
  }

  try {
    const parsed = new URL(signatureRequest.href);
    if (parsed.pathname === "/x509/cs03-document") {
      return fs.readFileSync(CS03_SAMPLE_DOCUMENT_PATH);
    }
  } catch {
    // Fall through to fetch below.
  }

  const response = await fetch(signatureRequest.href);
  if (!response.ok) {
    throw new Error(`Failed to resolve signed document '${signatureRequest.href}' (${response.status})`);
  }
  return Buffer.from(await response.arrayBuffer());
}

function verifySignatureOverBytes({ bytes, signature, signerCertificate }) {
  const publicKey = createPublicKey(signerCertificate);
  const verifier = createVerify("sha256");
  verifier.update(bytes);
  verifier.end();
  return verifier.verify(publicKey, signature);
}

function createItemResult(index, signatureRequest) {
  return {
    index,
    label: signatureRequest?.label || null,
    href: signatureRequest?.href || null,
    signatureFormat: signatureRequest?.signature_format || null,
    checksumExpected: signatureRequest?.checksum || null,
    checks: {
      payloadBase64Decoded: false,
      sourceDocumentResolved: false,
      sourceDocumentChecksumMatched: false,
      artifactFormatRecognized: false,
      artifactCryptographicallyVerified: false,
      artifactBoundToRequestedDocument: false,
      signerCertificateParsed: false,
    },
    artifactLength: 0,
    errors: [],
    warnings: [],
  };
}

export function extractCs03QesRequestFromSession(vpSession) {
  const transactionDataEntries = Array.isArray(vpSession?.transaction_data)
    ? vpSession.transaction_data
    : [];

  for (const entry of transactionDataEntries) {
    try {
      const qesRequest = decodeCs03TransactionDataEntry(entry);
      if (qesRequest) return qesRequest;
    } catch {
      // Ignore malformed non-CS03 transaction_data here; request validation handles that elsewhere.
    }
  }

  return null;
}

export function summarizeCs03ValidationForLog(validationResult) {
  if (!validationResult || typeof validationResult !== "object") {
    return { ok: false, error: "missing validation result" };
  }

  return {
    ok: !!validationResult.ok,
    credentialIds: validationResult.credentialIds || [],
    qesRequestSignatureRequestCount: validationResult.qesRequestSignatureRequestCount ?? 0,
    credentialSummaries: (validationResult.credentials || []).map((credential) => ({
      credentialId: credential.credentialId,
      artifactType: credential.artifactType || null,
      ok: !!credential.ok,
      payloadCount: credential.payloadCount ?? 0,
      expectedPayloadCount: credential.expectedPayloadCount ?? 0,
      signerCertificate: credential.signerCertificate
        ? {
            present: !!credential.signerCertificate.present,
            fingerprint256: credential.signerCertificate.fingerprint256 || null,
            subject: credential.signerCertificate.subject || null,
          }
        : { present: false },
      itemSummaries: (credential.items || []).map((item) => ({
        index: item.index,
        ok: !!item.ok,
        signatureFormat: item.signatureFormat || null,
        artifactLength: item.artifactLength || 0,
        checks: item.checks || {},
        errors: item.errors || [],
        warnings: item.warnings || [],
      })),
      errors: credential.errors || [],
      warnings: credential.warnings || [],
    })),
    errors: validationResult.errors || [],
  };
}

export async function validateCs03CredentialResponses({
  qesByCredentialId,
  vpSession,
  documentResolver,
}) {
  const qesRequest = extractCs03QesRequestFromSession(vpSession);
  if (!qesRequest) {
    return {
      ok: false,
      error: "missing_qes_request",
      errors: ["CS-03 qesRequest missing from session transaction_data"],
      credentialIds: Object.keys(qesByCredentialId || {}),
      qesRequestSignatureRequestCount: 0,
      credentials: [],
    };
  }

  const signatureRequests = Array.isArray(qesRequest.signatureRequests)
    ? qesRequest.signatureRequests
    : [];

  if (signatureRequests.length === 0) {
    return {
      ok: false,
      error: "invalid_qes_request",
      errors: ["CS-03 qesRequest must contain at least one signatureRequest"],
      credentialIds: Object.keys(qesByCredentialId || {}),
      qesRequestSignatureRequestCount: 0,
      credentials: [],
    };
  }

  const validationResult = {
    ok: true,
    credentialIds: Object.keys(qesByCredentialId || {}),
    qesRequestSignatureRequestCount: signatureRequests.length,
    credentials: [],
    errors: [],
  };

  for (const [credentialId, qesResponse] of Object.entries(qesByCredentialId || {})) {
    const qesShape = validateCs03QesResponse(qesResponse);
    const credentialResult = {
      credentialId,
      ok: true,
      artifactType: null,
      payloadCount: 0,
      expectedPayloadCount: signatureRequests.length,
      signerCertificate: { present: false },
      items: [],
      errors: [],
      warnings: [],
    };

    if (!qesShape.ok) {
      credentialResult.ok = false;
      credentialResult.errors.push(qesShape.error);
      validationResult.ok = false;
      validationResult.errors.push(`Credential '${credentialId}': ${qesShape.error}`);
      validationResult.credentials.push(credentialResult);
      continue;
    }

    const artifactType = Array.isArray(qesResponse.documentWithSignature)
      ? "documentWithSignature"
      : "signatureObject";
    const payloads = qesResponse[artifactType];

    credentialResult.artifactType = artifactType;
    credentialResult.payloadCount = payloads.length;

    if (payloads.length !== signatureRequests.length) {
      credentialResult.ok = false;
      credentialResult.errors.push(
        `Received ${payloads.length} ${artifactType} entr${payloads.length === 1 ? "y" : "ies"} but qesRequest expects ${signatureRequests.length}`,
      );
    }

    if (typeof qesResponse.signerCertificate === "string" && qesResponse.signerCertificate.trim()) {
      try {
        credentialResult.signerCertificate = buildCertificateSummary(qesResponse.signerCertificate);
      } catch (error) {
        credentialResult.ok = false;
        credentialResult.errors.push(`signerCertificate parse failed: ${error.message}`);
      }
    }

    if (artifactType === "signatureObject" && !credentialResult.signerCertificate.present) {
      credentialResult.warnings.push(
        "signerCertificate missing; cryptographic signature verification skipped",
      );
    }

    for (let index = 0; index < payloads.length; index += 1) {
      const signatureRequest = signatureRequests[index];
      const itemResult = createItemResult(index, signatureRequest);
      itemResult.ok = true;

      let artifactBytes;
      try {
        artifactBytes = strictBase64Decode(payloads[index]);
        itemResult.checks.payloadBase64Decoded = true;
        itemResult.artifactLength = artifactBytes.length;
      } catch (error) {
        itemResult.ok = false;
        itemResult.errors.push(error.message);
        credentialResult.ok = false;
        credentialResult.items.push(itemResult);
        continue;
      }

      let sourceDocumentBytes = null;
      try {
        sourceDocumentBytes = await resolveDocumentBytes(signatureRequest, { documentResolver });
        itemResult.checks.sourceDocumentResolved = true;
      } catch (error) {
        itemResult.ok = false;
        itemResult.errors.push(error.message);
        credentialResult.ok = false;
        credentialResult.items.push(itemResult);
        continue;
      }

      if (signatureRequest?.checksum) {
        const actualChecksum = toChecksum(sourceDocumentBytes);
        itemResult.actualChecksum = actualChecksum;
        if (actualChecksum === signatureRequest.checksum) {
          itemResult.checks.sourceDocumentChecksumMatched = true;
        } else {
          itemResult.ok = false;
          itemResult.errors.push(
            `Source document checksum mismatch: expected ${signatureRequest.checksum}, got ${actualChecksum}`,
          );
          credentialResult.ok = false;
        }
      } else {
        itemResult.warnings.push("signatureRequest.checksum missing; document binding check weakened");
      }

      if (artifactType === "signatureObject") {
        itemResult.checks.artifactFormatRecognized = true;
        itemResult.checks.artifactBoundToRequestedDocument = true;

        if (credentialResult.signerCertificate.present) {
          itemResult.checks.signerCertificateParsed = true;
          try {
            const verified = verifySignatureOverBytes({
              bytes: sourceDocumentBytes,
              signature: artifactBytes,
              signerCertificate: qesResponse.signerCertificate,
            });
            itemResult.checks.artifactCryptographicallyVerified = verified;
            if (!verified) {
              itemResult.ok = false;
              itemResult.errors.push("signatureObject verification failed against signerCertificate");
              credentialResult.ok = false;
            }
          } catch (error) {
            itemResult.ok = false;
            itemResult.errors.push(`signatureObject verification error: ${error.message}`);
            credentialResult.ok = false;
          }
        } else {
          itemResult.warnings.push(
            "signatureObject could not be cryptographically verified because signerCertificate is missing",
          );
        }
      } else if (artifactType === "documentWithSignature") {
        const recognizedPdf = isLikelyPdf(artifactBytes);
        itemResult.checks.artifactFormatRecognized = recognizedPdf;
        if (!recognizedPdf) {
          itemResult.ok = false;
          itemResult.errors.push("documentWithSignature is not a PDF");
          credentialResult.ok = false;
        }

        const hasPdfSignature = hasEmbeddedPdfSignature(artifactBytes);
        itemResult.checks.artifactCryptographicallyVerified = hasPdfSignature;
        if (!hasPdfSignature) {
          itemResult.ok = false;
          itemResult.errors.push("documentWithSignature does not expose PDF signature markers (/ByteRange and /Contents)");
          credentialResult.ok = false;
        }

        const differsFromSource = !artifactBytes.equals(sourceDocumentBytes);
        itemResult.checks.artifactBoundToRequestedDocument = differsFromSource;
        if (!differsFromSource) {
          itemResult.ok = false;
          itemResult.errors.push("documentWithSignature is byte-identical to the unsigned source document");
          credentialResult.ok = false;
        }
      }

      credentialResult.items.push(itemResult);
    }

    validationResult.credentials.push(credentialResult);
    if (!credentialResult.ok) {
      validationResult.ok = false;
      validationResult.errors.push(
        `Credential '${credentialId}' validation failed`,
      );
    }
  }

  return validationResult;
}
