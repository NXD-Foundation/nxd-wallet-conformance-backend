import { strict as assert } from "assert";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  summarizeCs03ValidationForLog,
  validateCs03CredentialResponses,
} from "../utils/cs03Validation.js";

function buildSessionWithQesRequest(qesRequest) {
  return {
    transaction_data: [Buffer.from(JSON.stringify(qesRequest)).toString("base64url")],
  };
}

describe("CS-03 signed artifact validation", () => {
  const certificatePem = fs.readFileSync(
    path.join(process.cwd(), "wallet-client", "x509CS03", "client_certificate.crt"),
    "utf8",
  );
  const privateKeyPem = fs.readFileSync(
    path.join(process.cwd(), "wallet-client", "x509CS03", "client_private_pkcs8.key"),
    "utf8",
  );
  const sourceDocument = Buffer.from("%PDF-1.7\noriginal\n");
  const checksum = `sha256-${crypto.createHash("sha256").update(sourceDocument).digest("base64")}`;
  const qesRequest = {
    type: "https://cloudsignatureconsortium.org/2025/qes",
    credential_ids: ["signing-cert-01"],
    signatureRequests: [
      {
        label: "Contract",
        href: "https://verifier.example/x509/cs03-document",
        checksum,
        signature_format: "P",
      },
    ],
  };

  async function validate(qesResponse) {
    return validateCs03CredentialResponses({
      qesByCredentialId: {
        "signing-cert-01": qesResponse,
      },
      vpSession: buildSessionWithQesRequest(qesRequest),
      documentResolver: async () => sourceDocument,
    });
  }

  it("verifies a valid signatureObject against the requested document", async () => {
    const signature = crypto
      .createSign("RSA-SHA256")
      .update(sourceDocument)
      .end()
      .sign(privateKeyPem, "base64");

    const result = await validate({
      signatureObject: [signature],
      signerCertificate: certificatePem,
    });

    assert.equal(result.ok, true);
    assert.equal(result.credentials[0].artifactType, "signatureObject");
    assert.equal(result.credentials[0].items[0].checks.payloadBase64Decoded, true);
    assert.equal(result.credentials[0].items[0].checks.sourceDocumentChecksumMatched, true);
    assert.equal(result.credentials[0].items[0].checks.artifactCryptographicallyVerified, true);
  });

  it("rejects signatureObject when the signature does not verify", async () => {
    const wrongBytes = Buffer.from("%PDF-1.7\ntampered\n");
    const signature = crypto
      .createSign("RSA-SHA256")
      .update(wrongBytes)
      .end()
      .sign(privateKeyPem, "base64");

    const result = await validate({
      signatureObject: [signature],
      signerCertificate: certificatePem,
    });

    assert.equal(result.ok, false);
    assert.match(
      result.credentials[0].items[0].errors.join(" "),
      /verification failed/i,
    );
  });

  it("rejects payload count mismatches against qesRequest.signatureRequests", async () => {
    const signature = crypto
      .createSign("RSA-SHA256")
      .update(sourceDocument)
      .end()
      .sign(privateKeyPem, "base64");

    const result = await validateCs03CredentialResponses({
      qesByCredentialId: {
        "signing-cert-01": {
          signatureObject: [signature, signature],
          signerCertificate: certificatePem,
        },
      },
      vpSession: buildSessionWithQesRequest(qesRequest),
      documentResolver: async () => sourceDocument,
    });

    assert.equal(result.ok, false);
    assert.match(result.credentials[0].errors.join(" "), /expects 1/i);
  });

  it("rejects invalid base64 payloads", async () => {
    const result = await validate({
      signatureObject: ["not-base64!!!"],
      signerCertificate: certificatePem,
    });

    assert.equal(result.ok, false);
    assert.match(result.credentials[0].items[0].errors.join(" "), /valid base64/i);
  });

  it("accepts documentWithSignature when the signed PDF differs and exposes signature markers", async () => {
    const signedPdf = Buffer.from(
      `%PDF-1.7\n1 0 obj\n<< /Type /Sig /ByteRange [0 10 20 30] /Contents <abcd> >>\nendobj\n`,
      "latin1",
    ).toString("base64");

    const result = await validate({
      documentWithSignature: [signedPdf],
    });

    assert.equal(result.ok, true);
    assert.equal(result.credentials[0].artifactType, "documentWithSignature");
    assert.equal(result.credentials[0].items[0].checks.artifactFormatRecognized, true);
    assert.equal(result.credentials[0].items[0].checks.artifactCryptographicallyVerified, true);
    assert.equal(result.credentials[0].items[0].checks.artifactBoundToRequestedDocument, true);
  });

  it("summarizes validation results for slog-safe logging", async () => {
    const signature = crypto
      .createSign("RSA-SHA256")
      .update(sourceDocument)
      .end()
      .sign(privateKeyPem, "base64");
    const result = await validate({
      signatureObject: [signature],
      signerCertificate: certificatePem,
    });

    const summary = summarizeCs03ValidationForLog(result);
    assert.equal(summary.ok, true);
    assert.equal(summary.credentialSummaries[0].artifactType, "signatureObject");
    assert.equal(summary.credentialSummaries[0].itemSummaries[0].checks.artifactCryptographicallyVerified, true);
    assert.equal(typeof summary.credentialSummaries[0].signerCertificate.fingerprint256, "string");
  });
});
