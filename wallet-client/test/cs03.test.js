import { expect } from "chai";
import {
  extractCs03Request,
  loadLocalCs03Signer,
  selectMatchingCs03Signer,
  buildCs03SignatureObject,
  buildInlineCs03VpToken,
  buildOobCs03VpToken,
  validateCs03OobResponseUri,
  sendCs03OobResponse,
} from "../src/lib/cs03.js";

describe("wallet-client CS-03 helpers", () => {
  it("detects a CSC X.509 qesRequest in transaction_data", () => {
    const qesRequest = {
      type: "https://cloudsignatureconsortium.org/2025/qes",
      credential_ids: ["signing-cert-01"],
      signatureRequests: [
        {
          href: "https://verifier.example/x509/cs03-document",
          checksum: "sha256-abc",
          signature_format: "P",
        },
      ],
    };
    const payload = {
      dcql_query: {
        credentials: [
          {
            id: "signing-cert-01",
            format: "https://cloudsignatureconsortium.org/2025/x509",
            meta: { certificatePolicies: ["0.4.0.2042.1"] },
          },
        ],
      },
      transaction_data: [
        Buffer.from(JSON.stringify(qesRequest)).toString("base64url"),
      ],
    };

    const extracted = extractCs03Request(payload);
    expect(extracted).to.not.equal(null);
    expect(extracted.qesRequest.type).to.equal(qesRequest.type);
    expect(extracted.credentialQueries[0].id).to.equal("signing-cert-01");
  });

  it("loads and matches the local CS-03 signer by certificate policy", () => {
    const signer = loadLocalCs03Signer();
    const selected = selectMatchingCs03Signer({
      credentialQueries: [
        {
          id: "signing-cert-01",
          format: "https://cloudsignatureconsortium.org/2025/x509",
          meta: { certificatePolicies: ["0.4.0.2042.1"] },
        },
      ],
      signer,
    });

    expect(selected.certificatePem).to.include("BEGIN CERTIFICATE");
    expect(selected.certificatePolicies).to.include("0.4.0.2042.1");
  });

  it("rejects a mismatched certificate policy", () => {
    const signer = loadLocalCs03Signer();
    expect(() =>
      selectMatchingCs03Signer({
        credentialQueries: [
          {
            id: "signing-cert-01",
            format: "https://cloudsignatureconsortium.org/2025/x509",
            meta: { certificatePolicies: ["1.2.3.4"] },
          },
        ],
        signer,
      }),
    ).to.throw(/certificatePolicies/i);
  });

  it("builds a signatureObject response for fetched document bytes", () => {
    const signer = loadLocalCs03Signer();
    const qesResponse = buildCs03SignatureObject({
      signer,
      documents: [{ bytes: Buffer.from("hello world") }],
    });

    expect(qesResponse.signatureObject).to.be.an("array").with.lengthOf(1);
    expect(qesResponse.signatureObject[0]).to.be.a("string").and.not.empty;
    expect(qesResponse.signerCertificate).to.include("BEGIN CERTIFICATE");
  });

  it("builds correct inline and OOB vp_token objects", () => {
    const inline = buildInlineCs03VpToken({
      credentialIds: ["signing-cert-01"],
      qesResponse: { signatureObject: ["abc"] },
    });
    const oob = buildOobCs03VpToken({
      credentialIds: ["signing-cert-01"],
    });

    expect(inline).to.deep.equal({
      "signing-cert-01": {
        qes: { signatureObject: ["abc"] },
      },
    });
    expect(oob).to.deep.equal({
      "signing-cert-01": {},
    });
  });

  it("accepts an https responseURI matching x509_san_dns client_id", () => {
    expect(() =>
      validateCs03OobResponseUri({
        responseURI: "https://verifier.example/x509/qes-callback/123",
        clientId: "x509_san_dns:verifier.example",
      }),
    ).to.not.throw();
  });

  it("accepts an https responseURI matching a verified metadata domain", () => {
    expect(() =>
      validateCs03OobResponseUri({
        responseURI: "https://callbacks.example/x509/qes-callback/123",
        clientId: "x509_san_dns:verifier.example",
        clientMetadata: {
          trusted_domains: ["https://callbacks.example"],
        },
      }),
    ).to.not.throw();
  });

  it("rejects non-https responseURI", () => {
    expect(() =>
      validateCs03OobResponseUri({
        responseURI: "http://verifier.example/x509/qes-callback/123",
        clientId: "x509_san_dns:verifier.example",
      }),
    ).to.throw(/must use https/i);
  });

  it("rejects responseURI host not controlled by RP", () => {
    expect(() =>
      validateCs03OobResponseUri({
        responseURI: "https://attacker.example/x509/qes-callback/123",
        clientId: "x509_san_dns:verifier.example",
      }),
    ).to.throw(/does not match RP client_id or verified metadata/i);
  });

  it("aborts when OOB POST returns non-2xx", async () => {
    let error;
    try {
      await sendCs03OobResponse(
        "https://verifier.example/x509/qes-callback/123",
        { signatureObject: ["abc"] },
        {
          clientId: "x509_san_dns:verifier.example",
          fetchImpl: async () => ({
            ok: false,
            status: 500,
            text: async () => "server error",
          }),
        },
      );
    } catch (e) {
      error = e;
    }

    expect(error).to.exist;
    expect(error.message).to.match(/POST failed 500/i);
  });
});
