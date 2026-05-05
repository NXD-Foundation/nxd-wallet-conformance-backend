import { expect } from "chai";
import * as jose from "jose";
import { decode } from "cbor-x";
import { parseDeviceResponse, parseIssuerSigned, Verifier } from "@animo-id/mdoc";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";
import { buildMdocPresentation } from "../wallet-client/utils/mdlVerification.js";
import { mdocContext } from "../wallet-client/utils/mdocContext.js";

const EXTERNAL_AV_DEVICE_RESPONSE =
  "uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxZXUuZXVyb3BhLmVjLmF2LjFsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhcWV1LmV1cm9wYS5lYy5hdi4xgdgYWGCkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xOGxlbGVtZW50VmFsdWX1ZnJhbmRvbVggcWxDs58q_JkG98y2ZnbCkprotSbnmE7djtf-EVoBFFZqaXNzdWVyQXV0aIRDoQEmomE0WCQxYWYwOGZmYi1iNTc4LTRiZjEtOGFjNS1jMDVkMTBiMmI3N2JiMzNZAa8wggGrMIIBUaADAgECAhEAmj4W5MHuIp6k1LWOzg7EYTAKBggqhkjOPQQDAjA9MS4wLAYDVQQDEyVNZG9jIEltcG9ydGVkIENlcnRpZmljYXRlIERlbW8gSXNzdWVyMQswCQYDVQQGEwJVUzAeFw0yNDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMD0xLjAsBgNVBAMTJU1kb2MgSW1wb3J0ZWQgQ2VydGlmaWNhdGUgRGVtbyBJc3N1ZXIxCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMg_M5BNxhRuaGYPGlSyJAJ7FMjCFaHG1uirLMGwHl4-WV-EcaAKU356i4Joln5bXtF5wQNpxa-hnZuZeqFteD6MyMDAwLgYDVR0RBCcwJYIjd2FsdHotbW9uaXRvci1oeWJyaWQubmdyb2stZnJlZS5kZXYwCgYIKoZIzj0EAwIDSAAwRQIhAK2RKPsmqLW0A6uNuqc-DYrW2OGHR9x4DF4eZRRzS45AAiBydb-k9Ei0Im1XLHZ2WXIVoGPpDVgglcs6MzpYhQBD1VkBydgYWQHEuQAGZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6FxZXUuZXVyb3BhLmVjLmF2LjGkAFggiBio4TaSwE-ixQj-SyFRONZsQ6kfvvgh4OxyEjPeMQQBWCCGHrAy0RwLXi319vzLCDZJMolQkNBF4eSZlId3ZpkjQgJYIHZZn0uH6iLnXYCFY-JGnr_6gD2JyeBvjOwtLhzwHfQUA1gg-eCUyAP-yuZj5GNrqQxk-RB_CWhs9gA079jSUBvPRi5tZGV2aWNlS2V5SW5mb7kAAWlkZXZpY2VLZXmlAQIDJiABIVggEDhWNnbY1nGSihJ7p7b5ZyynGJcUlVbumzQhwon_uoQiWCCd97fpvLX9Qp0V5KBbAYEcw6MBBgb3C2lDrPEJ9Hceamdkb2NUeXBlcWV1LmV1cm9wYS5lYy5hdi4xbHZhbGlkaXR5SW5mb7kAA2ZzaWduZWTAdDIwMjYtMDQtMjlUMTA6MTE6MTVaaXZhbGlkRnJvbcB0MjAyNi0wNC0yOVQxMDoxMToxNVpqdmFsaWRVbnRpbMB0MjAyNy0wNC0yOVQxMDoxMToxNVpYQJrSduh0xSlztkNTfShx9VgTXbB_H9MV2LckVTQeSCGtY21qf-6KdLtC1W3-YjFFMOUvoUHgS6K3NlG7VqJIVAFsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAp32pvANhK3bw3b8DR6KzMH3NuDCkws13Uefg_biYyj3v09CfdC8Xss1gLKwVQ5KEPGqGYsMxq8joGmGi7yAp42ZzdGF0dXMA";

const EXTERNAL_AV_DEVICE_RESPONSE_WITH_X5CHAIN_ARRAY =
  "uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxZXUuZXVyb3BhLmVjLmF2LjFsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhcWV1LmV1cm9wYS5lYy5hdi4xgdgYWGCkaGRpZ2VzdElEAHFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xOGxlbGVtZW50VmFsdWX1ZnJhbmRvbVggVgQyEsRNYxdiVOpaeJ1cObrABq5V8wRwAokqTh-RyfJqaXNzdWVyQXV0aIRDoQEmogRYJDkxOTA2ZWVjLWUwOTgtNGQyMy1hMWEzLTEwZTg1MTcyY2NjNhghgVkCozCCAp8wggJEoAMCAQICFDsQ-yRZCmIBT5PCd2ZkrBAtgR7VMAoGCCqGSM49BAMCMCgxCzAJBgNVBAYTAkRFMRkwFwYDVQQDDBBHZXJtYW4gUmVnaXN0cmFyMB4XDTI2MDQyMjA3NTkxNVoXDTI3MDQyMjA3NTkxNVowSjELMAkGA1UEBhMCREUxDTALBgNVBAoMBEhvdmkxHTAbBgNVBGEMFDk4NDUwMDJFMDJCNURCMEU3QTg3MQ0wCwYDVQQDDARIb3ZpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3CxMkOiGNbJyTcEf71Zto4qIXjHDF7y0-WfjLfPVp1NHWPDXJWvpvJla8dvNDm61so82gogHBoAEIKIuMz0xbaOCASgwggEkMAwGA1UdEwEB_wQCMAAwHQYDVR0OBBYEFPtEl4JwXE-he3uCaVHby9ZnM9UlMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMA4GA1UdDwEB_wQEAwIHgDASBgNVHSUECzAJBgcogYxdBQEGMGQGA1UdEQRdMFuCEmNvcmUtYWdlbnQuaG92aS5pZIIXdGVzdC1jb3JlLWFnZW50LmhvdmkuaWSCFmNvcmUtYWdlbnQtZGV2LmhvdmkuaWSCFGNvcmUtYWdlbnQubmdyb2suYXBwMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHBzOi8vc2FuZGJveC5ldWRpLXdhbGxldC5vcmcvYXBpL3N0YXR1cy1tYW5hZ2VtZW50L2NybDAKBggqhkjOPQQDAgNJADBGAiEAnLjEGEQjsdiE41puq733wsaO6qflaB8qyNCrXw1lF3ICIQD3qbK9RpK2RpQId2hqhXz1Eha-8-WgVyh6JAbVdfvbMFkBYNgYWQFbuQAGZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6FxZXUuZXVyb3BhLmVjLmF2LjGhAFggMVe1Bc9UHdxLp_cQKN47KWKUhRyJA4RCl0FIay27p4ttZGV2aWNlS2V5SW5mb7kAAWlkZXZpY2VLZXmlAQIDJiABIVggg2hkSOnqDNcdtyAf-tI153qEOjkh_6QGggSm636M8dgiWCCzhH12ilQBpt1pMJ27xpPU4vRA6S8DfNlgUCB0OE-SL2dkb2NUeXBlcWV1LmV1cm9wYS5lYy5hdi4xbHZhbGlkaXR5SW5mb7kAA2ZzaWduZWTAdDIwMjYtMDQtMzBUMTI6Mzc6NDNaaXZhbGlkRnJvbcB0MjAyNi0wNC0zMFQxMjozNzo0M1pqdmFsaWRVbnRpbMB0MjAyNy0wNC0zMFQxMjozNzo0M1pYQFeKDcXsqeRRFv1_abG3igXN1NYP_6N0SZR6qnB7tZz6gYp8CDd69KcCYJ0nFqyLeDO6BNki2bqWGP2-lILzQ-tsZGV2aWNlU2lnbmVkuQACam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGi5AAFvZGV2aWNlU2lnbmF0dXJlhEOhASahBFjDZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW5naU9pSm5NbWhyVTA5dWNVUk9ZMlIwZVVGbUxYUkpNVFV6Y1VWUGFtdG9YelpSUjJkblUyMDJNelpOT0dSbklpd2llU0k2SW5NMFVqbGtiM0JWUVdGaVpHRlVRMlIxT0dGVU1VOU1NRkZQYTNaQk0zcGFXVVpCWjJSRWFGQnJhVGdpTENKamNuWWlPaUpRTFRJMU5pSXNJbUZzWnlJNklrVlRNalUySW4w9lhAKlw9Ok32Qrd8h6GOviKlCtxG-N_FH9-ag0UQ1ZnB3fd8eC8MaCnHZ-ph79e08IH2JZ8Vlqv26xa4MmNmmJiU-WZzdGF0dXMA";

async function runAnimoDiagnostic(vpToken) {
  const checks = [];
  let error = null;

  try {
    await new Verifier().verifyDeviceResponse(
      {
        encodedDeviceResponse: Buffer.from(vpToken, "base64url"),
        trustedCertificates: [],
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext,
    );
  } catch (e) {
    error = e;
  }

  return { checks, error };
}

async function runIssuerSignedDiagnostic(mdlToken, now = new Date()) {
  const checks = [];
  let error = null;

  try {
    const document = parseIssuerSigned(Buffer.from(mdlToken, "base64url"));
    await new Verifier().verifyIssuerSignature(
      {
        issuerAuth: document.issuerSigned.issuerAuth,
        trustedCertificates: [],
        disableCertificateChainValidation: true,
        now,
        onCheckG: (check) => checks.push(check),
      },
      mdocContext,
    );
  } catch (e) {
    error = e;
  }

  return { checks, error };
}

async function buildTestIssuerSignedMdl() {
  const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
  const proofJwk = await jose.exportJWK(publicKey);

  const proofJwt = await new jose.SignJWT({
    iss: "did:example:holder",
    aud: "http://localhost:3000",
    nonce: "test-nonce-issuer-signed-diagnostic",
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: proofJwk,
    })
    .sign(privateKey);

  return handleCredentialGenerationBasedOnFormat(
    {
      vct: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
      proofs: { jwt: [proofJwt] },
    },
    {
      signatureType: "x509",
      isHaip: false,
    },
    "http://localhost:3000",
    "mDL",
  );
}

async function buildTestWalletVp() {
  const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
  const proofJwk = await jose.exportJWK(publicKey);
  const privateJwk = await jose.exportJWK(privateKey);

  const proofJwt = await new jose.SignJWT({
    iss: "did:example:holder",
    aud: "http://localhost:3000",
    nonce: "test-nonce-mdoc-paradym-diagnostic",
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: proofJwk,
    })
    .sign(privateKey);

  const issuedCredential = await handleCredentialGenerationBasedOnFormat(
    {
      vct: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
      proofs: { jwt: [proofJwt] },
    },
    {
      signatureType: "x509",
      isHaip: false,
    },
    "http://localhost:3000",
    "mDL",
  );

  return buildMdocPresentation(issuedCredential, {
    docType: "urn:eu.europa.ec.eudi:pid:1",
    clientId: "x509_san_dns:verifier.example.org",
    responseUri: "https://verifier.example.org/direct_post",
    verifierGeneratedNonce: "verifier-nonce-paradym-diagnostic",
    devicePrivateJwk: privateJwk,
    dcqlCredentialQuery: {
      id: "pid_credential",
      format: "mso_mdoc",
      meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
      claims: [{ path: ["urn:eu.europa.ec.eudi:pid:1", "given_name"] }],
    },
  });
}

describe("Paradym-style mdoc diagnostics", () => {
  it("emits issuerAuth x5chain in a shape @animo-id/mdoc can parse", async () => {
    const vpToken = await buildTestWalletVp();
    const deviceResponse = parseDeviceResponse(Buffer.from(vpToken, "base64url"));
    const issuerAuth = deviceResponse.documents[0].issuerSigned.issuerAuth;

    expect(issuerAuth.certificate).to.be.instanceOf(Uint8Array);
    expect(issuerAuth.certificate.length).to.be.greaterThan(0);
    expect(issuerAuth.certificateChain).to.be.an("array").with.length(1);

    const { checks, error } = await runAnimoDiagnostic(vpToken);
    const diagnostic = checks.map((check) => ({
      status: check.status,
      category: check.category,
      check: check.check,
      reason: check.reason,
    }));
    console.log("Animo mdoc diagnostic checks:", JSON.stringify(diagnostic, null, 2));

    expect(error?.message).to.not.equal("No certificate found");
  });

  it("diagnoses MDOC_DIAGNOSTIC_TOKEN when provided", async function () {
    const token = process.env.MDOC_DIAGNOSTIC_TOKEN;
    if (!token) this.skip();

    const { checks, error } = await runAnimoDiagnostic(token);
    console.log("MDOC_DIAGNOSTIC_TOKEN error:", error?.message || null);
    console.log("MDOC_DIAGNOSTIC_TOKEN checks:", JSON.stringify(checks, null, 2));

    expect(checks).to.be.an("array");
  });

  it("documents external AV DeviceResponse certificate-chain parsing failure", async () => {
    const deviceResponse = parseDeviceResponse(
      Buffer.from(EXTERNAL_AV_DEVICE_RESPONSE, "base64url"),
    );
    const rawDeviceResponse = decode(Buffer.from(EXTERNAL_AV_DEVICE_RESPONSE, "base64url"));
    const issuerAuthUnprotected =
      rawDeviceResponse.documents[0].issuerSigned.issuerAuth[1];
    const x5chain = issuerAuthUnprotected[33] ?? issuerAuthUnprotected["33"];

    expect(deviceResponse.version).to.equal("1.0");
    expect(deviceResponse.status).to.equal(0);
    expect(deviceResponse.documents).to.have.length(1);
    expect(deviceResponse.documents[0].docType).to.equal("eu.europa.ec.av.1");
    expect(x5chain).to.be.instanceOf(Uint8Array);

    const { checks, error } = await runAnimoDiagnostic(EXTERNAL_AV_DEVICE_RESPONSE);

    expect(checks.some((check) => check.category === "DOCUMENT_FORMAT")).to.equal(true);
    expect(error?.message).to.equal("No certificate found");
  });

  it("verifies external AV DeviceResponse when x5chain is encoded as an array", async () => {
    const deviceResponse = parseDeviceResponse(
      Buffer.from(EXTERNAL_AV_DEVICE_RESPONSE_WITH_X5CHAIN_ARRAY, "base64url"),
    );
    const rawDeviceResponse = decode(
      Buffer.from(EXTERNAL_AV_DEVICE_RESPONSE_WITH_X5CHAIN_ARRAY, "base64url"),
    );
    const issuerAuthUnprotected =
      rawDeviceResponse.documents[0].issuerSigned.issuerAuth[1];
    const x5chain = issuerAuthUnprotected[33] ?? issuerAuthUnprotected["33"];

    expect(deviceResponse.version).to.equal("1.0");
    expect(deviceResponse.status).to.equal(0);
    expect(deviceResponse.documents).to.have.length(1);
    expect(deviceResponse.documents[0].docType).to.equal("eu.europa.ec.av.1");
    expect(x5chain).to.be.an("array").with.length(1);
    expect(x5chain[0]).to.be.instanceOf(Uint8Array);

    const { checks, error } = await runAnimoDiagnostic(
      EXTERNAL_AV_DEVICE_RESPONSE_WITH_X5CHAIN_ARRAY,
    );
    const issuerSignatureCheck = checks.find(
      (check) => check.check === "Issuer signature must be valid",
    );
    const dataIntegrityCheck = checks.find(
      (check) =>
        check.check ===
        "The calculated digest for eu.europa.ec.av.1/age_over_18 attribute must match the digest in the issuerAuth element",
    );

    expect(error).to.equal(null);
    expect(issuerSignatureCheck?.status).to.equal("PASSED");
    expect(dataIntegrityCheck?.status).to.equal("PASSED");
  });

  it("verifies issuer signature for an issuer-signed mDL credential", async () => {
    const mdlToken = await buildTestIssuerSignedMdl();
    const document = parseIssuerSigned(Buffer.from(mdlToken, "base64url"));

    expect(document.docType).to.equal("urn:eu.europa.ec.eudi:pid:1");
    expect(document.issuerSigned.issuerAuth.certificate).to.be.instanceOf(Uint8Array);

    const { checks, error } = await runIssuerSignedDiagnostic(
      mdlToken,
      new Date("2026-05-01T00:00:00Z"),
    );
    const issuerSignatureCheck = checks.find(
      (check) => check.check === "Issuer signature must be valid",
    );

    expect(error).to.equal(null);
    expect(issuerSignatureCheck?.status).to.equal("PASSED");
  });

  it("diagnoses MDOC_ISSUER_SIGNED_TOKEN when provided", async function () {
    const token = process.env.MDOC_ISSUER_SIGNED_TOKEN;
    if (!token) this.skip();

    const { checks, error } = await runIssuerSignedDiagnostic(
      token,
      new Date("2025-03-25T00:00:00Z"),
    );
    console.log("MDOC_ISSUER_SIGNED_TOKEN error:", error?.message || null);
    console.log("MDOC_ISSUER_SIGNED_TOKEN checks:", JSON.stringify(checks, null, 2));

    expect(error).to.equal(null);
    expect(
      checks.find((check) => check.check === "Issuer signature must be valid")?.status,
    ).to.equal("PASSED");
  });
});
