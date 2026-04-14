import { strict as assert } from "assert";
import {
  CS03_SIGNING_CREDENTIAL_ID,
  buildCs03QesRequestPayload,
  processCs03PresentationResponse,
  validateCs03ResponseUriAlignment,
  validateCs03QesResponse,
} from "../utils/routeUtils.js";

describe("CS-03 remote signing helpers", () => {
  it("places responseURI inside signatureRequests for OOB mode", () => {
    const qesRequest = buildCs03QesRequestPayload(
      "https://verifier.example",
      "session-123",
      { oob: true, callbackToken: "cb-token-1" }
    );

    assert.equal(qesRequest.type, "https://cloudsignatureconsortium.org/2025/qes");
    assert.deepEqual(qesRequest.credential_ids, [CS03_SIGNING_CREDENTIAL_ID]);
    assert.ok(Array.isArray(qesRequest.signatureRequests));
    assert.equal(qesRequest.signatureRequests.length, 1);
    assert.equal(
      qesRequest.signatureRequests[0].responseURI,
      "https://verifier.example/x509/qes-callback/session-123?callback_token=cb-token-1"
    );
    assert.equal(qesRequest.responseURI, undefined);
  });

  it("does not include responseURI when OOB mode is disabled", () => {
    const qesRequest = buildCs03QesRequestPayload("https://verifier.example", "session-123");
    assert.equal(qesRequest.signatureRequests[0].responseURI, undefined);
  });

  it("accepts a valid inline qes response", () => {
    const result = processCs03PresentationResponse({
      [CS03_SIGNING_CREDENTIAL_ID]: {
        qes: {
          documentWithSignature: ["JVBERi0xLjQKJ..."],
        },
      },
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.claims.credentialIds, [CS03_SIGNING_CREDENTIAL_ID]);
    assert.deepEqual(result.qes[CS03_SIGNING_CREDENTIAL_ID], {
      documentWithSignature: ["JVBERi0xLjQKJ..."],
    });
  });

  it("rejects unexpected credential ids", () => {
    const result = processCs03PresentationResponse({
      wrong: {
        qes: {
          documentWithSignature: ["JVBERi0xLjQKJ..."],
        },
      },
    });

    assert.equal(result.ok, false);
    assert.match(result.error_description, /unexpected credential ids/i);
  });

  it("rejects missing qes in inline mode", () => {
    const result = processCs03PresentationResponse({
      [CS03_SIGNING_CREDENTIAL_ID]: {},
    });

    assert.equal(result.ok, false);
    assert.match(result.error_description, /must include qes/i);
  });

  it("accepts an empty credential response only in OOB mode", () => {
    const result = processCs03PresentationResponse(
      {
        [CS03_SIGNING_CREDENTIAL_ID]: {},
      },
      {
        oobRequested: true,
        oobResponse: {
          [CS03_SIGNING_CREDENTIAL_ID]: {
            documentWithSignature: ["JVBERi0xLjQKJ..."],
          },
        },
      }
    );

    assert.equal(result.ok, true);
    assert.equal(
      result.qes[CS03_SIGNING_CREDENTIAL_ID].empty_credential_response,
      true
    );
    assert.deepEqual(result.qes_combined.oob, {
      [CS03_SIGNING_CREDENTIAL_ID]: {
        documentWithSignature: ["JVBERi0xLjQKJ..."],
      },
    });
  });

  it("rejects inline qes when responseURI mode is enabled", () => {
    const result = processCs03PresentationResponse(
      {
        [CS03_SIGNING_CREDENTIAL_ID]: {
          qes: {
            documentWithSignature: ["JVBERi0xLjQKJ..."],
          },
        },
      },
      { oobRequested: true }
    );

    assert.equal(result.ok, false);
    assert.match(result.error_description, /must be empty when responseURI is used/i);
  });

  it("validates qes callback payload shape", () => {
    assert.equal(
      validateCs03QesResponse({ documentWithSignature: ["JVBERi0xLjQKJ..."] }).ok,
      true
    );
    assert.equal(
      validateCs03QesResponse({ signatureObject: ["MEUCIQ..."] }).ok,
      true
    );
    assert.equal(
      validateCs03QesResponse({
        documentWithSignature: ["JVBERi0xLjQKJ..."],
        signatureObject: ["MEUCIQ..."],
      }).ok,
      false
    );
    assert.equal(validateCs03QesResponse({}).ok, false);
  });

  it("accepts responseURI host aligned with SERVER_URL and x509 client_id", () => {
    const result = validateCs03ResponseUriAlignment({
      serverURL: "https://verifier.example",
      clientId: "x509_san_dns:verifier.example",
      responseURI: "https://verifier.example/x509/qes-callback/session-123?callback_token=cb-token-1",
    });

    assert.equal(result.ok, true);
  });

  it("rejects responseURI host mismatch against SERVER_URL", () => {
    const result = validateCs03ResponseUriAlignment({
      serverURL: "https://verifier.example",
      clientId: "x509_san_dns:verifier.example",
      responseURI: "https://attacker.example/x509/qes-callback/session-123?callback_token=cb-token-1",
    });

    assert.equal(result.ok, false);
    assert.match(result.error, /must match verifier SERVER_URL host/i);
  });

  it("rejects responseURI host mismatch against x509 client_id", () => {
    const result = validateCs03ResponseUriAlignment({
      serverURL: "https://verifier.example",
      clientId: "x509_san_dns:rp.example",
      responseURI: "https://verifier.example/x509/qes-callback/session-123?callback_token=cb-token-1",
    });

    assert.equal(result.ok, false);
    assert.match(result.error, /must match x509_san_dns client_id host/i);
  });

  it("rejects non-x509 client_id for CS-03 responseURI checks", () => {
    const result = validateCs03ResponseUriAlignment({
      serverURL: "https://verifier.example",
      clientId: "did:web:verifier.example",
      responseURI: "https://verifier.example/x509/qes-callback/session-123?callback_token=cb-token-1",
    });

    assert.equal(result.ok, false);
    assert.match(result.error, /requires an x509_san_dns client_id/i);
  });
});
