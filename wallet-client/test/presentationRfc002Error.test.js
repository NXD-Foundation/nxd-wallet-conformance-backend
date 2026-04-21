import assert from "assert";
import {
  mapWalletPresentationErrorToRfc002,
  WalletRfc002PresentationErrors,
} from "../src/lib/presentation.js";

describe("RFC002 §8.3.4 presentation error mapping (P1-W-10)", () => {
  it("maps invalid_request prefix to malformed_response", () => {
    const { code, description } = mapWalletPresentationErrorToRfc002(
      new Error("invalid_request: bad JAR"),
    );
    assert.strictEqual(code, WalletRfc002PresentationErrors.MALFORMED_RESPONSE);
    assert.strictEqual(description, "bad JAR");
  });

  it("maps JWS verification failure to malformed_response", () => {
    const { code } = mapWalletPresentationErrorToRfc002(
      new Error("Authorization request JWT verification failed"),
    );
    assert.strictEqual(code, WalletRfc002PresentationErrors.MALFORMED_RESPONSE);
  });

  it("maps missing credential to invalid_presentation", () => {
    const { code } = mapWalletPresentationErrorToRfc002(
      new Error("Credential not found in wallet cache"),
    );
    assert.strictEqual(code, WalletRfc002PresentationErrors.INVALID_PRESENTATION);
  });

  it("maps DCQL disclosure mismatch to failed_validation", () => {
    const { code } = mapWalletPresentationErrorToRfc002(
      new Error('DCQL claims ["x"] matched no disclosures in the SD-JWT'),
    );
    assert.strictEqual(code, WalletRfc002PresentationErrors.FAILED_VALIDATION);
  });

  it("maps ERR_JWT_EXPIRED to expired_request", () => {
    const err = new Error("timestamp check failed");
    err.code = "ERR_JWT_EXPIRED";
    const { code } = mapWalletPresentationErrorToRfc002(err);
    assert.strictEqual(code, WalletRfc002PresentationErrors.EXPIRED_REQUEST);
  });

  it("maps client_id mismatch to failed_correlation", () => {
    const { code } = mapWalletPresentationErrorToRfc002(
      new Error("Authorization request client_id does not match deep link client_id"),
    );
    assert.strictEqual(code, WalletRfc002PresentationErrors.FAILED_CORRELATION);
  });
});
