import { expect } from "chai";
import { buildCs02PresentationAcknowledgement } from "../utils/cs02VerifierResponse.js";

describe("CS-02 presentation acknowledgement (§6.1.7)", () => {
  it("returns redirect_uri in strict mode instead of status ok", () => {
    const body = buildCs02PresentationAcknowledgement("session-1", {
      serverURL: "https://verifier.example",
      strict: true,
    });
    expect(body.status).to.equal(undefined);
    expect(body.redirect_uri).to.equal(
      "https://verifier.example/verificationStatus?sessionId=session-1",
    );
  });

  it("keeps compatibility status ok when strict mode is off", () => {
    expect(
      buildCs02PresentationAcknowledgement("session-1", {
        serverURL: "https://verifier.example",
        strict: false,
      }),
    ).to.deep.equal({ status: "ok" });
  });

  for (const serverURL of [
    "https://verifier.example/rfc-issuer",
    "https://verifier.example/rfc-issuer/",
  ]) {
    it(`preserves the public mount prefix in redirects for ${serverURL}`, () => {
      const body = buildCs02PresentationAcknowledgement("session-1", { serverURL });
      expect(body.redirect_uri).to.equal(
        "https://verifier.example/rfc-issuer/verificationStatus?sessionId=session-1",
      );
      expect(body).to.not.have.property("status");
    });
  }
});
