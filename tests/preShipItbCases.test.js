import { expect } from "chai";
import {
  CASES,
  MDOC,
  PID,
  caseRequest,
  checkInvocationLink,
  classifyWalletFailure,
  judgeIssueStatus,
  judgeVerificationStatus,
  walletSessionBody,
} from "../scripts/preShipItbCases.js";

const HASH = "a".repeat(43);

describe("pre-ship ITB cases", () => {
  it("runs the twelve CTS v1.1 trust-framework cases in pre-ship order", () => {
    expect(CASES.map((entry) => entry.id)).to.deep.equal([
      "VCI-001",
      "VP-001",
      "VP-002",
      "VP-003",
      "VP-011",
      "VP-012",
      "VP-013",
      "VCI-005",
      "VP-007",
      "VCI-006",
      "VCI-007",
      "VCI-008",
    ]);
  });

  it("sends signatureType x509 for VCI-005 mdoc issuance", () => {
    const vci005 = CASES.find((entry) => entry.id === "VCI-005");
    const query = caseRequest(vci005, "session-1");
    expect(vci005.credentialType).to.equal(MDOC);
    expect(query.get("signatureType")).to.equal("x509");
    expect(query.get("credentialType")).to.equal(MDOC);
    expect(query.get("trustFramework")).to.equal("true");
    expect(JSON.stringify(CASES)).to.not.include("did:web");
  });

  it("omits response_mode on VP-001 and sends the invocation scheme on VP-011", () => {
    const vp001 = caseRequest(CASES.find((entry) => entry.id === "VP-001"), "session-1");
    const vp011 = caseRequest(CASES.find((entry) => entry.id === "VP-011"), "session-1");
    expect(vp001.get("response_mode")).to.equal(null);
    expect(vp001.get("invocation_scheme")).to.equal(null);
    expect(vp001.get("credentialType")).to.equal(PID);
    expect(vp011.get("response_mode")).to.equal("direct_post.jwt");
    expect(vp011.get("invocation_scheme")).to.equal("openid4vp");
  });

  it("accepts an empty-authority POST invocation link", () => {
    const link = `openid4vp://?request_uri=${encodeURIComponent("https://issuer.example/x509/x509VPrequest/session-1")}&client_id=${encodeURIComponent(`x509_hash:${HASH}`)}&request_uri_method=post`;
    expect(checkInvocationLink({
      deepLink: link,
      sessionId: "session-1",
      issuer: "https://issuer.example",
      scheme: "openid4vp",
      method: "post",
      requestPath: "/x509/x509VPrequest",
    })).to.deep.equal({ ok: true });
  });

  it("rejects a hashed client id with the wrong length", () => {
    const link = `openid4vp://?request_uri=${encodeURIComponent("https://issuer.example/x509/x509VPrequest/session-1")}&client_id=x509_hash:short`;
    const result = checkInvocationLink({
      deepLink: link,
      sessionId: "session-1",
      issuer: "https://issuer.example",
      scheme: "openid4vp",
      method: "get",
      requestPath: "/x509/x509VPrequest",
    });
    expect(result.ok).to.equal(false);
  });

  it("puts the transaction code on the wallet session only when VCI-007 returns one", () => {
    expect(walletSessionBody({
      deepLink: "openid-credential-offer://example",
      sessionId: "session-1",
      issuer: "https://issuer.example",
    })).to.not.have.property("pin");
    expect(walletSessionBody({
      deepLink: "openid-credential-offer://example",
      sessionId: "session-1",
      issuer: "https://issuer.example",
      pin: "1234",
    }).pin).to.equal("1234");
  });

  it("passes issuer success and presentation success only when claims are present", () => {
    expect(judgeIssueStatus({ status: "success" }).result).to.equal("pass");
    expect(judgeIssueStatus({ status: "failed", reason: "not found" }).result).to.equal("fail");
    expect(judgeVerificationStatus({ status: "success", claims: { family_name: "Doe" } }).result).to.equal("pass");
    expect(judgeVerificationStatus({ status: "success", claims: null }).result).to.equal("fail");
  });

  it("omits trustFramework for the non-trust run of the same cases", () => {
    const query = caseRequest(CASES.find((entry) => entry.id === "VCI-001"), "session-1", { trustFramework: false });
    expect(query.get("trustFramework")).to.equal(null);
    expect(query.get("signatureType")).to.equal("x509");
    expect(walletSessionBody({
      deepLink: "openid-credential-offer://example",
      sessionId: "session-1",
      issuer: "https://issuer.example",
      trustFramework: false,
    }).trustFramework).to.equal(false);
    expect(classifyWalletFailure(
      { id: "VP-001", optional: false },
      "verifier_info is missing registrar_dataset",
      { trustFramework: false },
    ).result).to.equal("fail");
  });

  it("classifies a missing registrar dataset as a counterpart stop", () => {
    expect(classifyWalletFailure(
      { id: "VP-001", optional: false },
      "verifier_info is missing registrar_dataset",
    ).result).to.equal("counterpart-stop");
    expect(classifyWalletFailure(
      { id: "VP-013", optional: true },
      "Unsupported request scheme",
    ).result).to.equal("skipped");
  });
});
