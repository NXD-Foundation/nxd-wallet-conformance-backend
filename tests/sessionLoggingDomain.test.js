import { expect } from "chai";
import { EventEmitter } from "node:events";
import { bindSessionLoggingContext } from "../utils/routeUtils.js";
import { getSessionLogContext, runWithSessionLogContext } from "../utils/sessionLogContext.js";

function responseStub() {
  const response = new EventEmitter();
  response.locals = {};
  return response;
}

describe("session logging domain correlation", () => {
  it("preserves the issuance domain for issuer route bindings", () => {
    const response = responseStub();
    bindSessionLoggingContext({ sessionLoggingDomain: "issuance" }, response, "issue-1");
    expect(getSessionLogContext()).to.include({ sessionId: "issue-1", domain: "issuance" });
    response.emit("finish");
  });

  it("defaults unclassified bindings to verification", () => {
    const response = responseStub();
    bindSessionLoggingContext({}, response, "verify-1");
    expect(getSessionLogContext()).to.include({ sessionId: "verify-1", domain: "verification" });
    response.emit("finish");
  });

  it("supports explicit domains for shared issuance flow helpers", async () => {
    await runWithSessionLogContext({ sessionId: "shared-issue-1", domain: "issuance" }, async () => {
      expect(getSessionLogContext()).to.include({ sessionId: "shared-issue-1", domain: "issuance" });
    });
    expect(getSessionLogContext()).to.equal(null);
  });
});
