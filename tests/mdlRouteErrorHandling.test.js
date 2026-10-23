import { expect } from "chai";
import sinon from "sinon";
import mdlRouter from "../routes/verify/mdlRoutes.js";

// Invoke the real async route handler directly so a rejected error handler fails
// the test immediately rather than becoming an unhandled rejection in Express 4.
function handler(path, method) {
  const route = mdlRouter.stack.find((layer) => layer.route?.path === path).route;
  return route.stack.filter((layer) => layer.method === method).at(-1).handle;
}

describe("mDL route error handling retains the session ID", () => {
  let previous;
  beforeEach(() => {
    previous = { ...process.env };
    process.env.NODE_ENV = "test";
    process.env.VERIFIER_CS02_COMPATIBILITY = "false";
    process.env.TRUST_WRPAC_CERT_PATH = "/missing/vp007-wrpac.pem";
  });
  afterEach(() => {
    for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
    Object.assign(process.env, previous);
  });

  for (const suppliedId of ["59a3e8a5-a033-4083-9f81-2f2dfeb0eab5", undefined]) {
    it(`returns the original trust-generation error without ReferenceError with ${suppliedId ? "a supplied" : "a generated"} session ID`, async () => {
      const res = { status: sinon.stub().returnsThis(), json: sinon.stub().returnsThis() };
      await handler("/generateVPRequest", "get")({ query: {
        ...(suppliedId ? { sessionId: suppliedId } : {}),
        credentialType: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
        trustFramework: "true", response_mode: "direct_post.jwt",
      } }, res);
      expect(res.status.calledOnceWith(500)).to.equal(true);
      expect(res.json.firstCall.args[0].body.error).to.include("/missing/vp007-wrpac.pem");
    });
  }

  it("returns a POST processing error instead of throwing a second sessionId ReferenceError", async () => {
    const res = { status: sinon.stub().returnsThis(), json: sinon.stub().returnsThis() };
    await handler("/VPrequest/:id?", "post")({ params: { id: "mdoc-post-error" }, body: undefined }, res);
    expect(res.status.calledOnceWith(500)).to.equal(true);
    expect(res.json.firstCall.args[0].body.error).to.include("wallet_nonce");
  });
});
