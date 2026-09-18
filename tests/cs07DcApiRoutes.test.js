import express from "express";
import request from "supertest";
import { expect } from "chai";
import dcApiIssuanceRouter from "../routes/issue/dcApiIssuanceRoutes.js";
import dcApiRouter from "../routes/verify/dcApiRoutes.js";
import dcApiDemoRouter from "../routes/verify/dcApiDemoRoutes.js";

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(dcApiRouter);

const issuanceApp = express();
issuanceApp.use(express.json({ limit: "10mb" }));
issuanceApp.use(dcApiIssuanceRouter);

const demoApp = express();
demoApp.use(dcApiDemoRouter);

describe("CS-07 verifier API route boundary", () => {
  it("requires an Origin header for request creation", async () => {
    const response = await request(app)
      .post("/vp/dc-api/request")
      .send({ profile: "pid-basic" });
    expect(response.status).to.equal(403);
    expect(response.body.error).to.equal("origin_not_allowed");
  });

  it("rejects origins that are not configured relying parties", async () => {
    const response = await request(app)
      .post("/vp/dc-api/request")
      .set("Origin", "https://unconfigured-rp.example")
      .send({ profile: "pid-basic" });
    expect(response.status).to.be.oneOf([400, 403]);
  });

  it("rejects oversized request bodies at the DC API route boundary", async () => {
    const response = await request(app)
      .post("/vp/dc-api/request")
      .set("Origin", "https://unconfigured-rp.example")
      .send({ profile: "x".repeat(20_000) });
    expect(response.status).to.equal(413);
    expect(response.body.error).to.equal("request_too_large");
  });

  it("does not expose a CS-07 API-hosted RP page or browser script", async () => {
    expect((await request(app).get("/vp/dc-api")).status).to.equal(404);
    expect((await request(app).get("/vp/dc-api/browser.js")).status).to.equal(404);
  });

  it("returns the decoded VP response when polling a successful CS-07 session", async function () {
    if (!process.env.ALLOW_NO_REDIS) process.env.ALLOW_NO_REDIS = "true";
    const { storeVPSession, getVPSession } = await import("../services/cacheServiceRedis.js");
    const sessionId = `cs07-poll-${Date.now()}`;
    await storeVPSession(sessionId, {
      transport_profile: "cs07-dc-api",
      verifier_origin: "https://rp.example",
      status: "success",
      profile_id: "ts12-dpc-pid",
      verified_credential_ids: ["sca_card_dpc", "cmwallet"],
      verification: "dcql_and_credential_binding_validated",
      dc_api_response: {
        vp_token: {
          sca_card_dpc: { claims: { vct: "https://webuildconsortium.eu/sca/sca-card-dpc/1.0", card_id: "****" } },
          cmwallet: { claims: { vct: "urn:eu.europa.ec.eudi:pid:1", family_name: "Neslo" } },
        },
      },
    });
    if (!await getVPSession(sessionId)) this.skip();
    const response = await request(app)
      .get(`/vp/dc-api/session/${sessionId}`)
      .set("Origin", "https://rp.example");
    expect(response.status).to.equal(200);
    expect(response.body.status).to.equal("success");
    expect(response.body.vp_response.vp_token.cmwallet.claims.family_name).to.equal("Neslo");
    expect(response.body.vp_response.vp_token.sca_card_dpc.claims.card_id).to.equal("****");
  });

  it("does not block VP preflight in the issuance CORS middleware", async () => {
    const response = await request(issuanceApp)
      .options("/vp/dc-api/request")
      .set("Origin", "https://rp.example")
      .set("Access-Control-Request-Method", "POST");
    expect(response.status).to.equal(404);
  });
});

describe("CS-07 local RP demo pages", () => {
  it("serves the TS12 payment demo and rp-client module", async () => {
    const page = await request(demoApp).get("/payment");
    expect(page.status).to.equal(200);
    expect(page.type).to.match(/html/);
    expect(page.text).to.include("ts12-dpc");
    expect(page.text).to.include("ts12-iban");
    expect(page.text).to.include("ts12-user");
    const script = await request(demoApp).get("/rp-client.js");
    expect(script.status).to.equal(200);
    expect(script.text).to.include("createDcApiVerifierClient");
  });
});
