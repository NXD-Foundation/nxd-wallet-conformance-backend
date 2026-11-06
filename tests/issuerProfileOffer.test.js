import { expect } from "chai";
import express from "express";
import request from "supertest";
import vciRouter from "../routes/issue/vciStandardRoutes.js";
import { client, getPreAuthSession } from "../services/cacheServiceRedis.js";

describe("profile-bound credential offers", function () {
  this.timeout(5000);
  let app;
  before(async () => {
    if (!client.isReady) await new Promise((resolve, reject) => { client.once("ready", resolve); setTimeout(() => reject(new Error("Redis is required for profile offer tests")), 3000).unref(); });
    process.env.ISSUER_PROFILES_ENABLED = "true";
    app = express(); app.use(vciRouter);
  });
  after(() => { delete process.env.ISSUER_PROFILES_ENABLED; });
  it("binds the offer and stored session to PID and rejects a cross-profile request", async () => {
    const response = await request(app).get("/vci/offer").query({ flow: "pre_authorized_code", credential_type: "urn:eu.europa.ec.eudi:pid:1", issuer_profile: "pid", signature_type: "x509" }).expect(200);
    const offerUri = new URL(response.body.deepLink).searchParams.get("credential_offer_uri");
    const path = new URL(offerUri);
    const offer = await request(app).get(path.pathname + path.search).expect(200);
    expect(offer.body.credential_issuer).to.match(/\/issuer\/pid$/);
    expect(offer.body.credential_configuration_ids).to.deep.equal(["urn:eu.europa.ec.eudi:pid:1"]);
    const session = await getPreAuthSession(response.body.sessionId);
    expect(session.issuerProfile).to.equal("pid");
    await request(app).get("/vci/offer").query({ flow: "pre_authorized_code", credential_type: "PhotoID", issuer_profile: "pid" }).expect(400);
  });
});
