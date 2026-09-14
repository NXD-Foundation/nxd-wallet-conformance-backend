import express from "express";
import request from "supertest";
import { expect } from "chai";
import dcApiRouter from "../routes/verify/dcApiRoutes.js";
import dcApiDemoRouter from "../routes/verify/dcApiDemoRoutes.js";

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(dcApiRouter);

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
});

describe("CS-07 local RP demo pages", () => {
  it("serves the TS12 payment demo and rp-client module", async () => {
    const page = await request(demoApp).get("/payment");
    expect(page.status).to.equal(200);
    expect(page.type).to.match(/html/);
    expect(page.text).to.include("ts12-dpc");
    const script = await request(demoApp).get("/rp-client.js");
    expect(script.status).to.equal(200);
    expect(script.text).to.include("createDcApiVerifierClient");
  });
});
