import { expect } from "chai";
import express from "express";
import request from "supertest";
import { decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { assertX509HashLeafMatchesClientId } from "../utils/cs02ClientIdBinding.js";
import ts12PaymentRouter from "../routes/verify/ts12PaymentRoutes.js";
import vpStandardRouter from "../routes/verify/vpStandardRoutes.js";
import x509Router from "../routes/verify/x509Routes.js";
import { CONFIG } from "../utils/routeUtils.js";
import { getVPSession } from "../services/cacheServiceRedis.js";

describe("CS-02 / CS-03 presentation route regressions", () => {
  let previous;
  let previousServerURL;
  beforeEach(() => {
    previous = { ...process.env };
    previousServerURL = CONFIG.SERVER_URL;
    CONFIG.SERVER_URL = "https://dev-i4mlab.aegean.gr";
    Object.assign(process.env, {
      NODE_ENV: "test", VERIFIER_CS02_COMPATIBILITY: "false",
      VERIFIER_CS03_COMPATIBILITY: "true",
    });
  });
  afterEach(() => {
    CONFIG.SERVER_URL = previousServerURL;
    for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
    Object.assign(process.env, previous);
  });
  const app = express();
  app.use(express.json());
  app.use(x509Router);
  app.use(vpStandardRouter);
  app.use(ts12PaymentRouter);

  for (const endpoint of ["generateVPRequestDCQL", "generateVPRequestDCQLGET", "generateVPRequestTransaction"]) {
    it(`${endpoint} keeps default CS-03 signing on plaintext direct_post`, async () => {
      const sessionId = `cs03-default-${endpoint}`;
      const res = await request(app).get(`/${endpoint}`).query({ cs03: "1", sessionId });
      expect(res.status, JSON.stringify(res.body)).to.equal(200);
      const session = await getVPSession(sessionId);
      expect(session.response_mode).to.equal("direct_post");
      expect(session.client_id).to.equal(CONFIG.CLIENT_ID);
      const fetched = await request(app).get(`/x509VPrequest/${sessionId}`).expect(200);
      const header = decodeProtectedHeader(fetched.text);
      const { payload } = await jwtVerify(fetched.text, await importX509(
        `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`, "ES256"));
      expect(payload.client_id).to.equal(CONFIG.CLIENT_ID);
      expect(payload.response_mode).to.equal("direct_post");
    });
  }

  for (const method of ["get", "post"]) {
    it(`retrieves the signed hash JAR over ${method.toUpperCase()} using the generated session identity`, async () => {
      const sessionId = `hash-retrieval-${method}`;
      const created = await request(app).get("/generateVPRequestDCQLGET").query({ sessionId }).expect(200);
      let retrieval = request(app)[method](`/x509VPrequest/${sessionId}`);
      if (method === "post") retrieval = retrieval.type("form").send({ wallet_nonce: "wallet-nonce" });
      const fetched = await retrieval.expect(200);
      const header = decodeProtectedHeader(fetched.text);
      const pem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
      const { payload } = await jwtVerify(fetched.text, await importX509(pem, "ES256"));
      const publishedId = new URL(created.body.deepLink).searchParams.get("client_id");
      expect(payload.client_id).to.equal(publishedId);
      assertX509HashLeafMatchesClientId(payload.client_id, header.x5c[0]);
      expect(payload.state).to.equal((await getVPSession(sessionId)).state);
      if (method === "post") expect(payload.wallet_nonce).to.equal("wallet-nonce");
    });
  }

  for (const mode of [undefined, "direct_post"]) {
    it(`standard requests use ${mode || "direct_post.jwt by default"} and retain hash identity on retrieval`, async () => {
      const sessionId = `standard-mode-${mode || "default"}`;
      const query = { session_id: sessionId, request_uri_method: "get" };
      if (mode) query.response_mode = mode;
      const created = await request(app).get("/vp/request").query(query).expect(200);
      expect((await getVPSession(sessionId)).response_mode).to.equal(mode || "direct_post.jwt");
      const fetched = await request(app).get(`/vp/x509VPrequest/${sessionId}`).expect(200);
      const header = decodeProtectedHeader(fetched.text);
      const { payload } = await jwtVerify(fetched.text, await importX509(
        `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`, "ES256"));
      expect(payload.response_mode).to.equal(mode || "direct_post.jwt");
      expect(payload.client_id).to.equal(new URL(created.body.deepLink).searchParams.get("client_id"));
    });
  }


  for (const compatibility of [false, true]) {
    it(`payment routes preserve plaintext ${compatibility ? "compatibility defaults" : "explicit overrides"}`, async () => {
      process.env.VERIFIER_CS02_COMPATIBILITY = String(compatibility);
      const sessionId = `payment-plaintext-${compatibility}`;
      const body = {
        session_id: sessionId, transaction_id: "tx-regression", merchant: "Test Shop",
        payee_id: "shop-1", currency: "EUR", amount: "12.34",
      };
      if (!compatibility) body.response_mode = "direct_post";
      await request(app).post("/ts12/payment/request").send(body).expect(200);
      expect((await getVPSession(sessionId)).response_mode).to.equal("direct_post");
    });
  }

  it("standard requests retain plaintext defaults in compatibility mode", async () => {
    process.env.VERIFIER_CS02_COMPATIBILITY = "true";
    const sessionId = "standard-compatibility-mode";
    await request(app).get("/vp/request").query({ session_id: sessionId }).expect(200);
    expect((await getVPSession(sessionId)).response_mode).to.equal("direct_post");
  });

  it("exposes all invocation schemes for the same strict CS-02 session", async () => {
    const res = await request(app).get("/generateVPRequestDCQLGET").query({ sessionId: "three-invocations" });
    expect(res.status, JSON.stringify(res.body)).to.equal(200);
    expect(res.body.qr).to.be.a("string");
    const original = new URL(res.body.deepLink);
    expect(original.protocol).to.equal("openid4vp:");
    for (const scheme of ["openid4vp", "eu-eaap", "haip-vp"]) {
      const invocation = new URL(res.body.deepLinks[scheme]);
      expect(invocation.protocol).to.equal(`${scheme}:`);
      expect(invocation.hostname).to.equal("");
      expect(invocation.search).to.equal(original.search);
    }
    expect((await getVPSession("three-invocations")).response_mode).to.equal("direct_post.jwt");
  });
});
