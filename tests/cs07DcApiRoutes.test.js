import { createHash, randomUUID, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import * as jose from "jose";
import { loadVerifierEncryptionKey } from "../utils/verifierEncryptionKeys.js";
import {
  installStatusListTestHooks,
  resetStatusListTestHooks,
  signStatusListToken,
  stubStatusListFetch,
} from "./helpers/wuaStatusListFixtures.js";
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

  it("rejects an invalid status-list signature by default and skips status only for the authorized session", async () => {
    const origin = "https://rp.example";
    const serviceKey = "test-checkout-service-key-".repeat(2);
    const settings = {
      ALLOW_NO_REDIS: "true",
      DC_API_RP_ORIGINS: origin,
      DC_API_RP_PROFILES: "pid-basic",
      DC_API_CHECKOUT_SERVICE_KEY: serviceKey,
      VERIFIER_CS02_COMPATIBILITY: "false",
    };
    const previous = Object.fromEntries(Object.keys(settings).map(key => [key, process.env[key]]));
    Object.assign(process.env, settings);
    try {
      const { default: router } = await import("../routes/verify/dcApiRoutes.js?checkout-status");
      const checkoutApp = express();
      checkoutApp.use(express.json(), router);
      const createSession = (body = {}, key) => {
        const call = request(checkoutApp).post("/vp/dc-api/request").set("Origin", origin);
        if (key) call.set("Authorization", `Bearer ${key}`);
        return call.send({ profile: "pid-basic", ...body });
      };
      const submit = (session, response) => request(checkoutApp)
        .post(`/vp/dc-api/response/${session.sessionId}`)
        .set("Origin", origin)
        .send({ protocol: session.protocol, data: { response } });

      const uri = `https://issuer.example/status/${randomUUID()}`;
      const issuerKey = await jose.importPKCS8(readFileSync("./x509EC/ec_private_pkcs8.key", "utf8"), "ES256");
      const issuerCert = new X509Certificate(readFileSync("./x509EC/client_certificate.crt"));
      const holder = await jose.generateKeyPair("ES256", { extractable: true });
      const now = Math.floor(Date.now() / 1000);
      const digest = value => createHash("sha256").update(value, "ascii").digest("base64url");
      const disclosure = Buffer.from(JSON.stringify(["salt", "family_name", "Neslo"])).toString("base64url");
      const issuerClaims = {
        iss: "https://issuer.example",
        iat: now,
        exp: now + 300,
        vct: "urn:eu.europa.ec.eudi:pid:1",
        cnf: { jwk: await jose.exportJWK(holder.publicKey) },
        _sd_alg: "sha-256",
        _sd: [digest(disclosure)],
        status: { status_list: { idx: 0, uri } },
      };
      const makeCredential = async header => {
        const issuerJwt = await new jose.SignJWT(issuerClaims)
          .setProtectedHeader({ alg: "ES256", typ: "dc+sd-jwt", ...header })
          .sign(issuerKey);
        return `${issuerJwt}~${disclosure}~`;
      };
      const credential = await makeCredential({ x5c: [issuerCert.raw.toString("base64")] });
      const statusToken = await signStatusListToken({ uri, privateKey: holder.privateKey });
      const fetchStatusList = stubStatusListFetch(statusToken);
      let statusFetches = 0;
      installStatusListTestHooks({
        fetchImpl: (...args) => {
          statusFetches++;
          return fetchStatusList(...args);
        },
      });

      const encryptionKey = await jose.importJWK(loadVerifierEncryptionKey().publicJwk, "ECDH-ES");
      const present = async (session, presentedCredential = credential) => {
        const binding = await new jose.SignJWT({
          nonce: jose.decodeJwt(session.request.data.request).nonce,
          aud: `origin:${origin}`,
          iat: now,
          sd_hash: digest(presentedCredential),
        }).setProtectedHeader({ alg: "ES256", typ: "kb+jwt" }).sign(holder.privateKey);
        return new jose.EncryptJWT({ vp_token: { cmwallet: [presentedCredential + binding] } })
          .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
          .encrypt(encryptionKey);
      };

      const standard = await createSession();
      expect(standard.status, JSON.stringify(standard.body)).to.equal(200);
      const rejected = await submit(standard.body, await present(standard.body));
      expect(rejected.status).to.equal(400);
      expect(rejected.body.error_description).to.match(/status.*signature verification failed/i);

      const skip = { credentialStatusCheck: "skip" };
      expect((await createSession(skip)).status).to.equal(403);
      expect((await createSession(skip, "wrong-key")).status).to.equal(403);
      expect((await createSession({ credentialStatusCheck: true }, serviceKey)).status).to.equal(400);
      delete process.env.DC_API_CHECKOUT_SERVICE_KEY;
      expect((await createSession(skip, serviceKey)).status).to.equal(403);
      process.env.DC_API_CHECKOUT_SERVICE_KEY = serviceKey;

      const demo = await createSession(skip, serviceKey);
      expect(demo.status, JSON.stringify(demo.body)).to.equal(200);
      expect(jose.decodeJwt(demo.body.request.data.request)).not.to.have.property("credentialStatusCheck");
      const demoPresentation = await present(demo.body);
      const accepted = await submit(demo.body, demoPresentation);
      expect(accepted.status, JSON.stringify(accepted.body)).to.equal(200);
      expect(accepted.body.credentialStatus).to.equal("skipped");
      const poll = await request(checkoutApp).get(`/vp/dc-api/session/${demo.body.sessionId}`).set("Origin", origin);
      expect(poll.body.credentialStatus).to.equal("skipped");
      expect(statusFetches).to.equal(1);

      const anotherDemo = await createSession(skip, serviceKey);
      expect(anotherDemo.status).to.equal(200);
      const replay = await submit(anotherDemo.body, demoPresentation);
      expect(replay.status).to.equal(400);
      expect(replay.body.error_description).to.match(/nonce/i);

      const unverified = await createSession(skip, serviceKey);
      expect(unverified.status).to.equal(200);
      const withoutIssuerKey = await present(unverified.body, await makeCredential({}));
      const unverifiedResult = await submit(unverified.body, withoutIssuerKey);
      expect(unverifiedResult.status).to.equal(400);
      expect(unverifiedResult.body.error_description).to.match(/issuer signature must be verified/i);
    } finally {
      resetStatusListTestHooks();
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
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
