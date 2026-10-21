import { expect } from "chai";
import { createWrprcFixture } from "./helpers/wrprcFixture.js";
import express from "express";
import request from "supertest";
import { createRequire } from "node:module";
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from "jose";
import fs from "fs";
import { X509Certificate } from "crypto";
import { resolveCs02InvocationScheme, resolveCs02InvocationSchemeInput, createOpenId4VpRequestUrl } from "../utils/cs02VerifierRequest.js";
import { CONFIG, generateVPRequest } from "../utils/routeUtils.js";
import { getVPSession } from "../services/cacheServiceRedis.js";
import { setTrustResolverForTests, clearTrustResolverForTests } from "../utils/trustFrameworkPolicy.js";
import x509Router from "../routes/verify/x509Routes.js";
import mdlRouter from "../routes/verify/mdlRoutes.js";
import didRouter from "../routes/verify/didRoutes.js";
import didJwkRouter from "../routes/verify/didJwkRoutes.js";
import verifierAttestationRouter from "../routes/verify/verifierAttestationRoutes.js";
import vpStandardRouter from "../routes/verify/vpStandardRoutes.js";
import ts12PaymentRouter from "../routes/verify/ts12PaymentRoutes.js";
import dcApiRouter from "../routes/verify/dcApiRoutes.js";

const require = createRequire(import.meta.url);
const jsQR = require("jsqr");
const { PNG } = require("pngjs");
function decodeQr(dataUri) {
  const png = PNG.sync.read(Buffer.from(dataUri.split(",")[1], "base64"));
  const decoded = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  expect(decoded, "generated QR must be decodable").to.not.equal(null);
  return decoded.data;
}
const schemes = ["openid4vp", "eu-eaap", "haip-vp"];
const payment = { transaction_id: "invocation-tx", merchant: "Shop", payee_id: "shop-1", currency: "EUR", amount: "12.34" };
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/x509", x509Router);
app.use("/mdl", mdlRouter);
app.use("/did", didRouter);
app.use("/did-jwk", didJwkRouter);
app.use(verifierAttestationRouter);
app.use(vpStandardRouter);
app.use(ts12PaymentRouter);
app.use(dcApiRouter);

describe("CS-02 parametric invocation scheme", () => {
  let previousEnv;
  let previousServer;
  let sequence = 0;
  const sessionId = () => `invocation-regression-${++sequence}`;
  beforeEach(() => {
    previousEnv = { ...process.env };
    previousServer = CONFIG.SERVER_URL;
    CONFIG.SERVER_URL = "https://dev-i4mlab.aegean.gr";
    Object.assign(process.env, { NODE_ENV: "test", VERIFIER_CS02_COMPATIBILITY: "false", VERIFIER_CS03_COMPATIBILITY: "true" });
  });
  afterEach(() => {
    CONFIG.SERVER_URL = previousServer;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    clearTrustResolverForTests();
  });

  it("defaults only an omitted selector and accepts the three exact values", () => {
    expect(resolveCs02InvocationScheme(undefined)).to.equal("openid4vp");
    for (const scheme of schemes) expect(resolveCs02InvocationScheme(scheme)).to.equal(scheme);
    for (const value of ["", "openid4vp:", "eu-eaap://", "unknown", ["eu-eaap"], {}, null, 1]) {
      expect(() => resolveCs02InvocationScheme(value)).to.throw(/invocation_scheme/);
    }
    expect(resolveCs02InvocationSchemeInput("eu-eaap", "eu-eaap")).to.equal("eu-eaap");
    expect(() => resolveCs02InvocationSchemeInput("eu-eaap", "haip-vp")).to.throw(/Conflicting/);
  });

  for (const scheme of schemes) for (const method of ["get", "post"]) {
    it(`encodes selected ${scheme} in both link and QR and preserves ${method.toUpperCase()} request retrieval`, async () => {
      const id = sessionId();
      const endpoint = method === "get" ? "generateVPRequestDCQLGET" : "generateVPRequestDCQL";
      const generated = await request(app).get(`/x509/${endpoint}`).query({ sessionId: id, invocation_scheme: scheme }).expect(200);
      expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
      const uri = new URL(generated.body.deepLink);
      expect(uri.protocol).to.equal(`${scheme}:`);
      expect(uri.hostname).to.equal("");
      expect(uri.searchParams.get("request_uri_method")).to.equal(method === "post" ? "post" : null);
      let fetched = request(app)[method](new URL(uri.searchParams.get("request_uri")).pathname);
      if (method === "post") fetched = fetched.type("form").send({ wallet_nonce: "wallet-nonce" });
      const jar = await fetched.expect(200);
      const payload = decodeJwt(jar.text);
      expect(payload.client_id).to.equal(uri.searchParams.get("client_id"));
      expect(payload.client_id).to.match(/^x509_hash:/);
      expect(payload.state).to.equal((await getVPSession(id)).state);
      expect(payload.response_mode).to.equal("direct_post.jwt");
      expect(payload.verifier_info.map(entry => entry.format)).to.deep.equal(["registrar_dataset"]);
      expect(payload.verifier_info[0].data.identifier).to.equal("VATEL-090264862");
      expect(payload.verifier_info[0].data.intendedUseIdentifier).to.be.a("string").and.not.equal("");
      if (method === "post") expect(payload.wallet_nonce).to.equal("wallet-nonce");
    });
  }

  for (const endpoint of [
    "/x509/generateVPRequest", "/x509/generateVPRequestGet", "/x509/generateVPRequestTransaction",
    "/mdl/generateVPRequest", "/mdl/generateVPRequestDCQL", "/vp/request",
    "/did/generateVPRequestDCQL", "/did-jwk/generateVPRequestDCQL", "/va/generateVPRequestDCQL",
  ]) {
    it(`${endpoint} rejects an unsupported selector before generation`, async () => {
      const id = sessionId();
      const result = await request(app).get(endpoint).query({ sessionId: id, session_id: id, invocation_scheme: "invalid" }).expect(400);
      expect(result.body.error).to.equal("invalid_request");
      expect(await getVPSession(id)).to.equal(null);
    });
    it(`${endpoint} forwards the selector to link and QR generation`, async () => {
      const id = sessionId();
      const generated = await request(app).get(endpoint).query({ sessionId: id, session_id: id, invocation_scheme: "eu-eaap" }).expect(200);
      expect(new URL(generated.body.deepLink).protocol).to.equal("eu-eaap:");
      expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
    });
  }

  it("omitting the selector preserves the default OpenID4VP link and QR", async () => {
    const generated = await request(app).get("/x509/generateVPRequestDCQL").query({ sessionId: sessionId() }).expect(200);
    expect(new URL(generated.body.deepLink).protocol).to.equal("openid4vp:");
    expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
  });

  for (const query of ["invocation_scheme=", "invocation_scheme=unknown", "invocation_scheme=eu-eaap&invocation_scheme=eu-eaap", "invocation_scheme[key]=eu-eaap"]) {
    it(`rejects ${query} before storing a session`, async () => {
      const id = sessionId();
      const result = await request(app).get(`/x509/generateVPRequestDCQL?sessionId=${id}&${query}`).expect(400);
      expect(result.body.error).to.equal("invalid_request");
      expect(await getVPSession(id)).to.equal(null);
    });
  }

  it("the shared generation helper rejects an invalid selector before signing or storing", async () => {
    const id = sessionId();
    let failure;
    try { await generateVPRequest({ sessionId: id, invocationScheme: [], clientId: CONFIG.CLIENT_ID }); }
    catch (error) { failure = error; }
    expect(failure?.errorCode).to.equal("invalid_request");
    expect(await getVPSession(id)).to.equal(null);
  });

  it("TS-12 selects a body scheme and rejects conflicting or invalid query/body values before storage", async () => {
    const id = sessionId();
    const generated = await request(app).post("/ts12/payment/request").send({ ...payment, session_id: id, invocation_scheme: "haip-vp" }).expect(200);
    expect(new URL(generated.body.deepLink).protocol).to.equal("haip-vp:");
    expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
    for (const [query, body] of [["eu-eaap", "haip-vp"], ["", "eu-eaap"], ["eu-eaap", []]]) {
      const rejectedId = sessionId();
      const result = await request(app).post("/ts12/payment/request").query({ invocation_scheme: query })
        .send({ ...payment, session_id: rejectedId, invocation_scheme: body }).expect(400);
      expect(result.body.error).to.equal("invalid_request");
      expect(await getVPSession(rejectedId)).to.equal(null);
    }
    const matching = await request(app).post("/ts12/payment/request").query({ invocation_scheme: "eu-eaap" })
      .send({ ...payment, session_id: sessionId(), invocation_scheme: "eu-eaap" }).expect(200);
    expect(new URL(matching.body.deepLink).protocol).to.equal("eu-eaap:");
  });

  it("TS-12 GET generation accepts a query selector", async () => {
    const generated = await request(app).get("/ts12/payment/request")
      .query({ ...payment, session_id: sessionId(), invocation_scheme: "haip-vp" }).expect(200);
    expect(new URL(generated.body.deepLink).protocol).to.equal("haip-vp:");
    expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
  });

  it("the shared DC API generation helper rejects a supplied selector before session creation", async () => {
    const id = sessionId();
    let failure;
    try { await generateVPRequest({ sessionId: id, cs07DcApi: true, invocationScheme: "openid4vp" }); }
    catch (error) { failure = error; }
    expect(failure?.errorCode).to.equal("invalid_request");
    expect(await getVPSession(id)).to.equal(null);
  });

  for (const scheme of ["eu-eaap", "haip-vp"]) {
    it(`compatibility mode retains explicit ${scheme} instead of overriding it with legacy present`, async () => {
      process.env.VERIFIER_CS02_COMPATIBILITY = "true";
      const generated = await request(app).get("/x509/generateVPRequestDCQL").query({ sessionId: sessionId(), invocation_scheme: scheme }).expect(200);
      expect(new URL(generated.body.deepLink).protocol).to.equal(`${scheme}:`);
      expect(new URL(generated.body.deepLink).hostname).to.equal("");
      expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
    });
  }
  it("retains legacy OpenID4VP compatibility when the selector is omitted", () => {
    expect(new URL(createOpenId4VpRequestUrl("https://verifier.example/request", "x509_san_dns:verifier.example", false,
      { VERIFIER_CS02_COMPATIBILITY: "true" })).hostname).to.equal("present");
  });

  it("signs retrieved x509 verifier requests with the Raidiam WRPAC", async () => {
    const id = sessionId();
    const generated = await request(app).get("/x509/generateVPRequestDCQL").query({ sessionId: id }).expect(200);
    const uri = new URL(generated.body.deepLink);
    const jar = await request(app).get(new URL(uri.searchParams.get("request_uri")).pathname).expect(200);
    const header = decodeProtectedHeader(jar.text);
    const wrpac = new X509Certificate(fs.readFileSync("certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem"));
    const leaf = new X509Certificate(Buffer.from(header.x5c[0], "base64"));
    const issuingCa = new X509Certificate(fs.readFileSync("certs/raidiam/eudi-sandbox-issuing-ca-g1.pem"));
    expect(header.alg).to.equal("ES256");
    expect(header.x5c).to.have.length(2);
    expect(leaf.raw.equals(wrpac.raw)).to.equal(true);
    expect(Buffer.from(header.x5c[1], "base64").equals(issuingCa.raw)).to.equal(true);
    expect(leaf.checkIssued(issuingCa)).to.equal(true);
    expect(decodeJwt(jar.text).client_id).to.equal(uri.searchParams.get("client_id"));
    await jwtVerify(jar.text, await importX509(wrpac.toString(), "ES256"));
  });

  it("selected scheme preserves CS-03 SAN identity and plaintext response mode", async () => {
    const id = sessionId();
    const generated = await request(app).get("/x509/generateVPRequestDCQL").query({ sessionId: id, cs03: "1", invocation_scheme: "eu-eaap" }).expect(200);
    const session = await getVPSession(id);
    expect(session.client_id).to.equal(CONFIG.CLIENT_ID);
    expect(session.response_mode).to.equal("direct_post");
    expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
  });

  it("selected scheme preserves opt-in trust policy and hash signing material", async () => {
    const fixture = await createWrprcFixture();
    process.env.TRUST_WRPRC_MANIFEST_PATH = fixture.manifestPath;
    try {
    delete process.env.TRUST_WRPRC_CERT_PATH;
    setTrustResolverForTests({ resolve: async () => ({ trusted: true, state: "trusted", reasonCode: "TRUSTED" }) });
    const id = sessionId();
    const generated = await request(app).get("/x509/generateVPRequestDCQLGET").query({ sessionId: id, invocation_scheme: "haip-vp", trustFramework: "true" }).expect(200);
    expect(decodeQr(generated.body.qr)).to.equal(generated.body.deepLink);
    expect((await getVPSession(id)).trustPolicy.mode).to.equal("webuild");
    const fetched = await request(app).get(`/x509/x509VPrequest/${id}`).expect(200);
    expect(decodeProtectedHeader(fetched.text).x5c).to.have.length.greaterThan(0);
    expect(decodeJwt(fetched.text).client_id).to.equal(new URL(generated.body.deepLink).searchParams.get("client_id"));
    expect(decodeJwt(fetched.text).verifier_info[0].data.intendedUseIdentifier).to.equal("use-pid-basic");
    } finally { await fixture.cleanup(); }
  });

  for (const location of ["query", "body"]) {
    it(`DC API rejects an invocation selector in ${location} as inapplicable`, async () => {
      const id = sessionId();
      let call = request(app).post("/vp/dc-api/request");
      if (location === "query") call = call.query({ invocation_scheme: "eu-eaap" });
      const result = await call.send({ sessionId: id, profile: "pid-basic", ...(location === "body" ? { invocation_scheme: "openid4vp" } : {}) }).expect(400);
      expect(result.body.error).to.equal("invalid_request");
      expect(result.body.error_description).to.match(/Digital Credentials API/);
      expect(await getVPSession(id)).to.equal(null);
    });
  }
});
