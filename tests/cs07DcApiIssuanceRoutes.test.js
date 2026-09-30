import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { resolveCredentialSelection, resolveCredentials, issuanceTtlSeconds, SCENARIOS, PROTOCOL, createOfferHandler, credentialOfferHandler, sessionHandler } from "../routes/issue/dcApiIssuanceRoutes.js";
import { offeredCredentialConfigurationIds } from "../utils/dcApiIssuance.js";
import { getDcApiIssuanceProgress, updateDcApiIssuanceProgress } from "../services/cacheServiceRedis.js";

describe("CS-07 DC API issuance route contract", () => {
  it("exposes only the supported scenarios and protocol", () => {
    assert.deepEqual(Object.keys(SCENARIOS), ["pid-pre-authorized", "pid-pre-authorized-tx-code", "pid-authorization-code"]);
    assert.equal(PROTOCOL, "openid4vci-v1");
  });
  it("accepts a configured credential and rejects an incompatible format", () => {
    const selection = resolveCredentialSelection({ credentialType: "VerifiablePortableDocumentA2SDJWT", credentialFormat: "sd-jwt" });
    assert.equal(selection.credentialType, "VerifiablePortableDocumentA2SDJWT");
    assert.throws(() => resolveCredentialSelection({ credentialType: "VerifiablePortableDocumentA2SDJWT", credentialFormat: "mso_mdoc" }), /incompatible/);
    assert.throws(() => resolveCredentialSelection({ credentialType: "does-not-exist" }), /Unsupported/);
  });
  it("uses the configured flow TTL", () => {
    const previous = process.env.VCI_PRE_AUTH_TIMEOUT;
    process.env.VCI_PRE_AUTH_TIMEOUT = "91";
    assert.equal(issuanceTtlSeconds("pre_authorized_code"), 91);
    if (previous === undefined) delete process.env.VCI_PRE_AUTH_TIMEOUT; else process.env.VCI_PRE_AUTH_TIMEOUT = previous;
  });
  it("accepts selected SD-JWT payloads and rejects duplicates, mdoc, and issuer-owned claims", () => {
    const credentials = resolveCredentials({ credentials: [
      { credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: { booking_reference: "REF-1" } },
      { credential_configuration_id: "VerifiableStudentIDSDJWT", payload: { student_id: "S-1" } },
    ] });
    assert.deepEqual(credentials.map(({ id }) => id), ["VerifiablePortableDocumentA2SDJWT", "VerifiableStudentIDSDJWT"]);
    assert.throws(() => resolveCredentials({ credentials: [
      { credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: { a: 1 } },
      { credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: { b: 2 } },
    ] }), /duplicate/);
    assert.throws(() => resolveCredentials({ credentials: [{ credential_configuration_id: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc", payload: { name: "A" } }] }), /SD-JWT/);
    assert.throws(() => resolveCredentials({ credentials: [{ credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: { iss: "attacker" } }] }), /issuer-owned/);
  });
  it("rejects an explicitly supplied credentials value unless it is an array", () => {
    for (const credentials of [{ credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: { name: "Ada" } }, "credential", null]) {
      assert.throws(() => resolveCredentials({ credentials }), /credentials must be an array/);
    }
    assert.equal(resolveCredentials({}).length, 1);
  });
  it("uses Redis atomic updates for concurrent credential progress writes", async () => {
    const calls = [];
    const originalSession = JSON.stringify({ dcApiState: {}, credentialPayloads: { first: { children: [], precise: 9007199254740993 } } });
    let storedSession = originalSession;
    const redisClient = {
      eval: async (script, options) => { calls.push({ script, options }); return 1; },
      sMembers: async () => ["pid", "loyalty"],
      hGetAll: async key => key.endsWith(":notifications") ? { n1: JSON.stringify({ credentialConfigurationId: "pid", event: "issued" }) } : { status: "success" },
    };
    const results = await Promise.all([
      updateDcApiIssuanceProgress("session-1", "pre-auth", { mode: "issued", credentialConfigurationId: "pid", notificationId: "n1" }, redisClient),
      updateDcApiIssuanceProgress("session-1", "pre-auth", { mode: "issued", credentialConfigurationId: "loyalty", notificationId: "n2" }, redisClient),
    ]);
    assert.deepEqual(results, [1, 1]);
    assert.equal(calls.length, 2);
    assert.ok(calls.every(({ script }) => script.includes("redis.call('EXISTS'") && script.includes("redis.call('SADD'") && script.includes("redis.call('HSET'") && !script.includes("redis.call('SET', KEYS[1]") && !script.includes("redis.call('GET', KEYS[1]")));
    assert.deepEqual(calls.map(({ options }) => options.keys.slice(1)), [
      ["dc-api-progress:pre-auth:session-1:issued", "dc-api-progress:pre-auth:session-1:notifications", "dc-api-progress:pre-auth:session-1:metadata"],
      ["dc-api-progress:pre-auth:session-1:issued", "dc-api-progress:pre-auth:session-1:notifications", "dc-api-progress:pre-auth:session-1:metadata"],
    ]);
    assert.equal(storedSession, originalSession);
    const progress = await getDcApiIssuanceProgress("session-1", "pre-auth", redisClient);
    assert.deepEqual(progress.issuedCredentialConfigurationIds, ["pid", "loyalty"]);
    assert.equal(progress.notifications.n1.credentialConfigurationId, "pid");
    assert.equal(progress.status, "success");
  });
  it("rejects cyclic and deeply nested payload data", () => {
    const cyclic = {}; cyclic.self = cyclic;
    assert.throws(() => resolveCredentials({ credentials: [{ credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: cyclic }] }));
    let deeplyNested = { value: true };
    for (let index = 0; index < 17; index += 1) deeplyNested = { nested: deeplyNested };
    assert.throws(() => resolveCredentials({ credentials: [{ credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: deeplyNested }] }), /nesting/);
  });
  it("executes the offer handler and returns the DC API envelope", async () => {
    const state = { statusCode: 200, headers: {}, body: null };
    const res = {
      set(name, value) { if (typeof name === "string") this.headers[name] = value; else Object.assign(this.headers, name); return this; },
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    Object.assign(res, state);
    const sessions = new Map();
    await createOfferHandler({ body: { scenario: "pid-pre-authorized" } }, res, {
      storePreAuthSession: async (id, session) => sessions.set(id, structuredClone(session)),
      getPreAuthSession: async (id) => sessions.get(id),
    });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.digital.requests[0].protocol, PROTOCOL);
    assert.ok(res.body.fallback.deepLink);
    assert.equal(res.body.credentialOffer.credential_configuration_ids[0], "VerifiablePortableDocumentA2SDJWT");
    assert.equal(res.body.digital.requests[0].data.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"], res.body.sessionId);
    assert.ok(res.body.statusToken);
    assert.equal(res.body.credentialOffer.statusToken, res.body.statusToken);
    assert.equal(res.body.credentialOffer.statusEndpoint, res.body.statusEndpoint);
    assert.equal(res.body.credentialOffer.credentialPayload, undefined);
    assert.match(res.body.fallback.deepLink, /credential_offer_uri=/);
  });
  it("omits the single-credential scope from multi-configuration authorization-code offers", async () => {
    const res = { statusCode: 200, body: null, set() { return this; }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    const sessions = new Map();
    await createOfferHandler({ body: {
      scenario: "pid-authorization-code",
      credentials: [
        { credential_configuration_id: "VerifiablePortableDocumentA2SDJWT", payload: { booking: [] } },
        { credential_configuration_id: "VerifiableStudentIDSDJWT", payload: { student_id: "S-1" } },
      ],
    } }, res, {
      storeCodeFlowSession: async (id, session) => sessions.set(id, structuredClone(session)),
      getCodeFlowSession: async (id) => sessions.get(id),
    });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.credentialOffer.credential_configuration_ids, ["VerifiablePortableDocumentA2SDJWT", "VerifiableStudentIDSDJWT"]);
    assert.equal(Object.hasOwn(res.body.credentialOffer.grants.authorization_code, "scope"), false);
    assert.equal(JSON.stringify(res.body).includes("S-1"), false);
    assert.equal(Object.hasOwn(res.body.credentialOffer, "credentialPayload"), false);
    assert.equal(Object.hasOwn(res.body.credentialOffer, "credentialPayloads"), false);
  });
  it("does not return an offer if session storage is unavailable", async () => {
    const res = {
      statusCode: 200, body: null,
      set() { return this; },
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    await createOfferHandler({ body: { scenario: "pid-pre-authorized" } }, res, {
      storePreAuthSession: async () => {}, getPreAuthSession: async () => null,
    });
    assert.equal(res.statusCode, 503);
    assert.equal(res.body.error, "temporarily_unavailable");
  });
  it("protects status with its capability and omits caller claim data", async () => {
    const token = "capability";
    const session = { dcApi: true, dcApiScenario: "pid-pre-authorized", flowType: "code", credentialType: "VerifiablePortableDocumentA2SDJWT", requestedCredentialConfigurationIds: ["wallet-selected-but-not-offered"], credentialPayloads: { VerifiablePortableDocumentA2SDJWT: { secret: "claim" } }, dcApiState: { expiresAt: 2000000000, statusTokenHash: createHash("sha256").update(token).digest("hex"), credentialConfigurationIds: ["VerifiablePortableDocumentA2SDJWT", "LoyaltyCard"], issuedCredentialConfigurationIds: [], notifications: {} } };
    const makeRes = () => ({ statusCode: 200, body: null, headers: {}, set(name, value) { if (typeof name === "string") this.headers[name] = value; else Object.assign(this.headers, name); return this; }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } });
    const invalid = makeRes();
    await sessionHandler({ params: { id: "s1" }, get: () => "Bearer wrong" }, invalid, { getPreAuthSession: async () => session });
    assert.equal(invalid.statusCode, 401);
    const valid = makeRes();
    await sessionHandler({ params: { id: "s1" }, get: () => `Bearer ${token}` }, valid, { getPreAuthSession: async () => session });
    assert.equal(valid.statusCode, 200);
    assert.deepEqual(valid.body.credentialConfigurationIds, ["VerifiablePortableDocumentA2SDJWT", "LoyaltyCard"]);
    assert.deepEqual(offeredCredentialConfigurationIds(session), ["VerifiablePortableDocumentA2SDJWT", "LoyaltyCard"]);
    assert.equal(JSON.stringify(valid.body).includes("claim"), false);
  });
  it("includes the status capability when a wallet retrieves the fallback offer URI", async () => {
    const token = "fallback-capability";
    const session = {
      dcApi: true, credentialType: "VerifiablePortableDocumentA2SDJWT", flowType: "pre-authorized",
      dcApiState: { expiresAt: Math.floor(Date.now() / 1000) + 60, statusToken: token, credentialConfigurationIds: ["VerifiablePortableDocumentA2SDJWT"] },
    };
    const res = { statusCode: 200, body: null, headers: {}, set(name, value) { if (typeof name === "string") this.headers[name] = value; else Object.assign(this.headers, name); return this; }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    await credentialOfferHandler({ params: { id: "s1" } }, res, { getPreAuthSession: async () => session });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.statusToken, token);
    assert.equal(res.body.statusEndpoint, "/vci/dc-api/session/s1");
  });
  it("omits the single-credential scope from a multi-configuration authorization-code fallback offer", async () => {
    const session = {
      dcApi: true, flowType: "code", credentialType: "VerifiablePortableDocumentA2SDJWT", txCodeRequired: false,
      credentialPayloads: { VerifiableStudentIDSDJWT: { private_marker: "DO_NOT_DISCLOSE" } },
      dcApiState: { expiresAt: Math.floor(Date.now() / 1000) + 60, statusToken: "fallback-token", credentialConfigurationIds: ["VerifiablePortableDocumentA2SDJWT", "VerifiableStudentIDSDJWT"] },
    };
    const res = { statusCode: 200, body: null, set() { return this; }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    await credentialOfferHandler({ params: { id: "code-session" } }, res, { getCodeFlowSession: async () => session });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.credential_configuration_ids, ["VerifiablePortableDocumentA2SDJWT", "VerifiableStudentIDSDJWT"]);
    assert.equal(Object.hasOwn(res.body.grants.authorization_code, "scope"), false);
    assert.equal(JSON.stringify(res.body).includes("DO_NOT_DISCLOSE"), false);
  });
  it("rejects status polling after the session expires", async () => {
    const token = "expired-capability";
    const session = { dcApi: true, dcApiState: { expiresAt: Math.floor(Date.now() / 1000) - 1, statusTokenHash: createHash("sha256").update(token).digest("hex") } };
    const res = { statusCode: 200, set() { return this; }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    await sessionHandler({ params: { id: "s-expired" }, get: () => `Bearer ${token}` }, res, { getPreAuthSession: async () => session });
    assert.equal(res.statusCode, 410);
    assert.equal(res.body.error, "expired");
  });
  it("rejects a malformed revocation flag before creating a session", async () => {
    const res = {
      headers: {},
      statusCode: 200,
      body: null,
      set() { return this; },
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    await createOfferHandler({ body: { scenario: "pid-pre-authorized", revocation: "yes" } }, res);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, "invalid_request");
    assert.match(res.body.error_description, /revocation must be a boolean/);
  });
});
