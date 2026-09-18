import { expect } from "chai";
import crypto from "crypto";
import fs from "fs";
import * as jose from "jose";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { validateCs02KeyBindingJwtClaims } from "../utils/cs02VerifierResponse.js";
import {
  buildCs07DigitalCredentialRequest,
  buildCs07SessionStatusPayload,
  cs07ExpectedAudience,
  decodeCs07AuthorizationResponse,
  normalizeCs07DigitalCredentialResponse,
  parseCs07AuthorizationResponse,
  resolveCs07VerifierOrigin,
} from "../utils/cs07DcApi.js";
import { DEFAULT_DCQL_QUERY } from "../utils/routeUtils.js";
import { createDcApiVerifierClient, DcApiClientError } from "../clients/dc-api/rp-client.js";
import { validateCs07Config, resolveCs07Profile, mergeEnvRelyingParties, loadCs07Config } from "../utils/cs07Config.js";
import { validateCs07CredentialPresentations } from "../utils/cs07ResponseValidation.js";
import {
  assertCs07DcApiRequestBodyKeys,
  buildCs07Ts12PaymentRequest,
  extractTs12PresentationArtifactsFromVpToken,
} from "../utils/cs07Ts12Payment.js";
import { Cs07DcApiResponseError } from "../utils/cs07DcApi.js";
import {
  TS12_PAYMENT_TRANSACTION_TYPE,
  TS12_PID_VCT,
  TS12_SCA_CARD_DPC_VCT,
  TS12_SCA_IBAN_VCT,
  TS12_SCA_USER_VCT,
  buildTs12DcqlQuery,
  buildTs12DpcWithPidDcqlQuery,
  buildTs12ScaWithPidDcqlQuery,
  computeTs12TransactionDataHash,
} from "../utils/ts12PaymentUtils.js";
import {
  validateTs12PaymentPresentationResponse,
} from "../utils/ts12Validation.js";

describe("CS-07 Digital Credentials API request profile", () => {
  it("canonicalizes a configured HTTPS origin and derives the origin audience", () => {
    expect(resolveCs07VerifierOrigin({
      serverURL: "https://verifier.example/",
      env: {},
    })).to.equal("https://verifier.example");
    expect(cs07ExpectedAudience("https://verifier.example")).to.equal(
      "origin:https://verifier.example",
    );
  });

  it("rejects a path and non-HTTPS origin unless HTTP is explicitly enabled", () => {
    expect(() => resolveCs07VerifierOrigin({
      serverURL: "https://verifier.example/path",
      env: {},
    })).to.throw(/must not contain a path/);
    expect(() => resolveCs07VerifierOrigin({
      serverURL: "http://localhost:3000",
      env: {},
    })).to.throw(/must use HTTPS/);
    expect(resolveCs07VerifierOrigin({
      serverURL: "http://localhost:3000",
      env: { DC_API_ALLOW_HTTP: "true" },
    })).to.equal("http://localhost:3000");
  });

  it("builds the required DigitalCredential request envelope", () => {
    const signed = "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6IngifQ.signature";
    expect(buildCs07DigitalCredentialRequest(signed)).to.deep.equal({
      protocol: "openid4vp-v1-signed",
      data: { request: signed },
    });
  });

  it("exposes a reusable RP adapter without requiring a DOM", () => {
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: { credentials: { get: () => Promise.resolve(null) } },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async () => ({ ok: true, json: async () => ({}) }),
    });
    expect(client.isSupported()).to.equal(true);
  });

  it("keeps a reverse-proxy path prefix when calling the verifier", async () => {
    const urls = [];
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://dev.example/rfc-issuer",
      secureContext: true,
      navigatorImpl: {
        credentials: {
          get: async () => ({ protocol: "openid4vp-v1-signed", data: { response: "a.b.c.d.e" } }),
        },
      },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url) => {
        urls.push(String(url));
        if (String(url).endsWith("/vp/dc-api/request")) {
          return {
            ok: true,
            json: async () => ({
              sessionId: "session-1",
              request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } },
            }),
          };
        }
        return { ok: true, json: async () => ({ status: "success" }) };
      },
    });
    const descriptor = await client.prepare({ profile: "pid-basic" });
    await client.present(descriptor);
    expect(urls[0]).to.equal("https://dev.example/rfc-issuer/vp/dc-api/request");
    expect(urls[1]).to.equal("https://dev.example/rfc-issuer/vp/dc-api/response/session-1");
  });

  it("forwards an optional external sessionId to request generation", async () => {
    let requestBody;
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: { credentials: { get: async () => ({ protocol: "openid4vp-v1-signed", data: { response: "a.b.c" } }) } },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url, options) => {
        if (String(url).endsWith("/vp/dc-api/request")) requestBody = JSON.parse(options.body);
        return { ok: true, json: async () => ({
          sessionId: "booking-12345",
          request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } },
        }) };
      },
    });

    await client.prepare({ profile: "pid-basic", sessionId: "booking-12345" });
    expect(requestBody).to.deep.equal({ profile: "pid-basic", sessionId: "booking-12345" });
  });

  it("forwards CS-12 payment fields when preparing a ts12-payment request", async () => {
    let requestBody;
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: { credentials: { get: async () => ({ protocol: "openid4vp-v1-signed", data: { response: "a.b.c" } }) } },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url, options) => {
        if (String(url).endsWith("/vp/dc-api/request")) requestBody = JSON.parse(options.body);
        return { ok: true, json: async () => ({
          sessionId: "pay-1",
          request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } },
        }) };
      },
    });

    await client.prepare({
      profile: "ts12-dpc",
      payment: {
        amount: "12.34",
        currency: "EUR",
        merchant: "Demo Merchant",
        payee_id: "merchant-001",
        transaction_id: "tx-12345",
        ignored: "nope",
      },
    });
    expect(requestBody).to.deep.equal({
      profile: "ts12-dpc",
      amount: "12.34",
      currency: "EUR",
      merchant: "Demo Merchant",
      payee_id: "merchant-001",
      transaction_id: "tx-12345",
    });
  });

  it("prepares a descriptor and presents it through the user-activation API", async () => {
    const calls = [];
    let credentialCalls = 0;
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: {
        credentials: {
          get: async (options) => {
            credentialCalls += 1;
            calls.push(options);
            return { protocol: "openid4vp-v1-signed", data: { response: "a.b.c.d.e" } };
          },
        },
      },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (calls.length === 1) {
          return { ok: true, json: async () => ({
            sessionId: "session-1",
            request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } },
            responseEndpoint: "https://verifier.example/vp/dc-api/response/session-1",
          }) };
        }
        return { ok: true, json: async () => ({ status: "success" }) };
      },
    });
    const descriptor = await client.prepare({ profile: "pid-basic" });
    const result = await client.present(descriptor);
    expect(result.status).to.equal("success");
    expect(credentialCalls).to.equal(1);
    expect(calls[1].digital.requests[0]).to.deep.equal(descriptor.request);
    expect(calls[2].options.body).to.equal(JSON.stringify({
      protocol: "openid4vp-v1-signed",
      data: { response: "a.b.c.d.e" },
    }));
  });

  it("prevents reuse of a prepared descriptor", async () => {
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: { credentials: { get: async () => ({ protocol: "openid4vp-v1-signed", data: { response: "a.b.c.d.e" } }) } },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url) => ({ ok: true, json: async () => url.endsWith("request")
        ? { sessionId: "session-1", request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } } }
        : { status: "failed" } }),
    });
    const descriptor = await client.prepare({ profile: "pid-basic" });
    await client.present(descriptor);
    try {
      await client.present(descriptor);
      throw new Error("expected reuse rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(DcApiClientError);
      expect(error.code).to.equal("invalid_state");
    }
  });

  it("validates configurable profile-to-DCQL and RP-origin mappings", () => {
    const config = validateCs07Config({
      default_profile: "pid-basic",
      profiles: { "pid-basic": { workflow: "presentation", dcql_query: DEFAULT_DCQL_QUERY } },
      relying_parties: { "https://rp.example": { profiles: ["pid-basic"] } },
    }, { env: {} });
    expect(resolveCs07Profile(config, { profileId: "pid-basic", origin: "https://rp.example" }).id).to.equal("pid-basic");
    expect(() => resolveCs07Profile(config, { profileId: "pid-basic", origin: "https://other.example" })).to.throw(/not authorized/);
    expect(() => validateCs07Config({
      default_profile: "missing",
      profiles: { "pid-basic": { workflow: "presentation", dcql_query: DEFAULT_DCQL_QUERY } },
      relying_parties: {},
    }, { env: {} })).to.throw(/default_profile/);
    expect(() => validateCs07Config({
      default_profile: "pid-basic",
      profiles: { "pid-basic": { workflow: "unknown", dcql_query: DEFAULT_DCQL_QUERY } },
      relying_parties: {},
    }, { env: {} })).to.throw(/Unknown CS-07 workflow/);
    expect(() => validateCs07Config({
      default_profile: "pid-basic",
      profiles: {
        "pid-basic": { workflow: "presentation", dcql_query: DEFAULT_DCQL_QUERY },
        "ts12-payment": { workflow: "ts12-payment", dcql_query: DEFAULT_DCQL_QUERY },
      },
      relying_parties: {},
    }, { env: {} })).not.to.throw();
  });

  it("merges relying-party origins from environment variables", () => {
    const base = {
      default_profile: "pid-basic",
      profiles: {
        "pid-basic": { workflow: "presentation", dcql_query: DEFAULT_DCQL_QUERY },
        "qualified-signing": { workflow: "cs03-inline-signing", dcql_query: DEFAULT_DCQL_QUERY },
      },
      relying_parties: {},
    };
    const withDefaultProfile = validateCs07Config(mergeEnvRelyingParties(structuredClone(base), {
      env: { DC_API_RP_ORIGINS: "https://rp.example, https://rp2.example" },
    }), { env: {} });
    expect(withDefaultProfile.relying_parties).to.deep.equal({
      "https://rp.example": { profiles: ["pid-basic"] },
      "https://rp2.example": { profiles: ["pid-basic"] },
    });
    expect(resolveCs07Profile(withDefaultProfile, {
      profileId: "pid-basic",
      origin: "https://rp2.example",
    }).id).to.equal("pid-basic");

    const withExplicitProfiles = validateCs07Config(mergeEnvRelyingParties(structuredClone(base), {
      env: {
        DC_API_RP_ORIGINS: "https://rp.example",
        DC_API_RP_PROFILES: "qualified-signing",
      },
    }), { env: {} });
    expect(withExplicitProfiles.relying_parties).to.deep.equal({
      "https://rp.example": { profiles: ["qualified-signing"] },
    });

    expect(() => validateCs07Config(mergeEnvRelyingParties(structuredClone(base), {
      env: { DC_API_RP_ORIGINS: "https://rp.example/path" },
    }), { env: {} })).to.throw(/must not contain a path/);

    expect(() => validateCs07Config(mergeEnvRelyingParties(structuredClone(base), {
      env: {
        DC_API_RP_ORIGINS: "https://rp.example",
        DC_API_RP_PROFILES: "missing-profile",
      },
    }), { env: {} })).to.throw(/references unknown profile/);

    const withJsonArray = validateCs07Config(mergeEnvRelyingParties(structuredClone(base), {
      env: {
        DC_API_RP_ORIGINS: '["https://rp.example","https://rp3.example"]',
        DC_API_RP_PROFILES: '["pid-basic","qualified-signing"]',
      },
    }), { env: {} });
    expect(withJsonArray.relying_parties).to.deep.equal({
      "https://rp.example": { profiles: ["pid-basic", "qualified-signing"] },
      "https://rp3.example": { profiles: ["pid-basic", "qualified-signing"] },
    });

    const withNativeArray = validateCs07Config(mergeEnvRelyingParties(structuredClone(base), {
      env: {
        DC_API_RP_ORIGINS: ["https://rp.example", "https://rp4.example"],
        DC_API_RP_PROFILES: ["qualified-signing"],
      },
    }), { env: {} });
    expect(withNativeArray.relying_parties).to.deep.equal({
      "https://rp.example": { profiles: ["qualified-signing"] },
      "https://rp4.example": { profiles: ["qualified-signing"] },
    });
  });

  it("rejects expired descriptors and classifies wallet protocol errors", async () => {
    const client = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: { credentials: { get: async () => ({ protocol: "openid4vp-v1-signed", data: { response: "a.b.c.d.e" } }) } },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url) => ({ ok: true, json: async () => url.endsWith("request")
        ? { sessionId: "expired", expiresAt: 1, request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } } }
        : { status: "success" } }),
    });
    const expired = await client.prepare({ profile: "pid-basic" });
    try { await client.present(expired); throw new Error("expected expiry"); } catch (error) {
      expect(error.code).to.equal("expired");
    }

    const walletClient = createDcApiVerifierClient({
      verifierBaseUrl: "https://verifier.example",
      secureContext: true,
      navigatorImpl: { credentials: { get: async () => ({ protocol: "openid4vp-v1-signed", data: { error: "access_denied" } }) } },
      digitalCredential: { userAgentAllowsProtocol: () => true },
      fetchImpl: async (url) => ({ ok: true, json: async () => url.endsWith("request")
        ? { sessionId: "wallet-error", request: { protocol: "openid4vp-v1-signed", data: { request: "a.b.c" } } }
        : { status: "failed" } }),
    });
    const walletDescriptor = await walletClient.prepare({ profile: "pid-basic" });
    try { await walletClient.present(walletDescriptor); throw new Error("expected wallet error"); } catch (error) {
      expect(error.code).to.equal("wallet_protocol_error");
    }
  });

  it("normalizes wallet protocol errors separately from compact JWE responses", () => {
    expect(normalizeCs07DigitalCredentialResponse({
      protocol: "openid4vp-v1-signed",
      data: { error: "access_denied" },
    })).to.deep.equal({
      protocol: "openid4vp-v1-signed",
      walletError: { error: "access_denied" },
    });
    expect(normalizeCs07DigitalCredentialResponse({
      protocol: "openid4vp-v1-signed",
      data: { response: "a.b.c.d.e" },
    })).to.deep.equal({
      protocol: "openid4vp-v1-signed",
      encryptedResponse: "a.b.c.d.e",
    });
  });

  it("rejects ambiguous or non-JWE DigitalCredential responses", () => {
    expect(() => normalizeCs07DigitalCredentialResponse({
      protocol: "openid4vp-v1-signed",
      data: { error: "access_denied", response: "a.b.c.d.e" },
    })).to.throw(/only error/);
    expect(() => normalizeCs07DigitalCredentialResponse({
      protocol: "openid4vp-v1-signed",
      data: { response: "a.b.c" },
    })).to.throw(/compact JWE/);
    expect(() => normalizeCs07DigitalCredentialResponse({
      protocol: "openid4vp-v1-signed",
      data: { response: "a.b.c.d.e" },
      extra: true,
    })).to.throw(/unexpected fields/);
  });

  it("rejects excessively nested or oversized-shape response envelopes", () => {
    let nested = { response: "a.b.c.d.e" };
    for (let index = 0; index < 10; index += 1) nested = { nested };
    expect(() => normalizeCs07DigitalCredentialResponse({
      protocol: "openid4vp-v1-signed",
      data: nested,
    })).to.throw(/deeply nested/);
  });

  it("parses and checks the decrypted Authorization Response against DCQL", () => {
    const query = { credentials: [
      { id: "one", multiple: false },
      { id: "optional", required: false, multiple: true },
    ] };
    const parsed = parseCs07AuthorizationResponse(
      JSON.stringify({ vp_token: { one: "presentation" } }),
      query,
    );
    expect(parsed.vpToken).to.deep.equal({ one: "presentation" });
    expect(() => parseCs07AuthorizationResponse(
      { vp_token: { unknown: "presentation" } },
      query,
    )).to.throw(/unknown/);
    expect(() => parseCs07AuthorizationResponse(
      { vp_token: { one: ["a", "b"] } },
      query,
    )).to.throw(/multiple presentations/);
  });

  it("decodes SD-JWT presentations in the Authorization Response for session polling", async () => {
    const issuer = await jose.generateKeyPair("ES256", { extractable: true });
    const holder = await jose.generateKeyPair("ES256", { extractable: true });
    const holderPublicJwk = await jose.exportJWK(holder.publicKey);
    const issuerKey = await jose.importJWK(await jose.exportJWK(issuer.privateKey), "ES256");
    const holderKey = await jose.importJWK(await jose.exportJWK(holder.privateKey), "ES256");
    const now = Math.floor(Date.now() / 1000);
    const disclosed = Buffer.from(JSON.stringify(["salt", "family_name", "Neslo"])).toString("base64url");
    const issuerJwt = await new jose.SignJWT({
      iss: "https://issuer.example", iat: now, exp: now + 300, vct: "test",
      cnf: { jwk: holderPublicJwk }, _sd_alg: "sha-256",
      _sd: [crypto.createHash("sha256").update(disclosed, "ascii").digest("base64url")],
    }).setProtectedHeader({ alg: "ES256", typ: "dc+sd-jwt" }).sign(issuerKey);
    const unsigned = `${issuerJwt}~${disclosed}~`;
    const sdHashInput = unsigned.endsWith("~") ? unsigned : `${unsigned}~`;
    const kbJwt = await new jose.SignJWT({
      nonce: "nonce", aud: "origin:https://rp.example", iat: now,
      sd_hash: crypto.createHash("sha256").update(Buffer.from(sdHashInput, "ascii")).digest("base64url"),
    }).setProtectedHeader({ alg: "ES256", typ: "kb+jwt" }).sign(holderKey);
    const decoded = decodeCs07AuthorizationResponse({
      vp_token: { pid: `${unsigned}${kbJwt}`, other: "not-a-jwt" },
    });
    expect(decoded.vp_token.pid.claims.family_name).to.equal("Neslo");
    expect(decoded.vp_token.pid.claims.vct).to.equal("test");
    expect(decoded.vp_token.pid.key_binding.aud).to.equal("origin:https://rp.example");
    expect(decoded.vp_token.other).to.equal("not-a-jwt");
    expect(JSON.stringify(decoded)).to.not.include(issuerJwt);

    const poll = buildCs07SessionStatusPayload("sess-1", {
      status: "success",
      profile_id: "ts12-dpc-pid",
      verified_credential_ids: ["pid"],
      verification: "dcql_and_credential_binding_validated",
      dc_api_response: decoded,
    });
    expect(poll.vp_response.vp_token.pid.claims.family_name).to.equal("Neslo");
    expect(buildCs07SessionStatusPayload("sess-2", {
      status: "success",
      dc_api_response: { parsed: true },
    }).vp_response).to.equal(undefined);
  });

  it("uses an explicit origin audience for CS-07 key-binding validation", () => {
    const common = {
      kbHeader: { typ: "kb+jwt" },
      kbPayload: { nonce: "nonce", aud: "origin:https://verifier.example", iat: 1, sd_hash: "hash" },
      sessionNonce: "nonce",
      clientId: "x509_san_dns:verifier.example",
      options: { strict: true },
    };
    expect(() => validateCs02KeyBindingJwtClaims({
      ...common,
      expectedAudience: "origin:https://verifier.example",
    })).not.to.throw();
    expect(() => validateCs02KeyBindingJwtClaims({
      ...common,
      expectedAudience: "origin:https://other.example",
    })).to.throw(/expected verifier audience/);
  });

  it("dispatches an mdoc presentation through the shared CS-02 validator", async () => {
    const result = await validateCs07CredentialPresentations({
      vpToken: { license: "mdoc-placeholder" },
      session: {
        nonce: "nonce",
        client_id: "x509_san_dns:verifier.example",
        expected_audience: "origin:https://rp.example",
        dcql_query: { credentials: [{ id: "license", format: "mso_mdoc" }] },
      },
      options: { cs02: { strict: true } },
    });
    expect(result).to.deep.equal({
      verifiedCredentialIds: ["license"],
      verification: "dcql_and_credential_binding_validated",
    });
  });

  it("builds a CS-07 request without redirect-only correlation fields", async () => {
    const previous = { ...process.env };
    process.env.CS03_COMPATIBILITY = "false";
    process.env.DC_API_VERIFIER_ORIGIN = "https://verifier.example";
    try {
      const requestJwt = await buildVpRequestJWT(
        "x509_san_dns:verifier.example",
        null,
        null,
        null,
        { client_name: "Verifier" },
        null,
        "https://verifier.example",
        "vp_token",
        "nonce-cs07",
        DEFAULT_DCQL_QUERY,
        null,
        "dc_api.jwt",
        undefined,
        undefined,
        null,
        null,
        null,
        "ES256",
        true,
        "https://verifier.example",
      );
      const payload = jose.decodeJwt(requestJwt);
      expect(payload.response_mode).to.equal("dc_api.jwt");
      expect(payload.expected_origins).to.deep.equal(["https://verifier.example"]);
      expect(payload.aud).to.equal("https://self-issued.me/v2");
      expect(payload).to.not.have.property("state");
      expect(payload).to.not.have.property("response_uri");
    } finally {
      process.env = previous;
    }
  });

  it("advertises an ECDH-ES P-256 encryption JWK in CS-07 request objects", async () => {
    const previous = { ...process.env };
    process.env.CS03_COMPATIBILITY = "false";
    process.env.DC_API_VERIFIER_ORIGIN = "https://verifier.example";
    try {
      const clientMetadata = JSON.parse(fs.readFileSync("./data/verifier-config.json", "utf8"));
      const requestJwt = await buildVpRequestJWT(
        "x509_san_dns:verifier.example",
        null,
        null,
        null,
        clientMetadata,
        null,
        "https://verifier.example",
        "vp_token",
        "nonce-cs07-enc",
        DEFAULT_DCQL_QUERY,
        null,
        "dc_api.jwt",
        undefined,
        undefined,
        null,
        null,
        null,
        "ES256",
        true,
        "https://verifier.example",
      );
      const payload = jose.decodeJwt(requestJwt);
      const encKey = payload.client_metadata?.jwks?.keys?.find((key) => key.use === "enc");
      expect(encKey).to.include({
        kty: "EC",
        crv: "P-256",
        use: "enc",
        alg: "ECDH-ES",
      });
      expect(encKey.kid).to.be.a("string").that.is.not.empty;
    } finally {
      process.env = previous;
    }
  });
});

describe("CS-07 TS12 payment DC API requests", () => {
  const paymentInput = {
    profile: "ts12-dpc",
    amount: "12.34",
    currency: "EUR",
    merchant: "Demo Merchant",
    payee_id: "merchant-001",
    transaction_id: "tx-dc-api-1",
  };
  const dpcDcql = buildTs12DcqlQuery("sca-card-dpc");
  const dpcPidDcql = buildTs12DpcWithPidDcqlQuery();
  const ibanDcql = buildTs12DcqlQuery("sca-iban");
  const ibanPidDcql = buildTs12ScaWithPidDcqlQuery("sca-iban");
  const userDcql = buildTs12DcqlQuery("sca-user");
  const userPidDcql = buildTs12ScaWithPidDcqlQuery("sca-user");

  it("loads the checked-in SCA payment profiles", () => {
    const config = loadCs07Config({ env: {} });
    expect(config.profiles["ts12-dpc"].workflow).to.equal("ts12-payment");
    expect(config.profiles["ts12-dpc"].dcql_query).to.deep.equal(dpcDcql);
    expect(config.profiles["ts12-dpc-pid"].dcql_query).to.deep.equal(dpcPidDcql);
    expect(config.profiles["ts12-iban"].dcql_query).to.deep.equal(ibanDcql);
    expect(config.profiles["ts12-iban-pid"].dcql_query).to.deep.equal(ibanPidDcql);
    expect(config.profiles["ts12-user"].dcql_query).to.deep.equal(userDcql);
    expect(config.profiles["ts12-user-pid"].dcql_query).to.deep.equal(userPidDcql);
    expect(config.profiles["ts12-payment"].dcql_query).to.deep.equal(dpcDcql);
    expect(dpcPidDcql.credentials.map((c) => c.meta.vct_values[0])).to.deep.equal([
      TS12_SCA_CARD_DPC_VCT,
      TS12_PID_VCT,
    ]);
    expect(dpcPidDcql.credentials[1].claims.map((c) => c.path.join("."))).to.deep.equal([
      "given_name",
      "family_name",
      "birthdate",
      "email",
      "nationalities",
      "phone_number",
      "address",
    ]);
    expect(dpcPidDcql.credentials[1].claim_sets.at(-1)).to.deep.equal([
      "given_name",
      "family_name",
      "birthdate",
      "nationalities",
    ]);
    expect(ibanPidDcql.credentials.map((c) => c.meta.vct_values[0])).to.deep.equal([
      TS12_SCA_IBAN_VCT,
      TS12_PID_VCT,
    ]);
    expect(userPidDcql.credentials.map((c) => c.meta.vct_values[0])).to.deep.equal([
      TS12_SCA_USER_VCT,
      TS12_PID_VCT,
    ]);
  });

  it("rejects payment fields on presentation profiles", () => {
    expect(() => assertCs07DcApiRequestBodyKeys({ profile: "pid-basic", amount: "12.34" }, "presentation"))
      .to.throw(Cs07DcApiResponseError, /Only profile and sessionId/);
    expect(() => assertCs07DcApiRequestBodyKeys({ profile: "ts12-payment", amount: "12.34" }, "ts12-payment"))
      .to.not.throw();
    expect(() => assertCs07DcApiRequestBodyKeys({ profile: "ts12-payment", extra: true }, "ts12-payment"))
      .to.throw(Cs07DcApiResponseError, /Unsupported CS-07 request field/);
  });

  it("builds SCA DCQL and encoded payment transaction_data for a specific amount", () => {
    const built = buildCs07Ts12PaymentRequest(paymentInput, dpcDcql);
    expect(built.attestationType.id).to.equal("sca-card-dpc");
    expect(built.attestationType.vct).to.equal(TS12_SCA_CARD_DPC_VCT);
    expect(built.dcqlQuery).to.deep.equal(dpcDcql);
    expect(built.paymentPayload.amount).to.equal(12.34);
    expect(built.paymentPayload.currency).to.equal("EUR");
    expect(built.transactionDataObj.type).to.equal(TS12_PAYMENT_TRANSACTION_TYPE);
    expect(built.transactionDataObj.credential_ids).to.deep.equal(["sca_card_dpc"]);
    const decoded = JSON.parse(Buffer.from(built.encodedTransactionData, "base64url").toString("utf8"));
    expect(decoded.payload.amount).to.equal(12.34);
    expect(decoded.payload.transaction_id).to.equal("tx-dc-api-1");
  });

  it("keeps DPC plus default PID when the combined profile DCQL is supplied", () => {
    const built = buildCs07Ts12PaymentRequest(paymentInput, dpcPidDcql);
    expect(built.attestationType.vct).to.equal(TS12_SCA_CARD_DPC_VCT);
    expect(built.dcqlQuery.credentials).to.have.length(2);
    expect(built.dcqlQuery.credentials[1].meta.vct_values).to.deep.equal([TS12_PID_VCT]);
    expect(built.transactionDataObj.credential_ids).to.deep.equal(["sca_card_dpc"]);
  });

  it("uses the profile DCQL for IBAN and user payment presentations", () => {
    const iban = buildCs07Ts12PaymentRequest({ ...paymentInput, profile: "ts12-iban" }, ibanDcql);
    expect(iban.attestationType.id).to.equal("sca-iban");
    expect(iban.attestationType.vct).to.equal(TS12_SCA_IBAN_VCT);
    expect(iban.dcqlQuery).to.deep.equal(ibanDcql);
    expect(iban.transactionDataObj.credential_ids).to.deep.equal(["sca_iban"]);

    const userPid = buildCs07Ts12PaymentRequest({ ...paymentInput, profile: "ts12-user-pid" }, userPidDcql);
    expect(userPid.attestationType.vct).to.equal(TS12_SCA_USER_VCT);
    expect(userPid.dcqlQuery.credentials).to.have.length(2);
    expect(userPid.transactionDataObj.credential_ids).to.deep.equal(["sca_user"]);
  });

  it("falls back to attestation_type DCQL when no profile query is supplied", () => {
    const iban = buildCs07Ts12PaymentRequest({ ...paymentInput, attestation_type: "sca-iban" });
    expect(iban.attestationType.vct).to.equal(TS12_SCA_IBAN_VCT);
    expect(iban.dcqlQuery).to.deep.equal(buildTs12DcqlQuery("sca-iban"));
    const user = buildCs07Ts12PaymentRequest({ ...paymentInput, attestation_type: "sca-user" });
    expect(user.attestationType.vct).to.equal(TS12_SCA_USER_VCT);
  });

  it("embeds the payment transaction_data in a dc_api.jwt request JWT", async () => {
    const previous = { ...process.env };
    process.env.CS03_COMPATIBILITY = "false";
    process.env.DC_API_VERIFIER_ORIGIN = "https://verifier.example";
    try {
      const built = buildCs07Ts12PaymentRequest(paymentInput, dpcDcql);
      const requestJwt = await buildVpRequestJWT(
        "x509_san_dns:verifier.example",
        null,
        null,
        null,
        { client_name: "Verifier" },
        null,
        "https://verifier.example",
        "vp_token",
        "nonce-ts12-dc-api",
        built.dcqlQuery,
        [built.encodedTransactionData],
        "dc_api.jwt",
        undefined,
        undefined,
        null,
        null,
        null,
        "ES256",
        true,
        "https://rp.example",
      );
      const payload = jose.decodeJwt(requestJwt);
      expect(payload.response_mode).to.equal("dc_api.jwt");
      expect(payload.aud).to.equal("https://self-issued.me/v2");
      expect(payload.dcql_query).to.deep.equal(built.dcqlQuery);
      expect(payload.transaction_data).to.deep.equal([built.encodedTransactionData]);
      const decodedTx = JSON.parse(Buffer.from(payload.transaction_data[0], "base64url").toString("utf8"));
      expect(decodedTx.payload.amount).to.equal(12.34);
      expect(decodedTx.type).to.equal(TS12_PAYMENT_TRANSACTION_TYPE);
    } finally {
      process.env = previous;
    }
  });

  it("rejects a DC API TS12 presentation when the transaction_data hash does not match", () => {
    const built = buildCs07Ts12PaymentRequest(paymentInput, dpcDcql);
    const result = validateTs12PaymentPresentationResponse({
      kbPayload: {
        jti: "auth-code-dc-api",
        response_mode: "dc_api.jwt",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: ["wrong-hash"],
        transaction_data_hashes_alg: "sha-256",
      },
      extractedClaims: [{ vct: TS12_SCA_CARD_DPC_VCT, card_id: "****" }],
      vpSession: {
        ts12_payment: true,
        response_mode: "dc_api.jwt",
        transaction_data: [built.encodedTransactionData],
        ts12_expected_vct: TS12_SCA_CARD_DPC_VCT,
        client_id: "x509_san_dns:verifier.example",
      },
    });
    expect(result.ok).to.equal(false);
    expect(result.code).to.equal("transaction_data_hash_mismatch");
  });

  it("accepts a DC API TS12 presentation without transaction_data_hashes when WALTID_DEMO is enabled", () => {
    const built = buildCs07Ts12PaymentRequest(paymentInput, dpcDcql);
    const result = validateTs12PaymentPresentationResponse({
      kbPayload: { nonce: "n1", aud: "origin:https://rp.example" },
      extractedClaims: [{ vct: TS12_SCA_CARD_DPC_VCT, card_id: "****" }],
      vpSession: {
        ts12_payment: true,
        response_mode: "dc_api.jwt",
        transaction_data: [built.encodedTransactionData],
        ts12_expected_vct: TS12_SCA_CARD_DPC_VCT,
        client_id: "x509_san_dns:verifier.example",
      },
      options: { waltidDemo: true },
    });
    expect(result.ok).to.equal(true);
  });

  it("rejects a DC API TS12 presentation of the wrong SCA attestation type", () => {
    const built = buildCs07Ts12PaymentRequest(paymentInput, dpcDcql);
    const hash = computeTs12TransactionDataHash(built.encodedTransactionData);
    const result = validateTs12PaymentPresentationResponse({
      kbPayload: {
        jti: "auth-code-wrong-vct",
        response_mode: "dc_api.jwt",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
        transaction_data_hashes_alg: "sha-256",
      },
      extractedClaims: [{ vct: TS12_SCA_USER_VCT, masked_psu_id: "psu-*" }],
      vpSession: {
        ts12_payment: true,
        response_mode: "dc_api.jwt",
        transaction_data: [built.encodedTransactionData],
        ts12_expected_vct: TS12_SCA_CARD_DPC_VCT,
        client_id: "x509_san_dns:verifier.example",
      },
    });
    expect(result.ok).to.equal(false);
    expect(result.code).to.equal("missing_sca_credential");
  });

  it("extracts KB-JWT claims from a CS-07 vp_token for TS12 checks", () => {
    const issuer = `header.${Buffer.from(JSON.stringify({ vct: "test" })).toString("base64url")}.sig`;
    const kbPayload = { jti: "auth-1", response_mode: "dc_api.jwt" };
    const kb = `header.${Buffer.from(JSON.stringify(kbPayload)).toString("base64url")}.sig`;
    const artifacts = extractTs12PresentationArtifactsFromVpToken({
      sca_iban: `${issuer}~${kb}`,
    });
    expect(artifacts.kbPayload).to.include(kbPayload);
  });
});
