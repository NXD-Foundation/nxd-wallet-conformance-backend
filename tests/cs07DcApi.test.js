import { expect } from "chai";
import * as jose from "jose";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { validateCs02KeyBindingJwtClaims } from "../utils/cs02VerifierResponse.js";
import {
  buildCs07DigitalCredentialRequest,
  cs07ExpectedAudience,
  normalizeCs07DigitalCredentialResponse,
  parseCs07AuthorizationResponse,
  resolveCs07VerifierOrigin,
} from "../utils/cs07DcApi.js";
import { DEFAULT_DCQL_QUERY } from "../utils/routeUtils.js";
import { createDcApiVerifierClient, DcApiClientError } from "../clients/dc-api/rp-client.js";
import { validateCs07Config, resolveCs07Profile, mergeEnvRelyingParties } from "../utils/cs07Config.js";
import { validateCs07CredentialPresentations } from "../utils/cs07ResponseValidation.js";

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
      expect(payload).to.not.have.property("state");
      expect(payload).to.not.have.property("response_uri");
      expect(payload).to.not.have.property("aud");
    } finally {
      process.env = previous;
    }
  });
});
