import { expect } from "chai";
import fs from "fs";
import path from "path";
import { SignJWT, importPKCS8, exportJWK, generateKeyPair } from "jose";
import {
  Cs02ValidationError,
  CS02_JAR_TYP,
  CS02_REQUEST_URI_CONTENT_TYPE,
  resolveCs02ValidationOptions,
  validateCs02DeepLink,
  validateCs02RequestUri,
  validateCs02RequestUriMethod,
  validateCs02RequestUriResponseContentType,
  validateCs02JarHeader,
  validateCs02JarPayload,
  validateCs02ClientId,
  validateCs02DeepLinkClientIdConsistency,
  validateAndVerifyCs02AuthorizationRequest,
  parseCs02ClientIdScheme,
  decodeJarParts,
} from "../src/lib/cs02RequestValidation.js";
import { OPENID4VP_PRESENT_URI } from "../src/lib/openid4vpUri.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";
import { setCs02TrustPlaceholderRecorder } from "../../utils/cs02TrustPolicy.js";

const ecKeyPath = path.join(process.cwd(), "x509EC", "ec_private_pkcs8.key");
const ecCertPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");

function strictOptions(overrides = {}) {
  return {
    strict: true,
    allowHttp: false,
    allowLegacyInvocation: false,
    walletAudiences: ["https://self-issued.me/v2"],
    requestMaxLifetimeSec: 300,
    clockSkewSec: 300,
    ...overrides,
  };
}

function baseJarPayload(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    client_id: "x509_san_dns:verifier.example.org",
    nonce: "nonce-123",
    response_uri: "https://verifier.example/response",
    response_type: "vp_token",
    response_mode: "direct_post",
    state: "state-123",
    iat: now,
    exp: now + 120,
    aud: "https://self-issued.me/v2",
    dcql_query: {
      credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["example.v1"] } }],
    },
    ...overrides,
  };
}

async function signJar(payload, headerOverrides = {}, { includeX5c = true } = {}) {
  let privateKey;
  let header = {
    alg: "ES256",
    typ: CS02_JAR_TYP,
    ...headerOverrides,
  };

  if (fs.existsSync(ecKeyPath)) {
    privateKey = await importPKCS8(fs.readFileSync(ecKeyPath, "utf8"), "ES256");
    if (includeX5c && !header.x5c && fs.existsSync(ecCertPath)) {
      const pem = fs.readFileSync(ecCertPath, "utf8");
      const der = pem
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s+/g, "");
      header = { ...header, x5c: [der] };
    }
  } else {
    throw new Error("Missing x509EC test key material");
  }

  return new SignJWT(payload).setProtectedHeader(header).sign(privateKey);
}

describe("CS-02 wallet request validation (Phase 1)", () => {
  afterEach(() => {
    setCs02TrustPlaceholderRecorder(null);
  });

  describe("resolveCs02ValidationOptions", () => {
    it("is strict by default", () => {
      const options = resolveCs02ValidationOptions({});
      expect(options.strict).to.equal(true);
      expect(options.allowHttp).to.equal(false);
      expect(options.allowLegacyInvocation).to.equal(false);
    });

    it("allows compatibility mode when CS02_COMPATIBILITY=true", () => {
      const options = resolveCs02ValidationOptions({ CS02_COMPATIBILITY: "true" });
      expect(options.strict).to.equal(false);
    });

    it("forces strict mode for webuild-cs02 profile", () => {
      const options = resolveCs02ValidationOptions({
        WALLET_PROFILE: WALLET_PROFILES.WEBUILD_CS02,
        CS02_COMPATIBILITY: "true",
      });
      expect(options.strict).to.equal(true);
    });
  });

  describe("deep link validation", () => {
    it("accepts CS-02 openid4vp://present with HTTPS request_uri", () => {
      const deepLink = `${OPENID4VP_PRESENT_URI}?request_uri=${encodeURIComponent(
        "https://verifier.example/request",
      )}`;
      const parsed = validateCs02DeepLink(deepLink, strictOptions());
      expect(parsed.requestUri).to.equal("https://verifier.example/request");
      expect(parsed.method).to.equal("get");
    });

    it("rejects legacy bare openid4vp:// without override", () => {
      const deepLink = `openid4vp://?request_uri=${encodeURIComponent("https://verifier.example/request")}`;
      expect(() => validateCs02DeepLink(deepLink, strictOptions())).to.throw(Cs02ValidationError);
      try {
        validateCs02DeepLink(deepLink, strictOptions());
      } catch (error) {
        expect(error.errorCode).to.equal("invalid_request");
      }
    });

    it("allows legacy invocation when CS02_ALLOW_LEGACY_INVOCATION is set", () => {
      const deepLink = `openid4vp://?request_uri=${encodeURIComponent("https://verifier.example/request")}`;
      const parsed = validateCs02DeepLink(
        deepLink,
        strictOptions({ allowLegacyInvocation: true }),
      );
      expect(parsed.requestUri).to.equal("https://verifier.example/request");
    });

    it("rejects missing request_uri", () => {
      expect(() => validateCs02DeepLink(`${OPENID4VP_PRESENT_URI}?client_id=test`, strictOptions())).to.throw(
        Cs02ValidationError,
      );
    });

    it("rejects HTTP request_uri without override", () => {
      expect(() =>
        validateCs02RequestUri("http://localhost/request", strictOptions()),
      ).to.throw(Cs02ValidationError);
      try {
        validateCs02RequestUri("http://localhost/request", strictOptions());
      } catch (error) {
        expect(error.errorCode).to.equal("invalid_request_uri");
      }
    });

    it("allows HTTP request_uri when CS02_ALLOW_HTTP is set", () => {
      expect(() =>
        validateCs02RequestUri("http://localhost/request", strictOptions({ allowHttp: true })),
      ).to.not.throw();
    });
  });

  describe("request_uri_method and response content type", () => {
    it("accepts get and post", () => {
      expect(validateCs02RequestUriMethod("get")).to.equal("get");
      expect(validateCs02RequestUriMethod("POST")).to.equal("post");
    });

    it("rejects unsupported request_uri_method", () => {
      expect(() => validateCs02RequestUriMethod("put")).to.throw(Cs02ValidationError);
      try {
        validateCs02RequestUriMethod("put");
      } catch (error) {
        expect(error.errorCode).to.equal("invalid_request_uri_method");
      }
    });

    it("requires oauth-authz-req+jwt response content type", () => {
      expect(() => validateCs02RequestUriResponseContentType("application/json")).to.throw(
        Cs02ValidationError,
      );
      expect(() =>
        validateCs02RequestUriResponseContentType(CS02_REQUEST_URI_CONTENT_TYPE),
      ).to.not.throw();
    });
  });

  describe("JAR structure validation", () => {
    it("rejects alg=none", () => {
      expect(() => validateCs02JarHeader({ alg: "none", typ: CS02_JAR_TYP })).to.throw(Cs02ValidationError);
    });

    it("rejects RS256", () => {
      expect(() => validateCs02JarHeader({ alg: "RS256", typ: CS02_JAR_TYP })).to.throw(Cs02ValidationError);
    });

    it("rejects missing typ", () => {
      expect(() => validateCs02JarHeader({ alg: "ES256" })).to.throw(Cs02ValidationError);
    });

    it("rejects wrong typ", () => {
      expect(() => validateCs02JarHeader({ alg: "ES256", typ: "JWT" })).to.throw(Cs02ValidationError);
    });

    it("requires mandatory payload fields including dcql_query", () => {
      const payload = baseJarPayload();
      delete payload.dcql_query;
      expect(() => validateCs02JarPayload(payload, strictOptions())).to.throw(Cs02ValidationError);
    });

    it("requires response_type vp_token", () => {
      expect(() =>
        validateCs02JarPayload(baseJarPayload({ response_type: "code" }), strictOptions()),
      ).to.throw(Cs02ValidationError);
    });

    it("rejects expired JAR", () => {
      const now = Math.floor(Date.now() / 1000);
      expect(() =>
        validateCs02JarPayload(
          baseJarPayload({ iat: now - 600, exp: now - 300 }),
          strictOptions(),
        ),
      ).to.throw(Cs02ValidationError);
    });

    it("rejects unsupported client identifier schemes", () => {
      expect(() => validateCs02ClientId("redirect_uri:https://example.com/cb")).to.throw(
        Cs02ValidationError,
      );
      try {
        validateCs02ClientId("redirect_uri:https://example.com/cb");
      } catch (error) {
        expect(error.errorCode).to.equal("invalid_client");
      }
    });

    it("accepts CS-02 client identifier schemes", () => {
      expect(parseCs02ClientIdScheme("x509_san_dns:verifier.example.org").scheme).to.equal(
        "x509_san_dns",
      );
      expect(parseCs02ClientIdScheme("verifier_attestation:verifier-1").scheme).to.equal(
        "verifier_attestation",
      );
      expect(parseCs02ClientIdScheme("did:web:example.org").scheme).to.equal("did:web");
      expect(parseCs02ClientIdScheme("did:jwk:eyJrdHkiOiJFQyJ9").scheme).to.equal("did:jwk");
    });

    it("rejects deep-link client_id mismatch", () => {
      expect(() =>
        validateCs02DeepLinkClientIdConsistency(
          "x509_san_dns:a.example",
          "x509_san_dns:b.example",
        ),
      ).to.throw(Cs02ValidationError);
    });
  });

  describe("signature verification", () => {
    before(function () {
      if (!fs.existsSync(ecKeyPath)) {
        this.skip();
      }
    });

    it("accepts a valid ES256 x509_san_dns signed JAR", async () => {
      const records = [];
      setCs02TrustPlaceholderRecorder((record) => records.push(record));
      const requestJwt = await signJar(baseJarPayload());
      const verified = await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
        options: strictOptions(),
      });
      expect(verified.payload.response_type).to.equal("vp_token");
      expect(verified.header.typ).to.equal(CS02_JAR_TYP);
      expect(records.some((record) =>
        record.kind === "x509_san_dns" &&
        record.placeholder === true &&
        record.enforced === false
      )).to.equal(true);
    });

    it("accepts a valid did:jwk signed JAR", async () => {
      const privateKey = await importPKCS8(fs.readFileSync(ecKeyPath, "utf8"), "ES256");
      const publicJwk = await exportJWK(privateKey);
      delete publicJwk.d;
      const clientId = `did:jwk:${Buffer.from(JSON.stringify(publicJwk)).toString("base64url")}`;
      const requestJwt = await new SignJWT(baseJarPayload({ client_id: clientId }))
        .setProtectedHeader({ alg: "ES256", typ: CS02_JAR_TYP })
        .sign(privateKey);

      const verified = await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
        options: strictOptions(),
      });
      expect(verified.payload.client_id).to.equal(clientId);
    });

    it("rejects unsigned JAR bodies before credential lookup", async () => {
      const { header, payload } = decodeJarParts(await signJar(baseJarPayload()));
      const unsigned = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.`;
      try {
        await validateAndVerifyCs02AuthorizationRequest(unsigned, { options: strictOptions() });
        expect.fail("expected unsigned JAR rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
      }
    });

    it("rejects x509_san_dns JAR without x5c", async () => {
      const requestJwt = await signJar(baseJarPayload(), {}, { includeX5c: false });
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, { options: strictOptions() });
        expect.fail("expected missing x5c rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
      }
    });

    it("rejects verifier_attestation JAR without jwt header", async () => {
      const requestJwt = await signJar(
        baseJarPayload({ client_id: "verifier_attestation:verifier-1" }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, { options: strictOptions() });
        expect.fail("expected missing VA-JWT header rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
      }
    });

    it("invokes verifier_attestation placeholder when JOSE header jwt is present", async () => {
      const records = [];
      setCs02TrustPlaceholderRecorder((record) => records.push(record));
      const requestJwt = await signJar(
        baseJarPayload({ client_id: "verifier_attestation:verifier-1" }),
        { jwt: "header.payload.signature" },
      );

      const verified = await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
        options: strictOptions(),
      });

      expect(verified.payload.client_id).to.equal("verifier_attestation:verifier-1");
      expect(records.some((record) =>
        record.kind === "verifier_attestation" &&
        record.placeholder === true &&
        record.enforced === false &&
        record.hasJwtHeader === true
      )).to.equal(true);
    });
  });

  describe("did:web and did:jwk trust policy (Phase A)", () => {
    const didWebClientId = "did:web:example.org";
    const didWebKid = `${didWebClientId}#keys-1`;
    const alternateKid = `${didWebClientId}#keys-2`;

    let privateKey;
    let publicJwk;
    let alternateJwk;

    before(async function () {
      if (!fs.existsSync(ecKeyPath)) {
        this.skip();
      }
      privateKey = await importPKCS8(fs.readFileSync(ecKeyPath, "utf8"), "ES256");
      publicJwk = await exportJWK(privateKey);
      delete publicJwk.d;
      const alternateKeyPair = await generateKeyPair("ES256");
      alternateJwk = await exportJWK(alternateKeyPair.publicKey);
      delete alternateJwk.d;
    });

    function mockDidWebFetch(document) {
      return async () => ({
        ok: true,
        json: async () => document,
      });
    }

    function didWebDocument() {
      return {
        id: didWebClientId,
        verificationMethod: [
          { id: didWebKid, type: "JsonWebKey2020", publicKeyJwk: publicJwk },
          { id: alternateKid, type: "JsonWebKey2020", publicKeyJwk: alternateJwk },
        ],
      };
    }

    async function signDidWebJar(headerOverrides = {}) {
      return new SignJWT(baseJarPayload({ client_id: didWebClientId }))
        .setProtectedHeader({ alg: "ES256", typ: CS02_JAR_TYP, kid: didWebKid, ...headerOverrides })
        .sign(privateKey);
    }

    it("accepts a valid did:web signed JAR with exact kid", async () => {
      const requestJwt = await signDidWebJar();
      const verified = await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
        options: strictOptions({ fetchImpl: mockDidWebFetch(didWebDocument()) }),
      });
      expect(verified.payload.client_id).to.equal(didWebClientId);
      expect(verified.header.kid).to.equal(didWebKid);
    });

    it("rejects did:web JAR without kid", async () => {
      const requestJwt = await signDidWebJar({ kid: undefined });
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({ fetchImpl: mockDidWebFetch(didWebDocument()) }),
        });
        expect.fail("expected missing did:web kid rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
        expect(error.message).to.match(/kid/i);
      }
    });

    it("rejects did:web kid pointing to a different verification method", async () => {
      const requestJwt = await signDidWebJar({ kid: alternateKid });
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({ fetchImpl: mockDidWebFetch(didWebDocument()) }),
        });
        expect.fail("expected mismatched did:web kid rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
      }
    });

    it("rejects did:web kid belonging to a different DID than client_id", async () => {
      const attackerKid = "did:web:attacker.example#keys-1";
      const requestJwt = await signDidWebJar({ kid: attackerKid });
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({ fetchImpl: mockDidWebFetch(didWebDocument()) }),
        });
        expect.fail("expected cross-DID kid rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
        expect(error.message).to.match(/client_id DID/);
      }
    });

    it("rejects did:web documents whose id does not match client_id", async () => {
      const requestJwt = await signDidWebJar();
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({
            fetchImpl: mockDidWebFetch({ ...didWebDocument(), id: "did:web:attacker.example" }),
          }),
        });
        expect.fail("expected DID document id mismatch rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
        expect(error.message).to.match(/document id/);
      }
    });

    it("does not fall back to unrelated did:web verification methods", async () => {
      const requestJwt = await signDidWebJar();
      const onlyAlternateKeyDoc = {
        id: didWebClientId,
        verificationMethod: [
          { id: alternateKid, type: "JsonWebKey2020", publicKeyJwk: alternateJwk },
        ],
      };
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({ fetchImpl: mockDidWebFetch(onlyAlternateKeyDoc) }),
        });
        expect.fail("expected rejection without kid fallback");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
      }
    });

    it("rejects did:jwk client_id with non-P-256 key material", async () => {
      const rsaJwk = { kty: "RSA", n: "abc", e: "AQAB" };
      const clientId = `did:jwk:${Buffer.from(JSON.stringify(rsaJwk)).toString("base64url")}`;
      const requestJwt = await new SignJWT(baseJarPayload({ client_id: clientId }))
        .setProtectedHeader({ alg: "ES256", typ: CS02_JAR_TYP })
        .sign(privateKey);

      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, { options: strictOptions() });
        expect.fail("expected non-P-256 did:jwk rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.errorCode).to.equal("invalid_client");
        expect(error.message).to.match(/EC\/P-256/);
      }
    });
  });

  describe("client_metadata_uri policy (Phase B)", () => {
    const metadataUri = "https://verifier.example/client-metadata";

    function validRemoteMetadata(overrides = {}) {
      return {
        vp_formats_supported: {
          "dc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256"],
            "kb-jwt_alg_values": ["ES256"],
          },
        },
        jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def", use: "enc", kid: "remote" }] },
        ...overrides,
      };
    }

    function mockMetadataFetch(metadata, { contentType = "application/json", status = 200 } = {}) {
      return async () => ({
        ok: status >= 200 && status < 300,
        status,
        headers: {
          get: (name) => (String(name || "").toLowerCase() === "content-type" ? contentType : null),
        },
        text: async () => JSON.stringify(metadata),
      });
    }

    before(function () {
      if (!fs.existsSync(ecKeyPath)) {
        this.skip();
      }
    });

    it("rejects http:// client_metadata_uri in strict mode", async () => {
      const requestJwt = await signJar(
        baseJarPayload({
          client_metadata_uri: "http://verifier.example/client-metadata",
        }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, { options: strictOptions() });
        expect.fail("expected http client_metadata_uri rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.message).to.match(/HTTPS/);
      }
    });

    it("rejects relative client_metadata_uri in strict mode", async () => {
      const requestJwt = await signJar(
        baseJarPayload({ client_metadata_uri: "/client-metadata" }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, { options: strictOptions() });
        expect.fail("expected relative client_metadata_uri rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.message).to.match(/absolute URI/);
      }
    });

    it("rejects remote metadata with unsupported strict CS-02 formats", async () => {
      const requestJwt = await signJar(
        baseJarPayload({ client_metadata_uri: metadataUri }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({
            fetchImpl: mockMetadataFetch({
              vp_formats_supported: { "jwt_vc_json": { alg_values: ["ES256"] } },
            }),
          }),
        });
        expect.fail("expected unsupported remote vp format rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.message).to.match(/unsupported vp format/);
      }
    });

    it("rejects remote metadata with unsupported KB-JWT algs", async () => {
      const requestJwt = await signJar(
        baseJarPayload({ client_metadata_uri: metadataUri }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({
            fetchImpl: mockMetadataFetch({
              vp_formats_supported: {
                "dc+sd-jwt": {
                  "sd-jwt_alg_values": ["ES256"],
                  "kb-jwt_alg_values": ["ES384"],
                },
              },
            }),
          }),
        });
        expect.fail("expected unsupported remote KB-JWT alg rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.message).to.match(/unsupported KB-JWT alg/);
      }
    });

    it("rejects remote metadata advertising direct_post encryption settings", async () => {
      const requestJwt = await signJar(
        baseJarPayload({
          response_mode: "direct_post",
          client_metadata_uri: metadataUri,
        }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({
            fetchImpl: mockMetadataFetch({
              authorization_encrypted_response_alg: "ECDH-ES+A256KW",
            }),
          }),
        });
        expect.fail("expected direct_post encrypted metadata rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.message).to.match(/encrypted response settings/);
      }
    });

    it("rejects remote metadata advertising direct_post encrypted response alg/enc arrays", async () => {
      const requestJwt = await signJar(
        baseJarPayload({
          response_mode: "direct_post",
          client_metadata_uri: metadataUri,
        }),
      );
      try {
        await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
          options: strictOptions({
            fetchImpl: mockMetadataFetch({
              encrypted_response_alg_values_supported: ["ECDH-ES+A256KW"],
              encrypted_response_enc_values_supported: ["A256GCM"],
            }),
          }),
        });
        expect.fail("expected direct_post encrypted metadata arrays rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02ValidationError);
        expect(error.message).to.match(/encrypted response settings/);
      }
    });

    it("accepts valid HTTPS remote metadata with supported JWKs", async () => {
      const requestJwt = await signJar(
        baseJarPayload({ client_metadata_uri: metadataUri }),
      );
      const verified = await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
        options: strictOptions({
          fetchImpl: mockMetadataFetch(validRemoteMetadata()),
        }),
      });
      expect(verified.effectiveClientMetadata.jwks.keys[0].kid).to.equal("remote");
    });

    it("prefers inline client_metadata over client_metadata_uri metadata", async () => {
      const requestJwt = await signJar(
        baseJarPayload({
          client_metadata_uri: metadataUri,
          client_metadata: {
            jwks: { keys: [{ kid: "inline", kty: "EC", crv: "P-256", x: "abc", y: "def" }] },
          },
        }),
      );
      const verified = await validateAndVerifyCs02AuthorizationRequest(requestJwt, {
        options: strictOptions({
          fetchImpl: mockMetadataFetch(validRemoteMetadata()),
        }),
      });
      expect(verified.effectiveClientMetadata.jwks.keys[0].kid).to.equal("inline");
    });
  });
});
