import { expect } from "chai";
import * as jose from "jose";
import { fetchDocument } from "../trust/fetch.js";
import {
  applyWiaStatusEvidenceToSession,
  encodeStatusListBytes,
  encodeStatusListLst,
  evaluateWuaStatusList,
  inflateStatusListLst,
  parseReferencedTokenStatus,
  publicJwkOnly,
  readStatusBit,
  STATUS_INVALID,
  STATUS_LIST_MEDIA_TYPE,
  STATUS_SUSPENDED,
  STATUS_VALID,
  WuaStatusListValidationError,
  resetWuaStatusListVerifierForTests,
} from "../utils/wuaStatusListVerifier.js";
import {
  installStatusListTestHooks,
  installValidStatusListForKey,
  KA_STATUS_LIST_URI,
  PUBLIC_RESOLVE_HOSTNAME,
  resetStatusListTestHooks,
  signStatusListToken,
  stubStatusListFetch,
  WIA_STATUS_LIST_URI,
} from "./helpers/wuaStatusListFixtures.js";

const ALG = "ES256";

describe("WUA status-list verifier", () => {
  afterEach(() => {
    resetStatusListTestHooks();
    resetWuaStatusListVerifierForTests();
  });

  describe("draft-20 encoding", () => {
    it("packs LSB-first matching the draft-20 example bitstring", () => {
      const bits = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
      const bytes = encodeStatusListBytes(bits);
      expect(bytes[0]).to.equal(0xb9);
      expect(bytes[1]).to.equal(0xa3);
      expect(readStatusBit(bytes, 0)).to.equal(STATUS_INVALID);
      expect(readStatusBit(bytes, 1)).to.equal(STATUS_VALID);
      expect(readStatusBit(bytes, 15)).to.equal(STATUS_INVALID);
      expect(readStatusBit(bytes, 16)).to.equal(null);
    });

    it("packs LSB-first matching the draft-20 bits=2 example", () => {
      const statuses = [0x01, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x03];
      const bytes = encodeStatusListBytes(statuses, { bits: 2 });
      expect(bytes[0]).to.equal(0xc9);
      expect(bytes[1]).to.equal(0x44);
      expect(bytes[2]).to.equal(0xf9);
      expect(readStatusBit(bytes, 0, 2)).to.equal(STATUS_INVALID);
      expect(readStatusBit(bytes, 1, 2)).to.equal(STATUS_SUSPENDED);
      expect(readStatusBit(bytes, 2, 2)).to.equal(STATUS_VALID);
      expect(readStatusBit(bytes, 11, 2)).to.equal(0x03);
      expect(readStatusBit(bytes, 12, 2)).to.equal(null);
    });

    it("round-trips ZLIB lst compression", () => {
      const lst = encodeStatusListLst([0, 1, 0, 1]);
      const bytes = inflateStatusListLst(lst);
      expect(readStatusBit(bytes, 0)).to.equal(STATUS_VALID);
      expect(readStatusBit(bytes, 1)).to.equal(STATUS_INVALID);
    });
  });

  describe("parseReferencedTokenStatus", () => {
    it("accepts a complete HTTPS reference", () => {
      const parsed = parseReferencedTokenStatus(
        { status: { status_list: { uri: WIA_STATUS_LIST_URI, idx: 3 } }, exp: 99 },
        { required: true, kind: "wia" }
      );
      expect(parsed).to.include({ uri: WIA_STATUS_LIST_URI, idx: 3, exp: 99, incomplete: false });
    });

    it("throws when a required reference is incomplete", () => {
      expect(() =>
        parseReferencedTokenStatus(
          { status: { status_list: { uri: WIA_STATUS_LIST_URI } }, exp: 99 },
          { required: true, kind: "wia" }
        )
      ).to.throw(WuaStatusListValidationError, /non-negative integer idx/i);
    });

    it("throws when a required uri is not HTTPS", () => {
      expect(() =>
        parseReferencedTokenStatus(
          { status: { status_list: { uri: "http://wallet.example/status", idx: 0 } } },
          { required: true, kind: "ka" }
        )
      ).to.throw(WuaStatusListValidationError, /HTTPS/);
    });
  });

  describe("evaluateWuaStatusList", () => {
    async function signer() {
      const pair = await jose.generateKeyPair(ALG, { extractable: true });
      const publicJwk = publicJwkOnly(await jose.exportJWK(pair.publicKey));
      return { ...pair, publicJwk };
    }

    it("accepts a valid VALID bit signed by the Wallet Provider key", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      const result = await evaluateWuaStatusList({
        uri: WIA_STATUS_LIST_URI,
        idx: 0,
        verificationJwk: publicJwk,
        kind: "wia",
      });
      expect(result.ok).to.equal(true);
      expect(result.status).to.equal(STATUS_VALID);
      expect(result.sub).to.equal(WIA_STATUS_LIST_URI);
    });

    it("rejects a revoked INVALID bit", async () => {
      const { privateKey, publicJwk } = await signer();
      await installValidStatusListForKey({
        privateKey,
        uri: KA_STATUS_LIST_URI,
        statuses: [STATUS_INVALID],
      });
      try {
        await evaluateWuaStatusList({
          uri: KA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "ka",
        });
        expect.fail("expected revocation rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(WuaStatusListValidationError);
        expect(error.reason).to.equal("revoked");
        expect(error.message).to.match(/revoked/i);
      }
    });

    it("rejects a Status List Token signed by a different key", async () => {
      const { publicJwk } = await signer();
      const other = await jose.generateKeyPair(ALG, { extractable: true });
      const jwt = await signStatusListToken({
        privateKey: other.privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected signature rejection");
      } catch (error) {
        expect(error.reason).to.equal("signature_invalid");
      }
    });

    it("accepts a Status List Token signed by a header jwk distinct from the WIA key", async () => {
      const { publicJwk } = await signer();
      const statusSigner = await jose.generateKeyPair(ALG, { extractable: true });
      const statusPublicJwk = await jose.exportJWK(statusSigner.publicKey);
      const jwt = await signStatusListToken({
        privateKey: statusSigner.privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
        header: { jwk: { kty: statusPublicJwk.kty, crv: statusPublicJwk.crv, x: statusPublicJwk.x, y: statusPublicJwk.y } },
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      const result = await evaluateWuaStatusList({
        uri: WIA_STATUS_LIST_URI,
        idx: 0,
        verificationJwk: publicJwk,
        kind: "wia",
      });
      expect(result.ok).to.equal(true);
      expect(result.status).to.equal(STATUS_VALID);
      expect(result.verificationJwk.x).to.equal(statusPublicJwk.x);
    });

    it("rejects wrong typ", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
        typ: "jwt",
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected typ rejection");
      } catch (error) {
        expect(error.reason).to.match(/invalid_token|signature_invalid/);
      }
    });

    it("rejects sub mismatch", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        sub: "https://wallet-provider.example/status-lists/other/1",
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected sub mismatch");
      } catch (error) {
        expect(error.reason).to.equal("sub_mismatch");
      }
    });

    it("accepts a Status List Token without exp (draft-20 RECOMMENDED)", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
        omitExp: true,
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      const result = await evaluateWuaStatusList({
        uri: WIA_STATUS_LIST_URI,
        idx: 0,
        verificationJwk: publicJwk,
        kind: "wia",
      });
      expect(result.ok).to.equal(true);
      expect(result.status).to.equal(STATUS_VALID);
      expect(result.exp).to.equal(undefined);
    });

    it("rejects an expired Status List Token", async () => {
      const { privateKey, publicJwk } = await signer();
      const now = Math.floor(Date.now() / 1000);
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
        iat: now - 120,
        exp: now - 30,
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
          now,
          clockTolerance: 0,
        });
        expect.fail("expected expiry rejection");
      } catch (error) {
        expect(error.reason).to.equal("expired");
      }
    });

    it("rejects malformed compression", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        lst: "not-zlib",
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected malformed lst rejection");
      } catch (error) {
        expect(error.reason).to.equal("malformed_lst");
      }
    });

    it("accepts a bits=2 Status List Token when the indexed value is VALID", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        bits: 2,
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      const result = await evaluateWuaStatusList({
        uri: WIA_STATUS_LIST_URI,
        idx: 0,
        verificationJwk: publicJwk,
        kind: "wia",
      });
      expect(result.ok).to.equal(true);
      expect(result.status).to.equal(STATUS_VALID);
    });

    it("rejects a bits=2 INVALID value as revoked", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        bits: 2,
        statuses: [STATUS_INVALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected revoked rejection");
      } catch (error) {
        expect(error.reason).to.equal("revoked");
      }
    });

    it("rejects a bits=2 SUSPENDED value as not VALID", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        bits: 2,
        statuses: [STATUS_SUSPENDED],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected unexpected_status rejection");
      } catch (error) {
        expect(error.reason).to.equal("unexpected_status");
      }
    });

    it("rejects unsupported bits", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        bits: 3,
        lst: encodeStatusListLst([STATUS_VALID]),
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected bits rejection");
      } catch (error) {
        expect(error.reason).to.equal("unsupported_bits");
      }
    });

    it("rejects an out-of-range idx", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 16,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected idx rejection");
      } catch (error) {
        expect(error.reason).to.equal("idx_out_of_range");
      }
    });

    it("rejects an unexpected content type", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
      });
      installStatusListTestHooks({
        fetchImpl: stubStatusListFetch(jwt, { contentType: "application/json" }),
      });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected content-type rejection");
      } catch (error) {
        expect(error.reason).to.equal("invalid_media_type");
      }
    });

    it("rejects a private/reserved address", async () => {
      const { publicJwk } = await signer();
      installStatusListTestHooks({
        fetchImpl: async () => ({ ok: true, headers: { get: () => STATUS_LIST_MEDIA_TYPE }, arrayBuffer: async () => Buffer.from("a.b.c") }),
        resolveHostname: async () => [{ address: "127.0.0.1" }],
      });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected SSRF rejection");
      } catch (error) {
        expect(error.reason).to.equal("fetch_failed");
        expect(error.message).to.match(/private|reserved/i);
      }
    });

    it("rejects a response that exceeds the size limit", async () => {
      const { publicJwk } = await signer();
      installStatusListTestHooks({
        fetchImpl: async () => ({
          ok: true,
          headers: { get: () => STATUS_LIST_MEDIA_TYPE },
          arrayBuffer: async () => Buffer.alloc(64),
        }),
      });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
          maxBytes: 8,
        });
        expect.fail("expected size rejection");
      } catch (error) {
        expect(error.reason).to.equal("fetch_failed");
        expect(error.message).to.match(/size limit/i);
      }
    });

    it("follows an HTTPS redirect to the Status List Token", async () => {
      const { privateKey, publicJwk } = await signer();
      const jwt = await signStatusListToken({
        privateKey,
        uri: WIA_STATUS_LIST_URI,
        statuses: [STATUS_VALID],
      });
      const redirected = "https://cdn.wallet-provider.example/status-lists/wia/1";
      installStatusListTestHooks({
        fetchImpl: async (url) => {
          if (String(url) === WIA_STATUS_LIST_URI) {
            return {
              ok: false,
              status: 302,
              headers: { get: (name) => (String(name).toLowerCase() === "location" ? redirected : null) },
              arrayBuffer: async () => Buffer.from(""),
            };
          }
          expect(String(url)).to.equal(redirected);
          return {
            ok: true,
            status: 200,
            headers: { get: (name) => (String(name).toLowerCase() === "content-type" ? STATUS_LIST_MEDIA_TYPE : null) },
            arrayBuffer: async () => Buffer.from(jwt, "utf8"),
          };
        },
      });
      const result = await evaluateWuaStatusList({
        uri: WIA_STATUS_LIST_URI,
        idx: 0,
        verificationJwk: publicJwk,
        kind: "wia",
      });
      expect(result.ok).to.equal(true);
      expect(result.status).to.equal(STATUS_VALID);
    });

    it("rejects an HTTPS redirect to a private address", async () => {
      const { publicJwk } = await signer();
      installStatusListTestHooks({
        fetchImpl: async () => ({
          ok: false,
          status: 302,
          headers: { get: (name) => (String(name).toLowerCase() === "location" ? "https://evil.example/list" : null) },
        }),
        resolveHostname: async (hostname) => {
          if (String(hostname) === "evil.example") return [{ address: "127.0.0.1" }];
          return [{ address: "1.1.1.1" }];
        },
      });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected private redirect rejection");
      } catch (error) {
        expect(error.reason).to.equal("fetch_failed");
        expect(error.message).to.match(/private|reserved/i);
      }
    });

    it("rejects an HTTP redirect target", async () => {
      const { publicJwk } = await signer();
      installStatusListTestHooks({
        fetchImpl: async () => ({
          ok: false,
          status: 302,
          headers: { get: (name) => (String(name).toLowerCase() === "location" ? "http://wallet-provider.example/list" : null) },
        }),
      });
      try {
        await evaluateWuaStatusList({
          uri: WIA_STATUS_LIST_URI,
          idx: 0,
          verificationJwk: publicJwk,
          kind: "wia",
        });
        expect.fail("expected http redirect rejection");
      } catch (error) {
        expect(error.reason).to.equal("fetch_failed");
        expect(error.message).to.match(/HTTP\(S\)/);
      }
    });
  });

  describe("session evidence", () => {
    it("stores only public JWK material", () => {
      const session = {};
      applyWiaStatusEvidenceToSession(session, {
        uri: WIA_STATUS_LIST_URI,
        idx: 2,
        exp: 99,
        wiaCnfJkt: "thumb",
        verificationJwk: { kty: "EC", crv: "P-256", x: "aa", y: "bb", d: "secret" },
      });
      expect(session.wiaStatusList.uri).to.equal(WIA_STATUS_LIST_URI);
      expect(session.wiaStatusList.idx).to.equal(2);
      expect(session.wiaCnfJkt).to.equal("thumb");
      expect(session.wiaStatusList.verificationJwk).to.deep.equal({
        kty: "EC",
        crv: "P-256",
        x: "aa",
        y: "bb",
      });
      expect(session.wiaStatusList.verificationJwk).to.not.have.property("d");
    });
  });
});

describe("trust fetch headers", () => {
  it("forwards request headers to fetchImpl", async () => {
    let seen;
    await fetchDocument("https://status.example/list", {
      resolveHostname: PUBLIC_RESOLVE_HOSTNAME,
      headers: { Accept: STATUS_LIST_MEDIA_TYPE },
      fetchImpl: async (url, init) => {
        seen = { url, init };
        return { ok: true, headers: { get: () => STATUS_LIST_MEDIA_TYPE }, arrayBuffer: async () => Buffer.from("ok") };
      },
    });
    expect(seen.init.headers.Accept).to.equal(STATUS_LIST_MEDIA_TYPE);
    expect(seen.init.redirect).to.equal("error");
  });
});
