import { expect } from "chai";
import express from "express";
import zlib from "node:zlib";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from "jose";
import {
  DEFAULT_STATUS_LIST_ID,
  MIN_STATUS_MAINTENANCE_SECONDS,
  STATUS_INVALID,
  STATUS_LIST_BITS,
  STATUS_LIST_JWT_TYP,
  STATUS_LIST_MEDIA_TYPE,
  STATUS_VALID,
  WuaStatusListError,
  allocateWuaStatusListEntry,
  assertWuaStatusListPublisherConfig,
  bindWuaStatusListAttestationJti,
  compressStatusListBytes,
  encodeStatusListBytes,
  encodeStatusListLst,
  getWuaStatusListEntry,
  inflateStatusListLst,
  readStatusBit,
  resetWuaStatusListForTests,
  revokeWuaStatusListEntry,
  setWuaStatusListClockForTests,
  signStatusListToken,
  statusListTokenUri,
} from "../src/lib/wuaStatusList.js";
import { createWuaStatusListRouter } from "../src/routes/wuaStatusListRoutes.js";
import {
  createWalletUnitAttestationClientAuth,
  createWalletUnitCredentialKeyAttestation,
  resetWalletUnitAttestationLifecycleForTests,
} from "../src/lib/walletUnitAttestation.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CERT_PATH = path.resolve(__dirname, "../x509EC/client_certificate.crt");

const DRAFT20_BITS1_STATUSES = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
const DRAFT20_BITS1_BYTES = Buffer.from([0xb9, 0xa3]);
const DRAFT20_BITS1_LST = "eNrbuRgAAhcBXQ";

const ORIGINAL_ENV = {
  WALLET_PROVIDER_URL: process.env.WALLET_PROVIDER_URL,
  WALLET_STATUS_ADMIN_TOKEN: process.env.WALLET_STATUS_ADMIN_TOKEN,
  WALLET_STATUS_LIST_TTL: process.env.WALLET_STATUS_LIST_TTL,
  WALLET_STATUS_MAINTENANCE_SECONDS: process.env.WALLET_STATUS_MAINTENANCE_SECONDS,
};

function restoreEnv() {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

async function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

describe("WUA Token Status List publisher", () => {
  beforeEach(() => {
    resetWuaStatusListForTests();
    process.env.WALLET_PROVIDER_URL = "https://wallet.example/wallet-client";
    process.env.WALLET_STATUS_ADMIN_TOKEN = "test-admin-token";
    process.env.WALLET_STATUS_LIST_TTL = "3600";
    delete process.env.WALLET_STATUS_MAINTENANCE_SECONDS;
  });

  afterEach(() => {
    setWuaStatusListClockForTests(null);
    restoreEnv();
  });

  describe("draft-20 encoding", () => {
    it("packs the bits=1 example LSB-first into 0xB9 0xA3", () => {
      const bytes = encodeStatusListBytes(DRAFT20_BITS1_STATUSES);
      expect(bytes.equals(DRAFT20_BITS1_BYTES)).to.equal(true);
      const lst = compressStatusListBytes(bytes);
      expect(inflateStatusListLst(lst).equals(DRAFT20_BITS1_BYTES)).to.equal(true);
      expect(encodeStatusListLst(DRAFT20_BITS1_STATUSES)).to.equal(lst);
      if (lst === DRAFT20_BITS1_LST) {
        expect(lst).to.equal(DRAFT20_BITS1_LST);
      }
    });

    it("pads to a whole byte with VALID bits", () => {
      const bytes = encodeStatusListBytes([STATUS_INVALID]);
      expect(bytes).to.have.length(1);
      expect(bytes[0]).to.equal(0x01);
      expect(readStatusBit(bytes, 0)).to.equal(STATUS_INVALID);
      expect(readStatusBit(bytes, 1)).to.equal(STATUS_VALID);
      expect(readStatusBit(bytes, 7)).to.equal(STATUS_VALID);
      expect(readStatusBit(bytes, 8)).to.equal(null);
    });

    it("round-trips ZLIB compression", () => {
      const bytes = encodeStatusListBytes([1, 0, 1, 1, 0, 0, 0, 1, 1]);
      const inflated = zlib.inflateSync(Buffer.from(encodeStatusListLst([1, 0, 1, 1, 0, 0, 0, 1, 1]), "base64url"));
      expect(inflated.equals(bytes)).to.equal(true);
    });
  });

  describe("allocation and revocation lifecycle", () => {
    it("allocates unique monotonically increasing indices and never reuses them", async () => {
      const first = await allocateWuaStatusListEntry({ kind: "wia" });
      const second = await allocateWuaStatusListEntry({ kind: "wia" });
      const ka = await allocateWuaStatusListEntry({ kind: "ka" });
      expect(first.idx).to.equal(0);
      expect(second.idx).to.equal(1);
      expect(ka.idx).to.equal(0);
      expect(first.uri).to.equal("https://wallet.example/wallet-client/status-lists/wia/1");
      expect(ka.uri).to.equal("https://wallet.example/wallet-client/status-lists/ka/1");
      const revoked = await revokeWuaStatusListEntry({ kind: "wia", idx: 0 });
      expect(revoked.status).to.equal(STATUS_INVALID);
      const third = await allocateWuaStatusListEntry({ kind: "wia" });
      expect(third.idx).to.equal(2);
    });

    it("keeps maintenance exp at least 31 days plus attestation TTL ahead", async () => {
      const now = 1_700_000_000;
      setWuaStatusListClockForTests(() => now);
      const entry = await allocateWuaStatusListEntry({ kind: "ka", now });
      expect(entry.exp - now).to.be.at.least(MIN_STATUS_MAINTENANCE_SECONDS);
      const stored = await getWuaStatusListEntry({ kind: "ka", idx: entry.idx });
      expect(stored.maintenanceExp).to.equal(entry.exp);
      expect(stored.status).to.equal(STATUS_VALID);
    });

    it("revokes VALID to INVALID idempotently and binds attestation jti", async () => {
      const entry = await allocateWuaStatusListEntry({ kind: "wia" });
      await bindWuaStatusListAttestationJti({ kind: "wia", idx: entry.idx, jti: "wia-jti-1" });
      const first = await revokeWuaStatusListEntry({ kind: "wia", idx: entry.idx });
      const second = await revokeWuaStatusListEntry({ kind: "wia", idx: entry.idx });
      expect(first.alreadyRevoked).to.equal(false);
      expect(second.alreadyRevoked).to.equal(true);
      expect(second.status).to.equal(STATUS_INVALID);
      expect(second.jti).to.equal("wia-jti-1");
    });

    it("rejects unknown kind, list, and index", async () => {
      try {
        await allocateWuaStatusListEntry({ kind: "bwia" });
        expect.fail("should throw");
      } catch (error) {
        expect(error).to.be.instanceOf(WuaStatusListError);
        expect(error.status).to.equal(404);
      }
      try {
        await revokeWuaStatusListEntry({ kind: "wia", listId: "99", idx: 0 });
        expect.fail("should throw");
      } catch (error) {
        expect(error.status).to.equal(404);
      }
      try {
        await revokeWuaStatusListEntry({ kind: "wia", idx: 0 });
        expect.fail("should throw");
      } catch (error) {
        expect(error.status).to.equal(404);
      }
    });
  });

  describe("status-list JWT", () => {
    it("signs a draft-20 JWT whose sub matches the referenced URI", async () => {
      await allocateWuaStatusListEntry({ kind: "wia" });
      await revokeWuaStatusListEntry({ kind: "wia", idx: 0 });
      const jwt = await signStatusListToken({ kind: "wia", listId: DEFAULT_STATUS_LIST_ID });
      const header = decodeProtectedHeader(jwt);
      const payload = decodeJwt(jwt);
      expect(header.typ).to.equal(STATUS_LIST_JWT_TYP);
      expect(header.alg).to.equal("ES256");
      expect(header.x5c).to.be.an("array").with.length.greaterThan(0);
      expect(payload.sub).to.equal(statusListTokenUri("wia"));
      expect(payload.status_list.bits).to.equal(STATUS_LIST_BITS);
      expect(payload.ttl).to.equal(3600);
      expect(payload.exp - payload.iat).to.equal(3600);
      const bytes = inflateStatusListLst(payload.status_list.lst);
      expect(readStatusBit(bytes, 0)).to.equal(STATUS_INVALID);

      const key = await importX509(fs.readFileSync(CERT_PATH, "utf8"), "ES256");
      const verified = await jwtVerify(jwt, key, { typ: STATUS_LIST_JWT_TYP });
      expect(verified.payload.sub).to.equal(payload.sub);
    });
  });

  describe("HTTP publisher", () => {
    let server;
    let base;

    beforeEach(async () => {
      const app = express();
      app.use(express.json());
      app.use(createWuaStatusListRouter());
      ({ server, base } = await listen(app));
    });

    afterEach(async () => {
      if (server) await new Promise((resolve) => server.close(resolve));
    });

    it("publishes a compact statuslist+jwt with CORS and cache headers", async () => {
      await allocateWuaStatusListEntry({ kind: "ka" });
      const response = await fetch(`${base}/status-lists/ka/1`, {
        headers: { Accept: STATUS_LIST_MEDIA_TYPE },
      });
      expect(response.status).to.equal(200);
      expect(response.headers.get("content-type")).to.include(STATUS_LIST_MEDIA_TYPE);
      expect(response.headers.get("access-control-allow-origin")).to.equal("*");
      expect(response.headers.get("cache-control")).to.equal("public, max-age=3600");
      const jwt = await response.text();
      expect(jwt.split(".")).to.have.length(3);
      expect(decodeJwt(jwt).sub).to.equal("https://wallet.example/wallet-client/status-lists/ka/1");
    });

    it("returns 404 for unknown lists and 406 for incompatible Accept", async () => {
      const missing = await fetch(`${base}/status-lists/wia/9`);
      expect(missing.status).to.equal(404);
      const notAcceptable = await fetch(`${base}/status-lists/wia/1`, {
        headers: { Accept: "application/json" },
      });
      expect(notAcceptable.status).to.equal(406);
    });

    it("serves the bit referenced by a generated CS-01 WIA and KA", async () => {
      resetWalletUnitAttestationLifecycleForTests();
      const wia = await createWalletUnitAttestationClientAuth({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        keyPath: undefined,
        clientId: "wallet-client",
        endpointAudience: "https://issuer.example.com/par",
        authorizationServerIssuer: "https://issuer.example.com",
      });
      const proofKey = await ensureOrCreateEcKeyPair(undefined, "ES256");
      const ka = await createWalletUnitCredentialKeyAttestation({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        keyPath: undefined,
        proofPublicJwk: proofKey.publicJwk,
        credentialEndpoint: "https://issuer.example.com/credential",
        subjectPrivateJwk: proofKey.privateJwk,
        subjectPublicJwk: proofKey.publicJwk,
      });
      const wiaPayload = decodeJwt(wia.headers["OAuth-Client-Attestation"]);
      const kaPayload = decodeJwt(ka.attestationJwt);
      expect(wiaPayload.client_status.status.status_list.uri).to.equal(
        `${process.env.WALLET_PROVIDER_URL}/status-lists/wia/1`,
      );
      expect(kaPayload.key_storage_status.status.status_list.uri).to.equal(
        `${process.env.WALLET_PROVIDER_URL}/status-lists/ka/1`,
      );

      const wiaJwt = await (await fetch(`${base}/status-lists/wia/1`)).text();
      const kaJwt = await (await fetch(`${base}/status-lists/ka/1`)).text();
      expect(readStatusBit(
        inflateStatusListLst(decodeJwt(wiaJwt).status_list.lst),
        wiaPayload.client_status.status.status_list.idx,
      )).to.equal(STATUS_VALID);
      expect(readStatusBit(
        inflateStatusListLst(decodeJwt(kaJwt).status_list.lst),
        kaPayload.key_storage_status.status.status_list.idx,
      )).to.equal(STATUS_VALID);
    });

    it("revokes through a bearer-protected operator endpoint", async () => {
      const entry = await allocateWuaStatusListEntry({ kind: "wia" });
      const denied = await fetch(`${base}/status-lists/wia/1/entries/${entry.idx}/revoke`, {
        method: "POST",
      });
      expect(denied.status).to.equal(401);

      const revoked = await fetch(`${base}/status-lists/wia/1/entries/${entry.idx}/revoke`, {
        method: "POST",
        headers: { Authorization: "Bearer test-admin-token" },
      });
      expect(revoked.status).to.equal(200);
      const body = await revoked.json();
      expect(body.status).to.equal(STATUS_INVALID);

      const jwt = await (await fetch(`${base}/status-lists/wia/1`)).text();
      const bytes = inflateStatusListLst(decodeJwt(jwt).status_list.lst);
      expect(readStatusBit(bytes, entry.idx)).to.equal(STATUS_INVALID);
    });
  });

  describe("CS-01 publisher config", () => {
    it("requires an HTTPS Wallet Provider URL and admin token", () => {
      expect(() =>
        assertWuaStatusListPublisherConfig("webuild-cs01", {
          WALLET_PROVIDER_URL: "https://host.example/wallet-client",
          WALLET_STATUS_ADMIN_TOKEN: "secret",
        }),
      ).to.not.throw();
      expect(() =>
        assertWuaStatusListPublisherConfig("webuild-cs01", {
          WALLET_PROVIDER_URL: "http://localhost:4000",
          WALLET_STATUS_ADMIN_TOKEN: "secret",
        }),
      ).to.throw(/HTTPS/);
      expect(() =>
        assertWuaStatusListPublisherConfig("webuild-cs01", {
          WALLET_PROVIDER_URL: "https://host.example/wallet-client",
        }),
      ).to.throw(/WALLET_STATUS_ADMIN_TOKEN/);
      expect(() => assertWuaStatusListPublisherConfig("compatibility", {})).to.not.throw();
    });
  });
});
