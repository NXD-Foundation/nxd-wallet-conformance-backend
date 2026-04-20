import { strict as assert } from "assert";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { expect } from "chai";
import jwt from "jsonwebtoken";
import {
  normalizeVpStateInput,
  evaluateDirectPostJwtStateCorrelation,
} from "../utils/vpSessionCorrelation.js";
import {
  patchVpSessionClientIdIfMissing,
  buildVpSessionRecordForStore,
} from "../utils/routeUtils.js";

const routeUtilsPath = fileURLToPath(new URL("../utils/routeUtils.js", import.meta.url));

describe("vpSessionCorrelation (direct_post.jwt state)", () => {
  describe("normalizeVpStateInput", () => {
    it("returns null for null, undefined, empty, whitespace", () => {
      assert.strictEqual(normalizeVpStateInput(null), null);
      assert.strictEqual(normalizeVpStateInput(undefined), null);
      assert.strictEqual(normalizeVpStateInput(""), null);
      assert.strictEqual(normalizeVpStateInput("   "), null);
    });

    it("trims and stringifies", () => {
      assert.strictEqual(normalizeVpStateInput("  abc  "), "abc");
      assert.strictEqual(normalizeVpStateInput(42), "42");
    });
  });

  describe("evaluateDirectPostJwtStateCorrelation", () => {
    const sessionState = "sess-state-7f3a";

    it("accepts when session has no bound state (legacy / test sessions)", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: null,
        sessionStateRaw: undefined,
      });
      assert.strictEqual(r.ok, true);
      assert.strictEqual(r.submittedState, null);
    });

    it("accepts matching state from form only (simulates outer JWT without state claim)", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: sessionState,
        outerJwtStateRaw: null,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
      assert.strictEqual(r.submittedState, sessionState);
    });

    it("accepts matching state from outer JWT only (encrypted-JWT-string / unencrypted branches)", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: sessionState,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
      assert.strictEqual(r.submittedState, sessionState);
    });

    it("accepts matching state from encrypted-object branch (payload.state)", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: sessionState,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
    });

    it("rejects when form and outer JWT state disagree", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: "a",
        outerJwtStateRaw: "b",
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, false);
      expect(r.error).to.match(/form body and response JWT/);
      assert.strictEqual(r.sessionError, "failed_correlation");
    });

    it("rejects missing state when session requires it", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: null,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, false);
      expect(r.error).to.match(/state missing/);
      assert.strictEqual(r.sessionError, "failed_correlation");
    });

    it("rejects wrong state when session requires it", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: "wrong",
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, false);
      expect(r.error).to.match(/state mismatch in direct_post\.jwt/);
      assert.strictEqual(r.sessionError, "failed_correlation");
    });

    it("prefers form state when only form matches session (outer empty)", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: sessionState,
        outerJwtStateRaw: null,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
    });
  });

  describe("outer JWT state extraction matches verifier branches (integration-style)", () => {
    const secret = "unit-test-secret";
    const sessionState = "corr-state-9e21";

    function stateFromEncryptedJwtStringBranch() {
      const inner = jwt.sign(
        { vp_token: "tok", state: sessionState, nonce: "n1" },
        secret,
        { algorithm: "HS256" }
      );
      return jwt.decode(inner)?.state ?? null;
    }

    function stateFromEncryptedObjectBranch() {
      return { vp_token: "tok", state: sessionState, nonce: "n1" }.state;
    }

    function stateFromUnencryptedBranch() {
      const outer = jwt.sign(
        { vp_token: "tok", state: sessionState, nonce: "n1" },
        secret,
        { algorithm: "HS256" }
      );
      return jwt.decode(outer)?.state ?? null;
    }

    it("encrypted JWT string path supplies state for correlation", () => {
      const outer = stateFromEncryptedJwtStringBranch();
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: outer,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
    });

    it("encrypted object path supplies state for correlation", () => {
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: stateFromEncryptedObjectBranch(),
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
    });

    it("unencrypted outer JWT path supplies state for correlation", () => {
      const outer = stateFromUnencryptedBranch();
      const r = evaluateDirectPostJwtStateCorrelation({
        formStateRaw: null,
        outerJwtStateRaw: outer,
        sessionStateRaw: sessionState,
      });
      assert.strictEqual(r.ok, true);
    });
  });
});

describe("VP session client_id persistence", () => {
  it("patchVpSessionClientIdIfMissing adds client_id when absent", () => {
    const session = { uuid: "s1", nonce: "n" };
    const { vpSession, didPatch } = patchVpSessionClientIdIfMissing(
      session,
      "x509_hash:new-id"
    );
    assert.strictEqual(didPatch, true);
    assert.strictEqual(vpSession.client_id, "x509_hash:new-id");
    assert.strictEqual(session.client_id, undefined, "does not mutate input");
  });

  it("patchVpSessionClientIdIfMissing skips when client_id already set", () => {
    const session = {
      uuid: "s2",
      client_id: "x509_hash:existing",
      nonce: "n",
    };
    const { vpSession, didPatch } = patchVpSessionClientIdIfMissing(
      session,
      "x509_hash:other"
    );
    assert.strictEqual(didPatch, false);
    assert.strictEqual(vpSession.client_id, "x509_hash:existing");
  });

  it("patchVpSessionClientIdIfMissing skips empty clientId", () => {
    const session = { uuid: "s3", nonce: "n" };
    const { vpSession, didPatch } = patchVpSessionClientIdIfMissing(session, "  ");
    assert.strictEqual(didPatch, false);
    assert.strictEqual(vpSession.client_id, undefined);
  });

  it("buildVpSessionRecordForStore preserves client_id and envelope fields", () => {
    const rec = buildVpSessionRecordForStore("sid-1", {
      client_id: "x509_hash:rec-test",
      nonce: "n",
      state: "st",
      response_mode: "direct_post.jwt",
    });
    assert.strictEqual(rec.uuid, "sid-1");
    assert.strictEqual(rec.client_id, "x509_hash:rec-test");
    assert.strictEqual(rec.nonce, "n");
    assert.strictEqual(rec.state, "st");
    assert.ok(rec.status);
    assert.strictEqual(rec.claims, null);
  });

  it("generateVPRequest session payload includes client_id (source contract)", () => {
    const src = readFileSync(routeUtilsPath, "utf8");
    const gIdx = src.indexOf("const sessionData = {");
    assert.ok(gIdx > 0, "expected generateVPRequest sessionData block");
    const block = src.slice(gIdx, gIdx + 400);
    assert.ok(
      block.includes("client_id: clientId"),
      "generateVPRequest must store client_id on the VP session"
    );
  });

  it("handleSessionCreation passes client_id into storeVPSessionData (source contract)", () => {
    const src = readFileSync(routeUtilsPath, "utf8");
    const hIdx = src.indexOf("export async function handleSessionCreation");
    assert.ok(hIdx > 0);
    const storeIdx = src.indexOf("await storeVPSessionData(sessionId,", hIdx);
    assert.ok(storeIdx > hIdx, "expected storeVPSessionData call in handleSessionCreation");
    const block = src.slice(storeIdx, storeIdx + 220);
    assert.ok(
      block.includes("client_id: clientId"),
      "handleSessionCreation must forward client_id into stored session"
    );
  });
});
