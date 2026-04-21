import assert from "assert";
import {
  normalizeDcqlCredentialFormat,
  storedRawMatchesDcqlEntry,
  filterSdJwtDisclosuresForDcqlClaims,
  normalizeDcqlClaimsToSegmentLists,
} from "../src/lib/presentation.js";

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

function minimalSdJwtWithVct(vct) {
  const header = b64urlJson({ alg: "ES256" });
  const payload = b64urlJson({ vct });
  return `${header}.${payload}.sig~disclosure`;
}

describe("DCQL vp_token helpers (P1-W-8)", () => {
  describe("normalizeDcqlCredentialFormat", () => {
    it("normalizes known formats", () => {
      assert.strictEqual(normalizeDcqlCredentialFormat("dc+sd-jwt"), "dc+sd-jwt");
      assert.strictEqual(normalizeDcqlCredentialFormat("MSO_MDOC"), "mso_mdoc");
      assert.strictEqual(normalizeDcqlCredentialFormat("  vc+sd-jwt "), "vc+sd-jwt");
    });
    it("returns null for empty input", () => {
      assert.strictEqual(normalizeDcqlCredentialFormat(""), null);
      assert.strictEqual(normalizeDcqlCredentialFormat(undefined), null);
    });
  });

  describe("storedRawMatchesDcqlEntry", () => {
    it("matches SD-JWT when vct_values includes credential vct", () => {
      const raw = minimalSdJwtWithVct("https://example.org/PID");
      const entry = {
        format: "dc+sd-jwt",
        meta: { vct_values: ["https://example.org/PID"] },
      };
      assert.strictEqual(
        storedRawMatchesDcqlEntry(entry, "pid_cfg", raw, "dc+sd-jwt"),
        true,
      );
    });

    it("rejects SD-JWT when vct_values is set but vct does not match", () => {
      const raw = minimalSdJwtWithVct("https://example.org/Other");
      const entry = {
        format: "dc+sd-jwt",
        meta: { vct_values: ["https://example.org/PID"] },
      };
      assert.strictEqual(
        storedRawMatchesDcqlEntry(entry, "pid_cfg", raw, "dc+sd-jwt"),
        false,
      );
    });

    it("allows SD-JWT when vct_values is absent", () => {
      const raw = minimalSdJwtWithVct("https://example.org/Anything");
      const entry = { format: "dc+sd-jwt", meta: {} };
      assert.strictEqual(
        storedRawMatchesDcqlEntry(entry, "cfg", raw, "dc+sd-jwt"),
        true,
      );
    });
  });

  describe("normalizeDcqlClaimsToSegmentLists", () => {
    it("accepts DCQL path objects, pointers, and plain claim names", () => {
      const lists = normalizeDcqlClaimsToSegmentLists([
        { path: ["given_name"] },
        { path: "/credentialSubject/family_name" },
        "birth_date",
      ]);
      assert.deepStrictEqual(lists, [
        ["given_name"],
        ["credentialSubject", "family_name"],
        ["birth_date"],
      ]);
    });
  });

  describe("filterSdJwtDisclosuresForDcqlClaims (P1-W-9)", () => {
    function minimalJwt() {
      const header = Buffer.from(JSON.stringify({ alg: "ES256" }), "utf8").toString(
        "base64url",
      );
      const payload = Buffer.from(JSON.stringify({ vct: "https://ex/PID" }), "utf8").toString(
        "base64url",
      );
      return `${header}.${payload}.sig`;
    }

    function disclosureSeg(claimName, value) {
      return Buffer.from(
        JSON.stringify(["salt", claimName, value]),
        "utf8",
      ).toString("base64url");
    }

    it("keeps only disclosures for requested claim keys", () => {
      const jwt = minimalJwt();
      const dGiven = disclosureSeg("given_name", "Jane");
      const dFamily = disclosureSeg("family_name", "Doe");
      const sd = `${jwt}~${dGiven}~${dFamily}`;
      const filtered = filterSdJwtDisclosuresForDcqlClaims(sd, {
        claims: [{ path: ["given_name"] }],
      });
      assert.strictEqual(filtered, `${jwt}~${dGiven}`);
    });

    it("leaves SD-JWT unchanged when claims are omitted", () => {
      const jwt = minimalJwt();
      const dGiven = disclosureSeg("given_name", "Jane");
      const sd = `${jwt}~${dGiven}`;
      assert.strictEqual(
        filterSdJwtDisclosuresForDcqlClaims(sd, { format: "dc+sd-jwt" }),
        sd,
      );
    });

    it("strips an existing KB JWT segment before filtering", () => {
      const jwt = minimalJwt();
      const dGiven = disclosureSeg("given_name", "Jane");
      const dFamily = disclosureSeg("family_name", "Doe");
      const fakeKb = [
        Buffer.from(JSON.stringify({ alg: "ES256" }), "utf8").toString("base64url"),
        Buffer.from(JSON.stringify({ nonce: "n" }), "utf8").toString("base64url"),
        "sig",
      ].join(".");
      const sd = `${jwt}~${dGiven}~${dFamily}~${fakeKb}`;
      const filtered = filterSdJwtDisclosuresForDcqlClaims(sd, {
        claims: [{ path: ["given_name"] }],
      });
      assert.strictEqual(filtered, `${jwt}~${dGiven}`);
    });

    it("throws when no disclosure matches requested claims", () => {
      const jwt = minimalJwt();
      const dFamily = disclosureSeg("family_name", "Doe");
      const sd = `${jwt}~${dFamily}`;
      assert.throws(
        () =>
          filterSdJwtDisclosuresForDcqlClaims(sd, {
            claims: [{ path: ["given_name"] }],
          }),
        /matched no disclosures/,
      );
    });
  });
});
