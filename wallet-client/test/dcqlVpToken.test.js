import assert from "assert";
import { createHash } from "crypto";
import {
  normalizeDcqlCredentialFormat,
  storedRawMatchesDcqlEntry,
  filterSdJwtDisclosuresForDcqlClaims,
  normalizeDcqlClaimsToSegmentLists,
  appendDcqlVpToken,
} from "../src/lib/presentation.js";

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

function disclosureDigest(encodedDisclosure) {
  return createHash("sha256").update(encodedDisclosure, "ascii").digest("base64url");
}

function unsignedJwt(payload) {
  return `${b64urlJson({ alg: "none", typ: "dc+sd-jwt" })}.${b64urlJson(payload)}.sig`;
}

function disclosureSeg(claimName, value) {
  return b64urlJson(["salt", claimName, value]);
}

function minimalSdJwtWithVct(vct) {
  const header = b64urlJson({ alg: "ES256" });
  const payload = b64urlJson({ vct });
  return `${header}.${payload}.sig~disclosure`;
}

describe("DCQL vp_token helpers (P1-W-8)", () => {
  describe("appendDcqlVpToken", () => {
    it("builds the OpenID4VP DCQL object shape with arrays per query id", () => {
      const vpToken = {};
      appendDcqlVpToken(vpToken, "cmwallet", "sd-jwt-one");
      appendDcqlVpToken(vpToken, "cmwallet", "sd-jwt-two");
      appendDcqlVpToken(vpToken, "other", "mdoc-one");

      assert.deepStrictEqual(vpToken, {
        cmwallet: ["sd-jwt-one", "sd-jwt-two"],
        other: ["mdoc-one"],
      });
      assert.deepStrictEqual(JSON.parse(JSON.stringify(vpToken)), vpToken);
    });

    it("rejects malformed query ids and presentation values", () => {
      assert.throws(() => appendDcqlVpToken({}, "", "token"), /query id/);
      assert.throws(() => appendDcqlVpToken({}, "cmwallet", ""), /presentation/);
    });
  });

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
    function minimalSdJwtWithDisclosures(disclosures) {
      const digests = disclosures.map(disclosureDigest);
      const jwt = unsignedJwt({
        vct: "https://ex/PID",
        _sd_alg: "sha-256",
        _sd: digests,
      });
      return `${jwt}~${disclosures.join("~")}~`;
    }

    it("keeps only disclosures for requested claim keys", () => {
      const dGiven = disclosureSeg("given_name", "Jane");
      const dFamily = disclosureSeg("family_name", "Doe");
      const sd = minimalSdJwtWithDisclosures([dGiven, dFamily]);
      const filtered = filterSdJwtDisclosuresForDcqlClaims(sd, {
        claims: [{ path: ["given_name"] }],
      });
      assert.strictEqual(filtered, `${sd.split("~")[0]}~${dGiven}~`);
    });

    it("leaves SD-JWT unchanged when claims are omitted", () => {
      const dGiven = disclosureSeg("given_name", "Jane");
      const sd = minimalSdJwtWithDisclosures([dGiven]);
      assert.strictEqual(
        filterSdJwtDisclosuresForDcqlClaims(sd, { format: "dc+sd-jwt" }),
        sd,
      );
    });

    it("strips an existing KB JWT segment before filtering", () => {
      const dGiven = disclosureSeg("given_name", "Jane");
      const dFamily = disclosureSeg("family_name", "Doe");
      const fakeKb = unsignedJwt({ typ: "kb+jwt", nonce: "n" });
      const sd = `${minimalSdJwtWithDisclosures([dGiven, dFamily]).slice(0, -1)}~${fakeKb}`;
      const filtered = filterSdJwtDisclosuresForDcqlClaims(sd, {
        claims: [{ path: ["given_name"] }],
      });
      assert.strictEqual(filtered, `${sd.split("~")[0]}~${dGiven}~`);
    });

    it("throws when no disclosure matches requested claims", () => {
      const dFamily = disclosureSeg("family_name", "Doe");
      const sd = minimalSdJwtWithDisclosures([dFamily]);
      assert.throws(
        () =>
          filterSdJwtDisclosuresForDcqlClaims(sd, {
            claims: [{ path: ["given_name"] }],
          }),
        /missing requested DCQL disclosure/,
      );
    });
  });
});
