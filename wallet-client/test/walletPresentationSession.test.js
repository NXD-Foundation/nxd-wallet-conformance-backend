import assert from "assert";
import { buildWalletPresentationSessionRecord } from "../src/lib/cache.js";

describe("wallet presentation session record (P1-W-11)", () => {
  it("stores RFC002 fields and normalizes response_mode from response_uri", () => {
    const rec = buildWalletPresentationSessionRecord(
      {
        client_id: "rp-1",
        response_uri: "https://rp.example/direct_post.jwt/callback",
        response_mode: "direct_post",
        nonce: "n1",
        state: "s1",
        dcql_query: { credentials: [] },
        transaction_data: ["e30"],
      },
      "deep-link-fallback",
    );
    assert.strictEqual(rec.client_id, "rp-1");
    assert.strictEqual(
      rec.response_uri,
      "https://rp.example/direct_post.jwt/callback",
    );
    assert.strictEqual(rec.response_mode, "direct_post.jwt");
    assert.strictEqual(rec.nonce, "n1");
    assert.strictEqual(rec.state, "s1");
    assert.ok(rec.dcql_query);
    assert.ok(Array.isArray(rec.transaction_data));
    assert.ok(rec.updatedAt);
  });

  it("falls back to deep-link client_id when payload omits it", () => {
    const rec = buildWalletPresentationSessionRecord(
      {
        response_uri: "https://rp.example/cb",
        nonce: "n",
      },
      "did:example:wallet",
    );
    assert.strictEqual(rec.client_id, "did:example:wallet");
  });
});
