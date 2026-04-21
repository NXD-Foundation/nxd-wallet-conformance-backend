import assert from "assert";
import { buildWalletMetadataForVpRequest } from "../src/lib/presentation.js";

describe("P2-W-6 wallet_metadata for request_uri POST", () => {
  it("buildWalletMetadataForVpRequest sets formats, response modes, JWE prefs, enc JWK, and mdoc nonce", () => {
    const publicJwk = {
      kty: "EC",
      crv: "P-256",
      x: "test-x",
      y: "test-y",
      alg: "ES256",
    };
    const nonce = "mdoc-nonce-abc";
    const meta = buildWalletMetadataForVpRequest({
      publicJwk,
      mdocGeneratedNonce: nonce,
    });

    assert.deepStrictEqual(meta.vp_formats_supported, [
      "jwt_vp",
      "dc+sd-jwt",
      "vc+sd-jwt",
      "mso_mdoc",
    ]);
    assert.deepStrictEqual(meta.response_modes_supported, [
      "direct_post",
      "direct_post.jwt",
    ]);
    assert.strictEqual(meta.authorization_encryption_alg_values_supported[0], "ECDH-ES+A256KW");
    assert.strictEqual(meta.authorization_encryption_enc_values_supported[0], "A256GCM");
    assert.strictEqual(meta.mdoc_generated_nonce, nonce);

    assert.ok(meta.jwks?.keys?.length === 1);
    const enc = meta.jwks.keys[0];
    assert.strictEqual(enc.use, "enc");
    assert.strictEqual(enc.kty, "EC");
    assert.strictEqual(enc.crv, "P-256");
    assert.strictEqual(enc.x, "test-x");
    assert.strictEqual(enc.y, "test-y");
    assert.strictEqual(enc.alg, undefined);
  });

  it("omits mdoc_generated_nonce when not provided", () => {
    const meta = buildWalletMetadataForVpRequest({
      publicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    });
    assert.strictEqual(meta.mdoc_generated_nonce, undefined);
  });
});
