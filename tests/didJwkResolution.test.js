import assert from "assert";
import { didKeyToJwks, parseDidJwk } from "../utils/cryptoUtils.js";

describe("did:jwk resolution", () => {
  it("strips the fragment before decoding the embedded JWK", async () => {
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: "UMLL2iqrq_gSh6JqSsIJq36n7z3lvVLIZUP1vrFIDBE",
      y: "oksScBhuH7NFOaCY7plj5y0DBM9wFoiLMZ70F_udtEM",
      use: "sig",
      alg: "ES256",
    };
    const did = `did:jwk:${Buffer.from(JSON.stringify(jwk)).toString("base64url")}#0`;

    const jwks = await didKeyToJwks(did);

    assert.deepStrictEqual(jwks, { keys: [jwk] });
  });

  it("strips an encoded fragment before decoding the embedded JWK", () => {
    const jwk = {
      alg: "ES256",
      use: "sig",
      kty: "EC",
      crv: "P-256",
      x: "UMLL2iqrq_gSh6JqSsIJq36n7z3lvVLIZUP1vrFIDBE",
      y: "oksScBhuH7NFOaCY7plj5y0DBM9wFoiLMZ70F_udtEM",
    };
    const did = `did:jwk:${Buffer.from(JSON.stringify(jwk)).toString("base64url")}%230`;

    assert.deepStrictEqual(parseDidJwk(did), jwk);
  });
});
