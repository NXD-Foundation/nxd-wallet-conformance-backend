import { expect } from "chai";
import { isStrictCs02Base64Url, decodeStrictCs02Base64Url, isStrictCs02EcP256Jwk, canonicalizeCs02Json } from "../utils/cs02Encoding.js";

describe("CS-02 shared encoding helpers", () => {
  it("accepts unpadded base64url and decodes it", () => {
    expect(isStrictCs02Base64Url("SGVsbG8tXw")).to.equal(true);
    expect(decodeStrictCs02Base64Url("SGVsbG8tXw").toString()).to.equal("Hello-_");
  });

  it("rejects padded and non-string values", () => {
    expect(isStrictCs02Base64Url("abc=")).to.equal(false);
    expect(isStrictCs02Base64Url(42)).to.equal(false);
    expect(() => decodeStrictCs02Base64Url("abc=")).to.throw(TypeError);
  });

  it("shares the EC/P-256 JWK shape predicate", () => {
    expect(isStrictCs02EcP256Jwk({ kty: "EC", crv: "P-256" })).to.equal(true);
    expect(isStrictCs02EcP256Jwk({ kty: "RSA", crv: "P-256" })).to.equal(false);
    expect(isStrictCs02EcP256Jwk({ kty: "EC", crv: "P-384" })).to.equal(false);
  });

  it("serializes JSON deterministically by sorting object keys", () => {
    expect(canonicalizeCs02Json({ z: 1, a: { y: true, x: 2 } })).to.equal('{"a":{"x":2,"y":true},"z":1}');
    expect(() => canonicalizeCs02Json({ invalid: undefined })).to.throw(TypeError);
  });
});
