import { expect } from "chai";
import { buildVPbyValue } from "../utils/tokenUtils.js";
import {
  OPENID4VP_CS02_QUERY_PREFIX,
  OPENID4VP_CS02_URI,
  isOpenId4VpDeepLink,
  parseInvocationDeepLink,
} from "../src/lib/openid4vpUri.js";

describe("openid4vp URI helpers (CS-02 invocation)", () => {
  it("defines the empty-authority form used for generated links", () => {
    expect(OPENID4VP_CS02_URI).to.equal("openid4vp://");
    expect(OPENID4VP_CS02_QUERY_PREFIX).to.equal("openid4vp://?");
  });

  describe("isOpenId4VpDeepLink", () => {
    it("matches openid4vp://present and empty-authority links", () => {
      expect(isOpenId4VpDeepLink("openid4vp://present?request_uri=x")).to.equal(true);
      expect(isOpenId4VpDeepLink("openid4vp://?request_uri=x")).to.equal(true);
    });

    it("rejects non-openid4vp schemes", () => {
      expect(isOpenId4VpDeepLink("https://example.com")).to.equal(false);
      expect(isOpenId4VpDeepLink(null)).to.equal(false);
    });
  });

  describe("parseInvocationDeepLink", () => {
    const query = new URLSearchParams({
      client_id: "x509_hash:verifier-hash",
      request_uri: "https://verifier.example/request/123",
      request_uri_method: "post",
    }).toString();

    for (const scheme of ["openid4vp", "eu-eaap", "haip-vp"]) {
      for (const host of ["", "present", "authorize", "another-invocation.example"]) {
        it(`reads the query from ${scheme} with hostname ${JSON.stringify(host)}`, () => {
          const parsed = parseInvocationDeepLink(`${scheme}://${host}?${query}`);
          expect(parsed.requestUri).to.equal("https://verifier.example/request/123");
          expect(parsed.clientId).to.equal("x509_hash:verifier-hash");
          expect(parsed.method).to.equal("post");
        });
      }
    }

    it("defaults request retrieval to GET", () => {
      expect(
        parseInvocationDeepLink(
          "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest",
        ).method,
      ).to.equal("get");
    });

    it("rejects unsupported schemes", () => {
      expect(() => parseInvocationDeepLink(`https://authorize?${query}`)).to.throw(
        "Unsupported request scheme",
      );
    });

    it("rejects malformed invocation URIs", () => {
      expect(() => parseInvocationDeepLink("openid4vp://[invalid")).to.throw();
    });
  });

  describe("buildVPbyValue", () => {
    it("MUST emit openid4vp://? per CS-02 §8.1", () => {
      const link = buildVPbyValue(
        "verifier-client",
        null,
        "x509_hash",
        null,
        "https://verifier.example/response",
        "state-1",
      );

      expect(link.startsWith(OPENID4VP_CS02_QUERY_PREFIX)).to.equal(true);
      const url = new URL(link);
      expect(url.protocol).to.equal("openid4vp:");
      expect(url.hostname).to.equal("");
      expect(url.searchParams.get("client_id")).to.equal("verifier-client");
      expect(url.searchParams.get("response_uri")).to.equal("https://verifier.example/response");
    });
  });
});
