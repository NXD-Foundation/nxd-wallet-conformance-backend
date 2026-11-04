import { expect } from "chai";
import { buildVPbyValue } from "../utils/tokenUtils.js";
import {
  OPENID4VP_PRESENT_HOST,
  OPENID4VP_PRESENT_QUERY_PREFIX,
  OPENID4VP_PRESENT_URI,
  isOpenId4VpDeepLink,
  isOpenId4VpPresentInvocation,
  parseOpenId4VpDeepLink,
} from "../src/lib/openid4vpUri.js";

describe("openid4vp URI helpers (local present convention)", () => {
  it("defines present authority constants", () => {
    expect(OPENID4VP_PRESENT_HOST).to.equal("present");
    expect(OPENID4VP_PRESENT_URI).to.equal("openid4vp://present");
    expect(OPENID4VP_PRESENT_QUERY_PREFIX).to.equal("openid4vp://present?");
  });

  describe("isOpenId4VpDeepLink", () => {
    it("matches openid4vp links with present and empty hostnames", () => {
      expect(isOpenId4VpDeepLink("openid4vp://present?request_uri=x")).to.equal(true);
      expect(isOpenId4VpDeepLink("openid4vp://?request_uri=x")).to.equal(true);
    });

    it("rejects non-openid4vp schemes", () => {
      expect(isOpenId4VpDeepLink("https://example.com")).to.equal(false);
      expect(isOpenId4VpDeepLink(null)).to.equal(false);
    });
  });

  describe("isOpenId4VpPresentInvocation", () => {
    it("is true for openid4vp://present authority", () => {
      const url = new URL("openid4vp://present?request_uri=https%3A%2F%2Fexample.com");
      expect(isOpenId4VpPresentInvocation(url)).to.equal(true);
    });

    it("is false for empty openid4vp:// authority", () => {
      const url = new URL("openid4vp://?request_uri=https%3A%2F%2Fexample.com");
      expect(isOpenId4VpPresentInvocation(url)).to.equal(false);
    });
  });

  describe("buildVPbyValue", () => {
    it("emits the local canonical openid4vp://present? form", () => {
      const link = buildVPbyValue(
        "verifier-client",
        null,
        "x509_hash",
        null,
        "https://verifier.example/response",
        "state-1",
      );

      expect(link.startsWith(OPENID4VP_PRESENT_QUERY_PREFIX)).to.equal(true);
      const url = new URL(link);
      expect(url.protocol).to.equal("openid4vp:");
      expect(url.hostname).to.equal("present");
      expect(url.searchParams.get("client_id")).to.equal("verifier-client");
      expect(url.searchParams.get("response_uri")).to.equal("https://verifier.example/response");
    });
  });
});


describe("presentation invocation query parsing", () => {
  const query = new URLSearchParams({
    client_id: "x509_hash:verifier-hash",
    request_uri: "https://verifier.example/request/123",
    request_uri_method: "post",
  }).toString();

  for (const scheme of ["openid4vp", "eu-eaap", "mdoc-openid4vp"]) {
    for (const host of ["", "present", "authorize", "another-invocation.example"]) {
      it(`resolves ${scheme} with hostname ${JSON.stringify(host)} from its query`, () => {
        expect(parseOpenId4VpDeepLink(`${scheme}://${host}?${query}`)).to.deep.equal({
          requestUri: "https://verifier.example/request/123",
          clientId: "x509_hash:verifier-hash",
          method: "post",
        });
      });
    }
  }

  it("defaults request retrieval to GET", () => {
    expect(parseOpenId4VpDeepLink("openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest").method).to.equal("get");
  });

  it("rejects unsupported schemes even with presentation query parameters", () => {
    expect(() => parseOpenId4VpDeepLink(`https://authorize?${query}`)).to.throw("Unsupported request scheme");
  });

  it("rejects malformed invocation URIs", () => {
    expect(() => parseOpenId4VpDeepLink("openid4vp://[invalid")).to.throw();
  });
});
