import { expect } from "chai";
import { buildVPbyValue } from "../utils/tokenUtils.js";
import {
  OPENID4VP_CS02_QUERY_PREFIX,
  OPENID4VP_CS02_URI,
  OPENID4VP_PRESENT_HOST,
  OPENID4VP_PRESENT_QUERY_PREFIX,
  OPENID4VP_PRESENT_URI,
  isOpenId4VpDeepLink,
  isOpenId4VpEmptyAuthorityInvocation,
  isOpenId4VpPresentInvocation,
} from "../src/lib/openid4vpUri.js";

describe("openid4vp URI helpers (CS-02 empty-authority invocation)", () => {
  it("defines CS-02 empty-authority and compatibility present constants", () => {
    expect(OPENID4VP_CS02_URI).to.equal("openid4vp://");
    expect(OPENID4VP_CS02_QUERY_PREFIX).to.equal("openid4vp://?");
    expect(OPENID4VP_PRESENT_HOST).to.equal("present");
    expect(OPENID4VP_PRESENT_URI).to.equal("openid4vp://present");
    expect(OPENID4VP_PRESENT_QUERY_PREFIX).to.equal("openid4vp://present?");
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

  describe("isOpenId4VpPresentInvocation", () => {
    it("is true for openid4vp://present authority", () => {
      const url = new URL("openid4vp://present?request_uri=https%3A%2F%2Fexample.com");
      expect(isOpenId4VpPresentInvocation(url)).to.equal(true);
    });

    it("is false for CS-02 empty-authority openid4vp://", () => {
      const url = new URL("openid4vp://?request_uri=https%3A%2F%2Fexample.com");
      expect(isOpenId4VpPresentInvocation(url)).to.equal(false);
      expect(isOpenId4VpEmptyAuthorityInvocation(url)).to.equal(true);
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
