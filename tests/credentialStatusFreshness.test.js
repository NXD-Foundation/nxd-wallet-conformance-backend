import { expect } from "chai";
import {
  CredentialStatusFreshnessError,
  evaluateCredentialStatusFreshness,
} from "../utils/credentialStatusFreshness.js";

describe("credential status freshness", () => {
  const fetchedAt = 1_000_000;

  it("caps cache lifetime at ttl and does not add clock skew", () => {
    const freshness = evaluateCredentialStatusFreshness({
      iat: fetchedAt,
      exp: fetchedAt + 3600,
      ttl: 60,
      fetchedAt,
      now: fetchedAt,
    });

    expect(freshness.clockSkewSeconds).to.equal(60);
    expect(freshness.cacheUntil).to.equal(fetchedAt + 60);
    expect(freshness.cacheable).to.equal(true);
  });

  it("uses 60 seconds when ttl is absent and still excludes skew", () => {
    const freshness = evaluateCredentialStatusFreshness({
      iat: fetchedAt,
      exp: fetchedAt + 3600,
      fetchedAt,
      now: fetchedAt,
    });
    expect(freshness.ttlSeconds).to.equal(60);
    expect(freshness.cacheUntil).to.equal(fetchedAt + 60);
  });

  it("stops the cache at exp when that is earlier than ttl plus skew", () => {
    const freshness = evaluateCredentialStatusFreshness({
      iat: fetchedAt - 20,
      exp: fetchedAt + 10,
      ttl: 60,
      fetchedAt,
      now: fetchedAt,
    });
    expect(freshness.cacheUntil).to.equal(fetchedAt + 10);
  });

  it("accepts an exp inside clock skew without extending the cache past exp", () => {
    const freshness = evaluateCredentialStatusFreshness({
      iat: fetchedAt - 120,
      exp: fetchedAt - 30,
      ttl: 60,
      fetchedAt,
      now: fetchedAt,
    });
    expect(freshness.acceptedNow).to.equal(true);
    expect(freshness.cacheUntil).to.equal(fetchedAt - 30);
    expect(freshness.cacheable).to.equal(false);
  });

  it("rejects an exp outside the skew window", () => {
    try {
      evaluateCredentialStatusFreshness({
        iat: fetchedAt - 300,
        exp: fetchedAt - 61,
        ttl: 60,
        fetchedAt,
        now: fetchedAt,
      });
      expect.fail("expected a stale status list");
    } catch (error) {
      expect(error).to.be.instanceOf(CredentialStatusFreshnessError);
      expect(error.reason).to.equal("stale");
    }
  });

  it("rejects a malformed ttl", () => {
    expect(() => evaluateCredentialStatusFreshness({
      iat: fetchedAt,
      exp: fetchedAt + 300,
      ttl: 60.5,
      fetchedAt,
      now: fetchedAt,
    })).to.throw(CredentialStatusFreshnessError, /ttl/);
  });

  it("caps a long ttl at five minutes", () => {
    const freshness = evaluateCredentialStatusFreshness({
      iat: fetchedAt,
      exp: fetchedAt + 86_400,
      ttl: 1000,
      fetchedAt,
      now: fetchedAt,
    });
    expect(freshness.cacheUntil).to.equal(fetchedAt + 300);
  });
});
