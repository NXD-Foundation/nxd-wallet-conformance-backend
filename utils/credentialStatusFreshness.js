/**
 * Status-list freshness.
 *
 * Clock skew applies only when accepting iat and exp. Cache lifetime is the
 * earliest of exp, fetch time plus ttl, and a local five-minute maximum.
 * Skew is not added to that deadline. Absent ttl uses 60 seconds.
 */

export const STATUS_CLOCK_SKEW_SECONDS = 60;
export const STATUS_DEFAULT_TTL_SECONDS = 60;
export const STATUS_CACHE_MAX_SECONDS = 300;

export class CredentialStatusFreshnessError extends Error {
  constructor(message, reason = "malformed_freshness") {
    super(message);
    this.name = "CredentialStatusFreshnessError";
    this.reason = reason;
  }
}

function integerTimestamp(value, name) {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new CredentialStatusFreshnessError(`${name} must be an integer timestamp`);
  }
  return value;
}

export function evaluateCredentialStatusFreshness({
  iat,
  exp,
  ttl,
  fetchedAt,
  now = fetchedAt,
  clockSkewSeconds = STATUS_CLOCK_SKEW_SECONDS,
} = {}) {
  const issuedAt = integerTimestamp(iat, "iat");
  const fetched = integerTimestamp(fetchedAt, "fetchedAt");
  const current = integerTimestamp(now, "now");
  if (!Number.isInteger(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new CredentialStatusFreshnessError("clock skew must be a non-negative integer");
  }

  let expiresAt = null;
  if (exp !== undefined && exp !== null) {
    expiresAt = integerTimestamp(exp, "exp");
    if (expiresAt < issuedAt) {
      throw new CredentialStatusFreshnessError("exp must be greater than or equal to iat");
    }
  }

  let ttlSeconds = STATUS_DEFAULT_TTL_SECONDS;
  if (ttl !== undefined && ttl !== null) {
    if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl <= 0) {
      throw new CredentialStatusFreshnessError("ttl must be a positive integer number of seconds");
    }
    ttlSeconds = ttl;
  }

  if (issuedAt > current + clockSkewSeconds) {
    throw new CredentialStatusFreshnessError("status list iat is too far in the future", "stale");
  }
  if (expiresAt !== null && expiresAt < current - clockSkewSeconds) {
    throw new CredentialStatusFreshnessError("status list exp is outside the clock skew window", "stale");
  }

  const cacheUntil = Math.min(
    fetched + ttlSeconds,
    fetched + STATUS_CACHE_MAX_SECONDS,
    ...(expiresAt === null ? [] : [expiresAt]),
  );

  return {
    acceptedNow: true,
    cacheUntil,
    cacheable: cacheUntil > current,
    ttlSeconds,
    clockSkewSeconds,
  };
}
