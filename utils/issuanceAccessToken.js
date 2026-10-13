import jwt from "jsonwebtoken";

/** Access-token authorization has its own lifetime, independent of refresh storage. */
export function assertIssuanceAccessTokenActive({ accessToken, session, publicKey, issuer, now = Date.now() }) {
  try {
    if (Number.isFinite(session?.accessTokenExpiresAt) && session.accessTokenExpiresAt <= now) {
      throw new Error("Expired access token");
    }
    if (typeof accessToken === "string" && accessToken.split(".").length === 3) {
      const payload = jwt.verify(accessToken, publicKey, {
        algorithms: ["ES256"], issuer, audience: issuer, clockTimestamp: Math.floor(now / 1000),
      });
      if (!Number.isFinite(payload.exp)) throw new Error("Access token has no expiry");
      return;
    }
    // Legacy test/compatibility sessions may hold opaque tokens. Refresh-enabled
    // opaque sessions must carry an explicit token expiry instead of borrowing the session TTL.
    if (session?.refreshBinding && !Number.isFinite(session.accessTokenExpiresAt)) {
      throw new Error("Opaque access token has no expiry");
    }
  } catch {
    const error = new Error("Access token is invalid or expired");
    error.errorCode = "invalid_token";
    throw error;
  }
}
