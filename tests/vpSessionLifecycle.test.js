import { expect } from "chai";
import { withVPSessionLifecycle } from "../services/cacheServiceRedis.js";

describe("VP session lifecycle", () => {
  it("adds bounded creation and expiry timestamps without overwriting existing values", () => {
    const session = withVPSessionLifecycle({ status: "pending" }, 1000, 180);
    expect(session).to.include({ created_at: 1000, expires_at: 1180 });

    const existing = withVPSessionLifecycle(
      { status: "success", created_at: 10, expires_at: 20 },
      1000,
      180,
    );
    expect(existing).to.include({ created_at: 10, expires_at: 20 });
  });

  it("persists the selected encryption key for encrypted response sessions", () => {
    const session = withVPSessionLifecycle({
      status: "pending",
      response_mode: "direct_post.jwt",
      client_metadata: {
        jwks: { keys: [{ kid: "enc-1", use: "enc", kty: "EC", crv: "P-256", alg: "ECDH-ES+A256KW" }] },
      },
    }, 1000, 180);
    expect(session.encryption_key).to.include({ kid: "enc-1", alg: "ECDH-ES+A256KW" });
  });
});
