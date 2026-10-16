import { expect } from "chai";
import fs from "fs";
import path from "path";
import {
  resolveKeyAttestationVerificationJwkFromX5c,
  validateWalletProviderCertificatePath,
  certificatesFromX5cHeader,
} from "../utils/keyAttestationX5cVerification.js";
import {
  createWalletProviderKeyAttestationCertFixtures,
  pemToX5cDerB64,
} from "./helpers/wpKeyAttestationCertFixtures.mjs";

describe("keyAttestationX5cVerification", () => {
  it("resolves verification JWK from x5c leaf with configured trust anchor", async () => {
    const fixtures = await createWalletProviderKeyAttestationCertFixtures();
    const jwk = resolveKeyAttestationVerificationJwkFromX5c(
      { alg: "ES256", x5c: fixtures.x5c },
      { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors }
    );
    expect(jwk).to.have.property("kty", "EC");
    expect(jwk).to.have.property("crv", "P-256");
  });

  it("rejects header.jwk without x5c", async () => {
    const { publicKey } = await import("jose").then((m) => m.generateKeyPair("ES256"));
    const pub = await import("jose").then((m) => m.exportJWK(publicKey));
    expect(() =>
      resolveKeyAttestationVerificationJwkFromX5c({ alg: "ES256", jwk: pub }, {})
    ).to.throw(/header\.jwk is not accepted/i);
  });

  it("rejects when wallet_provider_trust_anchors is missing", async () => {
    const fixtures = await createWalletProviderKeyAttestationCertFixtures();
    expect(() =>
      resolveKeyAttestationVerificationJwkFromX5c({ alg: "ES256", x5c: fixtures.x5c }, {})
    ).to.throw(/wallet_provider_trust_anchors are required/i);
  });

  it("rejects self-signed leaf in x5c", async () => {
    const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
    if (!fs.existsSync(certPath)) {
      return;
    }
    const pem = fs.readFileSync(certPath, "utf8");
    const x5c = [pemToX5cDerB64(pem)];
    expect(() =>
      validateWalletProviderCertificatePath({
        certificateChain: certificatesFromX5cHeader(x5c),
        anchorCertificates: [pem],
      })
    ).to.throw(/must not be self-signed/i);
  });

  it("rejects trust anchor embedded in x5c", async () => {
    const fixtures = await createWalletProviderKeyAttestationCertFixtures();
    const x5c = [fixtures.x5c[0], pemToX5cDerB64(fixtures.caPem)];
    expect(() =>
      resolveKeyAttestationVerificationJwkFromX5c(
        { alg: "ES256", x5c },
        { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors }
      )
    ).to.throw(/trust anchor certificate must not appear in the x5c/i);
  });
});
