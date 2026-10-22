import { expect } from "chai";
import fs from "fs";
import path from "path";
import crypto from "node:crypto";
import {
  X509CertificateGenerator,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
} from "@peculiar/x509";
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
  async function intermediateChain(rootLimit, intermediateLimit, subordinate = true) {
    const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
    const levels = [rootLimit, intermediateLimit, ...(subordinate ? [0] : []), null];
    const certificates = [];
    let parentKeys;
    for (const [index, limit] of levels.entries()) {
      const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
      const subject = `CN=Path test ${index}`;
      const options = {
        serialNumber: `0${index + 1}`,
        signingAlgorithm: algorithm,
        notBefore: new Date(Date.now() - 60_000),
        notAfter: new Date(Date.now() + 86_400_000),
        extensions: [
          new BasicConstraintsExtension(limit !== null, limit ?? undefined, true),
          new KeyUsagesExtension(limit !== null ? KeyUsageFlags.keyCertSign : KeyUsageFlags.digitalSignature, true),
        ],
      };
      const certificate = index === 0
        ? await X509CertificateGenerator.createSelfSigned({ ...options, name: subject, keys })
        : await X509CertificateGenerator.create({
          ...options, subject, issuer: certificates[index - 1].subject,
          signingKey: parentKeys.privateKey, publicKey: keys.publicKey,
        });
      certificates.push(certificate);
      parentKeys = keys;
    }
    return {
      certificateChain: certificates.slice(1).reverse().map(cert => cert.toString("pem")),
      anchorCertificates: [certificates[0].toString("pem")],
    };
  }

  it("rejects a subordinate CA below an intermediate with pathLenConstraint zero", async () => {
    const chain = await intermediateChain(2, 0);
    expect(() => validateWalletProviderCertificatePath(chain)).to.throw(/pathLenConstraint/);
  });

  it("accepts a signing leaf directly below an intermediate with pathLenConstraint zero", async () => {
    const chain = await intermediateChain(1, 0, false);
    expect(() => validateWalletProviderCertificatePath(chain)).not.to.throw();
  });

  it("accepts subordinate CAs within the permitted path length", async () => {
    const chain = await intermediateChain(2, 1);
    expect(() => validateWalletProviderCertificatePath(chain)).not.to.throw();
  });

  it("enforces the configured anchor's path length", async () => {
    const chain = await intermediateChain(1, 1);
    expect(() => validateWalletProviderCertificatePath(chain)).to.throw(/pathLenConstraint/);
  });
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

  it("warn mode permits a self-signed signer without claiming configured trust", async () => {
    const fixtures = await createWalletProviderKeyAttestationCertFixtures();
    const x5c = [pemToX5cDerB64(fixtures.caPem)];
    expect(resolveKeyAttestationVerificationJwkFromX5c({ alg: "ES256", x5c }, {})).to.have.property("kty", "EC");
    expect(() => resolveKeyAttestationVerificationJwkFromX5c(
      { alg: "ES256", x5c },
      { wallet_provider_trust_mode: "strict", wallet_provider_trust_anchors: fixtures.issuerConfigAnchors },
    )).to.throw(/self-signed/);
  });

  it("rejects when wallet_provider_trust_anchors is missing", async () => {
    const fixtures = await createWalletProviderKeyAttestationCertFixtures();
    expect(() =>
      resolveKeyAttestationVerificationJwkFromX5c({ alg: "ES256", x5c: fixtures.x5c }, { wallet_provider_trust_mode: "strict" })
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
        { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors, wallet_provider_trust_mode: "strict" }
      )
    ).to.throw(/trust anchor certificate must not appear in the x5c/i);
  });
});
