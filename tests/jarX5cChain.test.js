import { strict as assert } from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";
import * as jose from "jose";
import { X509Certificate } from "crypto";
import { buildVpRequestJWT, loadTrustFrameworkVerifierMaterial, loadVerifierP12 } from "../utils/cryptoUtils.js";

import { computeX509HashClientIdFromLeafCertBase64 } from "../utils/cs02ClientIdBinding.js";

function x5cToPem(x5cEntry) {
  return `-----BEGIN CERTIFICATE-----
${String(x5cEntry)
    .replace(/(.{64})/g, "$1\n")
    .trim()}
-----END CERTIFICATE-----
`;
}

async function buildEs256X509Jar(signingMaterial = null) {
  const material = signingMaterial || loadVerifierP12();
  return buildVpRequestJWT(
    computeX509HashClientIdFromLeafCertBase64(material.certChain[0]),
    "https://dev-i4mlab.aegean.gr/callback",
    null,
    null,
    { client_name: "Test Verifier" },
    null,
    "https://example.com",
    "vp_token",
    "test-nonce-jar-x5c",
    { credentials: [{ id: "pid", format: "dc+sd-jwt" }] },
    null,
    "direct_post",
    undefined,
    undefined,
    null,
    null,
    "test-state-jar-x5c",
    "ES256",
    false,
    null,
    material,
  );
}

describe("JAR x5c certificate chain", () => {
  const originalCaPem = process.env.WEBUILD_X5C_CA_PEM;
  const originalAllowLeafOnly = process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY;

  afterEach(() => {
    if (originalCaPem === undefined) {
      delete process.env.WEBUILD_X5C_CA_PEM;
    } else {
      process.env.WEBUILD_X5C_CA_PEM = originalCaPem;
    }

    if (originalAllowLeafOnly === undefined) {
      delete process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY;
    } else {
      process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY = originalAllowLeafOnly;
    }
  });

  it("excludes the PID trust anchor from ES256 x509_hash JARs", async () => {
    const requestJwt = await buildEs256X509Jar();
    const header = jose.decodeProtectedHeader(requestJwt);

    assert.ok(Array.isArray(header.x5c));
    assert.strictEqual(header.x5c.length, 1);

    const leaf = new X509Certificate(x5cToPem(header.x5c[0]));

    assert.match(leaf.subject, /CN=WE-BUILD Verifier/);
    assert.ok(!header.x5c.includes(new X509Certificate(fs.readFileSync("certs/pidissuerca02_eu.pem")).raw.toString("base64")));
  });

  it("verifies the emitted leaf against the shipped PID Issuer CA 02 certificate", async () => {
    const requestJwt = await buildEs256X509Jar();
    const header = jose.decodeProtectedHeader(requestJwt);
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "jar-x5c-"));
    const leafPath = path.join(tempDir, "leaf.pem");
    const caPath = path.resolve(process.cwd(), "certs", "pidissuerca02_eu.pem");

    fs.writeFileSync(leafPath, x5cToPem(header.x5c[0]));
    const output = execSync(`openssl verify -CAfile "${caPath}" "${leafPath}"`, {
      encoding: "utf8",
    });

    assert.match(output, /OK/);
  });

  it("fails fast when the configured CA PEM is missing", async () => {
    process.env.WEBUILD_X5C_CA_PEM = "certs/does-not-exist.pem";
    delete process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY;

    await assert.rejects(
      buildEs256X509Jar(),
      /WE-BUILD verifier x5c CA chain is unavailable/,
    );
  });

  it("uses the WRPAC leaf when trust-framework signing material is supplied", async () => {
    const requestJwt = await buildEs256X509Jar(loadTrustFrameworkVerifierMaterial());
    const header = jose.decodeProtectedHeader(requestJwt);
    const leaf = new X509Certificate(x5cToPem(header.x5c[0]));

    assert.match(leaf.subject, /CN=dev-i4mlab.aegean.gr/);
    assert.ok(header.x5c.every((entry) => {
      const cert = new X509Certificate(Buffer.from(entry, "base64"));
      return !(cert.ca && cert.checkIssued(cert) && cert.verify(cert.publicKey));
    }));
    assert.doesNotMatch(leaf.subject, /CN=WE-BUILD Verifier/);
  });

  it("refuses a trust-framework VP request when the WRPAC material is missing", () => {
    assert.throws(
      () => loadTrustFrameworkVerifierMaterial({
        certPath: "certs/does-not-exist-wrpac.pem",
        keyPath: "certs/does-not-exist-wrpac.key",
      }),
      /do not fall back to the preprod verifier certificate/,
    );
  });

  it("allows explicit leaf-only fallback when WEBUILD_X5C_ALLOW_LEAF_ONLY=true", async () => {
    process.env.WEBUILD_X5C_CA_PEM = "certs/does-not-exist.pem";
    process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY = "true";

    const requestJwt = await buildEs256X509Jar();
    const header = jose.decodeProtectedHeader(requestJwt);

    assert.ok(Array.isArray(header.x5c));
    assert.strictEqual(header.x5c.length, 1);
  });
});
