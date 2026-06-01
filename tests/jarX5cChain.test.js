import { strict as assert } from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";
import * as jose from "jose";
import { X509Certificate } from "crypto";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";

function x5cToPem(x5cEntry) {
  return `-----BEGIN CERTIFICATE-----
${String(x5cEntry)
    .replace(/(.{64})/g, "$1\n")
    .trim()}
-----END CERTIFICATE-----
`;
}

async function buildEs256X509Jar() {
  return buildVpRequestJWT(
    "x509_san_dns:dev-i4mlab.aegean.gr",
    "https://example.com/callback",
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

  it("includes the verifier leaf first and appends the issuing CA for ES256 x509 JARs", async () => {
    const requestJwt = await buildEs256X509Jar();
    const header = jose.decodeProtectedHeader(requestJwt);

    assert.ok(Array.isArray(header.x5c));
    assert.ok(header.x5c.length >= 2);

    const leaf = new X509Certificate(x5cToPem(header.x5c[0]));
    const issuer = new X509Certificate(x5cToPem(header.x5c[1]));

    assert.match(leaf.subject, /CN=WE-BUILD Verifier/);
    assert.match(issuer.subject, /CN=PID Issuer CA 02/);
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

  it("allows explicit leaf-only fallback when WEBUILD_X5C_ALLOW_LEAF_ONLY=true", async () => {
    process.env.WEBUILD_X5C_CA_PEM = "certs/does-not-exist.pem";
    process.env.WEBUILD_X5C_ALLOW_LEAF_ONLY = "true";

    const requestJwt = await buildEs256X509Jar();
    const header = jose.decodeProtectedHeader(requestJwt);

    assert.ok(Array.isArray(header.x5c));
    assert.strictEqual(header.x5c.length, 1);
  });
});
