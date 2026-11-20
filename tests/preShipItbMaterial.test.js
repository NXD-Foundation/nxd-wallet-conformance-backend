import { expect } from "chai";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { preparePreShipMetadataSigningMaterial } from "../scripts/preShipItbMaterial.js";

describe("pre-ship issuer metadata signing material", () => {
  it("builds the base metadata P12 from the listed WRPAC and matching key", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "pre-ship-material-test-"));
    const temporaryDirectories = [];
    try {
      cpSync("certs/we-build-wrpac.pem", path.join(root, "we-build-wrpac.pem"));
      cpSync("certs/dev-i4mlab.aegean.gr.key.pem", path.join(root, "metadata.key"));
      const certificatePath = path.join(root, "certs", "we-build-wrpac.pem");
      const keyPath = path.join(root, "certs", "dev-i4mlab.aegean.gr.key.pem");
      mkdirSync(path.dirname(certificatePath), { recursive: true });
      cpSync(path.join(root, "we-build-wrpac.pem"), certificatePath);
      cpSync(path.join(root, "metadata.key"), keyPath);

      const material = await preparePreShipMetadataSigningMaterial({ root, env: {}, temporaryDirectories });
      const pem = execFileSync("openssl", ["pkcs12", "-in", material.path, "-nokeys", "-passin", "pass:webuild"], { encoding: "utf8" });
      expect(new X509Certificate(pem).fingerprint256).to.equal(new X509Certificate(readFileSync(certificatePath)).fingerprint256);
      expect(temporaryDirectories).to.deep.equal([material.temporaryDirectory]);
    } finally {
      for (const directory of temporaryDirectories) rmSync(directory, { recursive: true, force: true });
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("prefers an explicitly configured deployment bundle", async () => {
    const pathValue = "/run/secrets/rfc-issuer/issuer-metadata.p12";
    const result = await preparePreShipMetadataSigningMaterial({ root: "/unused", env: { ISSUER_METADATA_SIGNING_P12_PATH: pathValue } });
    expect(result).to.deep.equal({ path: pathValue, temporaryDirectory: null });
  });
});
