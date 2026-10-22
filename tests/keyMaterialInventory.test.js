import { expect } from "chai";
import fs from "fs";
import crypto from "crypto";
import { KEY_MATERIAL_PATHS } from "../utils/keyMaterialPaths.js";
import { loadVerifierEncryptionKey } from "../utils/verifierEncryptionKeys.js";

function publicFingerprint(pem, type = "private") {
  const key = type === "private" ? crypto.createPrivateKey(pem) : crypto.createPublicKey(pem);
  const publicDer = (type === "private" ? crypto.createPublicKey(key) : key)
    .export({ format: "der", type: "spki" });
  return crypto.createHash("sha256").update(publicDer).digest("hex");
}

function certificateFingerprint(pem) {
  const certificate = new crypto.X509Certificate(pem);
  return crypto.createHash("sha256")
    .update(certificate.publicKey.export({ format: "der", type: "spki" }))
    .digest("hex");
}

describe("canonical key material inventory", () => {
  it("keeps the application signing private/public pair aligned", () => {
    const privatePem = fs.readFileSync(KEY_MATERIAL_PATHS.applicationSigningPrivateKey, "utf8");
    const publicPem = fs.readFileSync(KEY_MATERIAL_PATHS.applicationSigningPublicKey, "utf8");
    expect(publicFingerprint(privatePem)).to.equal(publicFingerprint(publicPem, "public"));
  });

  it("keeps the DID private/public pair aligned", () => {
    const privatePem = fs.readFileSync(KEY_MATERIAL_PATHS.didPrivateKeyPkcs8, "utf8");
    const publicPem = fs.readFileSync(KEY_MATERIAL_PATHS.didPublicKey, "utf8");
    expect(publicFingerprint(privatePem)).to.equal(publicFingerprint(publicPem, "public"));
  });

  it("keeps verifier encryption metadata, private key, and certificate aligned", () => {
    const configured = loadVerifierEncryptionKey();
    const certificatePem = fs.readFileSync(KEY_MATERIAL_PATHS.verifierEncryptionCertificate, "utf8");
    expect(publicFingerprint(configured.privateKeyPem)).to.equal(
      certificateFingerprint(certificatePem),
    );
    expect(configured.publicJwk.x).to.equal(configured.derivedPublicJwk.x);
    expect(configured.publicJwk.y).to.equal(configured.derivedPublicJwk.y);
  });

  it("does not leave backup material in active protocol directories", () => {
    const activeDirectories = ["x509", "x509EC", "wallet-client/x509", "wallet-client/x509EC"];
    const backupPattern = /(^|\.)(backup|bk)(\.|$)|_bk\./i;
    const leftovers = [];
    for (const directory of activeDirectories) {
      if (!fs.existsSync(directory)) continue;
      for (const entry of fs.readdirSync(directory)) {
        if (backupPattern.test(entry)) leftovers.push(`${directory}/${entry}`);
      }
    }
    expect(leftovers, `backup files remain: ${leftovers.join(", ")}`).to.deep.equal([]);
  });

  it("does not reference deprecated material from active source", () => {
    const sourceRoots = ["routes", "utils", "services", "wallet-client/src", "wallet-client/utils"];
    const forbidden = /(?:x509_bk|x509EC_bk|deprecated\/|\.backup\.)/;
    const matches = [];
    for (const root of sourceRoots) {
      if (!fs.existsSync(root)) continue;
      const stack = [root];
      while (stack.length) {
        const current = stack.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
          const full = `${current}/${entry.name}`;
          if (entry.isDirectory()) stack.push(full);
          else if (/\.(js|mjs|cjs|ts)$/.test(entry.name) && forbidden.test(fs.readFileSync(full, "utf8"))) {
            matches.push(full);
          }
        }
      }
    }
    expect(matches, `deprecated key references remain: ${matches.join(", ")}`).to.deep.equal([]);
  });
});
