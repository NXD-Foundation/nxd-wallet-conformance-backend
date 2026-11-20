import { execFileSync } from "node:child_process";
import { chmodSync, existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/** Resolve the signed issuer-metadata bundle used by trust-enabled pre-ship runs. */
export async function preparePreShipMetadataSigningMaterial({
  root,
  env = process.env,
  temporaryDirectories,
} = {}) {
  if (env.ISSUER_METADATA_SIGNING_P12_PATH) {
    return { path: env.ISSUER_METADATA_SIGNING_P12_PATH, temporaryDirectory: null };
  }

  const secretsBundle = path.join(root, "secrets", "issuer-metadata.p12");
  if (existsSync(secretsBundle)) return { path: secretsBundle, temporaryDirectory: null };

  const certificatePath = path.join(root, "certs", "we-build-wrpac.pem");
  const privateKeyPath = path.join(root, "certs", "dev-i4mlab.aegean.gr.key.pem");
  if (!existsSync(certificatePath) || !existsSync(privateKeyPath)) {
    throw new Error(
      "Trust-enabled pre-ship runs need ISSUER_METADATA_SIGNING_P12_PATH, " +
      "secrets/issuer-metadata.p12, or certs/we-build-wrpac.pem with its matching certs/dev-i4mlab.aegean.gr.key.pem",
    );
  }

  const directory = await mkdtemp(path.join(os.tmpdir(), "pre-ship-metadata-"));
  temporaryDirectories?.push(directory);
  const bundlePath = path.join(directory, "issuer-metadata.p12");
  try {
    execFileSync("openssl", [
      "pkcs12", "-export", "-in", certificatePath,
      "-inkey", privateKeyPath,
      "-out", bundlePath,
      "-passout", "pass:webuild",
    ], { stdio: "ignore" });
    chmodSync(bundlePath, 0o600);
  } catch (error) {
    throw new Error(`Unable to prepare trust-framework issuer metadata signing bundle: ${error.message}`);
  }
  return { path: bundlePath, temporaryDirectory: directory };
}
