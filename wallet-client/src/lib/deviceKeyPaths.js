import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Default on-disk path for the device-bound proof / DPoP key (RFC001 holder key). */
export const DEFAULT_DEVICE_KEY_PATH = path.join(__dirname, "..", "..", "data", "device-key.json");

/**
 * @param {string | undefined} explicitPath - CLI `--key` or server `keyPath` (device key only; never Wallet Provider)
 * @returns {string} Resolved filesystem path (always a string so keys persist across runs)
 */
export function resolveDeviceKeyPath(explicitPath) {
  const s = explicitPath != null ? String(explicitPath).trim() : "";
  if (s) return s;
  const env = process.env.WALLET_DEVICE_KEY_PATH?.trim();
  if (env) return env;
  return DEFAULT_DEVICE_KEY_PATH;
}

/**
 * Paths for N device-bound attested keys (RFC001 multi-key issuance). When N is 1, returns the same
 * path as {@link resolveDeviceKeyPath}. When N > 1, derives `stem-0.json` … `stem-(N-1).json` next to the base path.
 *
 * @param {string | undefined} explicitPath - Same as CLI `--key` / server `keyPath`
 * @param {number} count - Number of keys (1–32)
 * @returns {string[]}
 */
export function resolveAttestDeviceKeyPaths(explicitPath, count) {
  if (typeof count !== "number" || !Number.isInteger(count) || count < 1 || count > 32) {
    throw new Error("attestKeyCount must be an integer from 1 to 32");
  }
  if (count === 1) {
    return [resolveDeviceKeyPath(explicitPath)];
  }
  const base = resolveDeviceKeyPath(explicitPath);
  const dir = path.dirname(base);
  const ext = path.extname(base) || ".json";
  const stem = path.extname(base) ? path.basename(base, ext) : path.basename(base);
  return Array.from({ length: count }, (_, i) => path.join(dir, `${stem}-${i}${ext}`));
}
