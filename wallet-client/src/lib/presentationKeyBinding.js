import {
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
} from "./crypto.js";
import { resolveDeviceKeyPath } from "./deviceKeyPaths.js";

function publicJwkWithoutPrivateMaterial(jwk) {
  if (!jwk) return jwk;
  const publicJwk = { ...jwk };
  delete publicJwk.d;
  return publicJwk;
}

function bindingFromKeyBindingMaterial(binding) {
  if (!binding?.privateJwk || !binding?.publicJwk) return null;
  const privateJwk = binding.privateJwk;
  const publicJwk = publicJwkWithoutPrivateMaterial(binding.publicJwk);
  return {
    privateJwk,
    publicJwk,
    didJwk: binding.didJwk || generateDidJwkFromPrivateJwk(publicJwk),
    alg: privateJwk.alg || publicJwk.alg || "ES256",
  };
}

/**
 * Resolve holder keys for VP presentation.
 * Prefer issuance-time keyBinding on the picked credential entry, then single stored binding,
 * then device key file (RFC001 default path or explicit keyPath).
 */
export async function resolvePresentationKeyBinding({
  stored,
  pickedEntry,
  keyPath,
} = {}) {
  const fromPicked = bindingFromKeyBindingMaterial(pickedEntry?.keyBinding);
  if (fromPicked) {
    return { ...fromPicked, source: "stored_entry" };
  }

  if (!stored?.multi) {
    const fromStored = bindingFromKeyBindingMaterial(stored?.keyBinding);
    if (fromStored) {
      return { ...fromStored, source: "stored" };
    }
  }

  const resolvedDevicePath = resolveDeviceKeyPath(keyPath);
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(resolvedDevicePath);
  return {
    privateJwk,
    publicJwk,
    didJwk: generateDidJwkFromPrivateJwk(publicJwk),
    alg: privateJwk.alg || publicJwk.alg || "ES256",
    source: keyPath ? "deviceKeyPath" : "deviceKeyDefault",
  };
}
