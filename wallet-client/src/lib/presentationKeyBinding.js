import {
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
} from "./crypto.js";

function publicJwkWithoutPrivateMaterial(jwk) {
  if (!jwk) return jwk;
  const publicJwk = { ...jwk };
  delete publicJwk.d;
  return publicJwk;
}

export async function resolvePresentationKeyBinding({ stored, keyPath } = {}) {
  const storedBinding = stored?.keyBinding;
  if (storedBinding?.privateJwk && storedBinding?.publicJwk) {
    const privateJwk = storedBinding.privateJwk;
    const publicJwk = publicJwkWithoutPrivateMaterial(storedBinding.publicJwk);
    return {
      privateJwk,
      publicJwk,
      didJwk: storedBinding.didJwk || generateDidJwkFromPrivateJwk(publicJwk),
      alg: privateJwk.alg || publicJwk.alg || "ES256",
      source: "stored",
    };
  }

  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(
    keyPath || undefined,
  );
  return {
    privateJwk,
    publicJwk,
    didJwk: generateDidJwkFromPrivateJwk(publicJwk),
    alg: privateJwk.alg || publicJwk.alg || "ES256",
    source: keyPath ? "keyPath" : "generated",
  };
}
