import { expect } from "chai";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { resolvePresentationKeyBinding } from "../src/lib/presentationKeyBinding.js";

describe("presentation key binding selection", () => {
  it("uses the key-binding material stored with the credential", async () => {
    const issuedKey = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const unrelatedKey = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const resolved = await resolvePresentationKeyBinding({
      stored: {
        keyBinding: {
          privateJwk: issuedKey.privateJwk,
          publicJwk: issuedKey.publicJwk,
        },
      },
      keyPath: undefined,
    });

    expect(resolved.source).to.equal("stored");
    expect(resolved.publicJwk.x).to.equal(issuedKey.publicJwk.x);
    expect(resolved.publicJwk.x).to.not.equal(unrelatedKey.publicJwk.x);
    expect(resolved.publicJwk).to.not.have.property("d");
  });

  it("falls back to generated key material when no stored binding exists", async () => {
    const resolved = await resolvePresentationKeyBinding({});

    expect(resolved.source).to.equal("generated");
    expect(resolved.privateJwk).to.have.property("d");
    expect(resolved.publicJwk).to.not.have.property("d");
    expect(resolved.didJwk).to.match(/^did:jwk:/);
  });
});
