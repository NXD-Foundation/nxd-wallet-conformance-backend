import { expect } from "chai";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { resolvePresentationKeyBinding } from "../src/lib/presentationKeyBinding.js";

describe("presentation key binding selection", () => {
  it("uses key-binding material from the picked credential entry", async () => {
    const issuedKey = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const unrelatedKey = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const resolved = await resolvePresentationKeyBinding({
      stored: { multi: true, entries: [] },
      pickedEntry: {
        keyBinding: {
          privateJwk: issuedKey.privateJwk,
          publicJwk: issuedKey.publicJwk,
        },
      },
      keyPath: undefined,
    });

    expect(resolved.source).to.equal("stored_entry");
    expect(resolved.publicJwk.x).to.equal(issuedKey.publicJwk.x);
    expect(resolved.publicJwk.x).to.not.equal(unrelatedKey.publicJwk.x);
  });

  it("uses single stored key-binding when not multi", async () => {
    const issuedKey = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const resolved = await resolvePresentationKeyBinding({
      stored: {
        keyBinding: {
          privateJwk: issuedKey.privateJwk,
          publicJwk: issuedKey.publicJwk,
        },
      },
    });

    expect(resolved.source).to.equal("stored");
    expect(resolved.publicJwk.x).to.equal(issuedKey.publicJwk.x);
  });


  it("falls back to device key material when no stored key-binding exists", async () => {
    const resolved = await resolvePresentationKeyBinding({});

    expect(resolved.source).to.equal("deviceKeyDefault");
    expect(resolved.privateJwk).to.have.property("d");
    expect(resolved.publicJwk).to.not.have.property("d");
    expect(resolved.didJwk).to.match(/^did:jwk:/);
  });
});
