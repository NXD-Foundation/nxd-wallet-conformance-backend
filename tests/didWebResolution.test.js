import assert from "assert";
import { getDidWebDocumentUrl } from "../utils/cryptoUtils.js";

describe("did:web resolution", () => {
  it("strips the fragment before constructing the DID document URL", () => {
    const did = "did:web:issuer.example.com:path:issuer#keys-1";

    assert.strictEqual(
      getDidWebDocumentUrl(did),
      "https://issuer.example.com/path/issuer/did.json"
    );
  });

  it("preserves an encoded host:port in the authority segment", () => {
    const did = "did:web:localhost%3A3000#keys-1";

    assert.strictEqual(
      getDidWebDocumentUrl(did),
      "https://localhost:3000/.well-known/did.json"
    );
  });
});
