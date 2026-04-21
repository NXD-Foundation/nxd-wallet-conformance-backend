import { strict as assert } from "assert";
import { cborDecode } from "@animo-id/mdoc";
import { getSessionTranscriptBytes } from "../utils/mdlVerification.js";

describe("RFC002 OID4VPHandover SessionTranscript (P2-W-3)", () => {
  it("CBOR-decodes to [null, null, [OID4VPHandover, client_id, response_uri, mdoc_nonce, verifier_nonce]]", () => {
    const bytes = getSessionTranscriptBytes(
      {
        client_id: "c",
        response_uri: "https://rp/cb",
        nonce: "verifier-nonce",
      },
      "mdoc-generated-nonce",
    );
    const d = cborDecode(bytes).data;
    assert.ok(Array.isArray(d) && d.length === 3);
    assert.strictEqual(d[0], null);
    assert.strictEqual(d[1], null);
    assert.ok(Array.isArray(d[2]) && d[2].length === 5);
    assert.strictEqual(d[2][0], "OID4VPHandover");
    assert.strictEqual(d[2][1], "c");
    assert.strictEqual(d[2][2], "https://rp/cb");
    assert.strictEqual(d[2][3], "mdoc-generated-nonce");
    assert.strictEqual(d[2][4], "verifier-nonce");
  });
});
