import { expect } from "chai";
import {
  assertX509HashLeafMatchesClientId,
  computeX509HashClientIdFromLeafCertBase64,
} from "../utils/cs02ClientIdBinding.js";
import { loadVerifierP12 } from "../utils/cryptoUtils.js";

describe("CS-02 x509_hash client identifier binding", () => {
  it("computes x509_hash from the DER leaf certificate", () => {
    const { certChain } = loadVerifierP12();
    const clientId = computeX509HashClientIdFromLeafCertBase64(certChain[0]);
    expect(clientId).to.match(/^x509_hash:[A-Za-z0-9_-]+$/);
    assertX509HashLeafMatchesClientId(clientId, certChain[0]);
  });

  it("rejects a hash that does not match the x5c leaf", () => {
    const { certChain } = loadVerifierP12();
    expect(() =>
      assertX509HashLeafMatchesClientId("x509_hash:invalidhash", certChain[0]),
    ).to.throw(/x509_hash client_id mismatch/);
  });
});
