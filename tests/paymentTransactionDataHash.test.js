import { expect } from "chai";
import crypto from "node:crypto";
import { validateTransactionDataHashes } from "../routes/paymentRoutes.js";

describe("payment transaction_data hash validation", () => {
  it("accepts sha-256 base64url hashes for the original transaction_data string", () => {
    const txData = "eyJ0eXBlIjoicGF5bWVudF9kYXRhIn0";
    const hash = crypto.createHash("sha256").update(txData, "utf8").digest("base64url");
    const result = validateTransactionDataHashes(txData, [hash], "sha-256");
    expect(result.ok).to.equal(true);
    expect(result.hashAlg).to.equal("sha-256");
  });

  it("accepts legacy hex hashes for compatibility", () => {
    const txData = "eyJ0eXBlIjoicGF5bWVudF9kYXRhIn0";
    const hash = crypto.createHash("sha256").update(txData, "utf8").digest("hex");
    const result = validateTransactionDataHashes(txData, [hash], "sha-256");
    expect(result.ok).to.equal(true);
  });

  it("rejects unsupported transaction_data_hashes_alg values", () => {
    const result = validateTransactionDataHashes(
      "eyJ0eXBlIjoicGF5bWVudF9kYXRhIn0",
      ["abc"],
      "sha-512",
    );
    expect(result.ok).to.equal(false);
    expect(result.error).to.match(/Unsupported transaction_data_hashes_alg/);
  });
});
