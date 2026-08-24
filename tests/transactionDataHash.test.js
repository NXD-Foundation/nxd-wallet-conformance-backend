import { expect } from "chai";
import { createHash } from "crypto";
import { computeTransactionDataHash } from "../utils/transactionDataHash.js";

describe("OpenID4VP transaction-data hashing", () => {
  it("hashes the received base64url string without decoding it", () => {
    const transactionData = Buffer.from(JSON.stringify({ type: "payment_data", amount: 12.34 }), "utf8")
      .toString("base64url");

    expect(computeTransactionDataHash(transactionData)).to.equal(
      createHash("sha256").update(transactionData, "utf8").digest("base64url"),
    );
    expect(computeTransactionDataHash(transactionData)).to.not.equal(
      createHash("sha256").update(Buffer.from(transactionData, "base64url")).digest("base64url"),
    );
  });

  it("rejects empty and non-string transaction_data entries", () => {
    expect(() => computeTransactionDataHash("")).to.throw(TypeError, /non-empty string/);
    expect(() => computeTransactionDataHash(null)).to.throw(TypeError, /non-empty string/);
  });
});
