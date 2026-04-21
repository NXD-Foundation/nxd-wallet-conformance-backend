import { expect } from "chai";
import crypto from "node:crypto";
import {
  pickTransactionDataDigestAlgorithm,
  computeTransactionDataHashesEntries,
  transactionDataBindingForSdJwtKb,
} from "../src/lib/transactionDataKb.js";
import { createProofJwt, ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { decodeJwt } from "jose";

describe("transactionDataKb (RFC002 §8 / SD-JWT KB)", () => {
  it("pickTransactionDataDigestAlgorithm prefers first supported value from transaction_data_hashes_alg_values", () => {
    const p = pickTransactionDataDigestAlgorithm({
      transaction_data_hashes_alg_values: ["sha-256"],
    });
    expect(p.node).to.equal("sha256");
    expect(p.claim).to.equal("sha-256");
  });

  it("falls back to SHA-256 when alg_values missing or unsupported", () => {
    expect(pickTransactionDataDigestAlgorithm({})).to.deep.include({
      node: "sha256",
      claim: "sha-256",
    });
    expect(
      pickTransactionDataDigestAlgorithm({
        transaction_data_hashes_alg_values: ["unknown-alg"],
      }),
    ).to.deep.include({ node: "sha256", claim: "sha-256" });
  });

  it("computeTransactionDataHashesEntries hashes UTF-8 of each entry string; digest base64url", () => {
    const entries = ["eyJ0eXBlIjoiYSJ9", "eyJ0eXBlIjoiYiJ9"];
    const hashes = computeTransactionDataHashesEntries(entries, "sha256");
    expect(hashes).to.have.length(2);
    const expected0 = crypto.createHash("sha256").update(entries[0], "utf8").digest("base64url");
    expect(hashes[0]).to.equal(expected0);
  });

  it("transactionDataBindingForSdJwtKb matches manual hash for payment-style base64 JSON token", () => {
    const txObj = {
      type: "payment_data",
      credential_ids: ["cred1"],
      transaction_data_hashes_alg: ["sha-256"],
      payment_data: { payee: "m", currency_amount: { currency: "EUR", value: "1" } },
    };
    const b64 = Buffer.from(JSON.stringify(txObj)).toString("base64url");
    const ar = {
      transaction_data: [b64],
      transaction_data_hashes_alg_values: ["sha-256"],
    };
    const bind = transactionDataBindingForSdJwtKb(ar);
    expect(bind).to.not.equal(null);
    expect(bind.transaction_data_hashes_alg).to.equal("sha-256");
    const manual = crypto.createHash("sha256").update(b64, "utf8").digest("base64url");
    expect(bind.transaction_data_hashes[0]).to.equal(manual);
  });

  it("createProofJwt includes transaction_data_hashes and transaction_data_hashes_alg for kb+jwt", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const entry = Buffer.from(JSON.stringify({ type: "qes" })).toString("base64url");
    const bind = transactionDataBindingForSdJwtKb({
      transaction_data: [entry],
      transaction_data_hashes_alg_values: ["sha-256"],
    });
    const did = "did:jwk:test";
    const kb = await createProofJwt({
      privateJwk,
      publicJwk,
      audience: "https://verifier.example",
      nonce: "n1",
      issuer: did,
      typ: "kb+jwt",
      sdJwt: "abc.def.ghi~",
      transaction_data_hashes: bind.transaction_data_hashes,
      transaction_data_hashes_alg: bind.transaction_data_hashes_alg,
    });
    const payload = decodeJwt(kb);
    expect(payload.transaction_data_hashes).to.deep.equal(bind.transaction_data_hashes);
    expect(payload.transaction_data_hashes_alg).to.equal("sha-256");
    expect(payload).to.have.property("sd_hash");
  });
});
