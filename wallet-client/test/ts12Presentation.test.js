import { expect } from "chai";
import { createHash } from "crypto";
import {
  buildTs12ProofClaims,
  DEFAULT_TS12_AMR,
  resolveTs12TransactionDataForCredential,
  validateTs12PaymentPayloadSchema,
} from "../src/lib/ts12Presentation.js";
import { buildCs02TransactionDataProofClaims } from "../src/lib/presentation.js";
import {
  buildTs12PaymentTransactionData,
  computeTs12TransactionDataHash,
  encodeTs12TransactionData,
  TS12_PAYMENT_VCT,
  TS12_SCA_CATEGORY,
} from "../utils/ts12PaymentUtils.js";

describe("wallet-client ts12Presentation", () => {
  function buildStoredCredential(overrides = {}) {
    return {
      metadata: {
        configurationId: TS12_PAYMENT_VCT,
        credentialConfiguration: {
          vct: TS12_PAYMENT_VCT,
          category: TS12_SCA_CATEGORY,
          transaction_data_types: {
            [TS12_PAYMENT_VCT]: {
              schema: TS12_PAYMENT_VCT,
            },
          },
        },
        ...overrides.metadata,
      },
    };
  }

  it("resolves a matching TS12 transaction_data entry for the selected DCQL id", () => {
    const tx = buildTs12PaymentTransactionData({ transaction_id: "tx-1" });
    const encoded = encodeTs12TransactionData(tx);
    const result = resolveTs12TransactionDataForCredential({
      transactionData: [encoded],
      credentialQueryId: "ts12-payment-sca-01",
      stored: buildStoredCredential(),
    });

    expect(result).to.exist;
    expect(result.encodedTransactionData).to.equal(encoded);
    expect(result.decodedTransactionData.type).to.equal(TS12_PAYMENT_VCT);
    expect(result.expectedVct).to.equal(TS12_PAYMENT_VCT);
  });

  it("returns null when the request is not TS12 for the selected credential", () => {
    const encoded = Buffer.from(JSON.stringify({
      type: "qes_authorization",
      credential_ids: ["ts12-payment-sca-01"],
    })).toString("base64url");

    const result = resolveTs12TransactionDataForCredential({
      transactionData: [encoded],
      credentialQueryId: "ts12-payment-sca-01",
      stored: buildStoredCredential(),
    });

    expect(result).to.equal(null);
  });

  it("rejects missing stored credential metadata for TS12", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData({ transaction_id: "tx-2" }));
    expect(() =>
      resolveTs12TransactionDataForCredential({
        transactionData: [encoded],
        credentialQueryId: "ts12-payment-sca-01",
        stored: { metadata: {} },
      }),
    ).to.throw(/missing stored credential metadata/);
  });

  it("rejects stored credentials that are not advertised as SCA", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData({ transaction_id: "tx-3" }));
    expect(() =>
      resolveTs12TransactionDataForCredential({
        transactionData: [encoded],
        credentialQueryId: "ts12-payment-sca-01",
        stored: buildStoredCredential({
          metadata: {
            credentialConfiguration: {
              vct: TS12_PAYMENT_VCT,
              category: "not-sca",
              transaction_data_types: {
                [TS12_PAYMENT_VCT]: {
                  schema: TS12_PAYMENT_VCT,
                },
              },
            },
          },
        }),
      }),
    ).to.throw(/not advertised as TS12 SCA category/);
  });

  it("validates the TS12 payload against the supported schema", () => {
    expect(() =>
      validateTs12PaymentPayloadSchema(
        buildTs12PaymentTransactionData({ transaction_id: "tx-4" }).payload,
        TS12_PAYMENT_VCT,
      ),
    ).to.not.throw();

    expect(() =>
      validateTs12PaymentPayloadSchema(
        { payee: { name: "Coffee Shop", id: "shop-42" }, currency: "EUR", amount: 12.34 },
        TS12_PAYMENT_VCT,
      ),
    ).to.throw(/transaction_id/);
  });

  it("builds TS12 proof claims with response_mode, AMR, and dynamic-linking hashes", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData({ transaction_id: "tx-5" }));
    const claims = buildTs12ProofClaims({
      encodedTransactionData: encoded,
      responseMode: "direct_post",
    });

    expect(claims.response_mode).to.equal("direct_post");
    expect(claims.amr).to.deep.equal(DEFAULT_TS12_AMR);
    expect(claims.transaction_data_hashes).to.deep.equal([
      computeTs12TransactionDataHash(encoded),
    ]);
    expect(claims.transaction_data_hashes_alg).to.equal("sha-256");
  });

  it("hashes generic transaction_data as the received base64url string", () => {
    const encoded = Buffer.from(JSON.stringify({ type: "payment_data", amount: 12.34 }), "utf8")
      .toString("base64url");
    const claims = buildCs02TransactionDataProofClaims([encoded]);

    expect(claims.transaction_data_hashes).to.deep.equal([
      computeTs12TransactionDataHash(encoded),
    ]);
    expect(claims.transaction_data_hashes).to.not.deep.equal([
      createHash("sha256").update(Buffer.from(encoded, "base64url")).digest("base64url"),
    ]);
  });
});
