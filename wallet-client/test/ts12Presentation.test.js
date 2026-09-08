import { expect } from "chai";
import { createHash } from "crypto";
import {
  assertTs12RequestDelivery,
  assertTs12ScaPresentationConstraints,
  buildTs12ProofClaims,
  DEFAULT_TS12_AMR,
  resolveTs12TransactionDataForCredential,
  validateTs12PaymentPayloadSchema,
} from "../src/lib/ts12Presentation.js";
import { buildCs02TransactionDataProofClaims } from "../src/lib/presentation.js";
import {
  buildTs12DcqlQuery,
  buildTs12PaymentTransactionData,
  computeTs12TransactionDataHash,
  encodeTs12TransactionData,
  TS12_PAYMENT_TRANSACTION_TYPE,
  TS12_SCA_CATEGORY,
  TS12_SCA_IBAN_VCT,
  TS12_SCA_USER_VCT,
} from "../utils/ts12PaymentUtils.js";

describe("wallet-client ts12Presentation", () => {
  function buildStoredCredential(overrides = {}) {
    return {
      metadata: {
        configurationId: TS12_SCA_IBAN_VCT,
        credentialConfiguration: {
          vct: TS12_SCA_IBAN_VCT,
          category: TS12_SCA_CATEGORY,
          transaction_data_types: {
            [TS12_PAYMENT_TRANSACTION_TYPE]: {
              schema: TS12_PAYMENT_TRANSACTION_TYPE,
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
      credentialQueryId: "sca_iban",
      stored: buildStoredCredential(),
    });

    expect(result).to.exist;
    expect(result.encodedTransactionData).to.equal(encoded);
    expect(result.decodedTransactionData.type).to.equal(TS12_PAYMENT_TRANSACTION_TYPE);
    expect(result.expectedVct).to.equal(TS12_SCA_IBAN_VCT);
  });

  it("returns null when the request is not TS12 for the selected credential", () => {
    const encoded = Buffer.from(JSON.stringify({
      type: "qes_authorization",
      credential_ids: ["sca_iban"],
    })).toString("base64url");

    const result = resolveTs12TransactionDataForCredential({
      transactionData: [encoded],
      credentialQueryId: "sca_iban",
      stored: buildStoredCredential(),
    });

    expect(result).to.equal(null);
  });

  it("rejects missing stored credential metadata for TS12", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData({ transaction_id: "tx-2" }));
    expect(() =>
      resolveTs12TransactionDataForCredential({
        transactionData: [encoded],
        credentialQueryId: "sca_iban",
        stored: { metadata: {} },
      }),
    ).to.throw(/missing stored credential metadata/);
  });

  it("rejects stored credentials that are not advertised as SCA", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData({ transaction_id: "tx-3" }));
    expect(() =>
      resolveTs12TransactionDataForCredential({
        transactionData: [encoded],
        credentialQueryId: "sca_iban",
        stored: buildStoredCredential({
          metadata: {
            credentialConfiguration: {
              vct: TS12_SCA_IBAN_VCT,
              category: "not-sca",
              transaction_data_types: {
                [TS12_PAYMENT_TRANSACTION_TYPE]: {
                  schema: TS12_PAYMENT_TRANSACTION_TYPE,
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
        TS12_PAYMENT_TRANSACTION_TYPE,
      ),
    ).to.not.throw();

    expect(() =>
      validateTs12PaymentPayloadSchema(
        { payee: { name: "Coffee Shop", id: "shop-42" }, currency: "EUR", amount: 12.34 },
        TS12_PAYMENT_TRANSACTION_TYPE,
      ),
    ).to.throw(/transaction_id/);

    expect(() =>
      validateTs12PaymentPayloadSchema(
        {
          ...buildTs12PaymentTransactionData({ transaction_id: "tx-purpose" }).payload,
          purpose: "Online purchase",
          amount_estimated: true,
        },
        TS12_PAYMENT_TRANSACTION_TYPE,
      ),
    ).to.not.throw();
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

  it("rejects unencrypted or GET SCA request delivery", () => {
    const payload = {
      transaction_data: [encodeTs12TransactionData(buildTs12PaymentTransactionData({ transaction_id: "tx-6" }))],
    };
    expect(() => assertTs12RequestDelivery({ method: "get", encrypted: true, payload }))
      .to.throw(/request_uri_method=post/);
    expect(() => assertTs12RequestDelivery({ method: "post", encrypted: false, payload }))
      .to.throw(/must be encrypted/);
    expect(() => assertTs12RequestDelivery({ method: "post", encrypted: true, payload })).to.not.throw();
  });

  it("rejects combined SCA DCQL and sca-user aud mismatch", () => {
    const combined = {
      credentials: [
        ...buildTs12DcqlQuery("sca-iban").credentials,
        ...buildTs12DcqlQuery("sca-user").credentials,
      ],
    };
    expect(() =>
      assertTs12ScaPresentationConstraints({
        dcqlQuery: combined,
        stored: buildStoredCredential(),
        clientId: "x509_san_dns:localhost",
      }),
    ).to.throw(/at most one of sca-iban/);

    const duplicateType = {
      credentials: [
        ...buildTs12DcqlQuery("sca-iban").credentials,
        ...buildTs12DcqlQuery("sca-iban").credentials,
      ],
    };
    expect(() =>
      assertTs12ScaPresentationConstraints({
        dcqlQuery: duplicateType,
        stored: buildStoredCredential(),
        clientId: "x509_san_dns:localhost",
      }),
    ).to.throw(/at most one of sca-iban/);

    expect(() =>
      assertTs12ScaPresentationConstraints({
        dcqlQuery: buildTs12DcqlQuery("sca-user"),
        stored: {
          metadata: {
            configurationId: TS12_SCA_USER_VCT,
            credentialConfiguration: { vct: TS12_SCA_USER_VCT },
            aud: "x509_san_dns:other.example",
          },
        },
        clientId: "x509_san_dns:localhost",
      }),
    ).to.throw(/aud does not include/);
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
