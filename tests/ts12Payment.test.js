import { strict as assert } from "assert";
import { expect } from "chai";
import fs from "fs";
import ts12PaymentRouter from "../routes/verify/ts12PaymentRoutes.js";
import issuerConfig from "../data/issuer-config.json" with { type: "json" };
import {
  TS12_DCQL_QUERY,
  TS12_PAYMENT_TRANSACTION_TYPE,
  TS12_PAYMENT_VCT,
  TS12_SCA_CREDENTIAL_ID,
  buildTs12PaymentTransactionData,
  computeTs12TransactionDataHash,
  encodeTs12TransactionData,
  parseTs12PaymentRequestInput,
} from "../utils/ts12PaymentUtils.js";
import {
  validateTs12KeyBindingJwt,
  validateTs12PaymentPresentationResponse,
  validateTs12PresentedCredential,
} from "../utils/ts12Validation.js";

describe("TS12 payment helpers", () => {
  it("requests account attestation claims that match the issued credential payload", () => {
    const claimPaths = TS12_DCQL_QUERY.credentials[0].claims.map((c) => c.path.join("."));
    expect(claimPaths).to.deep.equal(["sub", "iban", "bic", "currency"]);
    expect(claimPaths).to.not.include("pan_last_four");
  });

  it("builds base64url transaction_data with urn:eudi:sca:payment:1 payload", () => {
    const tx = buildTs12PaymentTransactionData({
      merchant: "Coffee Shop",
      payee_id: "shop-42",
      currency: "EUR",
      amount: 12.34,
      transaction_id: "tx-123",
    });
    const encoded = encodeTs12TransactionData(tx);
    const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));

    assert.equal(decoded.type, TS12_PAYMENT_TRANSACTION_TYPE);
    assert.deepEqual(decoded.credential_ids, [TS12_SCA_CREDENTIAL_ID]);
    assert.deepEqual(decoded.transaction_data_hashes_alg, ["sha-256"]);
    assert.equal(decoded.payload.transaction_id, "tx-123");
    assert.equal(decoded.payload.payee.name, "Coffee Shop");
    assert.equal(decoded.payload.payee.id, "shop-42");
    assert.equal(decoded.payload.currency, "EUR");
    assert.equal(decoded.payload.amount, 12.34);
  });

  it("computes base64url SHA-256 over encoded transaction_data", () => {
    const tx = buildTs12PaymentTransactionData({ transaction_id: "hash-test" });
    const encoded = encodeTs12TransactionData(tx);
    const hash = computeTs12TransactionDataHash(encoded);

    assert.match(hash, /^[A-Za-z0-9_-]+$/);
    assert.equal(hash, computeTs12TransactionDataHash(encoded));
  });

  it("parses valid payment request input without adding non-TS12 fields", () => {
    const payload = parseTs12PaymentRequestInput({
      transaction_id: "tx-valid",
      merchant: "Coffee Shop",
      payee_id: "shop-42",
      currency: "EUR",
      amount: "12.34",
    });

    assert.equal(payload.transaction_id, "tx-valid");
    assert.equal(payload.payee.name, "Coffee Shop");
    assert.equal(payload.payee.id, "shop-42");
    assert.equal(payload.amount, 12.34);
    expect(payload).to.not.have.property("purpose");
  });

  it("rejects malformed TS12 payment request input", () => {
    assert.throws(
      () => parseTs12PaymentRequestInput({ transaction_id: "tx-missing", currency: "EUR", amount: "10" }),
      /payee.name is required.*payee.id is required/,
    );
    assert.throws(
      () => parseTs12PaymentRequestInput({
        transaction_id: "tx-invalid-amount",
        merchant: "Coffee Shop",
        payee_id: "shop-42",
        currency: "EUR",
        amount: "abc",
      }),
      /amount must be a finite number/,
    );
    assert.throws(
      () => parseTs12PaymentRequestInput({
        transaction_id: "tx-purpose",
        merchant: "Coffee Shop",
        payee_id: "shop-42",
        currency: "EUR",
        amount: "10",
        purpose: "not a TS12 payment field",
      }),
      /purpose is not defined/,
    );
  });

  it("rejects past execution dates and execution_date with recurrence", () => {
    assert.throws(
      () => parseTs12PaymentRequestInput({
        transaction_id: "tx-past",
        merchant: "Coffee Shop",
        payee_id: "shop-42",
        currency: "EUR",
        amount: "10",
        execution_date: "2000-01-01",
      }),
      /execution_date must not be in the past/,
    );

    assert.throws(
      () => parseTs12PaymentRequestInput({
        transaction_id: "tx-recur",
        merchant: "Coffee Shop",
        payee_id: "shop-42",
        currency: "EUR",
        amount: "10",
        execution_date: "2999-01-01",
        recurrence: { frequency: "MNTH" },
      }),
      /execution_date must not be present when recurrence is present/,
    );
  });
});

describe("TS12 payment validation", () => {
  it("accepts a valid KB-JWT with dynamic linking claims", () => {
    const tx = buildTs12PaymentTransactionData({ transaction_id: "valid-tx" });
    const encoded = encodeTs12TransactionData(tx);
    const hash = computeTs12TransactionDataHash(encoded);

    const result = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-1",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });

    assert.equal(result.ok, true);
  });

  it("rejects missing jti", () => {
    const tx = buildTs12PaymentTransactionData();
    const encoded = encodeTs12TransactionData(tx);
    const result = validateTs12KeyBindingJwt({
      kbPayload: {
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [computeTs12TransactionDataHash(encoded)],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "missing_jti");
  });

  it("rejects insufficient amr factor categories", () => {
    const tx = buildTs12PaymentTransactionData();
    const encoded = encodeTs12TransactionData(tx);
    const result = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-2",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { knowledge: "passphrase_12_or_more_chars" }],
        transaction_data_hashes: [computeTs12TransactionDataHash(encoded)],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "insufficient_amr_categories");
  });

  it("rejects unsupported amr categories and values", () => {
    const tx = buildTs12PaymentTransactionData();
    const encoded = encodeTs12TransactionData(tx);
    const hash = computeTs12TransactionDataHash(encoded);

    const invalidCategory = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-invalid-category",
        response_mode: "direct_post",
        amr: [{ location: "device" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });
    assert.equal(invalidCategory.ok, false);
    assert.equal(invalidCategory.code, "invalid_amr_category");

    const invalidValue = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-invalid-value",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });
    assert.equal(invalidValue.ok, false);
    assert.equal(invalidValue.code, "invalid_amr_value");
  });

  it("rejects transaction_data hash mismatch", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData());
    const result = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-3",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { inherence: "fingerprint_device" }],
        transaction_data_hashes: ["wrong-hash"],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "transaction_data_hash_mismatch");
  });

  it("validates presented credential vct and full TS12 response", () => {
    const tx = buildTs12PaymentTransactionData({ transaction_id: "full-flow" });
    const encoded = encodeTs12TransactionData(tx);
    const credential = { vct: TS12_PAYMENT_VCT, sub: "holder-1" };

    const credResult = validateTs12PresentedCredential([credential]);
    assert.equal(credResult.ok, true);

    const fullResult = validateTs12PaymentPresentationResponse({
      kbPayload: {
        jti: "auth-code-4",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [computeTs12TransactionDataHash(encoded)],
      },
      extractedClaims: [credential],
      vpSession: {
        ts12_payment: true,
        response_mode: "direct_post",
        transaction_data: [encoded],
        ts12_expected_vct: TS12_PAYMENT_VCT,
      },
    });

    assert.equal(fullResult.ok, true);
    assert.equal(fullResult.jti, "auth-code-4");
    assert.equal(fullResult.credential.sub, "holder-1");
  });
});

describe("TS12 issuer metadata", () => {
  it("advertises urn:eudi:sca:payment:1 with SCA category and transaction_data_types", () => {
    const config = issuerConfig.credential_configurations_supported["urn:eudi:sca:payment:1"];
    expect(config).to.exist;
    expect(config.vct).to.equal("urn:eudi:sca:payment:1");
    expect(config.category).to.equal("urn:eu:europa:ec:eudi:sua:sca");
    expect(config.transaction_data_types).to.have.property("urn:eudi:sca:payment:1");
    const txType = config.transaction_data_types["urn:eudi:sca:payment:1"];
    expect(txType.schema).to.equal("urn:eudi:sca:payment:1");
    expect(txType.ui_labels.affirmative_action_label).to.deep.equal([
      { lang: "en-GB", value: "Confirm payment" },
    ]);
    expect(txType.ui_labels.denial_action_label).to.deep.equal([
      { lang: "en-GB", value: "Cancel" },
    ]);
    expect(txType.ui_labels).to.not.have.property("confirm_payment");
  });
});

describe("TS12 payment routes", () => {
  it("exports an express router with TS12 payment endpoints", async () => {
    expect(ts12PaymentRouter).to.exist;
    const stack = ts12PaymentRouter.stack || [];
    const paths = stack
      .map((layer) => layer.route?.path)
      .filter(Boolean);
    expect(paths).to.include("/ts12/payment/request");
    expect(paths).to.include("/ts12/payment/x509VPrequest/:id");
  });
});

describe("TS12 payment schema asset", () => {
  it("ships the payment payload JSON schema file", () => {
    const schema = JSON.parse(
      fs.readFileSync("./data/ts12-urn-eudi-sca-payment-1-data-model.json", "utf8"),
    );
    expect(schema.$id).to.equal("urn:eudi:sca:payment:1");
    expect(schema.required).to.include.members(["transaction_id", "payee", "currency", "amount"]);
  });
});
