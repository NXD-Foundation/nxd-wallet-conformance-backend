process.env.ALLOW_NO_REDIS = "true";
process.env.NODE_ENV = process.env.NODE_ENV || "test";

import { strict as assert } from "assert";
import { expect } from "chai";
import fs from "fs";
import express from "express";
import request from "supertest";
import { compactDecrypt, exportJWK, generateKeyPair } from "jose";
import ts12PaymentRouter from "../routes/verify/ts12PaymentRoutes.js";
import { CONFIG } from "../utils/routeUtils.js";
import issuerConfig from "../data/issuer-config.json" with { type: "json" };
import {
  TS12_DCQL_QUERY,
  TS12_PAYMENT_TRANSACTION_TYPE,
  TS12_SCA_CREDENTIAL_ID,
  TS12_SCA_IBAN_VCT,
  TS12_SCA_USER_VCT,
  TS12_SCA_CARD_DPC_VCT,
  applyScaWuaExpiryHint,
  buildTs12DcqlQuery,
  buildTs12PaymentTransactionData,
  computeTs12TransactionDataHash,
  encodeTs12TransactionData,
  hasTs12EncryptionJwk,
  isTs12PaymentRequestUri,
  isTs12ScaCredentialType,
  parseTs12PaymentRequestInput,
  resolveTs12AttestationType,
} from "../utils/ts12PaymentUtils.js";
import {
  validateTs12KeyBindingJwt,
  validateTs12PaymentPresentationResponse,
  validateTs12PresentedCredential,
} from "../utils/ts12Validation.js";

describe("TS12 payment helpers", () => {
  it("requests sca-iban claims from the default DCQL query", () => {
    const claimPaths = TS12_DCQL_QUERY.credentials[0].claims.map((c) => c.path.join("."));
    expect(TS12_DCQL_QUERY.credentials[0].id).to.equal("sca_iban");
    expect(TS12_DCQL_QUERY.credentials[0].meta.vct_values).to.deep.equal([TS12_SCA_IBAN_VCT]);
    expect(claimPaths).to.deep.equal(["masked_iban", "iban", "bic", "currency"]);
    expect(claimPaths).to.not.include("pan_last_four");
  });

  it("builds a single-attestation DCQL query per CS-12 type", () => {
    const userQuery = buildTs12DcqlQuery("sca-user");
    expect(userQuery.credentials).to.have.length(1);
    expect(userQuery.credentials[0].id).to.equal("sca_user");
    expect(userQuery.credentials[0].meta.vct_values).to.deep.equal([TS12_SCA_USER_VCT]);
    expect(userQuery.credentials[0].claims.map((c) => c.path.join("."))).to.deep.equal(["masked_psu_id"]);

    const cardQuery = buildTs12DcqlQuery("sca-card-dpc");
    expect(cardQuery.credentials[0].id).to.equal("sca_card_dpc");
    expect(cardQuery.credentials[0].meta.vct_values).to.deep.equal([TS12_SCA_CARD_DPC_VCT]);
  });

  it("resolves attestation_type from ids and base VCT URLs", () => {
    expect(resolveTs12AttestationType("sca-iban").vct).to.equal(TS12_SCA_IBAN_VCT);
    expect(resolveTs12AttestationType(TS12_SCA_USER_VCT).id).to.equal("sca-user");
    expect(() => resolveTs12AttestationType("sca-unknown")).to.throw(/attestation_type must be one of/);
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

  it("forwards optional TS12 payload fields including purpose", () => {
    const payload = parseTs12PaymentRequestInput({
      transaction_id: "tx-purpose",
      merchant: "Coffee Shop",
      payee_id: "shop-42",
      currency: "EUR",
      amount: "10",
      purpose: "Online purchase",
      amount_estimated: "true",
      sct_inst: "false",
    });

    assert.equal(payload.purpose, "Online purchase");
    assert.equal(payload.amount_estimated, true);
    assert.equal(payload.sct_inst, false);
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
        transaction_id: "tx-purpose-type",
        merchant: "Coffee Shop",
        payee_id: "shop-42",
        currency: "EUR",
        amount: "10",
        purpose: 12,
      }),
      /purpose must be a string/,
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

  it("treats the legacy payment URN as an SCA credential type for WUA expiry capping", () => {
    expect(isTs12ScaCredentialType(TS12_SCA_IBAN_VCT)).to.equal(true);
    expect(isTs12ScaCredentialType(TS12_PAYMENT_TRANSACTION_TYPE)).to.equal(true);
    const requestBody = {};
    applyScaWuaExpiryHint(requestBody, 1_700_000_000);
    expect(requestBody._wuaExp).to.equal(1_700_000_000);
  });

  it("requires wallet_metadata encryption keys to advertise use=enc", () => {
    expect(hasTs12EncryptionJwk({ jwks: { keys: [{ kty: "EC", crv: "P-256", x: "a", y: "b" }] } })).to.equal(false);
    expect(hasTs12EncryptionJwk({ jwks: { keys: [{ kty: "EC", use: "sig", crv: "P-256" }] } })).to.equal(false);
    expect(hasTs12EncryptionJwk({ jwks: { keys: [{ kty: "EC", use: "enc", crv: "P-256" }] } })).to.equal(true);
    expect(isTs12PaymentRequestUri("http://localhost:3000/ts12/payment/x509VPrequest/abc")).to.equal(true);
    expect(isTs12PaymentRequestUri("https://verifier.example/x509VPrequest/abc")).to.equal(false);
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
        transaction_data_hashes_alg: "sha-256",
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
        transaction_data_hashes_alg: "sha-256",
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
        transaction_data_hashes_alg: "sha-256",
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
        transaction_data_hashes_alg: "sha-256",
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
        transaction_data_hashes_alg: "sha-256",
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
        transaction_data_hashes_alg: "sha-256",
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });

    assert.equal(result.ok, false);
    assert.equal(result.code, "transaction_data_hash_mismatch");
  });

  it("rejects missing, array-shaped, or unsupported transaction_data_hashes_alg", () => {
    const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData());
    const hash = computeTs12TransactionDataHash(encoded);

    const missing = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-missing-alg",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.code, "missing_transaction_data_hashes_alg");

    const arrayShaped = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-array-alg",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
        transaction_data_hashes_alg: ["sha-256"],
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });
    assert.equal(arrayShaped.ok, false);
    assert.equal(arrayShaped.code, "invalid_transaction_data_hashes_alg");

    const unsupported = validateTs12KeyBindingJwt({
      kbPayload: {
        jti: "auth-code-unsupported-alg",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [hash],
        transaction_data_hashes_alg: "sha-512",
      },
      expectedResponseMode: "direct_post",
      encodedTransactionData: encoded,
    });
    assert.equal(unsupported.ok, false);
    assert.equal(unsupported.code, "unsupported_transaction_data_hashes_alg");
  });

  it("validates presented credential vct and full TS12 response", () => {
    const tx = buildTs12PaymentTransactionData({ transaction_id: "full-flow" });
    const encoded = encodeTs12TransactionData(tx);
    const credential = { vct: TS12_SCA_IBAN_VCT, sub: "holder-1" };

    const credResult = validateTs12PresentedCredential([credential]);
    assert.equal(credResult.ok, true);

    const fullResult = validateTs12PaymentPresentationResponse({
      kbPayload: {
        jti: "auth-code-4",
        response_mode: "direct_post",
        amr: [{ knowledge: "pin_6_or_more_digits" }, { possession: "key_in_local_native_wscd" }],
        transaction_data_hashes: [computeTs12TransactionDataHash(encoded)],
        transaction_data_hashes_alg: "sha-256",
      },
      extractedClaims: [credential],
      vpSession: {
        ts12_payment: true,
        response_mode: "direct_post",
        transaction_data: [encoded],
        ts12_expected_vct: TS12_SCA_IBAN_VCT,
      },
    });

    assert.equal(fullResult.ok, true);
    assert.equal(fullResult.jti, "auth-code-4");
    assert.equal(fullResult.credential.sub, "holder-1");
  });

  it("rejects combined SCA presentations and sca-user aud mismatch", () => {
    const combined = validateTs12PresentedCredential([
      { vct: TS12_SCA_IBAN_VCT, sub: "holder-1" },
      { vct: TS12_SCA_USER_VCT, sub: "holder-2" },
    ]);
    assert.equal(combined.ok, false);
    assert.equal(combined.code, "combined_sca_presentation");

    const duplicateType = validateTs12PresentedCredential([
      { vct: TS12_SCA_IBAN_VCT, sub: "holder-1" },
      { vct: TS12_SCA_IBAN_VCT, sub: "holder-2" },
    ]);
    assert.equal(duplicateType.ok, false);
    assert.equal(duplicateType.code, "combined_sca_presentation");

    const audMismatch = validateTs12PresentedCredential(
      [{ vct: TS12_SCA_USER_VCT, sub: "holder-2", aud: "x509_san_dns:other.example" }],
      TS12_SCA_USER_VCT,
      { rpClientId: "x509_san_dns:localhost" },
    );
    assert.equal(audMismatch.ok, false);
    assert.equal(audMismatch.code, "aud_mismatch");

    const audOk = validateTs12PresentedCredential(
      [{ vct: TS12_SCA_USER_VCT, sub: "holder-2", aud: "x509_san_dns:localhost" }],
      TS12_SCA_USER_VCT,
      { rpClientId: "x509_san_dns:localhost" },
    );
    assert.equal(audOk.ok, true);
  });
});

describe("TS12 issuer metadata", () => {
  it("advertises the three CS-12 SCA attestation types with payment transaction_data_types", () => {
    for (const vct of [TS12_SCA_IBAN_VCT, TS12_SCA_USER_VCT, TS12_SCA_CARD_DPC_VCT]) {
      const config = issuerConfig.credential_configurations_supported[vct];
      expect(config, vct).to.exist;
      expect(config.vct).to.equal(vct);
      expect(config.category).to.equal("urn:eu:europa:ec:eudi:sua:sca");
      expect(config.extends).to.equal("https://webuildconsortium.eu/sca/1.0");
      expect(config.transaction_data_types).to.have.property("urn:eudi:sca:payment:1");
      expect(config.transaction_data_types["urn:eudi:sca:payment:1"].schema).to.equal(
        "urn:eudi:sca:payment:1",
      );
      expect(
        config.proof_types_supported?.jwt,
        `${vct} JWT proof metadata`,
      ).to.have.property("key_attestations_required");
    }
    const iban = issuerConfig.credential_configurations_supported[TS12_SCA_IBAN_VCT];
    const txType = iban.transaction_data_types["urn:eudi:sca:payment:1"];
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
  const validPayment = {
    transaction_id: "tx-route-1",
    merchant: "Coffee Shop",
    payee_id: "shop-42",
    currency: "EUR",
    amount: "12.34",
  };

  let app;
  const originalServerUrl = CONFIG.SERVER_URL;

  before(() => {
    CONFIG.SERVER_URL = "https://localhost:3000";
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use("/", ts12PaymentRouter);
  });

  after(() => {
    CONFIG.SERVER_URL = originalServerUrl;
  });

  it("exports an express router with TS12 payment endpoints", async () => {
    expect(ts12PaymentRouter).to.exist;
    const stack = ts12PaymentRouter.stack || [];
    const paths = stack
      .map((layer) => layer.route?.path)
      .filter(Boolean);
    expect(paths).to.include("/ts12/payment/request");
    expect(paths).to.include("/ts12/payment/x509VPrequest/:id");
  });

  it("always rejects GET delivery of the Request Object", async () => {
    const response = await request(app)
      .get("/ts12/payment/x509VPrequest/missing-session")
      .expect(400);

    expect(response.body.error).to.equal("invalid_request");
    expect(response.body.error_description).to.match(/forbids unencrypted GET/);
  });

  it("rejects POST Request Object delivery without an enc JWK", async () => {
    const missing = await request(app)
      .post("/ts12/payment/x509VPrequest/missing-session")
      .type("form")
      .send({})
      .expect(400);
    expect(missing.body.error_description).to.match(/encryption keys/);

    const sigOnly = await request(app)
      .post("/ts12/payment/x509VPrequest/missing-session")
      .type("form")
      .send({
        wallet_metadata: JSON.stringify({
          jwks: { keys: [{ kty: "EC", crv: "P-256", use: "sig", x: "a", y: "b" }] },
        }),
      })
      .expect(400);
    expect(sigOnly.body.error_description).to.match(/encryption keys/);
  });

  it("stores the selected attestation VCT and returns an encrypted JAR on POST", async function () {
    this.timeout(15000);

    const created = await request(app)
      .post("/ts12/payment/request")
      .send({
        ...validPayment,
        attestation_type: "sca-user",
        session_id: "ts12-route-sca-user",
      })
      .expect(200);

    expect(created.body.attestationType).to.equal("sca-user");
    expect(created.body.expectedVct).to.equal(TS12_SCA_USER_VCT);
    expect(created.body.sessionId).to.equal("ts12-route-sca-user");

    await request(app)
      .get(`/ts12/payment/x509VPrequest/${created.body.sessionId}`)
      .expect(400);

    const { publicKey, privateKey } = await generateKeyPair("ECDH-ES+A256KW", { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    publicJwk.kty = "EC";
    publicJwk.use = "enc";
    publicJwk.alg = "ECDH-ES+A256KW";

    const jarResponse = await request(app)
      .post(`/ts12/payment/x509VPrequest/${created.body.sessionId}`)
      .type("form")
      .send({
        wallet_metadata: JSON.stringify({
          jwks: { keys: [publicJwk] },
          authorization_encryption_alg_values_supported: ["ECDH-ES+A256KW"],
          authorization_encryption_enc_values_supported: ["A256GCM"],
        }),
      })
      .expect(200);

    const jar = jarResponse.text;
    expect(jar.split(".")).to.have.length(5);
    const { plaintext } = await compactDecrypt(jar, privateKey);
    const requestJwt = new TextDecoder().decode(plaintext);
    expect(requestJwt.split(".")).to.have.length(3);
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
