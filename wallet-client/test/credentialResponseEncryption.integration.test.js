import { expect } from "chai";
import { encryptCredentialResponseToJwe } from "../../utils/credentialResponseEncryption.js";
import {
  prepareCredentialResponseEncryption,
  parseCredentialResponsePayload,
} from "../src/lib/credentialResponseEncryption.js";

describe("credential response encryption (wallet client vs issuer)", () => {
  it("round-trips with issuer encrypt (A128GCM)", async () => {
    const issuerMeta = {
      credential_response_encryption: {
        alg_values_supported: ["ECDH-ES"],
        enc_values_supported: ["A128GCM"],
      },
    };
    const prep = await prepareCredentialResponseEncryption(issuerMeta);
    expect(prep).to.not.equal(null);
    expect(prep.credential_response_encryption.enc).to.equal("A128GCM");

    const issuerConfig = { credential_response_encryption: issuerMeta.credential_response_encryption };
    const payload = { credentials: [{ credential: "mock-sd-jwt" }], notification_id: "nid-1" };
    const jwe = await encryptCredentialResponseToJwe(
      payload,
      prep.credential_response_encryption,
      issuerConfig,
    );
    const parsed = await parseCredentialResponsePayload(jwe, "application/jwt", prep.privateKey);
    expect(parsed).to.deep.equal(payload);
  });

  it("round-trips with issuer encrypt (A256GCM)", async () => {
    const issuerMeta = {
      credential_response_encryption: {
        alg_values_supported: ["ECDH-ES"],
        enc_values_supported: ["A256GCM"],
      },
    };
    const prep = await prepareCredentialResponseEncryption(issuerMeta);
    expect(prep).to.not.equal(null);

    const issuerConfig = { credential_response_encryption: issuerMeta.credential_response_encryption };
    const payload = { credentials: [{ credential: "mock-2" }] };
    const jwe = await encryptCredentialResponseToJwe(
      payload,
      prep.credential_response_encryption,
      issuerConfig,
    );
    const parsed = await parseCredentialResponsePayload(jwe, "application/jwt", prep.privateKey);
    expect(parsed).to.deep.equal(payload);
  });

  it("prepareCredentialResponseEncryption returns null when not advertised", async () => {
    const prep = await prepareCredentialResponseEncryption({});
    expect(prep).to.equal(null);
  });
});
