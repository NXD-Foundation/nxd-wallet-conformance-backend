import { expect } from "chai";
import {
  applyIssuerOwnedCredentialStatus,
  disclosureFrameWithoutStatus,
  embedIssuerOwnedStatus,
  issueDeferredCredentialOnce,
} from "../utils/credentialStatusIssuance.js";

describe("issuer-owned credential status", () => {
  it("drops caller status and status_reference when revocation is off", () => {
    const requestBody = {
      status: { status_list: { uri: "https://attacker.example/list", idx: 1 } },
      status_reference: { status_list: { uri: "https://attacker.example/list", idx: 2 } },
      issuerStatusReference: { status_list: { uri: "https://attacker.example/list", idx: 3 } },
    };

    const status = applyIssuerOwnedCredentialStatus(requestBody, { enabled: false });

    expect(status).to.equal(null);
    expect(requestBody).to.deep.equal({});
  });

  it("embeds only the issuer allocation and ignores a caller-supplied reference", () => {
    const issuerStatus = { status_list: { uri: "https://issuer.example/status-lists/credentials/list-1", idx: 9 } };
    const requestBody = {
      status_reference: { status_list: { uri: "https://attacker.example/list", idx: 4 } },
    };
    applyIssuerOwnedCredentialStatus(requestBody, {
      enabled: true,
      allocate: () => issuerStatus,
    });

    const payload = embedIssuerOwnedStatus({
      vct: "urn:example:pid",
      status: { status_list: { uri: "https://attacker.example/list", idx: 4 } },
      credentialSubject: { status: { status_list: { uri: "https://attacker.example/subject", idx: 5 } } },
      family_name: "Neslo",
    }, requestBody);

    expect(requestBody.issuerStatusReference).to.equal(issuerStatus);
    expect(requestBody).to.not.have.property("status_reference");
    expect(payload.status).to.equal(issuerStatus);
    expect(payload.credentialSubject).to.not.have.property("status");
    expect(payload.family_name).to.equal("Neslo");
  });

  it("removes status from the selective disclosure frame", () => {
    expect(disclosureFrameWithoutStatus({
      family_name: true,
      status: true,
      credentialSubject: { status: true, given_name: true },
    })).to.deep.equal({
      family_name: true,
      credentialSubject: { given_name: true },
    });
  });

  it("reuses the first deferred credential instead of signing again", async () => {
    const session = { requestBody: {} };
    let calls = 0;
    const first = await issueDeferredCredentialOnce(session, async () => {
      calls += 1;
      return "credential-one";
    });
    const second = await issueDeferredCredentialOnce(session, async () => {
      calls += 1;
      return "credential-two";
    });

    expect(first).to.deep.equal({ credential: "credential-one", reused: false });
    expect(second).to.deep.equal({ credential: "credential-one", reused: true });
    expect(calls).to.equal(1);
    expect(session.issuedCredential).to.equal("credential-one");
  });
});
