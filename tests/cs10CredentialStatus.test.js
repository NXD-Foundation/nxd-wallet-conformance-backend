import { strict as assert } from "node:assert";
import { allocateCredentialStatus, revokeCredentialStatus, signCredentialStatusList, readCredentialStatusToken, statusListStoreForTests } from "../utils/credentialStatusList.js";

describe("CS-10 credential status lists", () => {
  beforeEach(() => statusListStoreForTests().clear());

  it("allocates a valid entry and publishes INVALID irreversibly", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const tokenBefore = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(tokenBefore, reference.idx).status, 0);

    revokeCredentialStatus(reference.listId, reference.idx);
    const tokenAfter = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(tokenAfter, reference.idx).status, 1);
    revokeCredentialStatus(reference.listId, reference.idx);
    const tokenAgain = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(tokenAgain, reference.idx).status, 1);
  });
});
