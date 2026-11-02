import { expect } from "chai";
import express from "express";
import request from "supertest";
import { credentialStatusRouter } from "../routes/credentialStatusRoutes.js";
import { CREDENTIAL_STATUS_LIST_PATH, allocateCredentialStatus, readCredentialStatusToken, resetCredentialStatusListsForTests } from "../utils/credentialStatusList.js";

describe("CS-10 status list HTTP publication", () => {
  const previous = {};
  const app = express();
  app.use(credentialStatusRouter());

  beforeEach(() => {
    previous.SERVER_URL = process.env.SERVER_URL;
    previous.ISSUER_STATUS_ADMIN_TOKEN = process.env.ISSUER_STATUS_ADMIN_TOKEN;
    process.env.SERVER_URL = "https://issuer.example";
    process.env.ISSUER_STATUS_ADMIN_TOKEN = "status-admin";
    resetCredentialStatusListsForTests();
  });

  afterEach(() => {
    restore("SERVER_URL");
    restore("ISSUER_STATUS_ADMIN_TOKEN");
  });

  function restore(name) {
    if (previous[name] === undefined) delete process.env[name];
    else process.env[name] = previous[name];
  }

  it("serves a signed status list to an unauthenticated caller", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const response = await request(app).get(`${CREDENTIAL_STATUS_LIST_PATH}/${reference.listId}`);

    expect(response.status).to.equal(200);
    expect(response.headers["content-type"]).to.equal("application/statuslist+jwt");
    expect(response.headers["cache-control"]).to.equal("public, max-age=300");
    const read = readCredentialStatusToken(response.text, reference.idx);
    expect(read.status).to.equal(0);
    expect(read.payload.sub).to.equal(reference.status.status_list.uri);
    expect(read.payload.status_list.bits).to.equal(1);
  });

  it("rejects an unauthorised revoke and publishes INVALID only after an authorised one", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const revokePath = `${CREDENTIAL_STATUS_LIST_PATH}/${reference.listId}/entries/${reference.idx}/revoke`;

    const missing = await request(app).post(revokePath);
    expect(missing.status).to.equal(401);

    const wrong = await request(app).post(revokePath).set("Authorization", "Bearer other-token");
    expect(wrong.status).to.equal(401);

    const badIndex = await request(app)
      .post(`${CREDENTIAL_STATUS_LIST_PATH}/${reference.listId}/entries/-1/revoke`)
      .set("Authorization", "Bearer status-admin");
    expect(badIndex.status).to.equal(400);

    const revoked = await request(app).post(revokePath).set("Authorization", "Bearer status-admin");
    expect(revoked.status).to.equal(200);
    expect(revoked.body.status).to.equal(1);

    const published = await request(app).get(`${CREDENTIAL_STATUS_LIST_PATH}/${reference.listId}`);
    expect(readCredentialStatusToken(published.text, reference.idx).status).to.equal(1);

    await request(app).post(revokePath).set("Authorization", "Bearer status-admin").expect(200);
    const again = await request(app).get(`${CREDENTIAL_STATUS_LIST_PATH}/${reference.listId}`);
    expect(readCredentialStatusToken(again.text, reference.idx).status).to.equal(1);
  });
});
