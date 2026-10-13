import { expect } from "chai";
import request from "supertest";
import express from "express";

describe("CS-01 v1.3 authorization server metadata", () => {
  let app;
  before(async () => {
    const { default: metadataRouter } = await import("../routes/metadataroutes.js");
    app = express();
    app.use(metadataRouter);
  });

  for (const path of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
    it(`${path} advertises refresh and pre-authorized grants without anonymous access`, async () => {
      const response = await request(app).get(path).expect(200);
      expect(response.body.grant_types_supported).to.include.members([
        "authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code", "refresh_token",
      ]);
      expect(response.body["pre-authorized_grant_anonymous_access_supported"]).to.equal(false);
    });
  }
});
