import { expect } from "chai";
import express from "express";
import request from "supertest";
import metadataRouter from "../routes/metadataroutes.js";

function appWithMetadataRoutes() {
  const app = express();
  app.use("/", metadataRouter);
  return app;
}

describe("CS-02 verifier metadata publication (Phase C)", () => {
  it("keeps broad client metadata available for CS-03 and compatibility", async () => {
    const res = await request(appWithMetadataRoutes()).get("/client-metadata").expect(200);
    expect(res.body.vp_formats_supported).to.have.property("dc+sd-jwt");
    expect(res.body.vp_formats_supported).to.have.property(
      "https://cloudsignatureconsortium.org/2025/x509",
    );
    expect(res.body.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.include("ES384");
  });

  it("publishes a strict CS-02 filtered metadata view", async () => {
    const res = await request(appWithMetadataRoutes()).get("/client-metadata/cs02").expect(200);
    expect(res.body.vp_formats_supported).to.have.property("dc+sd-jwt");
    expect(res.body.vp_formats_supported).to.have.property("mso_mdoc");
    expect(res.body.vp_formats_supported).to.not.have.property("jwt_vc_json");
    expect(res.body.vp_formats_supported).to.not.have.property(
      "https://cloudsignatureconsortium.org/2025/x509",
    );
    expect(res.body.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal([
      "ES256",
    ]);
    expect(res.body).to.not.have.property("encrypted_response_alg_values_supported");
    expect(res.body).to.not.have.property("encrypted_response_enc_values_supported");
  });

  it("keeps encrypted response metadata in strict CS-02 direct_post.jwt view", async () => {
    const res = await request(appWithMetadataRoutes())
      .get("/client-metadata")
      .query({ profile: "cs02", response_mode: "direct_post.jwt" })
      .expect(200);
    expect(res.body.vp_formats_supported).to.not.have.property(
      "https://cloudsignatureconsortium.org/2025/x509",
    );
    expect(res.body).to.have.property("encrypted_response_enc_values_supported");
  });
});
