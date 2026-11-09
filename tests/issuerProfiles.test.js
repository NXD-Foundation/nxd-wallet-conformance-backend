import { expect } from "chai";
import { issuerProfiles, getIssuerProfile, profileIssuerUrl, assertProfileCredential, sessionIssuerUrl } from "../utils/issuerProfiles.js";
import { loadProfileCredentialSigningMaterial } from "../utils/issuerProfileSigning.js";
import { X509Certificate } from "node:crypto";
import express from "express";
import request from "supertest";
import * as jose from "jose";
import metadataRouter from "../routes/metadataroutes.js";

describe("pilot issuer profiles", () => {
  it("assigns each configured credential to at most one initial profile", () => {
    const ids = Object.values(issuerProfiles).flatMap((profile) => profile.credentialConfigurationIds);
    expect(new Set(ids).size).to.equal(ids.length);
    expect(getIssuerProfile("pid").credentialConfigurationIds).to.include("urn:eu.europa.ec.eudi:pid:1");
    expect(getIssuerProfile("pub-eaa").credentialConfigurationIds).to.include("PhotoID");
    expect(getIssuerProfile("eaa").credentialConfigurationIds).to.include("VerifiableStudentIDSDJWT");
    expect(getIssuerProfile("qeaa").credentialConfigurationIds).to.be.empty;
  });

  it("constructs an issuer identifier under the existing public prefix", () => {
    expect(profileIssuerUrl("https://dev-i4mlab.aegean.gr/rfc-issuer/", "pid"))
      .to.equal("https://dev-i4mlab.aegean.gr/rfc-issuer/issuer/pid");
    expect(() => profileIssuerUrl("https://example.org/rfc-issuer", "unknown")).to.throw();
    expect(sessionIssuerUrl("https://example.org/rfc-issuer", { issuerProfile: "pid" })).to.equal("https://example.org/rfc-issuer/issuer/pid");
    expect(sessionIssuerUrl("https://example.org/rfc-issuer", {})).to.equal("https://example.org/rfc-issuer");
  });

  it("rejects cross-profile and unassigned credential configurations", () => {
    expect(() => assertProfileCredential("pid", "urn:eu.europa.ec.eudi:pid:1")).not.to.throw();
    expect(() => assertProfileCredential("pid", "PhotoID")).to.throw("not permitted");
    expect(() => assertProfileCredential("qeaa", "PhotoID")).to.throw("not permitted");
    expect(() => assertProfileCredential("unknown", "PhotoID")).to.throw("Unknown issuer profile");
  });

  it("selects the configured IdUnion certificate for each role and rejects a missing key", () => {
    const expectedSerials = {
      pid: "391F6DEAF83D8589D8930BF2BF9FF403",
      eaa: "391F6DEAF83D8589D8930BF2BF9FF403",
      "pub-eaa": "266DC3399B91DF86152AEE5C13BC93C2",
      qeaa: "040A3FE435ABBD6A498A00580A9C4BFA",
    };
    for (const [profile, serial] of Object.entries(expectedSerials)) {
      const material = loadProfileCredentialSigningMaterial(profile);
      const certificate = new X509Certificate(material.certificatePem);
      expect(certificate.serialNumber).to.equal(serial);
      expect(certificate.subject).to.include("UAegean");
    }
    expect(() => loadProfileCredentialSigningMaterial("eaa", { keyPath: "/no/such/key" })).to.throw("unavailable");
  });

  it("publishes PID profile metadata signed by its access certificate", async () => {
    const old = process.env.SERVER_URL;
    const oldEnabled = process.env.ISSUER_PROFILES_ENABLED;
    process.env.SERVER_URL = "https://dev-i4mlab.aegean.gr/rfc-issuer";
    process.env.ISSUER_PROFILES_ENABLED = "true";
    const app = express(); app.use(metadataRouter);
    try {
      const response = await request(app).get("/.well-known/openid-credential-issuer/rfc-issuer/issuer/pid").set("Accept", "application/jwt").expect(200);
      const header = jose.decodeProtectedHeader(response.text);
      const cert = new X509Certificate(Buffer.from(header.x5c[0], "base64"));
      const result = await jose.jwtVerify(response.text, cert.publicKey, { algorithms: ["ES256"] });
      expect(result.payload.sub).to.equal("https://dev-i4mlab.aegean.gr/rfc-issuer/issuer/pid");
      expect(result.payload.credential_issuer).to.equal(result.payload.sub);
      expect(result.payload.credential_configurations_supported).to.have.property("urn:eu.europa.ec.eudi:pid:1");
      expect(result.payload.credential_configurations_supported).not.to.have.property("PhotoID");
      expect(cert.serialNumber).to.equal("391F6DEAF83D8589D8930BF2BF9FF403");
    } finally {
      if (old === undefined) delete process.env.SERVER_URL; else process.env.SERVER_URL = old;
      if (oldEnabled === undefined) delete process.env.ISSUER_PROFILES_ENABLED; else process.env.ISSUER_PROFILES_ENABLED = oldEnabled;
    }
  });

});
