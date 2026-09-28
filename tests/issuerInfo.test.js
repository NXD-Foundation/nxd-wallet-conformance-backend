import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import {
  ISSUER_INFO_FORMAT_REGISTRAR_DATASET,
  ISSUER_INFO_FORMAT_REGISTRATION_CERT,
  buildIssuerInfo,
  pickIssuerInfoEntry,
} from "../utils/issuerInfo.js";

const CERT_PATH = path.join(process.cwd(), "x509EC", "client_certificate.crt");
const REGISTRATION_PATH = path.join(
  process.cwd(),
  "data",
  "issuer-registration.json",
);

function expectedCertData() {
  return fs
    .readFileSync(CERT_PATH, "utf-8")
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}

describe("buildIssuerInfo (ETSI TS 119 472-3 / RFC001 §7.7 SHALL 8)", () => {
  it("returns an array of {format, data} entries for registration_cert and registrar_dataset", async () => {
    const issuerInfo = await buildIssuerInfo({
      certPath: CERT_PATH,
      registrationPath: REGISTRATION_PATH,
    });

    expect(issuerInfo).to.be.an("array").with.lengthOf(2);
    for (const entry of issuerInfo) {
      expect(entry).to.have.keys("format", "data");
    }

    const registrationCert = pickIssuerInfoEntry(
      issuerInfo,
      ISSUER_INFO_FORMAT_REGISTRATION_CERT,
    );
    expect(registrationCert.data).to.equal(expectedCertData());
    expect(registrationCert.data).to.match(/^[A-Za-z0-9+/=]+$/);

    const registrarDataset = pickIssuerInfoEntry(
      issuerInfo,
      ISSUER_INFO_FORMAT_REGISTRAR_DATASET,
    );
    expect(registrarDataset.data).to.be.an("object");
    expect(registrarDataset.data).to.include.keys(
      "identifier",
      "srvDescription",
      "registryURI",
      "providesAttestations",
    );
    expect(registrarDataset.data.identifier).to.be.a("string").that.is.not.empty;
    expect(registrarDataset.data.srvDescription).to.be.an("array").that.is.not
      .empty;
    expect(registrarDataset.data.srvDescription[0]).to.include.keys(
      "lang",
      "content",
    );
    expect(registrarDataset.data.registryURI).to.match(/^https?:\/\//);
    expect(registrarDataset.data.providesAttestations).to.be.an("array");
  });

  it("does not publish the legacy flat object keys", async () => {
    const issuerInfo = await buildIssuerInfo({
      certPath: CERT_PATH,
      registrationPath: REGISTRATION_PATH,
    });

    expect(issuerInfo).to.be.an("array");
    expect(issuerInfo).to.not.have.property("registration_certificate");
    expect(issuerInfo).to.not.have.property("registration_certificate_pem");
    expect(issuerInfo).to.not.have.property("registration_certificate_summary");
    expect(issuerInfo).to.not.have.property("registration_information");
    expect(issuerInfo).to.not.have.property("profile");
  });

  it("returns null when the registration certificate cannot be read", async () => {
    const issuerInfo = await buildIssuerInfo({
      certPath: path.join(os.tmpdir(), "rfc-issuer-missing-registration.crt"),
    });
    expect(issuerInfo).to.equal(null);
  });
});
