import { expect } from "chai";
import fs from "node:fs/promises";
import { DOMParser } from "@xmldom/xmldom";
import { parseJsonDocument, parseXmlDocument, validateListShape } from "../trust/parsers.js";
import { loadTrustProfile } from "../trust/profile.js";
import { certificateFingerprint } from "../trust/crypto.js";
import { TRUST_REASON_CODES } from "../trust/errors.js";

const artifact = "tests/fixtures/trust/webuild-wp4/artifacts";

describe("Phase 1 trust-list parser and profile checks", () => {
  let profile;
  let lotl;

  before(async () => {
    profile = await loadTrustProfile("data/trust/webuild-wp4-pilot.json");
    lotl = JSON.parse(await fs.readFile(`${artifact}/list_of_trusted_lists.json`, "utf8"));
  });

  it("parses the WP4 JSON LoTL shape and its typed pointers", () => {
    const parsed = parseJsonDocument(lotl, { listType: null });
    expect(parsed.scheme.type).to.equal("http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists");
    expect(parsed.pointers).to.have.length(2);
    expect(parsed.pointers.map((pointer) => pointer.listTypeUri)).to.have.members([
      profile.listTypes["pid-provider"].referenceUri,
      profile.listTypes["qeaa-provider"].referenceUri,
    ]);
  });

  it("rejects a referenced list with the wrong ETSI type", () => {
    const parsed = parseJsonDocument(lotl, { listType: "pid-provider" });
    parsed.scheme.type = "http://example.invalid/wrong-type";
    let error;
    try {
      validateListShape(parsed, {
        expectedType: "pid-provider",
        expectedProfile: profile.listTypes["pid-provider"],
      });
    } catch (caught) {
      error = caught;
    }
    expect(error.reasonCode).to.equal(TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  });

  it("rejects an empty referenced list", () => {
    const parsed = parseJsonDocument(JSON.parse(JSON.stringify(lotl)), { listType: "pid-provider" });
    parsed.scheme.type = profile.listTypes["pid-provider"].referenceUri;
    parsed.entities = [];
    parsed.pointers = [];
    expect(() => validateListShape(parsed, {
      expectedType: "pid-provider",
      expectedProfile: profile.listTypes["pid-provider"],
    })).to.throw(/contains no entities or pointers/i);
  });

  it("parses TS 119 612 TSPService XML", async () => {
    const xml = await fs.readFile(`${artifact}/pid.xml`, "utf8");
    const parsed = parseXmlDocument(new DOMParser().parseFromString(xml, "application/xml"));
    expect(parsed.scheme.type).to.equal("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList");
    expect(parsed.entities).to.have.length(1);
    expect(parsed.entities[0].services[0].type).to.equal("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    expect(parsed.entities[0].services[0].certificates).to.have.length(1);
  });

  it("parses TS 119 602 TrustedEntity XML including nested NextUpdate", async () => {
    const xml = await fs.readFile(`${artifact}/wallet-provider-lote.xml`, "utf8");
    const pidCert = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    const parsed = parseXmlDocument(new DOMParser().parseFromString(xml, "application/xml"), {
      listType: "wallet-provider",
    });
    expect(parsed.scheme.type).to.equal(profile.listTypes["wallet-provider"].referenceUri);
    expect(parsed.scheme.issueTime).to.equal("2026-01-01T00:00:00.000Z");
    expect(parsed.scheme.nextUpdate).to.equal("2027-01-01T00:00:00.000Z");
    expect(parsed.entities).to.have.length(1);
    expect(parsed.entities[0].id).to.equal("LUTRA LABS, racunalnisko programiranje, d.o.o.");
    expect(parsed.entities[0].services[0]).to.include({
      name: "LutraID European Business Wallet",
      type: "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
      status: null,
    });
    expect(parsed.entities[0].services[0].certificates).to.deep.equal([certificateFingerprint(pidCert)]);
    validateListShape(parsed, {
      expectedType: "wallet-provider",
      expectedProfile: profile.listTypes["wallet-provider"],
    });
  });
});
