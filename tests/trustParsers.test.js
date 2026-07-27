import { expect } from "chai";
import fs from "node:fs/promises";
import { parseJsonDocument, validateListShape } from "../trust/parsers.js";
import { loadTrustProfile } from "../trust/profile.js";
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
});
