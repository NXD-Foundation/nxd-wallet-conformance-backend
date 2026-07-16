import { expect } from "chai";
import fs from "fs";
import { extractFcafSpecs, extractCategorizedSpecs, buildDispositionRegister, createDispositionTemplate, summarizeDispositionTemplate } from "../scripts/fcafDispositionRegister.js";

const overrides = JSON.parse(fs.readFileSync(new URL("../FCAFs/we-build-cs02-disposition-overrides.json", import.meta.url), "utf8"));

describe("FCAF per-ID disposition tooling", () => {
  it("extracts catalogue table rows with stable scoped IDs", () => {
    const specs = extractFcafSpecs("| 027 | credential_ids match DCQL IDs |\n| 028 | proceed |", "MessageStructure", "ProtocolMessages");
    expect(specs).to.have.length(2);
    expect(specs[0]).to.include({ id: "MessageStructure.ProtocolMessages.027", description: "credential_ids match DCQL IDs" });
  });

  it("fails closed when an available ID has no explicit disposition", () => {
    const specs = extractFcafSpecs("| 032 | no state |", "MessageStructure", "ProtocolMessages");
    expect(() => buildDispositionRegister(specs, {})).to.throw(/Missing disposition mappings/);
  });

  it("validates explicit dispositions and preserves evidence", () => {
    const specs = extractFcafSpecs("| 027 | credential_ids match DCQL IDs |", "MessageStructure", "ProtocolMessages");
    const result = buildDispositionRegister(specs, {
      "MessageStructure.ProtocolMessages.027": {
        disposition: "implemented",
        implementation_paths: ["wallet-client/src/lib/cs02RequestValidation.js"],
        test_paths: ["wallet-client/test/cs02RequestValidation.test.js"],
      },
    });
    expect(result[0].remaining_gap).to.equal(null);
  });

  it("discovers all IDs in the available source catalogues", () => {
    const message = fs.readFileSync("/home/ni/code/fcafs/message-structure-analysis/fcaf-ms-specs-categorized.md", "utf8");
    const security = fs.readFileSync("/home/ni/code/fcafs/security-mechanism-analysis/fcaf-sm-specs-categorized.md", "utf8");
    const messageSpecs = extractFcafSpecs(message, "MessageStructure", "Catalogue");
    const securitySpecs = extractFcafSpecs(security, "SecurityMechanisms", "Catalogue");
    // The categorized file declares 236, but contains 222 explicit table rows;
    // the discrepancy is preserved for catalogue reconciliation rather than guessed.
    expect(messageSpecs).to.have.length(222);
    expect(securitySpecs).to.have.length(79);
  });

  it("keeps strict-profile exclusions explicit", () => {
    expect(Object.keys(overrides)).to.have.length(85);
    expect(Object.values(overrides).filter((entry) => entry.disposition === "structural-only")).to.have.length(16);
    expect(Object.values(overrides).filter((entry) => entry.disposition === "inapplicable-cs02")).to.have.length(7);
    expect(Object.values(overrides).filter((entry) => entry.disposition === "implemented")).to.have.length(62);
  });

  it("creates an explicit unclassified template for remaining IDs", () => {
    const specs = extractFcafSpecs("| 032 | no state |", "MessageStructure", "ProtocolMessages");
    const template = createDispositionTemplate(specs, overrides);
    expect(template["MessageStructure.ProtocolMessages.032"].disposition).to.equal(null);
    expect(template["MessageStructure.ProtocolMessages.032"].remaining_gap).to.equal("Unclassified");
  });

  it("preserves scoped overrides when parsing categorized sources", () => {
    const source = "## ProtocolMessages (1)\n| Ref | Description |\n| 002 | unsigned |";
    const specs = extractCategorizedSpecs(source, "MessageStructure");
    const template = createDispositionTemplate(specs, overrides);
    expect(template["MessageStructure.ProtocolMessages.002"].disposition).to.equal("inapplicable-cs02");
  });

  it("summarizes classified and unclassified IDs without publishing coverage percentages", () => {
    const specs = extractFcafSpecs("| 027 | one |\n| 032 | two |", "MessageStructure", "ProtocolMessages");
    const summary = summarizeDispositionTemplate(createDispositionTemplate(specs, overrides));
    expect(summary).to.include({ total: 2, classified: 1, implemented: 1, unclassified: 1 });
  });
});
