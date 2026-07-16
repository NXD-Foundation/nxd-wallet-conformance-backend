import { expect } from "chai";
import fs from "fs";

const register = JSON.parse(
  fs.readFileSync(new URL("../FCAFs/we-build-fcaf-applicability.json", import.meta.url), "utf8"),
);
const inventory = JSON.parse(
  fs.readFileSync(new URL("../FCAFs/we-build-fcaf-catalogue-inventory.json", import.meta.url), "utf8"),
);
const dispositionOverrides = JSON.parse(
  fs.readFileSync(new URL("../FCAFs/we-build-cs02-disposition-overrides.json", import.meta.url), "utf8"),
);

const dispositions = new Set([
  "implemented",
  "partial",
  "structural-only",
  "inapplicable-cs02",
  "out-of-scope-datamodel",
  "not-required",
]);

describe("FCAF applicability register", () => {
  it("documents catalogue availability without inventing missing IDs", () => {
    expect(inventory.available_catalogues.map((entry) => entry.layer)).to.include.members([
      "MessageStructure", "SecurityMechanisms",
    ]);
    expect(inventory.unavailable_catalogues.map((entry) => entry.layer)).to.include.members([
      "Interaction", "Shared", "UseCases", "DataModel",
    ]);
    expect(inventory.policy).to.match(/Do not fabricate IDs/);
  });
  it("has explicit scope and disposition definitions", () => {
    expect(register.schema_version).to.equal("1.0");
    expect(register.profile).to.equal("WE BUILD CS-02");
    expect(register.scope).to.include({
      datamodels: "out-of-scope-datamodel",
      trust_framework: "structural-only",
      negative_e2e: "not-required",
    });
    for (const disposition of dispositions) {
      expect(register.disposition_definitions).to.have.property(disposition);
    }
  });

  it("keeps layer totals internally consistent", () => {
    const layers = register.layers;
    expect(layers).to.have.all.keys(
      "MessageStructure",
      "Interaction",
      "SecurityMechanisms",
      "Shared",
      "UseCases",
      "DataModel",
    );
    for (const layer of Object.values(layers)) {
      expect(layer.total_fafcs).to.be.a("number").and.greaterThan(0);
      expect(dispositions.has(layer.status)).to.equal(true);
      if (layer.areas) {
        const areaTotal = Object.values(layer.areas).reduce(
          (sum, area) => sum + area.fafcs,
          0,
        );
        expect(areaTotal).to.equal(layer.total_fafcs);
      }
    }
  });

  it("does not count deferred datamodel work as implementation coverage", () => {
    expect(register.layers.DataModel.status).to.equal("out-of-scope-datamodel");
    expect(register.layers.SecurityMechanisms.areas.TrustMechanisms.status).to.equal(
      "structural-only",
    );
  });

  it("keeps the aggregate disposition snapshot synchronized", () => {
    const snapshot = register.cs02_disposition_register;
    expect(snapshot).to.include({ explicit_catalogue_rows: 301, classified_rows: 301, unclassified_rows: 0 });
    const counts = {};
    for (const entry of Object.values(dispositionOverrides)) {
      counts[entry.disposition] = (counts[entry.disposition] || 0) + 1;
    }
    expect(snapshot.dispositions).to.deep.equal({
      implemented: counts.implemented,
      partial: counts.partial || 0,
      "structural-only": counts["structural-only"],
      "inapplicable-cs02": counts["inapplicable-cs02"],
      "out-of-scope-datamodel": counts["out-of-scope-datamodel"] || 0,
    });
  });
});
