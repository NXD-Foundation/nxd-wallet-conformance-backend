import { expect } from "chai";
import fs from "node:fs/promises";
import { loadTrustProfile, validateTrustProfile } from "../trust/profile.js";

describe("Phase 0 WE BUILD trust profile", () => {
  it("loads the checked-in profile and all eight WP4 list types", async () => {
    const profile = await loadTrustProfile("data/trust/webuild-wp4-pilot.json");
    expect(profile.id).to.equal("webuild-wp4-pilot");
    expect(Object.keys(profile.listTypes)).to.have.length(8);
    expect(profile.formats).to.deep.equal({ preferred: "json", fallback: "xml" });
  });

  it("rejects incomplete profiles", () => {
    expect(() => validateTrustProfile({ id: "bad" })).to.throw(/missing formats/i);
  });

  it("keeps the checked-in fixture manifest complete", async () => {
    const manifest = JSON.parse(await fs.readFile("tests/fixtures/trust/webuild-wp4/manifest.json", "utf8"));
    expect(manifest.artifacts).to.have.length(6);
    for (const artifact of manifest.artifacts) {
      await fs.access(`tests/fixtures/trust/webuild-wp4/artifacts/${artifact}`);
    }
    for (const fingerprint of Object.values(manifest.profile)) {
      expect(fingerprint).to.match(/^[a-f0-9]{64}$/);
    }
  });
});
