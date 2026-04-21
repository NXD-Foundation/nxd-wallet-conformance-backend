import { expect } from "chai";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { parseVerifierInfo } from "../src/lib/presentation.js";
import { normalizeVerifierInfo } from "../src/lib/verifierInfoNormalize.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(__dirname, "..", "..");
const verifierInfoPath = path.join(repoRoot, "data", "verifier-info.json");

describe("parseVerifierInfo (RFC002)", () => {
  it("returns null when absent", () => {
    expect(parseVerifierInfo({ client_id: "x" })).to.equal(null);
  });

  it("parses object claim and matches normalizeVerifierInfo", () => {
    const cfg = JSON.parse(fs.readFileSync(verifierInfoPath, "utf8"));
    const reg = ["MIICertBase64Mock"];
    const payload = {
      client_id: "x",
      verifier_info: {
        ...cfg,
        registration_certificate: reg,
      },
    };
    const got = parseVerifierInfo(payload);
    expect(got).to.deep.equal(normalizeVerifierInfo({ ...cfg, registration_certificate: reg }));
    expect(got.registration_certificate).to.deep.equal(reg);
  });

  it("parses JSON string claim", () => {
    const cfg = JSON.parse(fs.readFileSync(verifierInfoPath, "utf8"));
    const payload = {
      verifier_info: JSON.stringify({ purpose: cfg.purpose, verifier_id: cfg.verifier_id }),
    };
    const got = parseVerifierInfo(payload);
    expect(got.purpose).to.equal(cfg.purpose);
    expect(got.verifier_id).to.equal(cfg.verifier_id);
  });

  it("returns null for invalid JSON string", () => {
    expect(parseVerifierInfo({ verifier_info: "{not json" })).to.equal(null);
  });
});
