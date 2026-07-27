import { expect } from "chai";
import fs from "node:fs/promises";
import http from "node:http";
import { loadTrustProfile } from "../trust/profile.js";
import { loadTrustSnapshot, pointerForType } from "../trust/loader.js";
import { evaluateTrust } from "../trust/evaluate.js";
import { certificateFingerprint } from "../trust/crypto.js";

const artifact = "tests/fixtures/trust/webuild-wp4/artifacts";
const keyDir = "tests/fixtures/trust/webuild-wp4/keys";

describe("Phase 1 local trust-chain integration", () => {
  let server;
  let baseUrl;
  let profile;
  let pidCert;

  before(async () => {
    const files = new Map();
    for (const name of ["list_of_trusted_lists.json", "list_of_trusted_lists.xml", "pid.json", "pid.xml", "qeaa.json", "qeaa.xml"]) {
      files.set(`/${name}`, await fs.readFile(`${artifact}/${name}`));
    }
    server = http.createServer((req, res) => {
      const body = files.get(req.url);
      if (!body) {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": req.url.endsWith(".json") ? "application/json" : "application/xml" });
      res.end(body);
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    baseUrl = `http://127.0.0.1:${address.port}`;
    profile = await loadTrustProfile("data/trust/webuild-wp4-pilot.json");
    const lotlCert = await fs.readFile(`${keyDir}/lotl.crt`, "utf8");
    pidCert = await fs.readFile(`${keyDir}/pid.crt`, "utf8");
    profile.bootstrap.loTLSignerFingerprints = [certificateFingerprint(lotlCert)];
    profile.lotl.jsonUrl = `${baseUrl}/list_of_trusted_lists.json`;
    profile.lotl.xmlUrl = `${baseUrl}/list_of_trusted_lists.xml`;
    profile.network.allowInsecureHttp = true;
  });

  after(async () => new Promise((resolve) => server.close(resolve)));

  function fetchLocal(url, options) {
    return fetch(`${baseUrl}${new URL(url).pathname}`, options);
  }

  it("loads JSON LoTL, follows JSON PID and XML QEAA pointers, and evaluates PID trust", async () => {
    const snapshot = await loadTrustSnapshot({ profile, fetchImpl: fetchLocal, clock: () => new Date("2026-07-27T00:00:00Z") });
    expect(snapshot.format).to.equal("json");
    expect(snapshot.lists["pid-provider"].format).to.equal("json");
    expect(snapshot.lists["qeaa-provider"].format).to.equal("xml");
    const result = evaluateTrust({ snapshot, role: "pid-provider", presentedIdentity: { entityId: "Test PID Provider", certificatePem: pidCert } });
    expect(result).to.include({ trusted: true, state: "trusted", reasonCode: "TRUSTED" });
    expect(result.evidence.lotl.signerFingerprint).to.be.a("string");
  });

  it("uses the XML LoTL path when explicitly requested", async () => {
    const snapshot = await loadTrustSnapshot({ profile, format: "xml", fetchImpl: fetchLocal, clock: () => new Date("2026-07-27T00:00:00Z") });
    expect(snapshot.format).to.equal("xml");
    expect(snapshot.lists["pid-provider"].format).to.equal("xml");
  });

  it("rejects a listed entity with a mismatched certificate", async () => {
    const snapshot = await loadTrustSnapshot({ profile, fetchImpl: fetchLocal, clock: () => new Date("2026-07-27T00:00:00Z") });
    const result = evaluateTrust({ snapshot, role: "pid-provider", presentedIdentity: { entityId: "Test PID Provider", certificateFingerprint: "00".repeat(32) } });
    expect(result).to.include({ trusted: false, reasonCode: "ANCHOR_MISMATCH" });
  });

  it("fails closed on same-type pointers until the profile selects one", () => {
    const pointers = [
      { url: "https://ec.example/eaa.json", mimeType: "application/json", listTypeUri: "urn:eaa" },
      { url: "https://member-state.example/eaa.json", mimeType: "application/json", listTypeUri: "urn:eaa" },
    ];
    expect(() => pointerForType(pointers, { referenceUri: "urn:eaa" }, "json"))
      .to.throw(/Multiple trust-list pointers/);
    expect(pointerForType(pointers, { referenceUri: "urn:eaa", pointerUrl: "https://ec.example/eaa.json" }, "json"))
      .to.equal(pointers[0]);
  });
});
