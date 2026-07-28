import { expect } from "chai";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadTrustProfile } from "../trust/profile.js";
import { createTrustResolver } from "../trust/resolver.js";
import { createTrustResolverServer } from "../trust/http.js";
import { evaluateTrust } from "../trust/evaluate.js";

const execFileAsync = promisify(execFile);
const roles = ["pid-provider", "wallet-provider", "wrpac-provider", "wrprc-provider", "pub-eaa-provider", "eaa-provider", "qeaa-provider", "ebwoid-provider"];

function snapshotFor(profile) {
  return {
    profile,
    profileId: profile.id,
    lotl: { source: { url: "https://example.test/lotl.json" }, format: "json", scheme: { sequence: 1 }, signer: { fingerprint: "a".repeat(64) } },
    lists: Object.fromEntries(roles.map((role) => [role, {
      format: "json",
      source: { url: `https://example.test/${role}.json` },
      scheme: { sequence: 1 },
      entities: [{ id: `entity-${role}`, name: `entity-${role}`, services: [{ type: `service-${role}`, status: "valid", certificates: [] }] }],
    }])),
  };
}

describe("Phase 2 explicit trust resolver", () => {
  let profile;
  let snapshot;
  before(async () => {
    profile = await loadTrustProfile("data/trust/webuild-wp4-pilot.json");
    snapshot = snapshotFor(profile);
  });

  it("resolves every configured WP4 role through one request contract", async () => {
    const resolver = createTrustResolver({ profile, snapshot });
    for (const role of roles) {
      const result = await resolver.resolve({
        framework: profile.id,
        role,
        operation: "resolve-provider",
        presentedIdentity: { entityId: `entity-${role}` },
      });
      expect(result).to.include({ trusted: true, state: "trusted", reasonCode: "TRUSTED" });
      expect(result.evidence.role).to.equal(role);
    }
  });

  it("returns stable negative and indeterminate results", async () => {
    const resolver = createTrustResolver({ profile, snapshot });
    const missing = await resolver.resolve({ framework: profile.id, role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "missing" } });
    expect(missing).to.include({ trusted: false, state: "not_trusted", reasonCode: "ENTITY_NOT_LISTED" });
    const revocation = await resolver.resolve({ framework: profile.id, role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "entity-pid-provider" }, policy: { requireRevocation: true } });
    expect(revocation).to.include({ trusted: false, state: "indeterminate", reasonCode: "REVOCATION_UNKNOWN" });
  });

  it("trusts a certificate found in any authenticated same-role LoTE and retains unrelated failures", () => {
    const multiSnapshot = structuredClone(snapshot);
    const first = multiSnapshot.lists["pub-eaa-provider"];
    first.entities = [{ id: "other-provider", name: "other-provider", services: [{ type: "other", status: "valid", certificates: [] }] }];
    const second = structuredClone(first);
    second.source.url = "https://example.test/nxd-pub-eaa.json";
    second.entities = [{ id: "nxd-provider", name: "nxd-provider", services: [{ type: "eaa", status: "valid", certificates: [] }] }];
    multiSnapshot.lists["pub-eaa-provider"] = [first, second];
    multiSnapshot.listFailures = {
      "pub-eaa-provider": [{ url: "https://example.test/broken.xml", reasonCode: "REFERENCED_LIST_SIGNATURE_INVALID", message: "XML signature is missing" }],
    };
    const result = evaluateTrust({
      snapshot: multiSnapshot,
      role: "pub-eaa-provider",
      presentedIdentity: { entityId: "nxd-provider" },
    });
    expect(result).to.include({ trusted: true, reasonCode: "TRUSTED" });
    expect(result.evidence.list.url).to.equal("https://example.test/nxd-pub-eaa.json");
    expect(result.evidence.pointerFailures).to.have.length(1);
  });

  it("requires revocation evidence from the same LoTE that authorizes the identity", async () => {
    const multiSnapshot = structuredClone(snapshot);
    const unrelated = multiSnapshot.lists["pub-eaa-provider"];
    unrelated.revocation = { source: "unrelated-list" };
    unrelated.entities = [{ id: "other-provider", name: "other-provider", services: [{ type: "other", status: "valid", certificates: [] }] }];
    const authorizing = structuredClone(unrelated);
    authorizing.source.url = "https://example.test/nxd-pub-eaa.json";
    delete authorizing.revocation;
    authorizing.entities = [{ id: "nxd-provider", name: "nxd-provider", services: [{ type: "eaa", status: "valid", certificates: [] }] }];
    multiSnapshot.lists["pub-eaa-provider"] = [unrelated, authorizing];
    const resolver = createTrustResolver({ profile, snapshot: multiSnapshot });
    const result = await resolver.resolve({
      framework: profile.id,
      role: "pub-eaa-provider",
      operation: "resolve-provider",
      presentedIdentity: { entityId: "nxd-provider" },
      policy: { requireRevocation: true },
    });
    expect(result).to.include({ trusted: false, state: "indeterminate", reasonCode: "REVOCATION_UNKNOWN" });
    expect(result.evidence.details.url).to.equal("https://example.test/nxd-pub-eaa.json");
  });

  it("returns indeterminate when every same-role LoTE failed authentication", () => {
    const failedSnapshot = structuredClone(snapshot);
    failedSnapshot.lists["pub-eaa-provider"] = [];
    failedSnapshot.listFailures = {
      "pub-eaa-provider": [{ url: "https://example.test/broken.xml", reasonCode: "REFERENCED_LIST_SIGNATURE_INVALID", message: "XML signature is missing" }],
    };
    const result = evaluateTrust({ snapshot: failedSnapshot, role: "pub-eaa-provider", presentedIdentity: { entityId: "nxd-provider" } });
    expect(result).to.include({ trusted: false, state: "indeterminate", reasonCode: "TRUST_EVALUATION_INDETERMINATE" });
    expect(result.evidence.pointerFailures).to.have.length(1);
  });

  it("rejects supplied registrar scope evidence that does not authorize the credential", async () => {
    const resolver = createTrustResolver({ profile, snapshot });
    const result = await resolver.resolve({
      framework: profile.id,
      role: "pid-provider",
      operation: "verify-credential",
      presentedIdentity: { entityId: "entity-pid-provider" },
      credentialContext: { vct: "urn:test:pid", scopeEvidence: { verified: true, credentialTypes: ["urn:test:other"] } },
    });
    expect(result).to.include({ trusted: false, reasonCode: "CREDENTIAL_SCOPE_INVALID" });
  });

  it("records unverified scope without rejecting a currently trusted provider", async () => {
    const resolver = createTrustResolver({ profile, snapshot });
    const result = await resolver.resolve({ framework: profile.id, role: "pid-provider", operation: "verify-credential", presentedIdentity: { entityId: "entity-pid-provider" }, credentialContext: { vct: "urn:test:pid" } });
    expect(result).to.include({ trusted: true, reasonCode: "TRUSTED" });
    expect(result.evidence.scope).to.deep.include({ status: "unverified" });
  });

  it("rejects an injected stale snapshot unless explicitly allowed", async () => {
    const staleSnapshot = structuredClone(snapshot);
    staleSnapshot.lists["pid-provider"].scheme.nextUpdate = "2020-01-01T00:00:00Z";
    const resolver = createTrustResolver({ profile, snapshot: staleSnapshot, clock: () => new Date("2026-07-27T00:00:00Z") });
    const rejected = await resolver.resolve({ framework: profile.id, role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "entity-pid-provider" } });
    expect(rejected).to.include({ trusted: false, state: "not_trusted", reasonCode: "LIST_STALE" });
    const allowed = await resolver.resolve({ framework: profile.id, role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "entity-pid-provider" }, policy: { allowStaleSnapshot: true } });
    expect(allowed).to.include({ trusted: true, reasonCode: "TRUSTED" });
  });

  it("ignores a stale same-role sibling when a fresh LoTE authorizes the identity", async () => {
    const multiSnapshot = structuredClone(snapshot);
    const stale = multiSnapshot.lists["pub-eaa-provider"];
    stale.scheme.nextUpdate = "2020-01-01T00:00:00Z";
    stale.entities = [{ id: "stale-provider", name: "stale-provider", services: [{ type: "eaa", status: "valid", certificates: [] }] }];
    const fresh = structuredClone(stale);
    fresh.source.url = "https://example.test/nxd-pub-eaa.json";
    fresh.scheme.nextUpdate = "2027-01-01T00:00:00Z";
    fresh.entities = [{ id: "nxd-provider", name: "nxd-provider", services: [{ type: "eaa", status: "valid", certificates: [] }] }];
    multiSnapshot.lists["pub-eaa-provider"] = [stale, fresh];
    const resolver = createTrustResolver({ profile, snapshot: multiSnapshot, clock: () => new Date("2026-07-27T00:00:00Z") });
    const result = await resolver.resolve({ framework: profile.id, role: "pub-eaa-provider", operation: "resolve-provider", presentedIdentity: { entityId: "nxd-provider" } });
    expect(result).to.include({ trusted: true, reasonCode: "TRUSTED" });
    expect(result.evidence.list.url).to.equal("https://example.test/nxd-pub-eaa.json");
    expect(result.evidence.pointerFailures.some((failure) => (
      failure.url === stale.source.url && failure.reasonCode === "LIST_STALE"
    ))).to.equal(true);
  });

  it("rejects an unsupported framework without throwing", async () => {
    const resolver = createTrustResolver({ profile, snapshot });
    const result = await resolver.resolve({ framework: "other", role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "x" } });
    expect(result).to.include({ trusted: false, reasonCode: "UNSUPPORTED_FRAMEWORK" });
  });

  it("returns the same decision through the loopback HTTP adapter", async function () {
    this.timeout(10_000);
    const resolver = createTrustResolver({ profile, snapshot });
    const server = createTrustResolverServer({ resolver });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/trust/resolve`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ framework: profile.id, role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "entity-pid-provider" } }),
      });
      expect(response.status).to.equal(200);
      expect(await response.json()).to.include({ trusted: true, reasonCode: "TRUSTED" });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("produces the same result through the CLI and an injected snapshot", async function () {
    this.timeout(10_000);
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), "webuild-phase2-"));
    try {
      const request = { framework: profile.id, role: "pid-provider", operation: "resolve", presentedIdentity: { entityId: "entity-pid-provider" } };
      const profilePath = path.join(temp, "profile.json");
      const requestPath = path.join(temp, "request.json");
      const snapshotPath = path.join(temp, "snapshot.json");
      await fs.writeFile(profilePath, JSON.stringify(profile));
      await fs.writeFile(requestPath, JSON.stringify(request));
      await fs.writeFile(snapshotPath, JSON.stringify(snapshot));
      const { stdout } = await execFileAsync(process.execPath, ["scripts/trustResolver.js", "--profile", profilePath, "--request", requestPath, "--snapshot", snapshotPath]);
      expect(JSON.parse(stdout)).to.include({ trusted: true, reasonCode: "TRUSTED" });
    } finally {
      await fs.rm(temp, { recursive: true, force: true });
    }
  });
});
