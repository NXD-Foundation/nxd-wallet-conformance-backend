import { expect } from "chai";
import { createAuthenticatedSnapshotCache } from "../trust/snapshotCache.js";

describe("authenticated trust snapshot cache", () => {
  it("coalesces concurrent loads and refreshes before list expiry", async () => {
    let now = 0;
    let loads = 0;
    const cache = createAuthenticatedSnapshotCache({ clock: () => now, maxAgeMs: 24 * 60 * 60 * 1000, refreshLeadMs: 1000, maxEntries: 2 });
    const load = async () => { loads++; return { value: loads, lotl: { scheme: { nextUpdate: new Date(now + 10_000).toISOString() } }, lists: {} }; };
    const [first, joined] = await Promise.all([cache.get("profile|role", load), cache.get("profile|role", load)]);
    expect(loads).to.equal(1);
    expect(first).to.equal(joined);
    now = 9500;
    const refreshed = await cache.get("profile|role", load);
    expect(loads).to.equal(2);
    expect(refreshed.value).to.equal(2);
  });

  it("serves last authenticated evidence only until its NextUpdate after refresh failure", async () => {
    let now = 0;
    const cache = createAuthenticatedSnapshotCache({ clock: () => now, refreshLeadMs: 1000 });
    const valid = { marker: "last-good", lotl: { scheme: { nextUpdate: new Date(5000).toISOString() } }, lists: {} };
    await cache.get("key", async () => valid);
    now = 4500;
    expect(await cache.get("key", async () => { throw new Error("offline"); })).to.equal(valid);
    now = 5001;
    let caught;
    try { await cache.get("key", async () => { throw new Error("offline"); }); } catch (error) { caught = error; }
    expect(caught?.message).to.equal("offline");
  });
});
