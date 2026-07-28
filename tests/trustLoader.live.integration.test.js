import { expect } from "chai";
import { loadTrustProfile } from "../trust/profile.js";
import { loadTrustSnapshot } from "../trust/loader.js";

const runLiveTests = process.env.RUN_LIVE_TRUST_TESTS === "1";
const describeLive = runLiveTests ? describe : describe.skip;

describeLive("Live WE BUILD LoTL NXD integration", () => {
  it("fetches the published LoTL, follows the NXD EAA pointer, and validates it", async function () {
    this.timeout(30_000);
    const profile = await loadTrustProfile("data/trust/webuild-wp4-pilot.json");
    profile.bootstrap.loTLSignerFingerprints = [
      // Published by the WE BUILD LoTL JAdES x5c certificate as of 2026-07-27.
      "339753d8aed9b99febc13cc15c87e1e892e391a0dffb1bd3ac820d73219e38e1",
    ];
    profile.network.timeoutMs = 20_000;
    profile.network.maxBytes = 5_000_000;

    const snapshot = await loadTrustSnapshot({
      profile,
      listTypes: ["eaa-provider"],
    });
    const eaa = snapshot.lists["eaa-provider"].find((candidate) => (
      candidate.source.url === "https://trustlist.nxd.foundation/trust-lists/nxd-eaa-providers-lote.json"
    ));

    expect(snapshot.format).to.equal("json");
    expect(eaa).to.exist;
    expect(eaa.format).to.equal("json");
    expect(eaa.scheme.type).to.equal(profile.listTypes["eaa-provider"].referenceUri);
    expect(eaa.entities).to.not.be.empty;
    expect(eaa.signer.fingerprint).to.equal("6d96d9350e5f23018d8790cb6ff7c75aa8eb31d382fbd83f75db24f06ea1eb6e");
  });
});
