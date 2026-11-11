import { expect } from "chai";
import { exportJWK, generateKeyPair } from "jose";
import { Cs02StatusListError, resetCredentialStatusCacheForTests, validateCs02CredentialStatusList } from "../utils/cs02StatusList.js";
import {
  installStatusListTestHooks,
  resetStatusListTestHooks,
  signStatusListToken,
  stubStatusListFetch,
} from "./helpers/wuaStatusListFixtures.js";

const uri = "https://issuer.example/status-lists/credentials/list-1";
const issuer = "https://issuer.example";

function sdJwt(payload, disclosures = []) {
  const encoded = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const disclosurePart = disclosures.length ? `${disclosures.join("~")}~` : "";
  return `${encoded({ alg: "ES256", typ: "dc+sd-jwt" })}.${encoded(payload)}.sig~${disclosurePart}`;
}

function disclosure(name, value) {
  return Buffer.from(JSON.stringify(["salt", name, value])).toString("base64url");
}

describe("CS-10 relying party status checks", () => {
  let privateKey;
  let publicJwk;
  let otherJwk;
  let fetches;

  beforeEach(async () => {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const other = await generateKeyPair("ES256", { extractable: true });
    privateKey = keys.privateKey;
    publicJwk = await exportJWK(keys.publicKey);
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    otherJwk = await exportJWK(other.publicKey);
    otherJwk.alg = "ES256";
    otherJwk.use = "sig";
    fetches = 0;
    resetCredentialStatusCacheForTests();
  });

  afterEach(() => {
    resetCredentialStatusCacheForTests();
    resetStatusListTestHooks();
  });

  function install(token, { status = 200 } = {}) {
    installStatusListTestHooks({
      fetchImpl: async (url, init) => {
        fetches += 1;
        return stubStatusListFetch(token, { status })(url, init);
      },
    });
  }

  async function statusToken(overrides = {}) {
    return signStatusListToken({
      privateKey: overrides.privateKey || privateKey,
      uri,
      statuses: overrides.statuses ?? [0, 0, 0, overrides.bit ?? 0],
      bits: overrides.bits,
      lst: overrides.lst,
      sub: overrides.sub,
      typ: overrides.typ,
      iat: overrides.iat,
      exp: overrides.exp,
      ttl: overrides.ttl ?? 120,
      header: overrides.header,
    });
  }

  function check(idx = 3, jwk = publicJwk) {
    return validateCs02CredentialStatusList(
      sdJwt({ iss: issuer, status: { status_list: { idx, uri } } }),
      { verificationJwk: jwk },
    );
  }

  it("accepts a fresh VALID list and reuses it for the next presentation", async () => {
    install(await statusToken());
    const first = await check();
    const second = await check();

    expect(first).to.include({ statusState: "valid", enforced: true, fromCache: false });
    expect(second).to.include({ statusState: "valid", enforced: true, fromCache: true });
    expect(fetches).to.equal(1);
  });

  it("rejects an unexpired credential whose status bit is INVALID", async () => {
    install(await statusToken({ bit: 1 }));
    try {
      await check();
      expect.fail("expected a revoked credential");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("revoked");
      expect(error.message).to.equal("Credential status is INVALID");
    }
  });

  it("rejects a status claim that is only selectively disclosed", async () => {
    try {
      await validateCs02CredentialStatusList(
        sdJwt(
          { iss: issuer, _sd: ["digest"] },
          [disclosure("status", { status_list: { idx: 3, uri } })],
        ),
        { verificationJwk: publicJwk },
      );
      expect.fail("expected a disclosed status claim to be rejected");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.message).to.match(/issuer-signed payload/);
      expect(fetches).to.equal(0);
    }
  });

  it("rejects a status token with the wrong subject, type, bit size, signer, or index", async () => {
    const cases = [
      { token: await statusToken({ sub: "https://issuer.example/other" }) },
      { token: await statusToken({ typ: "JWT" }) },
      { token: await statusToken({ bits: 2, lst: "eNrbuRgAAhcBXQ" }) },
      { token: await statusToken({ privateKey: await generateKeyPair("ES256").then((keys) => keys.privateKey) }) },
      { token: await statusToken(), idx: 1000 },
    ];

    for (const item of cases) {
      fetches = 0;
      resetCredentialStatusCacheForTests();
      install(item.token);
      try {
        await check(item.idx ?? 3);
        expect.fail("expected status rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02StatusListError);
        expect(error.statusState).to.equal("status_unavailable");
      }
    }
  });

  it("does not accept a status list signed only by a header key", async () => {
    install(await statusToken({
      privateKey: await generateKeyPair("ES256").then((keys) => keys.privateKey),
      header: { jwk: otherJwk },
    }));
    try {
      await check();
      expect.fail("expected the credential issuer key to be required");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("status_unavailable");
    }
  });

  it("treats an expired status token as stale and an unreachable list as unavailable", async () => {
    const now = Math.floor(Date.now() / 1000);
    install(await statusToken({ iat: now - 300, exp: now - 120 }));
    try {
      await check();
      expect.fail("expected a stale status list");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("stale");
    }

    resetCredentialStatusCacheForTests();
    install("nope", { status: 503 });
    try {
      await check();
      expect.fail("expected an unavailable status list");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("status_unavailable");
    }
  });

  it("shares one fetch when two presentations check the same list together", async () => {
    let releaseFetch;
    const opened = new Promise((resolve) => {
      releaseFetch = resolve;
    });
    installStatusListTestHooks({
      fetchImpl: async () => {
        fetches += 1;
        await opened;
        const token = await statusToken({ statuses: [0, 1] });
        return stubStatusListFetch(token)();
      },
    });

    const first = check(0);
    const second = check(1);
    releaseFetch();
    const results = await Promise.allSettled([first, second]);

    expect(fetches).to.equal(1);
    expect(results[0].status).to.equal("fulfilled");
    expect(results[0].value.statusState).to.equal("valid");
    expect(results[1].status).to.equal("rejected");
    expect(results[1].reason.statusState).to.equal("revoked");
  });
});
