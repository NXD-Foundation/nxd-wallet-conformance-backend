import { expect } from "chai";
import zlib from "node:zlib";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Cs02StatusListError, validateCs02CredentialStatusList } from "../utils/cs02StatusList.js";

const uri = "https://issuer.example/status-lists/credentials/list-1";
const issuer = "https://issuer.example";

function sdJwt(payload) {
  const encoded = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encoded({ alg: "ES256", typ: "dc+sd-jwt" })}.${encoded(payload)}.sig`;
}

function bitList(idx, bit) {
  const bytes = Buffer.alloc(16);
  if (bit) bytes[Math.floor(idx / 8)] |= 1 << (idx % 8);
  return zlib.deflateSync(bytes).toString("base64url");
}

describe("CS-10 relying party status checks", () => {
  let privateKey;
  let publicJwk;
  let otherJwk;
  let requests;
  let originalFetch;

  beforeEach(async () => {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const other = await generateKeyPair("ES256", { extractable: true });
    privateKey = keys.privateKey;
    publicJwk = await exportJWK(keys.publicKey);
    publicJwk.kid = "status-key";
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    otherJwk = await exportJWK(other.publicKey);
    otherJwk.kid = "status-key";
    otherJwk.alg = "ES256";
    otherJwk.use = "sig";
    requests = [];
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function install({ token, status = 200, jwk = publicJwk, jwksStatus = 200 } = {}) {
    globalThis.fetch = async (url, init) => {
      requests.push({ url: String(url), init });
      if (String(url).endsWith("/jwks")) {
        return new Response(JSON.stringify({ keys: jwk ? [jwk] : [] }), {
          status: jwksStatus,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(token ?? "", { status, headers: { "content-type": "application/statuslist+jwt" } });
    };
  }

  async function statusToken(overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      sub: overrides.sub ?? uri,
      iat: overrides.iat ?? now,
      exp: overrides.exp ?? now + 300,
      ttl: overrides.ttl ?? 120,
      status_list: {
        bits: overrides.bits ?? 1,
        lst: overrides.lst ?? bitList(overrides.idx ?? 3, overrides.bit ?? 0),
      },
    }).setProtectedHeader({
      alg: "ES256",
      typ: overrides.typ ?? "statuslist+jwt",
      kid: "status-key",
    }).sign(privateKey);
  }

  function check(idx = 3) {
    return validateCs02CredentialStatusList(
      sdJwt({ iss: issuer, status: { status_list: { idx, uri } } }),
      { enforceStatus: true, jwksUri: `${issuer}/jwks` },
    );
  }

  it("accepts a fresh VALID list fetched without credential identity", async () => {
    install({ token: await statusToken() });
    const result = await check();

    expect(result.statusState).to.equal("valid");
    expect(result.enforced).to.equal(true);
    expect(requests.map((call) => call.url)).to.deep.equal([uri, `${issuer}/jwks`]);
    expect(requests[0].init.redirect).to.equal("error");
    expect(requests[0].init.headers.Accept).to.equal("application/statuslist+jwt");
    expect(requests[0].init.headers).to.not.have.property("Authorization");
    expect(requests[0].url).to.equal(uri);
  });

  it("rejects an unexpired credential whose status bit is INVALID", async () => {
    install({ token: await statusToken({ bit: 1 }) });
    try {
      await check();
      expect.fail("expected a revoked credential");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("revoked");
    }
  });

  it("rejects a status token with the wrong subject, type, bit size, signer, or index", async () => {
    const cases = [
      { token: await statusToken({ sub: "https://issuer.example/other" }), state: "status_unavailable" },
      { token: await statusToken({ typ: "JWT" }), state: "status_unavailable" },
      { token: await statusToken({ bits: 2 }), state: "status_unavailable" },
      { token: await statusToken(), jwk: otherJwk, state: "status_unavailable" },
      { token: await statusToken(), idx: 1000, state: "status_unavailable" },
    ];

    for (const item of cases) {
      requests = [];
      install(item);
      try {
        await check(item.idx ?? 3);
        expect.fail(`expected rejection for ${item.state}`);
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02StatusListError);
        expect(error.statusState).to.equal(item.state);
      }
    }
  });

  it("treats an expired status token as stale and an unreachable list as unavailable", async () => {
    const now = Math.floor(Date.now() / 1000);
    install({ token: await statusToken({ iat: now - 300, exp: now - 120 }) });
    try {
      await check();
      expect.fail("expected a stale status list");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("stale");
    }

    requests = [];
    install({ token: "nope", status: 503 });
    try {
      await check();
      expect.fail("expected an unavailable status list");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("status_unavailable");
    }
  });
});
