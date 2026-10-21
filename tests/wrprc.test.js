import { expect } from "chai";
import forge from "node-forge";
import { SignJWT, importPKCS8 } from "jose";
import { assertQueryScope, resolveRegistrationIntendedUse, encodeRegistrationCertificate, decodeRegistrationCertificate, verifyWrprc, assertRegistrarDataset } from "../utils/wrprc.js";

const credential = (type = "pid", paths = [["family_name"]]) => ({ format: "dc+sd-jwt", meta: { vct_values: [type] }, claims: paths.map((path) => ({ path })) });
const use = { intendedUseIdentifier: "use-1", credentials: [credential()], purpose: [{ lang: "en", content: "Identify" }], privacyPolicy: [{ url: "https://rp.example/privacy" }] };
const registration = { sub: "rp", serviceId: "service", intendedUse: [use] };
const dataset = { identifier: "rp", intendedUseIdentifier: "use-1", registryURI: "https://registry.example", srvDescription: [{ lang: "en", value: "Verifier" }], purpose: [{ lang: "en", value: "Identify" }], policyURI: "https://rp.example/privacy" };

describe("WRPRC scoped registration helpers", () => {
  it("does not union claims across intended uses or credential entries", () => {
    const record = { intendedUse: [use, { intendedUseIdentifier: "use-2", credentials: [credential("pid", [["birth_date"]])] }] };
    const selected = resolveRegistrationIntendedUse(record, { intendedUseId: "use-1" });
    expect(() => assertQueryScope({ credentials: [credential("pid", [["birth_date"]])] }, selected)).to.throw("scope");
    expect(() => resolveRegistrationIntendedUse(record)).to.throw("ambiguous");
    expect(() => assertQueryScope({ credentials: [credential("pid", [["family_name"], ["birth_date"]])] }, { credentials: [credential(), credential("pid", [["birth_date"]])] })).to.throw("scope");
  });
  it("rejects undeclared scopes, missing query claims, and unregistered type alternatives", () => {
    expect(() => resolveRegistrationIntendedUse({})).to.throw("not declared");
    expect(() => assertQueryScope({ credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["pid"] } }] }, use)).to.throw("scope");
    const query = credential(); query.meta.vct_values.push("unregistered");
    expect(() => assertQueryScope({ credentials: [query] }, use)).to.throw("scope");
  });
  it("compares complete nested paths and numeric/null path components", () => {
    const registered = { credentials: [credential("pid", [["address", "street"], ["items", null, "name"], ["items", 0, "name"]])] };
    expect(assertQueryScope({ credentials: [credential("pid", [["address", "street"], ["items", null, "name"]])] }, registered)).to.equal(true);
    expect(() => assertQueryScope({ credentials: [credential("pid", [["address"]])] }, registered)).to.throw("scope");
    expect(() => assertQueryScope({ credentials: [credential("pid", [["items", 1, "name"]])] }, registered)).to.throw("scope");
  });
  it("handles mdoc and CSC policy scopes without permitting unsupported formats", () => {
    const mdoc = { format: "mso_mdoc", meta: { doctype_value: "pid" }, claims: [{ path: ["namespace", "name"] }] };
    const csc = { format: "https://cloudsignatureconsortium.org/2025/x509", meta: { certificatePolicies: ["1.2.3"] } };
    expect(assertQueryScope({ credentials: [mdoc, csc] }, { credentials: [mdoc, csc] })).to.equal(true);
    expect(() => assertQueryScope({ credentials: [{ ...mdoc, meta: { doctype_value: "mdl" } }] }, { credentials: [mdoc] })).to.throw("scope");
  });
  it("rejects conflicting service and intended-use bindings", () => {
    expect(() => resolveRegistrationIntendedUse(registration, { serviceId: "other", intendedUseId: "use-1" })).to.throw("service mismatch");
    expect(() => resolveRegistrationIntendedUse(registration, { intendedUseId: "other" })).to.throw("missing or ambiguous");
    const raidiam = { id: "certificate-id", intended_use_id: "use-1", credentials: [credential()] };
    expect(resolveRegistrationIntendedUse(raidiam, { intendedUseId: "use-1" })).to.equal(raidiam);
    expect(() => resolveRegistrationIntendedUse(raidiam, { intendedUseId: "other" })).to.throw("intended use mismatch");
  });
  it("encodes a compact JWT exactly once and rejects malformed encodings", () => {
    expect(decodeRegistrationCertificate(encodeRegistrationCertificate("a.b.c"))).to.equal("a.b.c");
    expect(() => decodeRegistrationCertificate("a.b.c")).to.throw("base64url");
    expect(() => decodeRegistrationCertificate("YQ")).to.throw("compact");
    expect(() => encodeRegistrationCertificate("a.b.")).to.throw("compact");
  });
  it("requires registrar dataset purpose, privacy and identity consistency", () => {
    const options = { registration, intendedUse: use, entityId: "rp", intendedUseId: "use-1", serviceId: "service" };
    expect(assertRegistrarDataset(dataset, options)).to.equal(true);
    for (const patch of [{ identifier: "other" }, { intendedUseIdentifier: "other" }, { purpose: [{ lang: "en", value: "Other" }] }, { policyURI: "https://other.example" }]) {
      expect(() => assertRegistrarDataset({ ...dataset, ...patch }, options)).to.throw("mismatch");
    }
    expect(() => assertRegistrarDataset(dataset, { ...options, registration: { ...registration, registry_uri: "https://different.example" } })).to.throw("registry URI mismatch");
    expect(() => assertRegistrarDataset(dataset, { ...options, registration: { ...registration, srv_description: [{ lang: "en", value: "Different service" }] } })).to.throw("service description mismatch");
    expect(assertRegistrarDataset(dataset, { ...options, registration: { ...registration, srv_description: [[{ lang: "en", value: "Verifier" }]] } })).to.equal(true);
  });
  it("accepts registrar privacy outside a Raidiam certificate only when the dataset URL is valid", () => {
    const raidiam = { sub: "rp", intended_use_id: "use-1", credentials: [credential()], purpose: use.purpose };
    const options = { registration: raidiam, intendedUse: raidiam, entityId: "rp", intendedUseId: "use-1" };
    expect(assertRegistrarDataset(dataset, options)).to.equal(true);
    for (const policyURI of [undefined, "", "not a URL", "javascript:alert(1)", "https://user:pass@example.org/privacy"]) {
      expect(() => assertRegistrarDataset({ ...dataset, policyURI }, options)).to.throw("privacy policy URL");
    }
    expect(() => assertRegistrarDataset(dataset, { ...options, intendedUse: { ...raidiam, privacy_policy: "https://other.example/privacy" } })).to.throw("privacy policy mismatch");
  });
});

describe("WRPRC cryptographic verification", () => {
  let key; let x5c;
  before(async () => {
    const pair = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = pair.publicKey; cert.serialNumber = "01";
    cert.validity.notBefore = new Date("2020-01-01"); cert.validity.notAfter = new Date("2035-01-01");
    cert.setSubject([{ name: "commonName", value: "Test WRPRC signer" }]); cert.setIssuer(cert.subject.attributes);
    cert.sign(pair.privateKey, forge.md.sha256.create());
    x5c = [forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())];
    key = await importPKCS8(forge.pki.privateKeyInfoToPem(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(pair.privateKey))), "RS256");
  });
  async function token(patch = {}, header = {}) {
    return new SignJWT({ ...registration, entitlements: ["https://uri.etsi.org/19475/Entitlement/Service_Provider"], exp: 2000000000, ...patch }).setProtectedHeader({ alg: "RS256", typ: "rc-wrp+jwt", x5c, ...header }).sign(key);
  }
  const options = () => ({ entityId: "rp", intendedUseId: "use-1", serviceId: "service", checkTrust: async () => ({ trusted: true }), currentDate: new Date("2026-01-01") });
  async function rejects(value, opts, text) {
    let caught; try { await verifyWrprc(value, opts); } catch (error) { caught = error; }
    expect(caught, "verification must reject").to.be.instanceOf(Error);
    if (text) expect(caught.message).to.include(text);
  }
  it("verifies signature, trusted chain and bound single intended use", async () => {
    const verified = await verifyWrprc(await token(), options());
    expect(verified.intendedUse).to.deep.equal(use);
  });
  it("rejects expired or missing-exp tokens and WRPAC subject mismatch", async () => {
    await rejects(await token({ exp: 100 }), options(), "exp");
    await rejects(await token({ exp: undefined }), options(), "exp");
    await rejects(await token({ sub: "other" }), options(), "subject");
  });
  it("rejects untrusted signer, missing entitlement, invalid type and tampered signature", async () => {
    await rejects(await token(), { ...options(), checkTrust: async () => ({ trusted: false }) }, "not trusted");
    await rejects(await token({ entitlements: [] }), options(), "entitlement");
    await rejects(await token({ entitlements: "https://uri.etsi.org/19475/Entitlement/Service_Provider" }), options(), "entitlement");
    await rejects(await token({}, { typ: "JWT" }), options(), "type");
    const signed = await token(); const parts = signed.split(".");
    parts[1] = Buffer.from(JSON.stringify({ ...registration, exp: 2000000000 })).toString("base64url");
    await rejects(parts.join("."), options(), "signature");
  });
});
