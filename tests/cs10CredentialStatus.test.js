import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import zlib from "node:zlib";
import { jwtVerify } from "jose";
import { allocateCredentialStatus, allocateIssuedCredentialStatus, revokeCredentialStatus, signCredentialStatusList, readCredentialStatusToken, resetCredentialStatusListsForTests } from "../utils/credentialStatusList.js";
import { resolveIssuerSigningMaterial } from "../utils/credGenerationUtils.js";

describe("CS-10 credential status lists", () => {
  beforeEach(() => resetCredentialStatusListsForTests());

  it("allocates a valid entry and publishes INVALID irreversibly", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const tokenBefore = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(tokenBefore, reference.idx).status, 0);

    revokeCredentialStatus(reference.listId, reference.idx);
    const tokenAfter = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(tokenAfter, reference.idx).status, 1);
    revokeCredentialStatus(reference.listId, reference.idx);
    const tokenAgain = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(tokenAgain, reference.idx).status, 1);
  });

  it("marks an issued credential INVALID before the credential is returned", async () => {
    const status = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example", revoked: true });
    const listId = status.status_list.uri.split("/").pop();
    const token = await signCredentialStatusList(listId, { issuer: "https://issuer.example" });
    assert.equal(readCredentialStatusToken(token, status.status_list.idx).status, 1);
  });

  it("gives two revocable credentials the same status list and different unused indices", () => {
    const first = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const second = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const third = allocateCredentialStatus({ baseUrl: "https://issuer.example" });

    assert.equal(first.status.status_list.uri, second.status.status_list.uri);
    assert.equal(second.status.status_list.uri, third.status.status_list.uri);
    assert.equal(new Set([first.idx, second.idx, third.idx]).size, 3);
  });

  it("publishes a 1-bit status list token whose subject is the retrieval URI", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const now = Math.floor(Date.now() / 1000);
    const token = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example", now });
    const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    const read = readCredentialStatusToken(token, reference.idx);
    const bytes = zlib.inflateSync(Buffer.from(read.payload.status_list.lst, "base64url"));

    assert.equal(header.typ, "statuslist+jwt");
    assert.equal(header.alg, "ES256");
    assert.equal(read.payload.sub, reference.status.status_list.uri);
    assert.equal(read.payload.exp, now + 300);
    assert.equal(read.payload.ttl, 300);
    assert.equal(read.payload.status_list.bits, 1);
    assert.ok(bytes.length * 8 >= 65536);
    await jwtVerify(token, crypto.createPublicKey(fs.readFileSync("./private-key.pem")), { algorithms: ["ES256"] });
  });

  it("signs a status list with the credential key and separates different certificates", async () => {
    const first = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const second = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const firstPem = first.privateKey.export({ type: "pkcs8", format: "pem" });
    const secondPem = second.privateKey.export({ type: "pkcs8", format: "pem" });
    const firstSigning = { privateKeyPem: firstPem, header: { x5c: ["cert-a"] } };
    const secondSigning = { privateKeyPem: secondPem, header: { x5c: ["cert-b"] } };

    const a = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example", signing: firstSigning });
    const a2 = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example", signing: { privateKeyPem: firstPem, header: { x5c: ["cert-a"] } } });
    const sameKey = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example", signing: { privateKeyPem: firstPem, header: { x5c: ["cert-c"] } } });
    const b = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example", signing: secondSigning });
    const application = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example" });

    assert.equal(a.status_list.uri, a2.status_list.uri);
    assert.notEqual(a.status_list.uri, sameKey.status_list.uri);
    assert.notEqual(a.status_list.uri, b.status_list.uri);
    assert.notEqual(a.status_list.uri, application.status_list.uri);

    const token = await signCredentialStatusList(a.status_list.uri.split("/").pop(), { issuer: "https://issuer.example" });
    const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    assert.equal(header.typ, "statuslist+jwt");
    assert.deepEqual(header.x5c, ["cert-a"]);
    assert.equal(header.kid, undefined);
    await jwtVerify(token, first.publicKey, { algorithms: ["ES256"] });
    await assert.rejects(
      () => jwtVerify(token, crypto.createPublicKey(fs.readFileSync("./private-key.pem")), { algorithms: ["ES256"] }),
      (error) => /signature verification failed/i.test(error.message),
    );
  });

  it("publishes an x509 session status list under that session certificate", async () => {
    const signing = resolveIssuerSigningMaterial({ signatureType: "x509" }, "https://issuer.example");
    const status = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example", signing });
    const kidSession = allocateIssuedCredentialStatus({
      baseUrl: "https://issuer.example",
      signing: resolveIssuerSigningMaterial({ signatureType: "kid-jwk" }, "https://issuer.example"),
    });
    const application = allocateIssuedCredentialStatus({ baseUrl: "https://issuer.example" });
    const token = await signCredentialStatusList(status.status_list.uri.split("/").pop(), { issuer: "https://issuer.example" });
    const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    const certificate = new crypto.X509Certificate(fs.readFileSync("./x509EC/client_certificate.crt"));

    assert.deepEqual(header.x5c, [certificate.raw.toString("base64")]);
    assert.equal(kidSession.status_list.uri, application.status_list.uri);
    assert.notEqual(status.status_list.uri, application.status_list.uri);
    await jwtVerify(token, certificate.publicKey, { algorithms: ["ES256"] });
  });

  it("packs status bits least-significant-bit first and leaves other entries valid", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    revokeCredentialStatus(reference.listId, 0);
    revokeCredentialStatus(reference.listId, 8);
    const token = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    const read = readCredentialStatusToken(token, 0);
    const bytes = zlib.inflateSync(Buffer.from(read.payload.status_list.lst, "base64url"));

    assert.equal(bytes[0] & 1, 1);
    assert.equal(bytes[0] & 0b10, 0);
    assert.equal(bytes[1] & 1, 1);
    assert.equal(readCredentialStatusToken(token, reference.idx).status, reference.idx === 0 || reference.idx === 8 ? 1 : 0);
    assert.equal(readCredentialStatusToken(token, 1).status, 0);
  });

  it("keeps a revoked index INVALID when later credentials are allocated on the same list", async () => {
    const first = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    revokeCredentialStatus(first.listId, first.idx);
    const second = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    const token = await signCredentialStatusList(first.listId, { issuer: "https://issuer.example" });

    assert.equal(second.status.status_list.uri, first.status.status_list.uri);
    assert.notEqual(second.idx, first.idx);
    assert.equal(readCredentialStatusToken(token, first.idx).status, 1);
    assert.equal(readCredentialStatusToken(token, second.idx).status, 0);
  });

  it("rejects an index outside the list and a status list that is not 1 bit", async () => {
    const reference = allocateCredentialStatus({ baseUrl: "https://issuer.example" });
    assert.throws(() => revokeCredentialStatus(reference.listId, -1), (error) => error.status === 400);
    assert.throws(() => revokeCredentialStatus(reference.listId, 131072), (error) => error.status === 400);

    const token = await signCredentialStatusList(reference.listId, { issuer: "https://issuer.example" });
    assert.throws(() => readCredentialStatusToken(token, -1), /out of range/);
    const payload = readCredentialStatusToken(token, reference.idx).payload;
    payload.status_list.bits = 2;
    const widened = `${token.split(".")[0]}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;
    assert.throws(() => readCredentialStatusToken(widened, reference.idx), /unsupported status-list bits/);
  });
});
