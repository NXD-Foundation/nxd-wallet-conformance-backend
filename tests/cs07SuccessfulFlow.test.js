import fs from "fs";
import crypto from "crypto";
import * as jose from "jose";
import { expect } from "chai";
import { decryptJWE } from "../utils/cryptoUtils.js";
import { parseCs07AuthorizationResponse } from "../utils/cs07DcApi.js";
import { validateCs07CredentialPresentations } from "../utils/cs07ResponseValidation.js";

function disclosure(name, value) {
  return Buffer.from(JSON.stringify(["salt", name, value])).toString("base64url");
}

function sdHash(sdJwt) {
  const parts = sdJwt.split("~");
  parts.pop();
  let input = parts.join("~");
  if (!input.endsWith("~")) input += "~";
  return crypto.createHash("sha256").update(Buffer.from(input, "ascii")).digest("base64url");
}

describe("CS-07 successful encrypted response flow", () => {
  it("decrypts a dc_api.jwt response and validates an mdoc presentation", async () => {
    const privateKeyPem = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
    const privateKey = await jose.importPKCS8(privateKeyPem, "ES256");
    const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: "spki", format: "pem" });
    const publicKey = await jose.exportJWK(await jose.importSPKI(publicKeyPem, "ES256"));
    const encryptionKey = await jose.importJWK(publicKey, "ECDH-ES");
    const encrypted = await new jose.EncryptJWT({
      vp_token: { license: "mdoc-placeholder" },
    })
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
      .encrypt(encryptionKey);

    const decrypted = await decryptJWE(encrypted, privateKeyPem, "dc_api.jwt");
    const parsed = parseCs07AuthorizationResponse(decrypted, {
      credentials: [{ id: "license", format: "mso_mdoc" }],
    });
    const result = await validateCs07CredentialPresentations({
      vpToken: parsed.vpToken,
      session: {
        nonce: "nonce",
        client_id: "x509_san_dns:verifier.example",
        expected_audience: "origin:https://rp.example",
        dcql_query: { credentials: [{ id: "license", format: "mso_mdoc" }] },
      },
      options: { cs02: { strict: true } },
    });
    expect(result.verifiedCredentialIds).to.deep.equal(["license"]);
  });

  it("runs the generic SD-JWT dispatch after encrypted response parsing", async () => {
    const issuer = await jose.generateKeyPair("ES256", { extractable: true });
    const holder = await jose.generateKeyPair("ES256", { extractable: true });
    const issuerPrivateJwk = await jose.exportJWK(issuer.privateKey);
    const issuerPublicJwk = await jose.exportJWK(issuer.publicKey);
    const holderPrivateJwk = await jose.exportJWK(holder.privateKey);
    const holderPublicJwk = await jose.exportJWK(holder.publicKey);
    const issuerKey = await jose.importJWK(issuerPrivateJwk, "ES256");
    const now = Math.floor(Date.now() / 1000);
    const disclosed = disclosure("family_name", "Neslo");
    const issuerJwt = await new jose.SignJWT({
      iss: "https://issuer.example", iat: now, exp: now + 300, vct: "test",
      cnf: { jwk: holderPublicJwk }, _sd_alg: "sha-256",
      _sd: [crypto.createHash("sha256").update(disclosed, "ascii").digest("base64url")],
    }).setProtectedHeader({ alg: "ES256", typ: "dc+sd-jwt" }).sign(issuerKey);
    const unsigned = `${issuerJwt}~${disclosed}~`;
    const holderKey = await jose.importJWK(holderPrivateJwk, "ES256");
    const kbJwt = await new jose.SignJWT({
      nonce: "nonce", aud: "origin:https://rp.example", iat: now, sd_hash: sdHash(unsigned),
    }).setProtectedHeader({ alg: "ES256", typ: "kb+jwt" }).sign(holderKey);
    const sdJwt = `${unsigned}${kbJwt}`;
    const result = await validateCs07CredentialPresentations({
      vpToken: { pid: sdJwt },
      session: {
        nonce: "nonce",
        client_id: "x509_san_dns:verifier.example",
        expected_audience: "origin:https://rp.example",
        dcql_query: { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["test"] }, claims: [{ path: ["family_name"] }] }] },
      },
      options: { cs02: { strict: true }, issuerVerificationJwk: issuerPublicJwk, rejectUnsolicitedDisclosures: true },
    });
    expect(result.verifiedCredentialIds).to.deep.equal(["pid"]);
  });
});
