import { expect } from "chai";
import http from "node:http";
import fs from "node:fs";
import { SignJWT, importPKCS8 } from "jose";
import { performPresentation } from "../src/lib/presentation.js";
import { setWalletTrustSessionStorageForTests } from "../src/lib/trustFramework.js";
import { computeX509HashClientIdFromLeafCertBase64 } from "../../utils/cs02ClientIdBinding.js";

describe("strict wallet presentation error submission", () => {
  it("posts error, description and state when trust checking fails after JAR verification", async () => {
    const previous = { ...process.env };
    Object.assign(process.env, { CS02_COMPATIBILITY: "false", CS02_ALLOW_HTTP: "true" });
    const leaf = fs.readFileSync("x509EC/client_certificate.crt", "utf8")
      .replace(/-----[^\n]+-----/g, "").replace(/\s+/g, "");
    const clientId = computeX509HashClientIdFromLeafCertBase64(leaf);
    let jwt;
    let submitted;
    const server = http.createServer(async (req, res) => {
      if (req.url === "/request") {
        res.setHeader("content-type", "application/oauth-authz-req+jwt");
        res.end(jwt);
      } else {
        let body = "";
        for await (const chunk of req) body += chunk;
        submitted = { method: req.method, contentType: req.headers["content-type"], form: new URLSearchParams(body) };
        res.end("{}");
      }
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      const key = await importPKCS8(fs.readFileSync("x509EC/ec_private_pkcs8.key", "utf8"), "ES256");
      jwt = await new SignJWT({
        client_id: clientId, response_uri: `${base}/response`, state: "echo-this-state",
        nonce: "nonce-123", response_type: "vp_token", response_mode: "direct_post",
        aud: "https://self-issued.me/v2",
        dcql_query: { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:test:pid"] } }] },
      }).setProtectedHeader({ alg: "ES256", typ: "oauth-authz-req+jwt", x5c: [leaf] })
        .setIssuedAt().setExpirationTime("5m").sign(key);
      setWalletTrustSessionStorageForTests({ get: async () => { throw new Error("Verifier trust check failed"); } });
      let failure;
      try {
        await performPresentation({ deepLink: `openid4vp://?request_uri=${encodeURIComponent(`${base}/request`)}&client_id=${encodeURIComponent(clientId)}`, credentialType: "pid" }, "trust-error-session");
      } catch (error) { failure = error; }
      expect(failure?.message).to.equal("Verifier trust check failed");
      expect(submitted?.method).to.equal("POST");
      expect(submitted.contentType).to.equal("application/x-www-form-urlencoded");
      expect(Object.fromEntries(submitted.form)).to.deep.equal({
        error: "server_error", error_description: "Verifier trust check failed", state: "echo-this-state",
      });
    } finally {
      setWalletTrustSessionStorageForTests(null);
      await new Promise(resolve => server.close(resolve));
      for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
      Object.assign(process.env, previous);
    }
  });
});
