import { expect } from "chai";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, calculateJwkThumbprint } from "jose";
import { postFormWithAttestationNonceRetry } from "../src/lib/dpopIssuanceTransport.js";
import { createWalletUnitAttestationClientAuth } from "../src/lib/walletUnitAttestation.js";
import { createAttestationChallengeState } from "../src/lib/attestationChallenge.js";
import { createDpopNonceState } from "../src/lib/dpopNonce.js";
import { assertCs01ParRequestContract } from "../src/lib/cs01Conformance.js";
import { assertPreAuthorizedAllowed } from "../src/lib/profile.js";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";

const cs01 = "webuild-cs01";
const json = (body, status = 200) => new Response(JSON.stringify(body), { status });

describe("CS-01 PAR dpop_jkt", () => {
  it("includes dpop_jkt matching PAR DPoP proof independently of WIA cnf for authorization-code PAR", async () => {
    const cnfKeyPair = await ensureOrCreateEcKeyPair(null, "ES256");
    const dpopKeyPair = await ensureOrCreateEcKeyPair(null, "ES256");
    const expectedJkt = await calculateJwkThumbprint(dpopKeyPair.publicJwk, "sha256");
    let capturedParams;
    let capturedProof;
    let capturedHeaders;
    await postFormWithAttestationNonceRetry({
      url: "https://issuer.example/par",
      params: {
        response_type: "code",
        client_id: "wallet-client",
        scope: "VerifiableIdCard",
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: "openid4vp://",
        state: "st",
        dpop_jkt: expectedJkt,
      },
      cnfKeyPair,
      dpopKeyPair,
      nonceState: createDpopNonceState(),
      challengeState: createAttestationChallengeState(),
      buildAttestation: (session) =>
        createWalletUnitAttestationClientAuth({
          profile: cs01,
          clientId: "wallet-client",
          endpointAudience: "https://issuer.example/par",
          authorizationServerIssuer: "https://issuer.example",
          stage: "PAR",
          ...session,
        }),
      postForm: async (_url, params, proof, headers) => {
        capturedParams = params;
        capturedProof = proof;
        capturedHeaders = headers;
        return json({ request_uri: "urn:par:1" }, 201);
      },
    });
    expect(capturedParams.dpop_jkt).to.equal(expectedJkt);
    const wiaCnf = decodeJwt(capturedHeaders["OAuth-Client-Attestation"]).cnf.jwk;
    expect(await calculateJwkThumbprint(wiaCnf, "sha256")).not.to.equal(expectedJkt);
    expect(decodeProtectedHeader(capturedProof).jwk).to.deep.equal(dpopKeyPair.publicJwk);
    await jwtVerify(capturedProof, await importJWK(dpopKeyPair.publicJwk, "ES256"));
    assertCs01ParRequestContract({
      profile: cs01,
      parParams: capturedParams,
      attestationHeaders: capturedHeaders,
      usedPar: true,
    });
  });

  it("pre-authorized token request omits dpop_jkt", async () => {
    assertPreAuthorizedAllowed(cs01, { env: { CS01_DISABLE_PRE_AUTHORIZED: "false" } });
    const binding = await ensureOrCreateEcKeyPair(null);
    const params = {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": "code",
      tx_code: "1234",
    };
    await postFormWithAttestationNonceRetry({
      url: "https://issuer.example/token",
      params,
      cnfKeyPair: binding,
      buildAttestation: async () => ({ headers: { "OAuth-Client-Attestation": "wia" } }),
      postForm: async (_url, body) => {
        expect(body).to.not.have.property("dpop_jkt");
        return json({ access_token: "token" });
      },
    });
  });
});
