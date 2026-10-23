import { expect } from "chai";
import fs from "node:fs";
import { X509Certificate, verify } from "node:crypto";
import * as jose from "jose";
import { decode, encode } from "cbor-x";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";
import { buildMdocPresentation } from "../wallet-client/utils/mdlVerification.js";
import { verifyMdlToken } from "../utils/mdlVerification.js";
import { extractMdocIssuerCertificate } from "../utils/mdocClaims.js";
import { certificateFingerprint } from "../trust/crypto.js";
import { evaluateTrust } from "../trust/evaluate.js";
import { loadTrustProfile } from "../trust/profile.js";
import { trustFrameworkSessionProps, setTrustResolverForTests, clearTrustResolverForTests } from "../utils/trustFrameworkPolicy.js";
import { validateCs02SdJwtEntriesInVpToken } from "../utils/cs02VerifierResponse.js";

const session = trustFrameworkSessionProps({ trustFramework: true });
const chain = fs.readFileSync("certs/id-union-pid-certificate.pem", "utf8")
  .match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
const chainDer = chain.map((pem) => new X509Certificate(pem).raw);
const doctypes = ["urn:eu.europa.ec.eudi:pid:1", "urn:eudi:pid:lsp:1"];

function issuerSignedWithChain(x5chain) {
  return { nameSpaces: {}, issuerAuth: [Buffer.alloc(0), new Map([[33, x5chain]]), Buffer.alloc(0), Buffer.alloc(0)] };
}
function presentation(issuerSigned, docType) {
  return Buffer.from(encode({ version: "1.0", documents: [{ docType, issuerSigned,
    deviceSigned: { nameSpaces: {}, deviceAuth: {} } }] })).toString("base64url");
}

async function listedCaResolver(anchor = chain.at(-1)) {
  const profile = await loadTrustProfile("data/trust/webuild-wp4-pilot.json");
  const snapshot = { profile, profileId: profile.id,
    lotl: { source: { url: "https://trust.example/lotl" }, format: "json", scheme: {}, signer: {} },
    lists: { "pid-provider": { source: { url: "https://trust.example/pid" }, scheme: {},
      entities: [{ id: "dev-i4mlab.aegean.gr", services: [{ type: "pid", status: "valid",
        certificates: [certificateFingerprint(anchor)], certificatePems: [anchor] }] }] } } };
  return { resolve: async (request) => evaluateTrust({ snapshot, ...request }) };
}

describe("mdoc COSE certificate-chain extraction", () => {
  it("retains all DER certificates in leaf-first order for CA-anchor matching", () => {
    const result = extractMdocIssuerCertificate(issuerSignedWithChain(chainDer));
    expect(result.certificateChain.map(certificateFingerprint)).to.deep.equal(chain.map(certificateFingerprint));
    expect(result.certificatePem).to.equal(result.certificateChain[0]);
  });
  it("accepts a single certificate encoded as a COSE byte string", () => {
    expect(extractMdocIssuerCertificate(issuerSignedWithChain(chainDer[0])).certificateChain).to.have.length(1);
  });
  for (const [label, invalid] of [["empty", []], ["malformed entry", [chainDer[0], "invalid"]], ["missing", null]]) {
    it(`rejects a chain with ${label}`, () => {
      expect(extractMdocIssuerCertificate(issuerSignedWithChain(invalid))).to.equal(null);
    });
  }
});

describe("Trust Framework Integration mdoc PID issuance and presentation", () => {
  afterEach(clearTrustResolverForTests);
  for (const configuration of doctypes) {
    it(`preserves the configured CA chain through wallet presentation for ${configuration}`, async () => {
      const docType = doctypes[0];
      const holder = await jose.generateKeyPair("ES256");
      const proof = await new jose.SignJWT({ nonce: "chain-regression" })
        .setProtectedHeader({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk: await jose.exportJWK(holder.publicKey) })
        .sign(holder.privateKey);
      const issued = await handleCredentialGenerationBasedOnFormat({
        vct: `${configuration}:mso_mdoc`, proofs: { jwt: [proof] },
      }, { signatureType: "x509", isHaip: false, ...session }, "http://localhost:3000", "mDL");
      const issuerSigned = decode(Buffer.from(issued, "base64url"));
      const evidence = extractMdocIssuerCertificate(issued);
      expect(evidence.certificateChain.map(certificateFingerprint)).to.deep.equal(chain.map(certificateFingerprint));
      // Adding the unprotected chain must leave the actual issuerAuth signature valid.
      const [protectedHeaders, , payload, signature] = issuerSigned.issuerAuth;
      expect(verify("sha256", encode(["Signature1", protectedHeaders, Buffer.alloc(0), payload]),
        { key: new X509Certificate(chain[0]).publicKey, dsaEncoding: "ieee-p1363" }, signature)).to.equal(true);
      const credQuery = { id: "pid", format: "mso_mdoc", meta: { doctype_value: docType },
        claims: [{ path: [docType, "family_name"] }] };
      const walletPresentation = await buildMdocPresentation(issued, {
        docType, clientId: "x509_hash:verifier", responseUri: "https://verifier.example/direct_post/test",
        verifierGeneratedNonce: "vp007-nonce", devicePrivateJwk: await jose.exportJWK(holder.privateKey),
        dcqlCredentialQuery: credQuery,
      });
      const legacyResult = await verifyMdlToken(walletPresentation, {}, docType);
      expect(legacyResult.success).to.equal(true);
      expect(legacyResult.issuerCertificate.certificateChain.map(certificateFingerprint))
        .to.deep.equal(chain.map(certificateFingerprint));
      setTrustResolverForTests(await listedCaResolver());
      const result = await validateCs02SdJwtEntriesInVpToken(
        { pid: [walletPresentation] },
        { credentials: [credQuery] },
        { session }, { strict: true });
      expect(result[0].trust).to.include({ trusted: true, reasonCode: "TRUSTED" });
      expect(result[0].trust.evidence.certificatePath.anchorFingerprint).to.equal(certificateFingerprint(chain.at(-1)));
    });
  }
  for (const variant of ["missing CA", "unrelated CA", "injected unrelated CA"]) {
    it(`still rejects a PID with ${variant} instead of trusting its embedded certificates`, async () => {
      const anchor = variant.includes("unrelated CA") ? fs.readFileSync("x509EC/client_certificate.crt", "utf8") : chain.at(-1);
      setTrustResolverForTests(await listedCaResolver(anchor));
      const presentedChain = variant === "missing CA" ? [chainDer[0]]
        : variant === "injected unrelated CA" ? [...chainDer, new X509Certificate(anchor).raw] : chainDer;
      try {
        await validateCs02SdJwtEntriesInVpToken(
          { pid: [presentation(issuerSignedWithChain(presentedChain), doctypes[0])] },
          { credentials: [{ id: "pid", format: "mso_mdoc", meta: { doctype_value: doctypes[0] } }] },
          { session }, { strict: true });
        expect.fail("Expected credential trust rejection");
      } catch (error) {
        expect(error.errorCode).to.equal("invalid_credential");
        expect(error.trustDecision).to.include({ trusted: false, reasonCode: variant === "injected unrelated CA" ? "CERTIFICATE_PATH_INVALID" : "ANCHOR_MISMATCH" });
      }
    });
  }
});
