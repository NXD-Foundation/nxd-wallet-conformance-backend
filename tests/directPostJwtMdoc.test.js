import fs from "fs";
import { expect } from "chai";
import * as jose from "jose";
import { encode } from "cbor-x";
import { DEFAULT_MDL_DCQL_QUERY } from "../utils/routeUtils.js";
import { loadVerifierEncryptionKey } from "../utils/verifierEncryptionKeys.js";
import {
  Cs02VerifierResponseError,
  unwrapOpenid4VpAuthorizationResponse,
} from "../utils/cs02VerifierResponse.js";

function buildMdocPresentation(docType = "urn:eu.europa.ec.eudi:pid:1") {
  return Buffer.from(
    encode({
      version: "1.0",
      documents: [
        {
          docType,
          issuerSigned: {
            nameSpaces: {},
            issuerAuth: new Uint8Array([1]),
          },
          deviceSigned: { nameSpaces: {}, deviceAuth: {} },
        },
      ],
    }),
  ).toString("base64url");
}

describe("direct_post.jwt mdoc authorization response unwrap", () => {
  it("unwraps encrypted direct_post.jwt into a DCQL mdoc vp_token without top-level vp_token", async () => {
    const configured = loadVerifierEncryptionKey();
    const publicKey = await jose.importJWK(configured.publicJwk, configured.publicJwk.alg);
    const mdocPresentation = buildMdocPresentation();
    const session = {
      response_mode: "direct_post.jwt",
      state: "acc10f8963eec0f28a4c34801201debe",
      client_id: "x509_san_dns:dev-i4mlab.aegean.gr",
      encryption_key: configured.publicJwk,
      dcql_query: DEFAULT_MDL_DCQL_QUERY,
    };
    const payload = {
      vp_token: { cred1: mdocPresentation },
      state: session.state,
    };
    const compactJwe = await new jose.EncryptJWT(payload)
      .setProtectedHeader({
        alg: configured.publicJwk.alg,
        enc: "A256GCM",
        kid: configured.publicJwk.kid,
      })
      .encrypt(publicKey);

    const unwrapped = await unwrapOpenid4VpAuthorizationResponse(
      { response: compactJwe },
      session,
      {
        strict: true,
        clientMetadata: JSON.parse(fs.readFileSync("./data/verifier-config.json", "utf8")),
      },
    );

    expect(unwrapped.vp_token).to.be.an("object");
    expect(unwrapped.vp_token.cred1).to.equal(mdocPresentation);
    expect(unwrapped.state).to.equal(session.state);
    expect(unwrapped.vp_token).to.not.equal(undefined);
  });

  it("requires response parameter for direct_post.jwt unwrap", async () => {
    const session = {
      response_mode: "direct_post.jwt",
      state: "state-1",
      client_id: "x509_san_dns:verifier.example",
    };

    try {
      await unwrapOpenid4VpAuthorizationResponse({}, session, { strict: true });
      expect.fail("expected unwrap to reject missing response");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02VerifierResponseError);
      expect(error.message).to.match(/response parameter/i);
    }
  });

  it("passes through direct_post vp_token without response parameter", async () => {
    const unwrapped = await unwrapOpenid4VpAuthorizationResponse(
      { vp_token: { cred1: "mdoc-token" }, state: "state-1" },
      { response_mode: "direct_post", state: "state-1" },
      { strict: true },
    );
    expect(unwrapped.vp_token).to.deep.equal({ cred1: "mdoc-token" });
    expect(unwrapped.state).to.equal("state-1");
  });

  it("unwraps authorization responses before mdoc verification in verifierRoutes", () => {
    const source = fs.readFileSync("./routes/verify/verifierRoutes.js", "utf8");
    const unwrapIndex = source.indexOf("unwrapOpenid4VpAuthorizationResponse(");
    const mdocMissingIndex = source.indexOf("No vp_token found in mDL request body");
    expect(unwrapIndex).to.be.greaterThan(-1);
    expect(mdocMissingIndex).to.be.greaterThan(-1);
    expect(unwrapIndex).to.be.lessThan(mdocMissingIndex);
  });
});
