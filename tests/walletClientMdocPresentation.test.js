import { expect } from "chai";
import * as jose from "jose";
import { decode } from "cbor-x";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";
import {
  buildMdocPresentation,
  presentationDefinitionFromDcqlMdocClaims,
  verifyReceivedMdlToken,
} from "../wallet-client/utils/mdlVerification.js";

describe("wallet-client mdoc presentation", () => {
  it("rebuilds a stored DeviceResponse with current SessionTranscript and selective disclosure", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const proofJwk = await jose.exportJWK(publicKey);
    const privateJwk = await jose.exportJWK(privateKey);

    const proofJwt = await new jose.SignJWT({
      iss: "did:example:holder",
      aud: "http://localhost:3000",
      nonce: "test-nonce-wallet-mdoc-presentation",
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        jwk: proofJwk,
      })
      .sign(privateKey);

    const issuedCredential = await handleCredentialGenerationBasedOnFormat(
      {
        vct: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
        proofs: { jwt: [proofJwt] },
      },
      {
        signatureType: "x509",
        isHaip: false,
      },
      "http://localhost:3000",
      "mDL",
    );

    const presentationDefinition = {
      id: "pid_mdoc",
      input_descriptors: [
        {
          id: "urn:eu.europa.ec.eudi:pid:1",
          format: { mso_mdoc: { alg: ["ES256"] } },
          constraints: {
            limit_disclosure: "required",
            fields: [
              {
                path: ["$['urn:eu.europa.ec.eudi:pid:1']['given_name']"],
                intent_to_retain: false,
              },
              {
                path: ["$['urn:eu.europa.ec.eudi:pid:1']['family_name']"],
                intent_to_retain: false,
              },
              {
                path: ["$['urn:eu.europa.ec.eudi:pid:1']['birth_date']"],
                intent_to_retain: false,
              },
            ],
          },
        },
      ],
    };

    const { vpToken: initialVpToken } = await buildMdocPresentation(
      issuedCredential,
      {
        docType: "urn:eu.europa.ec.eudi:pid:1",
        clientId: "x509_san_dns:verifier.example.org",
        responseUri: "https://verifier.example.org/direct_post",
        verifierGeneratedNonce: "verifier-nonce-initial",
        devicePrivateJwk: privateJwk,
        presentationDefinition,
      },
    );

    const { vpToken, mdocGeneratedNonce } = await buildMdocPresentation(
      initialVpToken,
      {
        docType: "urn:eu.europa.ec.eudi:pid:1",
        clientId: "x509_san_dns:verifier.example.org",
        responseUri: "https://verifier.example.org/direct_post",
        verifierGeneratedNonce: "verifier-nonce-123",
        devicePrivateJwk: privateJwk,
        dcqlEntry: { claims: [{ path: ["given_name"] }] },
      },
    );
    expect(vpToken).to.not.equal(initialVpToken);
    expect(mdocGeneratedNonce).to.be.a("string").with.lengthOf.at.least(8);

    const deviceResponse = decode(Buffer.from(vpToken, "base64url"));
    expect(deviceResponse).to.have.property("version", "1.0");
    expect(deviceResponse.documents).to.be.an("array").with.length(1);

    const [document] = deviceResponse.documents;
    expect(document).to.have.property("docType", "urn:eu.europa.ec.eudi:pid:1");
    expect(document).to.have.property("issuerSigned");
    expect(document).to.have.property("deviceSigned");
    expect(document.deviceSigned).to.have.property("deviceAuth");

    const issuerAuthHeaders = document.issuerSigned.issuerAuth[1];
    expect(issuerAuthHeaders).to.be.an("object");
    expect(issuerAuthHeaders["33"]).to.be.an("array").that.is.not.empty;

    const verification = await verifyReceivedMdlToken(
      vpToken,
      { validateStructure: true, includeMetadata: true },
      "urn:eu.europa.ec.eudi:pid:1",
    );
    expect(verification.success).to.equal(true);
    expect(Object.keys(verification.claims)).to.deep.equal(["given_name"]);

    const { vpToken: sameDisclosureDifferentTranscript } =
      await buildMdocPresentation(initialVpToken, {
        docType: "urn:eu.europa.ec.eudi:pid:1",
        clientId: "x509_san_dns:verifier.example.org",
        responseUri: "https://verifier.example.org/other-direct-post",
        verifierGeneratedNonce: "verifier-nonce-123",
        devicePrivateJwk: privateJwk,
        dcqlEntry: { claims: [{ path: ["given_name"] }] },
        mdocGeneratedNonceOverride: mdocGeneratedNonce,
      });
    expect(sameDisclosureDifferentTranscript).to.not.equal(vpToken);
  });

  it("DCQL claims narrow actual disclosed mdoc attributes", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const proofJwk = await jose.exportJWK(publicKey);
    const privateJwk = await jose.exportJWK(privateKey);

    const proofJwt = await new jose.SignJWT({
      iss: "did:example:holder",
      aud: "http://localhost:3000",
      nonce: "test-nonce-dcql-mdoc-sd",
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        jwk: proofJwk,
      })
      .sign(privateKey);

    const issuedCredential = await handleCredentialGenerationBasedOnFormat(
      {
        vct: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
        proofs: { jwt: [proofJwt] },
      },
      {
        signatureType: "x509",
        isHaip: false,
      },
      "http://localhost:3000",
      "mDL",
    );

    const dcqlOne = { claims: [{ path: ["given_name"] }] };
    const syntheticPd = presentationDefinitionFromDcqlMdocClaims(
      "urn:eu.europa.ec.eudi:pid:1",
      dcqlOne,
    );
    expect(syntheticPd.input_descriptors[0].constraints.fields).to.deep.equal([
      {
        path: ["$['urn:eu.europa.ec.eudi:pid:1']['given_name']"],
        intent_to_retain: false,
      },
    ]);

    const baseOpts = {
      docType: "urn:eu.europa.ec.eudi:pid:1",
      clientId: "x509_san_dns:verifier.example.org",
      responseUri: "https://verifier.example.org/direct_post",
      verifierGeneratedNonce: "verifier-nonce-dcql",
      devicePrivateJwk: privateJwk,
      presentationDefinition: undefined,
    };

    const { vpToken: vpOne } = await buildMdocPresentation(issuedCredential, {
      ...baseOpts,
      dcqlEntry: dcqlOne,
    });

    const { vpToken: vpThree } = await buildMdocPresentation(issuedCredential, {
      ...baseOpts,
      verifierGeneratedNonce: "verifier-nonce-dcql-2",
      dcqlEntry: {
        claims: [
          { path: ["given_name"] },
          { path: ["family_name"] },
          { path: ["birth_date"] },
        ],
      },
    });

    const oneClaims = await verifyReceivedMdlToken(
      vpOne,
      { validateStructure: true },
      "urn:eu.europa.ec.eudi:pid:1",
    );
    const threeClaims = await verifyReceivedMdlToken(
      vpThree,
      { validateStructure: true },
      "urn:eu.europa.ec.eudi:pid:1",
    );

    expect(oneClaims.success).to.equal(true);
    expect(threeClaims.success).to.equal(true);
    expect(Object.keys(oneClaims.claims)).to.deep.equal(["given_name"]);
    expect(Object.keys(threeClaims.claims).sort()).to.deep.equal([
      "birth_date",
      "family_name",
      "given_name",
    ]);
    expect(vpOne.length).to.be.below(vpThree.length);
  });
});
