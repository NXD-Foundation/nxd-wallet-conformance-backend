import { expect } from "chai";
import * as jose from "jose";
import { decode } from "cbor-x";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";
import { buildMdocPresentation } from "../wallet-client/utils/mdlVerification.js";

describe("wallet-client mdoc presentation", () => {
  it("builds a DeviceResponse with deviceSigned and preserves issuerAuth x5chain", async () => {
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
            ],
          },
        },
      ],
    };

    const vpToken = await buildMdocPresentation(issuedCredential, {
      docType: "urn:eu.europa.ec.eudi:pid:1",
      clientId: "x509_san_dns:verifier.example.org",
      responseUri: "https://verifier.example.org/direct_post",
      verifierGeneratedNonce: "verifier-nonce-123",
      devicePrivateJwk: privateJwk,
      presentationDefinition,
    });

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
  });
});
