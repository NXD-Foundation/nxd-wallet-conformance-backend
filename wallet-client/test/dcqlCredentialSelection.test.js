import { expect } from "chai";
import { encode } from "cbor-x";
import base64url from "base64url";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import {
  storedCredentialMatchesDcqlQuery,
  presentationFormatFromDcqlQuery,
  selectWalletCredentialTypeForDcql,
} from "../src/lib/dcqlCredentialSelection.js";

function buildMdocB64ForTests(docType) {
  const cbor = encode({
    docType,
    issuerSigned: { nameSpaces: {}, issuerAuth: new Uint8Array([1]) },
  });
  return base64url.encode(cbor, "utf8");
}

async function buildDcSdJwtForTests(vct) {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const pub = await exportJWK(publicKey);
  const first = await new SignJWT({ vct })
    .setProtectedHeader({ typ: "dc+sd-jwt", alg: "ES256", jwk: pub })
    .sign(privateKey);
  return `${first}~WyJ4IiwiZmFtaWx5X25hbWUiLCJOZXNsbyJd`;
}

describe("dcqlCredentialSelection", () => {
  const pidDoctype = "eu.europa.ec.eudi.pid.1";

  describe("presentationFormatFromDcqlQuery", () => {
    it("returns mso_mdoc for mso_mdoc", () => {
      expect(
        presentationFormatFromDcqlQuery({ format: "mso_mdoc" }),
      ).to.equal("mso_mdoc");
    });
    it("returns dc+sd-jwt for dc+sd-jwt", () => {
      expect(
        presentationFormatFromDcqlQuery({ format: "dc+sd-jwt" }),
      ).to.equal("dc+sd-jwt");
    });
    it("returns vc+sd-jwt for vc+sd-jwt", () => {
      expect(
        presentationFormatFromDcqlQuery({ format: "vc+sd-jwt" }),
      ).to.equal("vc+sd-jwt");
    });
  });

  describe("storedCredentialMatchesDcqlQuery", () => {
    it("matches mso_mdoc when doctype_value equals stored document", () => {
      const b64 = buildMdocB64ForTests(pidDoctype);
      const q = {
        format: "mso_mdoc",
        meta: { doctype_value: pidDoctype },
      };
      expect(storedCredentialMatchesDcqlQuery(q, b64)).to.equal(true);
    });
    it("rejects mso_mdoc when doctype_value does not match", () => {
      const b64 = buildMdocB64ForTests("org.iso.18013.5.1.mDL");
      const q = {
        format: "mso_mdoc",
        meta: { doctype_value: pidDoctype },
      };
      expect(storedCredentialMatchesDcqlQuery(q, b64)).to.equal(false);
    });
    it("rejects mso_mdoc when token is an SD-JWT (dc+sd-jwt on wire)", async () => {
      const sd = await buildDcSdJwtForTests("eu.test.demo");
      const q = { format: "mso_mdoc", meta: { doctype_value: pidDoctype } };
      expect(storedCredentialMatchesDcqlQuery(q, sd)).to.equal(false);
    });
    it("matches dc+sd-jwt to SD-JWT and optional vct_values", async () => {
      const vct = "eu.webuildconsortium.helloworld.v1";
      const sd = await buildDcSdJwtForTests(vct);
      const q = {
        format: "dc+sd-jwt",
        meta: { vct_values: [vct, "other"] },
      };
      expect(storedCredentialMatchesDcqlQuery(q, sd)).to.equal(true);
    });
    it("rejects dc+sd-jwt when vct is not in vct_values", async () => {
      const sd = await buildDcSdJwtForTests("a.b.c");
      const q = {
        format: "dc+sd-jwt",
        meta: { vct_values: ["x.y.z"] },
      };
      expect(storedCredentialMatchesDcqlQuery(q, sd)).to.equal(false);
    });
  });

  describe("selectWalletCredentialTypeForDcql", () => {
    it("picks the mdoc-typed configuration when DCQL requests mso_mdoc even if SD-JWT is first in the list", async () => {
      const sdJwt = await buildDcSdJwtForTests("eu.dummy");
      const mdocB64 = buildMdocB64ForTests(pidDoctype);
      const store = {
        "sd-first": { credential: { credential: sdJwt } },
        [pidDoctype]: { credential: { credential: mdocB64 } },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "0b5cd0a2-f8bc-4c5e-a13c-a94d57939d16",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
            claims: [
              { path: ["org.iso.18013.5.1", "family_name"] },
            ],
          },
        ],
      };
      const result = await selectWalletCredentialTypeForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () =>
          Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => {
          if (env?.credential && typeof env.credential === "string")
            return env.credential;
          return null;
        },
      });
      expect(result).to.not.equal(null);
      expect(result.selectedType).to.equal(pidDoctype);
      expect(result.matchedQuery.format).to.equal("mso_mdoc");
      expect(
        presentationFormatFromDcqlQuery(result.matchedQuery),
      ).to.equal("mso_mdoc");
    });

    it("picks the SD-JWT-typed config when DCQL requests dc+sd-jwt with vct_values", async () => {
      const vctWanted = "eu.webuildconsortium.helloworld.v1";
      const wrongMdoc = buildMdocB64ForTests(pidDoctype);
      const sd = await buildDcSdJwtForTests(vctWanted);
      const store = {
        [pidDoctype]: { credential: { credential: wrongMdoc } },
        "helloworld-sd": { credential: { credential: sd } },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "q1",
            format: "dc+sd-jwt",
            meta: { vct_values: [vctWanted] },
          },
        ],
      };
      const result = await selectWalletCredentialTypeForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () =>
          Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) =>
          (env?.credential && typeof env.credential === "string"
            ? env.credential
            : null),
      });
      expect(result).to.not.equal(null);
      expect(result.selectedType).to.equal("helloworld-sd");
      expect(
        presentationFormatFromDcqlQuery(result.matchedQuery),
      ).to.equal("dc+sd-jwt");
    });

    it("returns null when no credential matches the DCQL mso_mdoc request", async () => {
      const sdOnly = await buildDcSdJwtForTests("x");
      const store = { only: { credential: { credential: sdOnly } } };
      const dcqlQuery = {
        credentials: [
          {
            id: "c1",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
          },
        ],
      };
      const result = await selectWalletCredentialTypeForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(result).to.equal(null);
    });
  });
});
