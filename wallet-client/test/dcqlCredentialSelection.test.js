import { expect } from "chai";
import { encode } from "cbor-x";
import base64url from "base64url";
import { createHash } from "crypto";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import {
  storedCredentialMatchesDcqlQuery,
  presentationFormatFromDcqlQuery,
  selectWalletCredentialTypeForDcql,
  selectWalletCredentialsForDcql,
} from "../src/lib/dcqlCredentialSelection.js";
import { extractMdocDocType } from "../src/lib/mdocDocType.js";

function buildMdocB64ForTests(docType) {
  const cbor = encode({
    docType,
    issuerSigned: { nameSpaces: {}, issuerAuth: new Uint8Array([1]) },
  });
  return base64url.encode(cbor, "utf8");
}

function buildMdocWithClaimsForTests(docType, namespace, claims = {}) {
  const nameSpaceItems = Object.entries(claims).map(([elementIdentifier, elementValue]) =>
    encode({ elementIdentifier, elementValue }),
  );
  const cbor = encode({
    docType,
    issuerSigned: {
      nameSpaces: { [namespace]: nameSpaceItems },
      issuerAuth: new Uint8Array([1]),
    },
  });
  return base64url.encode(cbor, "utf8");
}

function buildIssuerSignedOnlyMdocForTests(docType = null) {
  const issuerAuth = docType
    ? [new Uint8Array(), {}, encode({ docType }), new Uint8Array()]
    : new Uint8Array([1]);
  return base64url.encode(
    encode({
      nameSpaces: {},
      issuerAuth,
    }),
    "utf8",
  );
}

async function buildDcSdJwtForTests(vct, disclosures = [disclosure("family_name", "Neslo")]) {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const pub = await exportJWK(publicKey);
  const first = await new SignJWT({
    vct,
    _sd_alg: "sha-256",
    _sd: disclosures.map(disclosureDigest),
  })
    .setProtectedHeader({ typ: "dc+sd-jwt", alg: "ES256", jwk: pub })
    .sign(privateKey);
  return `${first}~${disclosures.join("~")}~`;
}

function disclosure(name, value) {
  return base64url.encode(JSON.stringify(["salt", name, value]), "utf8");
}

function disclosureDigest(encodedDisclosure) {
  return createHash("sha256").update(encodedDisclosure, "ascii").digest("base64url");
}

describe("dcqlCredentialSelection", () => {
  const pidDoctype = "urn:eu.europa.ec.eudi:pid:1";

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

  describe("extractMdocDocType", () => {
    it("extracts docType from an embedded Document structure", () => {
      const mdoc = buildMdocB64ForTests("org.iso.18013.5.1.mDL");
      expect(extractMdocDocType(mdoc)).to.equal("org.iso.18013.5.1.mDL");
    });

    it("extracts docType from an IssuerSigned issuerAuth MSO payload", () => {
      const mdoc = buildIssuerSignedOnlyMdocForTests(
        "urn:eu.europa.ec.eudi:pid:1",
      );
      expect(extractMdocDocType(mdoc)).to.equal(
        "urn:eu.europa.ec.eudi:pid:1",
      );
    });

    it("falls back to metadata doctype when IssuerSigned has no readable MSO payload", () => {
      const mdoc = buildIssuerSignedOnlyMdocForTests();
      expect(
        extractMdocDocType(mdoc, {
          fallbackDocType: "urn:eu.europa.ec.eudi:pid:1",
        }),
      ).to.equal("urn:eu.europa.ec.eudi:pid:1");
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
    it("matches IssuerSigned-only mdoc using a metadata doctype fallback", () => {
      const issuerSignedOnly = buildIssuerSignedOnlyMdocForTests();
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
      };
      expect(
        storedCredentialMatchesDcqlQuery(q, issuerSignedOnly, undefined, {
          fallbackDocType: "urn:eu.europa.ec.eudi:pid:1",
        }),
      ).to.equal(true);
    });
    it("matches IssuerSigned-only mdoc using the docType from issuerAuth MSO", () => {
      const issuerSignedOnly = buildIssuerSignedOnlyMdocForTests(
        "urn:eu.europa.ec.eudi:pid:1",
      );
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
      };
      expect(storedCredentialMatchesDcqlQuery(q, issuerSignedOnly)).to.equal(
        true,
      );
    });
    it("rejects IssuerSigned-only mdoc when fallback doctype does not match", () => {
      const issuerSignedOnly = buildIssuerSignedOnlyMdocForTests();
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
      };
      expect(
        storedCredentialMatchesDcqlQuery(q, issuerSignedOnly, undefined, {
          fallbackDocType: "org.iso.18013.5.1.mDL",
        }),
      ).to.equal(false);
    });
    it("does not let fallback doctype override an embedded mdoc docType", () => {
      const mdoc = buildMdocB64ForTests("org.iso.18013.5.1.mDL");
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
      };
      expect(
        storedCredentialMatchesDcqlQuery(q, mdoc, undefined, {
          fallbackDocType: "urn:eu.europa.ec.eudi:pid:1",
        }),
      ).to.equal(false);
    });
    it("matches mso_mdoc when a requested nested claim path is present", () => {
      const mdoc = buildMdocWithClaimsForTests(
        pidDoctype,
        "urn:eu.europa.ec.eudi:pid:1",
        { family_name: "Neslo" },
      );
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: pidDoctype },
        claims: [{ path: ["urn:eu.europa.ec.eudi:pid:1", "family_name"] }],
      };
      expect(storedCredentialMatchesDcqlQuery(q, mdoc)).to.equal(true);
    });
    it("rejects mso_mdoc when a requested nested claim path is missing", () => {
      const mdoc = buildMdocWithClaimsForTests(
        pidDoctype,
        "urn:eu.europa.ec.eudi:pid:1",
        { given_name: "Alice" },
      );
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: pidDoctype },
        claims: [{ path: ["urn:eu.europa.ec.eudi:pid:1", "family_name"] }],
      };
      expect(storedCredentialMatchesDcqlQuery(q, mdoc)).to.equal(false);
    });
    it("matches mso_mdoc when a requested claim satisfies a DCQL values constraint", () => {
      const mdoc = buildMdocWithClaimsForTests(
        pidDoctype,
        "urn:eu.europa.ec.eudi:pid:1",
        { family_name: "Neslo" },
      );
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: pidDoctype },
        claims: [{ path: ["urn:eu.europa.ec.eudi:pid:1", "family_name"], values: ["Neslo"] }],
      };
      expect(storedCredentialMatchesDcqlQuery(q, mdoc)).to.equal(true);
    });
    it("rejects mso_mdoc when no DCQL claim_sets option is satisfied", () => {
      const mdoc = buildMdocWithClaimsForTests(
        pidDoctype,
        "urn:eu.europa.ec.eudi:pid:1",
        { family_name: "Neslo" },
      );
      const q = {
        id: "cred1",
        format: "mso_mdoc",
        meta: { doctype_value: pidDoctype },
        claims: [
          { id: "family_name_claim", path: ["urn:eu.europa.ec.eudi:pid:1", "family_name"] },
          { id: "given_name_claim", path: ["urn:eu.europa.ec.eudi:pid:1", "given_name"] },
        ],
        claim_sets: [["given_name_claim"]],
      };
      expect(storedCredentialMatchesDcqlQuery(q, mdoc)).to.equal(false);
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
    it("matches dc+sd-jwt when a nested disclosed object path is present", async () => {
      const addressDisclosure = disclosure("address", { locality: "Athens", country: "GR" });
      const sd = await buildDcSdJwtForTests("eu.test.demo", [addressDisclosure]);
      const q = {
        id: "cred1",
        format: "dc+sd-jwt",
        claims: [{ path: ["address", "locality"] }],
      };
      expect(storedCredentialMatchesDcqlQuery(q, sd)).to.equal(true);
    });
    it("matches dc+sd-jwt when a dotted disclosure key satisfies a nested path", async () => {
      const schemeDisclosure = disclosure("identifier.schemeID", "European Student Identifier");
      const sd = await buildDcSdJwtForTests("eu.test.demo", [schemeDisclosure]);
      const q = {
        id: "cred1",
        format: "dc+sd-jwt",
        claims: [{ path: ["identifier", "schemeID"], values: ["European Student Identifier"] }],
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
    it("matches dc+sd-jwt when a top-level claim satisfies a DCQL values constraint", async () => {
      const sd = await buildDcSdJwtForTests("a.b.c");
      const q = {
        id: "cred1",
        format: "dc+sd-jwt",
        claims: [{ path: ["family_name"], values: ["Neslo"] }],
      };
      expect(storedCredentialMatchesDcqlQuery(q, sd)).to.equal(true);
    });
    it("rejects dc+sd-jwt when a top-level claim does not satisfy a DCQL values constraint", async () => {
      const sd = await buildDcSdJwtForTests("a.b.c");
      const q = {
        id: "cred1",
        format: "dc+sd-jwt",
        claims: [{ path: ["family_name"], values: ["Doe"] }],
      };
      expect(storedCredentialMatchesDcqlQuery(q, sd)).to.equal(false);
    });
  });

  describe("selectWalletCredentialTypeForDcql", () => {
    it("picks the mdoc-typed configuration when DCQL requests mso_mdoc even if SD-JWT is first in the list", async () => {
      const sdJwt = await buildDcSdJwtForTests("eu.dummy");
      const mdocB64 = buildMdocWithClaimsForTests(
        pidDoctype,
        "org.iso.18013.5.1",
        { family_name: "Neslo" },
      );
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

    it("accepts a required credential_set option that references the matched credential query id", async () => {
      const mdocB64 = buildMdocWithClaimsForTests(
        pidDoctype,
        "org.iso.18013.5.1",
        { family_name: "Neslo" },
      );
      const store = {
        [pidDoctype]: { credential: { credential: mdocB64 } },
      };
      const dcqlQuery = {
        credential_sets: [
          {
            required: true,
            options: [["b9d5165a-c3a0-437e-b397-cdf351331f3f"]],
          },
        ],
        credentials: [
          {
            id: "b9d5165a-c3a0-437e-b397-cdf351331f3f",
            format: "mso_mdoc",
            multiple: false,
            meta: { doctype_value: pidDoctype },
            claims: [
              { path: ["org.iso.18013.5.1", "family_name"] },
            ],
          },
        ],
      };
      const result = await selectWalletCredentialTypeForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(result).to.not.equal(null);
      expect(result.selectedType).to.equal(pidDoctype);
      expect(result.matchedQuery.id).to.equal(
        "b9d5165a-c3a0-437e-b397-cdf351331f3f",
      );
    });

    it("uses the mso_mdoc configuration id as a doctype fallback for IssuerSigned-only stored credentials", async () => {
      const issuerSignedOnly = buildIssuerSignedOnlyMdocForTests();
      const store = {
        "urn:eu.europa.ec.eudi:pid:1:mso_mdoc": {
          credential: { credential: issuerSignedOnly },
          metadata: {
            configurationId: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
            format: "mso_mdoc",
          },
        },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "cred1",
            format: "mso_mdoc",
            meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
          },
        ],
      };
      const result = await selectWalletCredentialTypeForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(result).to.not.equal(null);
      expect(result.selectedType).to.equal(
        "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
      );
    });

    it("uses stored metadata.doctype before deriving a fallback from the wallet type", async () => {
      const issuerSignedOnly = buildIssuerSignedOnlyMdocForTests();
      const store = {
        pid: {
          credential: { credential: issuerSignedOnly },
          metadata: {
            configurationId: "pid",
            format: "mso_mdoc",
            doctype: "urn:eu.europa.ec.eudi:pid:1",
          },
        },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "cred1",
            format: "mso_mdoc",
            meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
          },
        ],
      };
      const result = await selectWalletCredentialTypeForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(result).to.not.equal(null);
      expect(result.selectedType).to.equal("pid");
    });

    it("returns null when an IssuerSigned-only mdoc fallback doctype mismatches DCQL", async () => {
      const issuerSignedOnly = buildIssuerSignedOnlyMdocForTests();
      const store = {
        "org.iso.18013.5.1.mDL:mso_mdoc": {
          credential: { credential: issuerSignedOnly },
          metadata: {
            configurationId: "org.iso.18013.5.1.mDL:mso_mdoc",
            format: "mso_mdoc",
          },
        },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "cred1",
            format: "mso_mdoc",
            meta: { doctype_value: "urn:eu.europa.ec.eudi:pid:1" },
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

    it("rejects credential_sets options that reference unknown credential query ids", async () => {
      const dcqlQuery = {
        credential_sets: [
          {
            required: true,
            options: [["missing-id"]],
          },
        ],
        credentials: [
          {
            id: "known-id",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
          },
        ],
      };

      let error;
      try {
        await selectWalletCredentialTypeForDcql({
          dcqlQuery,
          listWalletCredentialTypes: async () => [],
          getWalletCredentialByType: async () => null,
          extractCredentialString: () => null,
        });
      } catch (e) {
        error = e;
      }
      expect(error).to.be.instanceOf(Error);
      expect(error.message).to.include("unknown credential id");
    });

    it("does not select a single credential query that cannot satisfy required credential_sets", async () => {
      const mdocB64 = buildMdocB64ForTests(pidDoctype);
      const store = {
        [pidDoctype]: { credential: { credential: mdocB64 } },
      };
      const dcqlQuery = {
        credential_sets: [
          {
            required: true,
            options: [["c1", "c2"]],
          },
        ],
        credentials: [
          {
            id: "c1",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
          },
          {
            id: "c2",
            format: "dc+sd-jwt",
            meta: { vct_values: ["missing"] },
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

    it("returns all matching credentials when multiple=true", async () => {
      const vctWanted = "eu.webuildconsortium.helloworld.v1";
      const sd1 = await buildDcSdJwtForTests(vctWanted);
      const sd2 = await buildDcSdJwtForTests(vctWanted);
      const store = {
        "cred-a": { credential: { credential: sd1 } },
        "cred-b": { credential: { credential: sd2 } },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "q1",
            format: "dc+sd-jwt",
            multiple: true,
            meta: { vct_values: [vctWanted] },
          },
        ],
      };
      const selections = await selectWalletCredentialsForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(selections).to.have.length(2);
      expect(selections.map((entry) => entry.selectedType).sort()).to.deep.equal([
        "cred-a",
        "cred-b",
      ]);
    });

    it("returns all requested credential queries when no credential_sets are present", async () => {
      const mdocB64 = buildMdocB64ForTests(pidDoctype);
      const sd = await buildDcSdJwtForTests("eu.test.demo");
      const store = {
        pid: { credential: { credential: mdocB64 } },
        demo: { credential: { credential: sd } },
      };
      const dcqlQuery = {
        credentials: [
          {
            id: "mdoc-id",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
          },
          {
            id: "sd-id",
            format: "dc+sd-jwt",
            meta: { vct_values: ["eu.test.demo"] },
          },
        ],
      };
      const selections = await selectWalletCredentialsForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(selections).to.have.length(2);
      expect(selections.map((entry) => entry.matchedQuery.id).sort()).to.deep.equal([
        "mdoc-id",
        "sd-id",
      ]);
    });

    it("satisfies required credential_sets options with multiple credential queries", async () => {
      const mdocB64 = buildMdocB64ForTests(pidDoctype);
      const sd = await buildDcSdJwtForTests("eu.test.demo");
      const store = {
        pid: { credential: { credential: mdocB64 } },
        demo: { credential: { credential: sd } },
      };
      const dcqlQuery = {
        credential_sets: [{ required: true, options: [["mdoc-id", "sd-id"]] }],
        credentials: [
          {
            id: "mdoc-id",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
          },
          {
            id: "sd-id",
            format: "dc+sd-jwt",
            meta: { vct_values: ["eu.test.demo"] },
          },
        ],
      };
      const selections = await selectWalletCredentialsForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(selections).to.have.length(2);
      expect(selections.map((entry) => entry.matchedQuery.id).sort()).to.deep.equal([
        "mdoc-id",
        "sd-id",
      ]);
    });

    it("requires every required credential_set to be satisfiable", async () => {
      const sd = await buildDcSdJwtForTests("eu.test.demo");
      const store = {
        demo: { credential: { credential: sd } },
      };
      const dcqlQuery = {
        credential_sets: [
          { required: true, options: [["sd-id"]] },
          { required: true, options: [["missing-mdoc"]] },
        ],
        credentials: [
          {
            id: "sd-id",
            format: "dc+sd-jwt",
            meta: { vct_values: ["eu.test.demo"] },
          },
          {
            id: "missing-mdoc",
            format: "mso_mdoc",
            meta: { doctype_value: pidDoctype },
          },
        ],
      };
      const selections = await selectWalletCredentialsForDcql({
        dcqlQuery,
        listWalletCredentialTypes: async () => Object.keys(store),
        getWalletCredentialByType: async (t) => store[t] || null,
        extractCredentialString: (env) => env?.credential || null,
      });
      expect(selections).to.deep.equal([]);
    });
  });
});
