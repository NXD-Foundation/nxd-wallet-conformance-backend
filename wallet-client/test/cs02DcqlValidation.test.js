import { expect } from "chai";
import { Cs02ValidationError } from "../src/lib/cs02RequestValidation.js";
import {
  validateCs02DcqlQuery,
  validateCs02PresentationQuery,
  validateDcqlClaimPath,
  buildCs02VpTokenMember,
  buildCs02VpTokenObject,
  resolveCs02KbJwtAudience,
} from "../src/lib/cs02DcqlValidation.js";

function validDcqlQuery(overrides = {}) {
  return {
    credentials: [
      {
        id: "pid",
        format: "dc+sd-jwt",
        meta: { vct_values: ["example.v1"] },
        claims: [{ path: ["family_name"] }],
      },
    ],
    ...overrides,
  };
}

describe("CS-02 DCQL validation (Phase 2)", () => {
  const strictOptions = { strict: true };

  it("requires dcql_query in CS-02 mode", () => {
    expect(() => validateCs02PresentationQuery({}, strictOptions)).to.throw(Cs02ValidationError);
  });

  it("rejects presentation_definition in CS-02 mode", () => {
    expect(() =>
      validateCs02PresentationQuery(
        { dcql_query: validDcqlQuery(), presentation_definition: { id: "pd" } },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects scope-only queries in CS-02 mode", () => {
    expect(() => validateCs02PresentationQuery({ scope: "openid" }, strictOptions)).to.throw(
      Cs02ValidationError,
    );
  });

  it("rejects both dcql_query and scope", () => {
    expect(() =>
      validateCs02PresentationQuery(
        { dcql_query: validDcqlQuery(), scope: "openid" },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects duplicate credential query ids", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            { id: "a", format: "dc+sd-jwt" },
            { id: "a", format: "mso_mdoc" },
          ],
        },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects invalid credential query id characters", () => {
    expect(() =>
      validateCs02DcqlQuery(
        { credentials: [{ id: "bad id", format: "dc+sd-jwt" }] },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects missing format", () => {
    expect(() =>
      validateCs02DcqlQuery({ credentials: [{ id: "pid" }] }, strictOptions),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects unsupported format in CS-02 mode", () => {
    expect(() =>
      validateCs02DcqlQuery(
        { credentials: [{ id: "pid", format: "jwt_vc_json" }] },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects invalid claim paths", () => {
    expect(() => validateDcqlClaimPath([], "test")).to.throw(Cs02ValidationError);
    expect(() => validateDcqlClaimPath([""], "test")).to.throw(Cs02ValidationError);
    expect(() => validateDcqlClaimPath([false], "test")).to.throw(Cs02ValidationError);
    expect(() => validateDcqlClaimPath([-1], "test")).to.throw(Cs02ValidationError);
  });

  it("rejects nested SD-JWT claim paths until explicit support exists", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "dc+sd-jwt",
              claims: [{ path: ["address", "locality"] }],
            },
          ],
        },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError, /top-level claim/);
  });

  it("allows nested mdoc claim paths", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "mso_mdoc",
              meta: { doctype_value: "org.iso.18013.5.1.mDL" },
              claims: [{ path: ["org.iso.18013.5.1", "family_name"] }],
            },
          ],
        },
        strictOptions,
      ),
    ).to.not.throw();
  });

  it("accepts syntactically valid DCQL claim values constraints", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "dc+sd-jwt",
              claims: [{ path: ["family_name"], values: ["Doe"] }],
            },
          ],
        },
        strictOptions,
      ),
    ).to.not.throw();
  });

  it("rejects malformed DCQL claim values constraints", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "dc+sd-jwt",
              claims: [{ path: ["family_name"], values: [] }],
            },
          ],
        },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError, /must be a non-empty array/);
  });

  it("logs trusted_authorities as advisory when no trust registry is configured", () => {
    const logs = [];
    validateCs02DcqlQuery(
      {
        credentials: [
          {
            id: "pid",
            format: "dc+sd-jwt",
            trusted_authorities: [{ type: "openid_federation", entity_id: "https://ta.example" }],
          },
        ],
      },
      strictOptions,
      (...args) => logs.push(args),
    );

    expect(logs.some(([message, data]) =>
      message === "[CS02] trusted_authorities ignored (no trust registry configured)" &&
      data?.credentialId === "pid"
    )).to.equal(true);
  });

  it("requires claim ids when claim_sets is present", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "dc+sd-jwt",
              claims: [{ path: ["family_name"] }],
              claim_sets: [["family_name_claim"]],
            },
          ],
        },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects claim_sets references to unknown claim ids", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "dc+sd-jwt",
              claims: [{ id: "c1", path: ["family_name"] }],
              claim_sets: [["missing"]],
            },
          ],
        },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("rejects require_cryptographic_holder_binding=false for SD-JWT", () => {
    expect(() =>
      validateCs02DcqlQuery(
        {
          credentials: [
            {
              id: "pid",
              format: "dc+sd-jwt",
              require_cryptographic_holder_binding: false,
            },
          ],
        },
        strictOptions,
      ),
    ).to.throw(Cs02ValidationError);
  });

  it("builds vp_token members according to multiple policy", () => {
    expect(buildCs02VpTokenMember(["pres-1"], false)).to.equal("pres-1");
    expect(buildCs02VpTokenMember(["pres-1", "pres-2"], true)).to.deep.equal([
      "pres-1",
      "pres-2",
    ]);
  });

  it("builds vp_token object keyed by credential query id", () => {
    const object = buildCs02VpTokenObject([
      { credQueryId: "pid", presentations: ["pres-1"], multiple: false },
    ]);
    expect(object).to.deep.equal({ pid: "pres-1" });
  });

  it("resolves KB-JWT audience from JAR client_id", () => {
    expect(
      resolveCs02KbJwtAudience(
        { client_id: "x509_san_dns:verifier.example.org" },
        null,
      ),
    ).to.equal("x509_san_dns:verifier.example.org");
  });
});
