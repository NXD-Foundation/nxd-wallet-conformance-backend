import { expect } from "chai";
import {
  isSupportedCs02ClaimPathSegment,
  validateSupportedCs02ClaimPath,
  evaluateCs02CredentialSets,
  isCs02PresentationCardinalityValid,
} from "../utils/cs02DcqlCore.js";

describe("shared CS-02 DCQL structural rules", () => {
  it("accepts ordinary nested claim paths", () => {
    expect(validateSupportedCs02ClaimPath(["address", "locality"])).to.deep.equal([
      "address",
      "locality",
    ]);
  });

  it("rejects JSONPath and array-index syntax", () => {
    expect(isSupportedCs02ClaimPathSegment("claims[0]")).to.equal(false);
    expect(isSupportedCs02ClaimPathSegment("$.claims")).to.equal(false);
    expect(() => validateSupportedCs02ClaimPath(["claims[0]"])).to.throw(/unsupported/);
  });

  it("evaluates required credential-set options consistently", () => {
    const result = evaluateCs02CredentialSets(
      { credentials: [{ id: "pid" }, { id: "mdoc" }], credential_sets: [{ required: true, options: [["pid"], ["mdoc"]] }] },
      { mdoc: "presentation" },
    );
    expect(result.satisfied).to.equal(true);
    expect(Array.from(result.allowedIds)).to.deep.equal(["mdoc"]);
  });

  it("shares multiple-cardinality semantics", () => {
    expect(isCs02PresentationCardinalityValid(["a", "b"], true)).to.equal(true);
    expect(isCs02PresentationCardinalityValid("a", true)).to.equal(false);
    expect(isCs02PresentationCardinalityValid(["a"], false)).to.equal(true);
    expect(isCs02PresentationCardinalityValid(["a", "b"], false)).to.equal(false);
  });

  it("reports unknown credential-set option IDs", () => {
    const result = evaluateCs02CredentialSets(
      { credentials: [{ id: "pid" }], credential_sets: [{ options: [["unknown"]] }] },
      {},
    );
    expect(result.unknownOptionIds).to.deep.equal(["unknown"]);
  });
});
