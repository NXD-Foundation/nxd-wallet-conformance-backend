import { expect } from "chai";
import { readFileSync } from "node:fs";
import { certificateSubject } from "../wallet-client/src/lib/trustFramework.js";

describe("wallet trust framework certificate identity parsing", () => {
  it("reads an EC WRPAC subject without assuming an RSA public key", () => {
    const certificate = readFileSync("certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem", "utf8");
    expect(certificateSubject(certificate)).to.deep.equal({
      entityId: "VATEL-090264862",
      commonName: "University of the Aegean",
    });
  });
});
