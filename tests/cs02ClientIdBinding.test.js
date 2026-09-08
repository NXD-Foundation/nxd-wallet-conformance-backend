import { expect } from "chai";
import fs from "fs";
import {
  Cs02ClientIdBindingError,
  assertX509SanDnsLeafMatchesClientId,
  assertX509SanDnsResponseUriFqdn,
  parseDnsNamesFromSubjectAltName,
  parseTrustedX509ClientIds,
  parseX509SanDnsClientId,
} from "../utils/cs02ClientIdBinding.js";

describe("CS-02 x509_san_dns client_id binding", () => {
  it("parses the DNS name after the x509_san_dns prefix", () => {
    expect(parseX509SanDnsClientId("x509_san_dns:Verifier.Example.ORG")).to.equal("Verifier.Example.ORG");
    expect(parseX509SanDnsClientId("decentralized_identifier:did:web:example")).to.equal(null);
  });

  it("parses trusted client id allowlists", () => {
    expect(parseTrustedX509ClientIds("x509_san_dns:a.example, x509_san_dns:b.example")).to.deep.equal([
      "x509_san_dns:a.example",
      "x509_san_dns:b.example",
    ]);
  });

  it("extracts non-wildcard DNS SAN names", () => {
    expect(parseDnsNamesFromSubjectAltName("DNS:a.example, DNS:*.example, URI:https://a.example")).to.deep.equal([
      "a.example",
    ]);
  });

  it("requires response_uri FQDN to match client_id DNS name", () => {
    const result = assertX509SanDnsResponseUriFqdn(
      "x509_san_dns:Verifier.Example.ORG",
      "https://verifier.example.org/direct_post/1",
    );
    expect(result).to.deep.include({ skipped: false, dns: "Verifier.Example.ORG", hostname: "verifier.example.org" });
  });

  it("rejects a mismatched response_uri FQDN", () => {
    expect(() =>
      assertX509SanDnsResponseUriFqdn(
        "x509_san_dns:verifier.example.org",
        "https://other.example/response",
      ),
    ).to.throw(Cs02ClientIdBindingError, /FQDN/);
  });

  it("skips FQDN matching for an explicit trusted client_id", () => {
    const result = assertX509SanDnsResponseUriFqdn(
      "x509_san_dns:verifier.example.org",
      "https://other.example/response",
      { trustedClientIds: ["x509_san_dns:verifier.example.org"] },
    );
    expect(result.skipped).to.equal(true);
  });

  it("requires the leaf certificate SAN to include the client_id DNS name", () => {
    const pem = fs.readFileSync("./x509EC/client_certificate.crt", "utf8");
    const result = assertX509SanDnsLeafMatchesClientId("x509_san_dns:dss.aegean.gr", pem);
    expect(result.dns).to.equal("dss.aegean.gr");
    expect(result.dnsNames).to.include("dss.aegean.gr");
    expect(() =>
      assertX509SanDnsLeafMatchesClientId("x509_san_dns:unrelated.example", pem),
    ).to.throw(Cs02ClientIdBindingError, /dNSName SAN/);
  });
});
