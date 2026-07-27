import fs from "node:fs/promises";
import path from "node:path";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { CompactSign } from "jose";
import xmlCrypto from "xml-crypto";
import { stableJsonStringify } from "../trust/crypto.js";

const { SignedXml } = xmlCrypto;

const root = path.resolve("tests/fixtures/trust/webuild-wp4");
const keyDir = path.join(root, "keys");
const artifactDir = path.join(root, "artifacts");

async function read(name) {
  return fs.readFile(path.join(keyDir, name), "utf8");
}

function certDerB64(pem) {
  return new X509Certificate(pem).raw.toString("base64");
}

function fingerprint(pem) {
  return new X509Certificate(pem).fingerprint256.replaceAll(":", "").toLowerCase();
}

async function signJson(payload, keyPem, certPem) {
  const key = createPrivateKey(keyPem);
  const compact = await new CompactSign(Buffer.from(stableJsonStringify(payload)))
    .setProtectedHeader({ alg: "RS256", x5c: [certDerB64(certPem)], iat: 1767225600 })
    .sign(key);
  const [protectedPart, , signaturePart] = compact.split(".");
  return { ...payload, signature: { protected: protectedPart, signature: signaturePart } };
}

function signXml(xml, keyPem, certPem) {
  const signer = new SignedXml({ privateKey: keyPem, publicCert: certPem });
  signer.addReference({
    xpath: "/*",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    isEmptyUri: true,
  });
  signer.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  signer.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  signer.computeSignature(xml, { location: { reference: "/*", action: "append" } });
  return signer.getSignedXml();
}

function scheme(type, sequence = 1) {
  return {
    LoTEVersionIdentifier: 1,
    LoTESequenceNumber: sequence,
    LoTEType: type,
    SchemeOperatorName: [{ lang: "en", value: "WE BUILD Test TLP" }],
    SchemeOperatorAddress: {
      SchemeOperatorPostalAddress: [{ lang: "en", StreetAddress: "Test", Country: "EU" }],
      SchemeOperatorElectronicAddress: [{ lang: "en", uriValue: "https://example.test/trust" }],
    },
    SchemeName: [{ lang: "en", value: "WE BUILD Test List" }],
    ListIssueDateTime: "2026-01-01T00:00:00Z",
    NextUpdate: "2027-01-01T00:00:00Z",
  };
}

function entityList(type, certPem, status = "valid") {
  const listType = type === "pid"
    ? "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
    : "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList";
  return {
    LoTE: {
      ListAndSchemeInformation: scheme(listType),
      TrustedEntitiesList: [{
        TrustedEntityInformation: {
          TEName: [{ lang: "en", value: type === "pid" ? "Test PID Provider" : "Test QEAA Provider" }],
        },
        TrustedEntityServices: [{
          ServiceInformation: {
            ServiceTypeIdentifier: type === "pid" ? "http://uri.etsi.org/19602/SvcType/PID/Issuance" : "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
            ServiceName: [{ lang: "en", value: "Test service" }],
            ServiceDigitalIdentity: { X509Certificates: [{ val: certDerB64(certPem) }] },
            ServiceStatus: status,
          },
        }],
      }],
    },
  };
}

function xmlEntityList(certPem, status = "valid", sequence = 1, listType = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric") {
  const cert = certDerB64(certPem);
  return `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/19612/v2.4.1#" Id="test-tsl">
  <SchemeInformation>
    <TSLVersionIdentifier>6</TSLVersionIdentifier>
    <TSLSequenceNumber>${sequence}</TSLSequenceNumber>
    <TSLType>${listType}</TSLType>
    <SchemeOperatorName><Name xml:lang="en">WE BUILD Test TLP</Name></SchemeOperatorName>
    <SchemeTerritory>EU</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate>2027-01-01T00:00:00Z</NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation><TSPName><Name xml:lang="en">Test QEAA Provider</Name></TSPName></TSPInformation>
      <TSPServices><TSPService><ServiceInformation>
        <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
        <ServiceName><Name xml:lang="en">Test service</Name></ServiceName>
        <ServiceDigitalIdentity><DigitalId><X509Certificate>${cert}</X509Certificate></DigitalId></ServiceDigitalIdentity>
        <ServiceStatus>${status}</ServiceStatus>
      </ServiceInformation></TSPService></TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`;
}

async function main() {
  const lotlKey = await read("lotl.key");
  const lotlCert = await read("lotl.crt");
  const pidKey = await read("pid.key");
  const pidCert = await read("pid.crt");
  const qeaaKey = await read("qeaa.key");
  const qeaaCert = await read("qeaa.crt");

  const pidJson = await signJson(entityList("pid", pidCert), pidKey, pidCert);
  const qeaaJson = await signJson(entityList("qeaa", qeaaCert), qeaaKey, qeaaCert);
  const lotlPayload = {
    LoTE: {
      ListAndSchemeInformation: {
        ...scheme("http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists"),
        DistributionPoints: ["http://127.0.0.1/list_of_trusted_lists.json"],
        PointersToOtherLoTE: [
          {
            LoTELocation: "http://127.0.0.1/pid.json",
            ServiceDigitalIdentities: [{ X509Certificates: [{ val: certDerB64(pidCert) }] }],
            LoTEQualifiers: [{ LoTEType: "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList", SchemeOperatorName: [{ lang: "en", value: "Test PID" }], MimeType: "application/json" }],
          },
          {
            LoTELocation: "http://127.0.0.1/qeaa.xml",
            ServiceDigitalIdentities: [{ X509Certificates: [{ val: certDerB64(qeaaCert) }] }],
            LoTEQualifiers: [{ LoTEType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", SchemeOperatorName: [{ lang: "en", value: "Test QEAA" }], MimeType: "application/xml" }],
          },
        ],
      },
    },
  };
  const lotlJson = await signJson(lotlPayload, lotlKey, lotlCert);
  const lotlXml = signXml(`<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/19612/v2.4.1#" Id="test-lotl">
  <SchemeInformation>
    <TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">WE BUILD Test TLP</Name></SchemeOperatorName><SchemeTerritory>EU</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate>2027-01-01T00:00:00Z</NextUpdate>
  </SchemeInformation>
  <OtherLoTEPointer><LoTELocation>http://127.0.0.1/pid.xml</LoTELocation><LoTEType>http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList</LoTEType><MimeType>application/xml</MimeType><X509Certificate>${certDerB64(pidCert)}</X509Certificate></OtherLoTEPointer>
  <OtherLoTEPointer><LoTELocation>http://127.0.0.1/qeaa.xml</LoTELocation><LoTEType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</LoTEType><MimeType>application/xml</MimeType><X509Certificate>${certDerB64(qeaaCert)}</X509Certificate></OtherLoTEPointer>
</TrustServiceStatusList>`, lotlKey, lotlCert);
  const pidXml = signXml(xmlEntityList(pidCert, "valid", 1, "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"), pidKey, pidCert);
  const qeaaXml = signXml(xmlEntityList(qeaaCert), qeaaKey, qeaaCert);
  await fs.writeFile(path.join(artifactDir, "list_of_trusted_lists.json"), JSON.stringify(lotlJson, null, 2));
  await fs.writeFile(path.join(artifactDir, "list_of_trusted_lists.xml"), lotlXml);
  await fs.writeFile(path.join(artifactDir, "pid.json"), JSON.stringify(pidJson, null, 2));
  await fs.writeFile(path.join(artifactDir, "pid.xml"), pidXml);
  await fs.writeFile(path.join(artifactDir, "qeaa.json"), JSON.stringify(qeaaJson, null, 2));
  await fs.writeFile(path.join(artifactDir, "qeaa.xml"), qeaaXml);
  const manifest = { profile: { lotlSignerFingerprint: fingerprint(lotlCert), pidSignerFingerprint: fingerprint(pidCert), qeaaSignerFingerprint: fingerprint(qeaaCert) }, artifacts: ["list_of_trusted_lists.json", "list_of_trusted_lists.xml", "pid.json", "pid.xml", "qeaa.json", "qeaa.xml"] };
  await fs.writeFile(path.join(root, "manifest.json"), JSON.stringify(manifest, null, 2));
}

await main();
