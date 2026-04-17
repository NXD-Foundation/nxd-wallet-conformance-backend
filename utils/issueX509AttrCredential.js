/**
 * RFC001 / ETSI TS 119 472-3 — `x509_attr` credential format (RFC 5755 Attribute Certificate).
 *
 * Issues a minimal X.509 Attribute Certificate whose attributes carry a pilot JSON
 * claim blob (OCTET STRING) for interoperability testing. Wallets that expect a
 * full ETSI X509-AC EAA profile may require additional OIDs and extensions.
 */

import fs from "fs";
import { createHash, createSign, randomBytes } from "crypto";
import * as asn1js from "asn1js";
import { AsnConvert } from "@peculiar/asn1-schema";
import {
  AttributeCertificate,
  AttributeCertificateInfo,
  AttCertVersion,
  Holder,
  AttCertIssuer,
  V2Form,
  AttCertValidityPeriod,
} from "@peculiar/asn1-x509-attr";
import {
  GeneralName,
  GeneralNames,
  Attribute,
  AlgorithmIdentifier,
} from "@peculiar/asn1-x509";

const ECDSA_WITH_SHA256_OID = "1.2.840.10045.4.3.2";

/** Pilot / dev OID for JSON-encoded claim set inside an Attribute (not ETSI-registered). */
export const APTITUDE_EAA_ATTR_CLAIMS_OID = "1.3.6.1.4.1.54851.119472.3.1";

function derEncodeOctetString(buf) {
  const os = new asn1js.OctetString({ valueHex: new Uint8Array(buf).buffer });
  return new Uint8Array(os.toBER(false)).buffer;
}

function holderHintFromCnf(cnf) {
  if (!cnf) return "no-cnf";
  try {
    const json = JSON.stringify(cnf.jwk ?? cnf);
    return createHash("sha256").update(json).digest("hex").slice(0, 32);
  } catch {
    return "unknown";
  }
}

/**
 * @param {object} opts
 * @param {string} opts.issuerUri Credential Issuer identifier (HTTPS URL)
 * @param {object} [opts.cnf] Holder binding cnf (e.g. { jwk })
 * @param {object} opts.claimsObject Plain claim object serialized into the AC attribute
 * @param {string} opts.privateKeyPem Issuer EC private key PEM (ES256)
 * @returns {string} Base64-encoded DER AttributeCertificate
 */
export function issueX509AttrCredential({
  issuerUri,
  cnf,
  claimsObject,
  privateKeyPem,
}) {
  const base = String(issuerUri || "").replace(/\/$/, "");
  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setMonth(notAfter.getMonth() + 6);

  const serialNumber = new Uint8Array(randomBytes(8)).buffer;

  const hint = holderHintFromCnf(cnf);
  const holderGn = new GeneralNames([
    new GeneralName({
      uniformResourceIdentifier: `${base}#holder:${hint}`,
    }),
  ]);
  const holder = new Holder({ entityName: holderGn });

  const issuerGn = new GeneralNames([
    new GeneralName({ uniformResourceIdentifier: base }),
  ]);
  const issuer = new AttCertIssuer({
    v2Form: new V2Form({ issuerName: issuerGn }),
  });

  const sigAlg = new AlgorithmIdentifier({ algorithm: ECDSA_WITH_SHA256_OID });

  const validity = new AttCertValidityPeriod({
    notBeforeTime: now,
    notAfterTime: notAfter,
  });

  const claimJson = Buffer.from(JSON.stringify(claimsObject), "utf8");
  const attr = new Attribute({
    type: APTITUDE_EAA_ATTR_CLAIMS_OID,
    values: [derEncodeOctetString(claimJson)],
  });

  const acinfo = new AttributeCertificateInfo({
    version: AttCertVersion.v2,
    holder,
    issuer,
    signature: sigAlg,
    serialNumber,
    attrCertValidityPeriod: validity,
    attributes: [attr],
  });

  const tbsDer = Buffer.from(AsnConvert.serialize(acinfo));

  const sign = createSign("sha256");
  sign.update(tbsDer);
  sign.end();
  const sigDer = sign.sign(privateKeyPem);

  const signatureValue = new Uint8Array(sigDer).buffer;

  const ac = new AttributeCertificate({
    acinfo,
    signatureAlgorithm: new AlgorithmIdentifier({
      algorithm: ECDSA_WITH_SHA256_OID,
    }),
    signatureValue,
  });

  const der = Buffer.from(AsnConvert.serialize(ac));
  return der.toString("base64");
}

/**
 * Loads ./private-key.pem from cwd (same convention as credGenerationUtils).
 */
export function issueX509AttrCredentialWithDefaultKey(opts) {
  const privateKeyPem = fs.readFileSync("./private-key.pem", "utf-8");
  return issueX509AttrCredential({ ...opts, privateKeyPem });
}
