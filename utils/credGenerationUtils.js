import jwt from "jsonwebtoken";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../utils/sdjwtUtils.js";
import {
  pemToJWK,
  generateNonce,
  didKeyToJwks,
  jwkFromX5cFirstCert,
} from "../utils/cryptoUtils.js";
import {
  computeDidJwkIssuerDidAndKidFromDidKeys,
  getIssuerJwkPairAlignedWithDidDocument,
} from "../utils/issuerDidKeys.js";
import fs from "fs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";

/** JWT typ header for SD-JWT credentials 
 * https://www.w3.org/TR/vc-jose-cose/?utm_source=chatgpt.com#securing-with-sd-jwt 
 * The typ header parameter SHOULD be vc+sd-jwt. When present, the cty header parameter SHOULD be vc.*/
const VCDM_2_0_SD_JWT_CREDENTIAL_TYP_HEADER = "vc+sd-jwt";

const SDJWT_CREDENTIAL_TYP_HEADER = "dc+sd-jwt";

// Standardize on 'cbor' library for EUDI Wallet compliance (matches ISO 18013-5 spec)
// Note: cbor-x is faster but cbor library matches the spec and reference implementations
import cbor from 'cbor';


import {
  getPIDSDJWTData,
  getStudentIDSDJWTData,
  getGenericSDJWTData,
  getEPassportSDJWTData,
  getVReceiptSDJWTData,
  getVReceiptSDJWTDataWithPayload,
  createPaymentWalletAttestationPayload,
  createPhotoIDAttestationPayload,
  getFerryBoardingPassSDJWTData,
  createPCDAttestationPayload,
  getPIDSDJWTDataMsoMdoc,
  getLoyaltyCardSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";

import {
  MDoc,
  Document,
  IssuerSignedDocument
} from "@auth0/mdl";

import cryptoModule from "crypto";
import { Buffer } from "buffer";
import { encode } from "cbor-x";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
const privateKeyPemX509 = fs.readFileSync(
  "./x509EC/ec_private_pkcs8.key",
  "utf8"
);
const certificatePemX509 = fs.readFileSync(
  "./x509EC/client_certificate.crt",
  "utf8"
);
// DID Web key pair - must match the keys published in the DID document
let privateKeyPemDidWeb = null;
let publicKeyPemDidWeb = null;
try {
  privateKeyPemDidWeb = fs.readFileSync(
    "./didjwks/did_private_pkcs8.key",
    "utf8",
  );
  publicKeyPemDidWeb = fs.readFileSync("./didjwks/did_public.pem", "utf8");
} catch (e) {
  console.warn(
    "DID Web key files not found. did:web signature type may not work correctly.",
    e.message,
  );
}

/**
 * Normalize COSE_Sign1 issuerAuth headers produced by @auth0/mdl.
 *
 * Context / rationale:
 * - The @auth0/mdl library builds the COSE_Sign1 structure (issuerAuth) internally when
 *   we call document.sign({ issuerPrivateKey, issuerCertificate, alg }).
 * - Its public API does NOT expose direct control over the COSE header maps (protected /
 *   unprotected) or individual parameters like header 4 (kid).
 * - In some cases, the resulting unprotected headers map may contain entries whose values
 *   are `undefined` (e.g., field 4 = kid -> undefined).
 *
 * COSE & RFC 9052 requirements:
 * - Header parameter 4 (key identifier / kid) is defined as a bstr.
 * - Optional header parameters MUST be omitted when not used; they MUST NOT appear with
 *   an invalid value such as `undefined`.
 *   - IANA COSE header registry: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 *   - RFC 9052 Section 3.1: header parameters are CBOR encoded according to their types.
 *
 * Because we cannot influence the library's header construction, we perform a small,
 * spec‑compliant normalization step after prepare():
 * - Walk the unprotected headers (issuerAuth[1]).
 * - Drop any entries whose value is `undefined`, so that optional fields (like 4/kid)
 *   are effectively "absent" rather than "present with an invalid value".
 *
 * This helper keeps that behavior encapsulated and self‑documented instead of inlining
 * it in the issuance flow.
 *
 * @param {object} preparedIssuerSigned - The IssuerSigned structure returned by signedDocument.prepare().get("issuerSigned").
 */
function normalizeIssuerAuthHeaders(preparedIssuerSigned) {
  if (!preparedIssuerSigned || !Array.isArray(preparedIssuerSigned.issuerAuth)) {
    return;
  }

  const issuerAuth = preparedIssuerSigned.issuerAuth;
  if (issuerAuth.length < 2) {
    return;
  }

  const unprotectedHeaders = issuerAuth[1];

  // Case 1: Map (expected when using CBOR Maps for COSE headers)
  if (unprotectedHeaders instanceof Map) {
    const cleanedMap = new Map();
    for (const [key, value] of unprotectedHeaders.entries()) {
      if (value !== undefined) {
        cleanedMap.set(key, value);
      } else {
        console.log(
          `[mdl-issue] Removing undefined value from unprotected header field ${key} (COSE header should be omitted when not set)`
        );
      }
    }
    issuerAuth[1] = cleanedMap;
    console.log(
      `[mdl-issue] ✅ Normalized unprotected headers (Map): removed undefined values, kept ${cleanedMap.size} valid entries`
    );
    return;
  }

  // Case 2: Plain object (defensive: in case any future refactor returns a JS object)
  if (unprotectedHeaders && typeof unprotectedHeaders === "object") {
    const cleanedMap = new Map();
    for (const [key, value] of Object.entries(unprotectedHeaders)) {
      if (value !== undefined) {
        // Convert numeric string keys to integers to preserve COSE label semantics
        const intKey = /^\d+$/.test(key) ? parseInt(key, 10) : key;
        cleanedMap.set(intKey, value);
      } else {
        console.log(
          `[mdl-issue] Removing undefined value from unprotected header field ${key} (COSE header should be omitted when not set)`
        );
      }
    }
    issuerAuth[1] = cleanedMap;
    console.log(
      `[mdl-issue] ✅ Normalized unprotected headers (object -> Map): removed undefined values, kept ${cleanedMap.size} valid entries`
    );
  }
}

function resolveMsoMdocNamespace(credentialConfiguration, credPayload) {
  const metadataNamespace =
    credentialConfiguration?.credential_metadata?.claims?.find(
      (claim) =>
        Array.isArray(claim?.path) &&
        claim.path.length === 1 &&
        Array.isArray(claim.claims)
    )?.path?.[0];

  if (metadataNamespace) {
    return metadataNamespace;
  }

  const payloadNamespaces = Object.keys(credPayload?.claims || {});
  if (payloadNamespaces.length === 1) {
    return payloadNamespaces[0];
  }

  throw new Error(
    `Unable to resolve mso_mdoc namespace. Available payload namespaces: ${payloadNamespaces.join(", ") || "none"}`
  );
}

// Load issuer configuration for KID and JWK header preference
let issuerConfigValues = {};
try {
  const issuerConfigRaw = fs.readFileSync("./data/issuer-config.json", "utf-8");
  issuerConfigValues = JSON.parse(issuerConfigRaw);
} catch (err) {
  console.warn(
    "Could not load ./data/issuer-config.json for KID, using defaults.",
    err,
  );
}
const defaultSigningKid =
  issuerConfigValues.default_signing_kid || "aegean#authentication-key";

// Helper function to compute did:web identifier from serverURL
function computeDidWebFromServerURL(serverURL) {
  const proxyPath = process.env.PROXY_PATH || null;
  let controller = serverURL;
  if (proxyPath) {
    controller = serverURL.replace("/" + proxyPath, "") + ":" + proxyPath;
  }
  controller = controller.replace("https://", "").replace("http://", "");
  const did = `did:web:${controller}`;
  return did;
}

// Helper function to compute did:jwk identifier from public key
async function computeDidJwkFromPublic() {
  return computeDidJwkIssuerDidAndKidFromDidKeys().did;
}

// const issuerConfig = require("../data/issuer-config.json");

// Convert DER signature to IEEE P1363 format (raw r,s values) for COSE
function derToP1363(derSignature) {
  // DER signature format parsing
  // DER: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  
  if (derSignature[0] !== 0x30) {
    throw new Error('Invalid DER signature format');
  }
  
  let offset = 2; // Skip 0x30 and total length
  
  // Read R value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature format - R not found');
  }
  offset++;
  const rLength = derSignature[offset];
  offset++;
  let rValue = derSignature.slice(offset, offset + rLength);
  offset += rLength;
  
  // Read S value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature format - S not found');
  }
  offset++;
  const sLength = derSignature[offset];
  offset++;
  let sValue = derSignature.slice(offset, offset + sLength);
  
  // Remove leading zeros but ensure 32 bytes for each value (ES256)
  if (rValue.length > 32) {
    rValue = rValue.slice(rValue.length - 32);
  } else if (rValue.length < 32) {
    const padding = Buffer.alloc(32 - rValue.length);
    rValue = Buffer.concat([padding, rValue]);
  }
  
  if (sValue.length > 32) {
    sValue = sValue.slice(sValue.length - 32);
  } else if (sValue.length < 32) {
    const padding = Buffer.alloc(32 - sValue.length);
    sValue = Buffer.concat([padding, sValue]);
  }
  
  // Concatenate r and s for IEEE P1363 format
  return Buffer.concat([rValue, sValue]);
}

// Maps claims from existing payload to mso_mdoc format
// This is a simplified mapper and needs to be extended for different VCTs
function mapClaimsToMsoMdoc(claims, vct) {
  const msoMdocClaims = { ...claims }; // Start by copying all claims

  // mDL uses 'birth_date', SD-JWT might use 'birthdate'
  if (claims.birthdate) {
    msoMdocClaims.birth_date = claims.birthdate;
    delete msoMdocClaims.birthdate; // remove original to avoid duplication
  } else if (claims.birth_date) {
    msoMdocClaims.birth_date = claims.birth_date;
  }

  // mDL 'issue_date' and 'expiry_date' for the document itself
  if (claims.issuance_date) {
    msoMdocClaims.issue_date = claims.issuance_date; // Map PID's issuance_date
    delete msoMdocClaims.issuance_date;
  } else if (claims.issue_date) {
    msoMdocClaims.issue_date = claims.issue_date;
  }

  if (claims.expiry_date) {
    msoMdocClaims.expiry_date = claims.expiry_date; // Map PID's expiry_date
  }

  // Placeholder for other claims and VCT specific mappings
  // For example, for a driver's license (mDL docType):
  // if (vct === 'some_driver_license_vct') {
  //   msoMdocClaims.driving_privileges = claims.driving_privileges;
  //   msoMdocClaims.portrait = claims.portrait; // Needs to be bytes
  //   msoMdocClaims.document_number = claims.document_number;
  //   msoMdocClaims.issuing_country = claims.issuing_country;
  // }

  if (
    claims.unique_id &&
    (vct === "VerifiablePIDSDJWT" ||
      vct === "VerifiablePIDSDJWTAttestation" ||
      vct === "urn:eu.europa.ec.eudi:pid:1")
  ) {
    msoMdocClaims.unique_identifier = claims.unique_id; // Example mapping for PID
    delete msoMdocClaims.unique_id;
  }

  // Add more specific mappings based on vct and mDL data element definitions
  // console.log("Mapped mDL claims:", msoMdocClaims);
  return msoMdocClaims;
}

const DOC_TYPE_MDL = "org.iso.18013.5.1.mDL";
const DEFAULT_MDL_NAMESPACE = "org.iso.18013.5.1";

function isDidKidIdentifier(kid) {
  return (
    kid &&
    (kid.startsWith("did:key:") ||
      kid.startsWith("did:web:") ||
      kid.startsWith("did:jwk:"))
  );
}

/**
 * Holder binding (cnf) from OID4VCI proof JWT protected header (jwk, x5c, kid).
 * @param {object} holderJWKS - decoded JWT protected header
 * @returns {Promise<{ jwk?: object, kid?: string } | null>}
 */
export async function buildHolderCnfFromProofJwtHeader(holderJWKS) {
  if (holderJWKS.jwk) {
    return { jwk: holderJWKS.jwk };
  }
  if (
    Array.isArray(holderJWKS.x5c) &&
    holderJWKS.x5c.length > 0 &&
    !holderJWKS.kid
  ) {
    return {
      jwk: await jwkFromX5cFirstCert(
        holderJWKS.x5c,
        holderJWKS.alg || "ES256"
      ),
    };
  }
  if (holderJWKS.kid && isDidKidIdentifier(holderJWKS.kid)) {
    return { kid: holderJWKS.kid };
  }
  if (holderJWKS.kid) {
    const keys = await didKeyToJwks(holderJWKS.kid);
    return keys?.keys?.[0] ? { jwk: keys.keys[0] } : null;
  }
  return null;
}

export async function handleCredentialGenerationBasedOnFormat(
  requestBody,
  sessionObject,
  serverURL,
  format = "vc+sd-jwt",
) {
  const vct = requestBody.vct;
  const resolvedServerURL =
    serverURL ?? process.env.SERVER_URL ?? "http://localhost:3000";

  let signer, verifier;
  let headerOptions; // Define headerOptions here to be populated based on sig type

  const effectiveSignatureType =
    sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
      ? "x509"
      : sessionObject.signatureType;

  if (effectiveSignatureType === "x509") {
    console.log("x509 signature type selected.");
    ({ signer, verifier } = await createSignerVerifierX509(
      privateKeyPemX509,
      certificatePemX509,
    ));
    headerOptions = {
      header: {
        x5c: [pemToBase64Der(certificatePemX509)],
      },
    };
  } else {
    // Covers "jwk", "kid-jwk", "did:web", and "did:jwk"
    let publicJwkForSigning;
    let privateJwkForSigning;

    if (effectiveSignatureType === "did:web" || effectiveSignatureType === "did:jwk") {
      const { privateJwk, publicJwk } =
        getIssuerJwkPairAlignedWithDidDocument();
      privateJwkForSigning = privateJwk;
      publicJwkForSigning = publicJwk;
      console.log(
        `${effectiveSignatureType} signature type selected. Using DID-aligned key pair from ./didjwks/`,
      );
    } else {
      // Legacy JWK/KID modes use the default key pair
      publicJwkForSigning = pemToJWK(publicKeyPem, "public");
      privateJwkForSigning = pemToJWK(privateKey, "private");
    }

    ({ signer, verifier } = await createSignerVerifier(
      privateJwkForSigning,
      publicJwkForSigning,
    ));

    let joseHeader = {};
    if (effectiveSignatureType === "jwk") {
      console.log("jwk signature type selected: Using embedded JWK in header.");
      joseHeader = {
        jwk: publicJwkForSigning,
        alg: "ES256", // Algorithm must be specified when jwk is used in header
      };
    } else if (effectiveSignatureType === "kid-jwk") {
      // Assuming "kid-jwk" as the type for kid-based JWK signing
      console.log(
        `kid-jwk signature type selected: Using KID: ${defaultSigningKid} in header.`,
      );
      joseHeader = {
        kid: defaultSigningKid,
        alg: "ES256", // alg is also typically included with kid for clarity, though not strictly required by RFC7515 if kid is enough for resolution
      };
    } else if (effectiveSignatureType === "did:web") {
      console.log("did:web signature type selected.");
      const proxyPath = process.env.PROXY_PATH || null;
      let controller = resolvedServerURL;
      if (proxyPath) {
        controller =
          resolvedServerURL.replace("/" + proxyPath, "") + ":" + proxyPath;
      }
      controller = controller.replace("https://", "").replace("http://", "");
      const kid = `did:web:${controller}#keys-1`;
      console.log(
        `Using KID: ${kid} for did:web signing with DID Web key pair.`,
      );
      joseHeader = {
        kid: kid,
        alg: "ES256",
      };
    } else if (effectiveSignatureType === "did:jwk") {
      console.log("did:jwk signature type selected.");
      const { kid } = computeDidJwkIssuerDidAndKidFromDidKeys();
      joseHeader = {
        kid,
        alg: "ES256",
      };
    } else {
      // Fallback or default if signatureType is something else (e.g., a generic 'jwk' without specific instruction)
      // For now, defaulting to KID if not explicitly 'jwk' for direct embedding.
      // This matches the previous default behavior when jwkHeaderPreference was 'kid'.
      console.warn(
        `Unspecified or unrecognized JWK signature type '${effectiveSignatureType}', defaulting to KID: ${defaultSigningKid}.`,
      );
      joseHeader = {
        kid: defaultSigningKid,
        alg: "ES256",
      };
    }
    headerOptions = { header: joseHeader };
  }

  console.log("vc+sd-jwt ", vct);

  // Holder binding: jwt proof uses PoP header/kid; attestation proof uses attested_keys from key-attestation JWT (see sharedIssuanceFlows proof comments).
  const credentialProofKind = requestBody.credentialRequestProofKind || "jwt";

  let cnf;
  if (credentialProofKind === "attestation") {
    if (!requestBody._credentialBindingCnf) {
      throw new Error(
        "Credential binding missing for attestation proof (internal error)."
      );
    }
    cnf = requestBody._credentialBindingCnf;
  } else {
    if (!requestBody.proofs || !requestBody.proofs.jwt) {
      const error = new Error("proof not found");
      error.status = 400;
      throw error;
    }

    const rawJwtProof = requestBody.proofs.jwt;
    const holderProofJwt = Array.isArray(rawJwtProof) ? rawJwtProof[0] : rawJwtProof;
    console.log("requestBody.proofs.jwt", requestBody.proofs.jwt);
    console.log("decoding jwt");
    const decodedWithHeader = jwt.decode(holderProofJwt, {
      complete: true,
    });
    const holderJWKS = decodedWithHeader.header;

    cnf = await buildHolderCnfFromProofJwtHeader(holderJWKS);
    if (!cnf) {
      throw new Error(
        "Could not determine holder binding from proof JWT header (missing jwk, resolvable kid, or x5c)"
      );
    }
  }

  const credType = vct;
  let credPayload = {};

  // Determine issuer identifier based on signature type
  // For did:web signature type, use did:web identifier
  // For did:jwk signature type, use did:jwk identifier
  // Otherwise use serverURL
  let issuerIdentifier = resolvedServerURL;
  if (effectiveSignatureType === "did:web") {
    issuerIdentifier = computeDidWebFromServerURL(resolvedServerURL);
  } else if (effectiveSignatureType === "did:jwk") {
    issuerIdentifier = await computeDidJwkFromPublic();
  }

  let issuerName = resolvedServerURL;
  const match = resolvedServerURL.match(/^(?:https?:\/\/)?([^/]+)/);
  if (match) {
    issuerName = match[1];
  }

  // Determine credential payload based on type
  switch (credType) {
    case "VerifiableIdCardJwtVc":
    case "VerifiablePIDSDJWT":
    case "VerifiablePIDSDJWTAttestation":
    case "urn:eu.europa.ec.eudi:pid:1":
    case "test-cred-config": // For testing purposes
      credPayload = getPIDSDJWTData();
      break;
    case "VerifiableePassportCredentialSDJWT":
      credPayload = getEPassportSDJWTData();
      break;
    case "VerifiableStudentIDSDJWT":
      credPayload = sessionObject
        ? getStudentIDSDJWTData(sessionObject.credentialPayload, null)
        : getVReceiptSDgetStudentIDSDJWTDataJWTData();
      break;
    case "ferryBoardingPassCredential":
    case "VerifiableFerryBoardingPassCredentialSDJWT":
      credPayload = await getFerryBoardingPassSDJWTData();
      break;
    case "VerifiablePortableDocumentA1SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "PaymentWalletAttestation":
      credPayload = createPaymentWalletAttestationPayload(issuerName);
      break;
    case "VerifiablevReceiptSDJWT":
      credPayload = sessionObject
        ? getVReceiptSDJWTDataWithPayload(sessionObject.credentialPayload)
        : getVReceiptSDJWTData();
      break;
    case "VerifiablePortableDocumentA2SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "eu.europa.ec.eudi.photoid.1":
    case "PhotoID":
      credPayload = createPhotoIDAttestationPayload(issuerName);
      break;
    case "eu.europa.ec.eudi.pcd.1":
      credPayload = createPCDAttestationPayload(issuerName);
      break;
    case "urn:eu.europa.ec.eudi:pid:1:mso_mdoc":
      // TODO update this for mso_mdoc
      credPayload = getPIDSDJWTDataMsoMdoc();
      break;
    case "LoyaltyCard":
      credPayload = getLoyaltyCardSDJWTDataWithPayload(
        sessionObject.credentialPayload,
      );
      break;
    default:
      throw new Error(`Unsupported credential type: ${credType}`);
  }

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);

  if (format === "vc+sd-jwt") {
    // W3C VCDM 2.0 secured with SD-JWT (VC-JOSE-COSE) — DIIP v5 compliant
    console.log(
      "Issuing a vc+sd-jwt format credential (W3C VCDM 2.0 + SD-JWT per VC-JOSE-COSE)",
    );
    const sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: "ES256",
      hasher: digest,
      hashAlg: "sha-256",
      saltGenerator: generateSalt,
    });

    // Build W3C VCDM 2.0 payload structure secured with SD-JWT
    const sdPayload = {
      iss: issuerIdentifier,
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      vct: credType,
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", credType],
      issuer: issuerIdentifier,
      validFrom: now.toISOString(),
      validUntil: expiryDate.toISOString(),
      credentialSubject: credPayload.claims,
      cnf,
    };

    // If a status list reference was attached upstream, embed it in the payload
    if (requestBody.status_reference) {
      sdPayload.status = requestBody.status_reference;
    }

    // For VCDM 2.0 + SD-JWT, selective disclosure applies to claims within credentialSubject
    const vcdmDisclosureFrame = {
      credentialSubject: credPayload.disclosureFrame,
    };

    const vcSdJwtHeader = {
      header: {
        ...headerOptions.header,
        typ: VCDM_2_0_SD_JWT_CREDENTIAL_TYP_HEADER,
        cty: "vc",
      },
    };
    const credential = await sdjwt.issue(
      sdPayload,
      vcdmDisclosureFrame,
      vcSdJwtHeader,
    );
    console.log(
      "Credential issued (vc+sd-jwt VCDM 2.0, typ=vc+sd-jwt): ",
      credential,
    );
    return credential;
  } else if (format === "dc+sd-jwt") {
    // SD-JWT VC (flat claims) — DIIP v5 compliant
    console.log("Issuing a dc+sd-jwt format credential (SD-JWT VC)");
    const sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: "ES256",
      hasher: digest,
      hashAlg: "sha-256",
      saltGenerator: generateSalt,
    });

    const sdPayload = {
      iss: issuerIdentifier,
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      vct: credType,
      ...credPayload.claims,
      cnf,
    };

    // If a status list reference was attached upstream, embed it in the payload
    if (requestBody.status_reference) {
      sdPayload.status = requestBody.status_reference;
    }

    const dcSdJwtHeader = {
      header: { ...headerOptions.header, typ: SDJWT_CREDENTIAL_TYP_HEADER },
    };
    const credential = await sdjwt.issue(
      sdPayload,
      credPayload.disclosureFrame,
      dcSdJwtHeader,
    );
    console.log("Credential issued (dc+sd-jwt): ", credential);
    return credential;
  } else if (format === "jwt_vc_json") {
    // Legacy jwt_vc_json format — kept for backward compatibility but NOT DIIP v5 compliant
    // DIIP v5 requires SD-JWT for securing W3C VCDM credentials (use vc+sd-jwt instead)
    console.warn(
      "WARNING: jwt_vc_json format is not DIIP v5 compliant. Use vc+sd-jwt for W3C VCDM credentials.",
    );
    console.log("Issuing a jwt_vc_json format credential (legacy)");
    const vcPayload = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", vct],
      credentialSubject: credPayload.claims,
      issuer: issuerIdentifier,
      validFrom: now.toISOString(),
      validUntil: expiryDate.toISOString(),
    };

    const jwtPayload = {
      iss: issuerIdentifier,
      iat: Math.floor(now.getTime() / 1000),
      nbf: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      vc: vcPayload,
      cnf: cnf,
    };

    const privateKeyForSigning =
      effectiveSignatureType === "x509" ? privateKeyPemX509 : privateKey;

    const signOptions = {
      algorithm: "ES256",
      ...headerOptions,
    };

    const credential = jwt.sign(jwtPayload, privateKeyForSigning, signOptions);
    return credential;
  } else if (format === "mDL" || format === "mdl") {
    // mDL deviceKeyInfo requires JWK per ISO 18013-5; resolve DID to JWK if cnf has kid
    let cnfForMdl = cnf;
    if (cnf.kid && !cnf.jwk && isDidKidIdentifier(cnf.kid)) {
      const keys = await didKeyToJwks(cnf.kid);
      if (!keys?.keys?.[0]) {
        throw new Error(
          `mDL requires device key as JWK; could not resolve DID: ${cnf.kid}`
        );
      }
      cnfForMdl = { jwk: keys.keys[0] };
    }
    console.log("Generating mDL credential using @auth0/mdl library...");
    try {
      return await generateMdlCredentialWithAuth0Library(
        requestBody,
        sessionObject,
        resolvedServerURL,
        vct,
        credPayload,
        cnfForMdl,
        issuerConfigValues,
      );
    } catch (error) {
      console.error("Error generating mDL with @auth0/mdl:", error);
      throw new Error(`Failed to generate mDL: ${error.message}`);
    }
  } else {
    throw new Error(`Unsupported format: ${format}`);
  }
}

/**
 * DEPRECATED: Manual CBOR construction method - kept for reference but not used
 * This method manually constructs the mDL credential using CBOR encoding
 * @deprecated Use generateMdlCredentialWithAuth0Library instead
 */
async function generateMdlCredentialManually(
  requestBody,
  sessionObject,
  serverURL,
  vct,
  credPayload,
  cnf,
  issuerConfigValues
) {
  console.log("Attempting to generate mDL credential using manual CBOR construction...");
  try {
     
      const credentialConfiguration =
        issuerConfigValues.credential_configurations_supported[vct];
      if (!credentialConfiguration) {
        throw new Error(`Configuration not found for VCT: ${vct}`);
      }

      const docType = credentialConfiguration.doctype;
      if (!docType) {
        throw new Error(`'doctype' not defined for VCT: ${vct}`);
      }
      const namespace = resolveMsoMdocNamespace(
        credentialConfiguration,
        credPayload
      );

      const claims = credPayload;
      const msoMdocClaims = claims.claims[namespace];
      
      if (!msoMdocClaims) {
        throw new Error(`Claims not found under namespace '${namespace}' for VCT: ${vct}. Available namespaces: ${Object.keys(claims.claims || {}).join(', ')}`);
      }

      const currentEffectiveSignatureType =
      (sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") || sessionObject.signatureType === "x509"
      ? "x509"
      : "jwk";

      const mDLClaimsMapped = mapClaimsToMsoMdoc(msoMdocClaims, vct);
      
      const devicePublicKeyJwk = cnf.jwk;
      let issuerPrivateKeyForSign, issuerCertificateForSign;
      
      if (currentEffectiveSignatureType === "x509") {
        console.log("Using X.509 for mDL signing.");
        issuerPrivateKeyForSign = privateKeyPemX509; // Use PEM string directly for crypto operations
        issuerCertificateForSign = certificatePemX509;
      } else {
        console.log("Using JWK for mDL signing.");
        issuerPrivateKeyForSign = privateKeyPemX509; // Use PEM string directly for crypto operations
        issuerCertificateForSign = certificatePemX509;
      }
      
      // Create individual claim items manually
      const standardNamespace = namespace//"org.iso.18013.5.1";
      const nameSpaceItems = [];
      const valueDigests = {};
      valueDigests[namespace] = {};
      
      Object.entries(mDLClaimsMapped).forEach(([key, value], index) => {
        // Create the IssuerSignedItem structure manually
        // Per ISO/IEC 18013-5:2021 Section 9.1.2.2, IssuerSignedItem contains:
        // - digestID: Integer identifier
        // - random: Random bytes for security
        // - elementIdentifier: String identifier
        // - elementValue: The actual claim value
        const randomBytes = cryptoModule.randomBytes(16);
        const issuerSignedItem = {
          digestID: index,
          random: randomBytes,
          elementIdentifier: key,
          elementValue: value
        };
        
        // Encode the item as CBOR using cbor library (matches ISO 18013-5 spec)
        // This ensures consistency with EUDI Wallet reference implementations
        // Reference: https://www.iso.org/standard/69084.html (ISO/IEC 18013-5:2021)
        const encodedItem = cbor.encode(issuerSignedItem);
        
        // Calculate digest on the encoded item
        // Per ISO/IEC 18013-5:2021, SHA-256 digest is calculated on the encoded CBOR bytes
        const hash = cryptoModule.createHash('sha256');
        hash.update(encodedItem);
        const digest = hash.digest(); // Store digest result - hash object is finalized after this call
        valueDigests[namespace][index] = digest;
        
        // Create tag 24 with the ENCODED CBOR bytes using cbor library for proper tag handling
        // This creates the correct 24(<<{...}>>) structure where the tag contains encoded CBOR
        // Per ISO/IEC 18013-5:2021 Section 9.1.2.2, IssuerSignedItem MUST be wrapped in Tag 24
        // Tag 24 = CBOR-encoded CBOR as defined in RFC 7049
        const taggedItem = new cbor.Tagged(24, encodedItem);
        
        nameSpaceItems.push(taggedItem);
        
        console.log(`Added claim: ${key} = ${value} (digestID: ${index}), encoded length: ${encodedItem.length} bytes, digest: ${digest.toString('hex').substring(0, 16)}...`);
      });
      
      // Create the issuerSigned structure manually
      const issuerSignedData = {
        nameSpaces: {},
        issuerAuth: null // Will be populated during signing
      };
      
      // Set the namespace with our manually created items
      issuerSignedData.nameSpaces[namespace] = nameSpaceItems;
      
      // console.log("Manual nameSpaces structure:", Object.keys(issuerSignedData.nameSpaces));
      // console.log(`${namespace} contains ${nameSpaceItems.length} items`);
      
      // Create the Mobile Security Object (MSO) manually
      const validityInfo = {
        signed: new Date().toISOString(),
        validFrom: new Date().toISOString(),
        validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      };
      
      // MSO structure per ISO/IEC 18013-5:2021 Section 9.1.2.4
      const mobileSecurityObject = {
        version: "1.0", // MSO version
        digestAlgorithm: "SHA-256", // Digest algorithm for valueDigests
        valueDigests: valueDigests, // Map: namespace → digestID → digest bytes
        deviceKeyInfo: {
          deviceKey: devicePublicKeyJwk // JWK of device public key for holder binding
        },
        docType: docType, // Document type identifier
        validityInfo: validityInfo // Validity period information (ISO 8601 timestamps)
      };
      
      console.log(`MSO created for docType: ${docType}, namespace: ${namespace}, ${Object.keys(mDLClaimsMapped).length} claims`);
      
      // Encode the MSO using cbor library (standardized for EUDI compliance)
      // This ensures consistency with ISO 18013-5 and EUDI Wallet reference implementations
      // Reference: https://www.iso.org/standard/69084.html (ISO/IEC 18013-5:2021)
      const encodedMSO = cbor.encode(mobileSecurityObject);
      
      // Debug: Log the MSO to verify it's properly encoded
      console.log("MSO encoded length:", encodedMSO.length, "bytes");
      console.log("MSO encoded (first 50 bytes):", encodedMSO.slice(0, 50).toString('hex'));
      
      // Create proper COSE Sign1 structure for issuerAuth
      // COSE Sign1 format: [protected, unprotected, payload, signature]
      
      // Critical fix: Ensure COSE labels are properly encoded as integers
      // Use cbor-x consistently and be explicit about integer keys
      
      // Protected headers (must be a bstr containing encoded CBOR map)
      // Create Map with explicit integer keys to ensure proper CBOR encoding
      const protectedHeadersMap = new Map();
      protectedHeadersMap.set(1, -7); // alg: ES256 (COSE algorithm identifier) - integer key 1
      
      // Encode using cbor library (standardized for EUDI compliance)
      const encodedProtectedHeaders = cbor.encode(protectedHeadersMap);
      
      // Unprotected headers (CBOR map, not encoded) - use Map with integer keys
      // x5c (label 33) MUST be an array per COSE spec (RFC 8152)
      const unprotectedHeadersMap = new Map();
      unprotectedHeadersMap.set(33, [Buffer.from(pemToBase64Der(issuerCertificateForSign), 'base64')]); // x5c: certificate chain array - integer key 33
      
      console.log("COSE Headers Debug:");
      console.log("Protected headers Map keys:", Array.from(protectedHeadersMap.keys()), "values:", Array.from(protectedHeadersMap.values()));
      console.log("Protected headers encoded length:", encodedProtectedHeaders.length, "bytes");
      console.log("Unprotected headers Map keys:", Array.from(unprotectedHeadersMap.keys()), "values types:", Array.from(unprotectedHeadersMap.values()).map(v => typeof v));
      
      // Verify the encoded protected headers by decoding them
      try {
        const decodedProtected = cbor.decode(encodedProtectedHeaders);
        console.log("Decoded protected headers:", decodedProtected);
        console.log("Decoded protected headers type:", decodedProtected.constructor.name);
        if (decodedProtected instanceof Map) {
          console.log("Decoded protected headers keys:", Array.from(decodedProtected.keys()));
        } else {
          console.log("Decoded protected headers keys:", Object.keys(decodedProtected));
        }
      } catch (e) {
        console.error("Failed to decode protected headers:", e);
      }
      
      // Create COSE_Sign1 structure to sign 
      // Use the raw MSO bytes for signing
      // Per RFC 8152 Section 4.4: ToBeSigned = [
      //   "Signature1",  // context string
      //   protected_bstr,
      //   external_aad,
      //   payload_bstr
      // ]
      // Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
      const toBeSigned = cbor.encode([
        "Signature1", // context string for Sign1 (RFC 8152 Section 4.4)
        encodedProtectedHeaders, // protected headers as bstr
        Buffer.alloc(0), // external_aad (empty for Sign1)
        encodedMSO // payload (MSO as encoded bytes for signing)
      ]);
      
      console.log(`Creating signature over MSO (${encodedMSO.length} bytes) using ES256`);
      
      // Create actual signature using the private key
      // Per ISO/IEC 18013-5:2021, ES256 (ECDSA P-256 with SHA-256) is used
      const sign = cryptoModule.createSign('SHA256');
      sign.update(toBeSigned);
      const derSignature = sign.sign(issuerPrivateKeyForSign);
      
      // Convert DER signature to IEEE P1363 format (raw r,s values) for COSE
      // Per RFC 8152 Section 8.1, ES256 signatures are 64 bytes (32 bytes r + 32 bytes s)
      // IEEE P1363 format is required for COSE, not DER format
      const signature = derToP1363(derSignature);
      
      if (signature.length !== 64) {
        console.warn(`⚠️ Warning: Signature length is ${signature.length} bytes, expected 64 bytes for ES256`);
      } else {
        console.log("✅ Signature created successfully (64 bytes, IEEE P1363 format)");
      }
      
      // Critical fix for MSO byte string issue:
      // Create the COSE Sign1 structure where the MSO is the payload as a byte string
      // The payload MUST be the encoded MSO bytes, not a decoded object
      
      // Ensure the MSO payload is treated correctly as encoded CBOR bytes
      // In COSE Sign1: [protected_bstr, unprotected_map, payload_bstr, signature_bstr]
      // CRITICAL: Unprotected headers MUST remain as a Map with integer keys (not plain object)
      // Converting to plain object changes integer keys (33) to string keys ('33'), which breaks COSE compliance
      // The cbor library correctly handles Map encoding with integer keys
      
      const coseSign1 = [
        encodedProtectedHeaders, // protected headers as encoded bstr  
        unprotectedHeadersMap, // unprotected headers as Map (preserves integer keys for COSE compliance)
        encodedMSO, // payload as bstr - THIS MUST BE THE ENCODED MSO BYTES
        signature // signature as bstr
      ];
      
      console.log("COSE Sign1 structure types:", [
        "encodedProtectedHeaders:", typeof encodedProtectedHeaders, encodedProtectedHeaders.constructor.name,
        "unprotectedHeadersMap:", typeof unprotectedHeadersMap, unprotectedHeadersMap.constructor.name, "keys:", Array.from(unprotectedHeadersMap.keys()),
        "encodedMSO:", typeof encodedMSO, encodedMSO.constructor.name, 
        "signature:", typeof signature, signature.constructor.name
      ]);
      
      // CRITICAL: Per ISO/IEC 18013-5:2021 and RFC 8152, issuerAuth MUST be a COSE_Sign1_Tagged structure
      // This means the COSE Sign1 array MUST be wrapped in CBOR Tag 18
      // Tag 18 = COSE_Sign1_Tagged as defined in RFC 8152 Section 4.2
      // Reference: https://www.iso.org/standard/69084.html (ISO/IEC 18013-5:2021)
      // Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.2 (RFC 8152)
      const coseSign1Tagged = new cbor.Tagged(18, coseSign1);
      
      console.log("COSE Sign1 wrapped in Tag 18 (COSE_Sign1_Tagged) for ISO/IEC 18013-5:2021 compliance");
      
      // The issuerAuth IS the COSE Sign1 structure wrapped in Tag 18
      const issuerAuth = coseSign1Tagged;
      
      issuerSignedData.issuerAuth = issuerAuth;
      
      // Encode the complete IssuerSigned structure using cbor library for proper Tag handling
      const finalIssuerSigned = cbor.encode(issuerSignedData);
      
      // Verify Tag 18 is properly encoded
      try {
        const decodedTest = cbor.decode(finalIssuerSigned);
        if (decodedTest.issuerAuth instanceof cbor.Tagged && decodedTest.issuerAuth.tag === 18) {
          console.log("✅ Verified: issuerAuth is properly wrapped in Tag 18 (COSE_Sign1_Tagged)");
        } else {
          console.warn("⚠️ Warning: issuerAuth Tag 18 verification failed. Expected Tag 18, got:", decodedTest.issuerAuth?.tag || typeof decodedTest.issuerAuth);
        }
      } catch (e) {
        console.error("Failed to verify Tag 18 wrapping:", e.message);
      }
      
      
      
      const encodedMobileDocument = Buffer.from(finalIssuerSigned).toString("base64url");
      console.log("Manual mDL Credential generated (base64url):", encodedMobileDocument);

      return encodedMobileDocument;
    } catch (error) {
      console.error("Error in manual mDL construction:", error);
      throw new Error(`Failed to generate mDL manually: ${error.message}`);
    }
}

/**
 * Generate mDL credential using @auth0/mdl library
 * This is the preferred method for ISO/IEC 18013-5:2021 compliant mDL issuance
 * Reference: https://github.com/auth0-lab/mdl#issuing-a-credential
 */
async function generateMdlCredentialWithAuth0Library(
  requestBody,
  sessionObject,
  serverURL,
  vct,
  credPayload,
  cnf,
  issuerConfigValues
) {
  console.log(`[mdl-issue] Starting mDL credential generation using @auth0/mdl library for VCT: ${vct}`);
  
  // Step 1: Get credential configuration
  const credentialConfiguration =
    issuerConfigValues.credential_configurations_supported[vct];
  if (!credentialConfiguration) {
    const availableConfigs = Object.keys(issuerConfigValues.credential_configurations_supported || {}).join(', ') || 'none';
    console.error(`[mdl-issue] Configuration not found. Received VCT: '${vct}', Expected: one of [${availableConfigs}]`);
    throw new Error(`Configuration not found for VCT: ${vct}. Received: '${vct}', Expected: one of [${availableConfigs}]`);
  }
  console.log(`[mdl-issue] Found credential configuration for VCT: ${vct}`);

  const docType = credentialConfiguration.doctype;
  if (!docType) {
    console.error(`[mdl-issue] doctype not defined. Received: undefined, Expected: a doctype string in credential configuration for VCT: ${vct}`);
    throw new Error(`'doctype' not defined for VCT: ${vct}. Received: undefined, Expected: a doctype string`);
  }
  const namespace = resolveMsoMdocNamespace(
    credentialConfiguration,
    credPayload
  );
  console.log(`[mdl-issue] Using docType: ${docType}, namespace: ${namespace}`);

  // Step 2: Extract claims
  const claims = credPayload;
  const msoMdocClaims = claims.claims[namespace];
  
  if (!msoMdocClaims) {
    const availableNamespaces = Object.keys(claims.claims || {}).join(', ') || 'none';
    console.error(`[mdl-issue] Claims not found under namespace. Received namespace: '${namespace}', Available namespaces: [${availableNamespaces}]`);
    throw new Error(`Claims not found under namespace '${namespace}' for VCT: ${vct}. Received namespace: '${namespace}', Expected: one of [${availableNamespaces}]`);
  }
  console.log(`[mdl-issue] Found claims under namespace '${namespace}': ${Object.keys(msoMdocClaims).length} claim(s)`);

  // Step 3: Determine signature type
  const currentEffectiveSignatureType =
    (sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509") || sessionObject.signatureType === "x509"
    ? "x509"
    : "jwk";
  console.log(`[mdl-issue] Signature type determined: ${currentEffectiveSignatureType} (isHaip: ${sessionObject.isHaip}, ISSUER_SIGNATURE_TYPE: ${process.env.ISSUER_SIGNATURE_TYPE}, sessionObject.signatureType: ${sessionObject.signatureType})`);

  // Step 4: Map claims to mDL format
  const mDLClaimsMapped = mapClaimsToMsoMdoc(msoMdocClaims, vct);
  console.log(`[mdl-issue] Mapped ${Object.keys(mDLClaimsMapped).length} claims to mDL format:`, Object.keys(mDLClaimsMapped));
  
  // Step 5: Get device public key and issuer keys
  const devicePublicKeyJwk = cnf.jwk;
  if (!devicePublicKeyJwk) {
    console.error(`[mdl-issue] Device public key JWK not found. Received: ${JSON.stringify(cnf)}, Expected: cnf.jwk to contain a JWK object`);
    throw new Error(`Device public key JWK not found. Received: ${JSON.stringify(cnf)}, Expected: cnf.jwk to contain a JWK object`);
  }
  console.log(`[mdl-issue] Device public key JWK found: kty=${devicePublicKeyJwk.kty}, crv=${devicePublicKeyJwk.crv || 'N/A'}`);
  
  let issuerPrivateKeyForSign, issuerCertificateForSign;
  
  if (currentEffectiveSignatureType === "x509") {
    console.log("[mdl-issue] Using X.509 certificate for mDL signing");
    issuerPrivateKeyForSign = privateKeyPemX509;
    issuerCertificateForSign = certificatePemX509;
    
    if (!issuerPrivateKeyForSign) {
      console.error(`[mdl-issue] Issuer private key (X.509) not found. Received: ${typeof issuerPrivateKeyForSign}, Expected: a PEM string`);
      throw new Error(`Issuer private key (X.509) not found. Received: ${typeof issuerPrivateKeyForSign}, Expected: a PEM string`);
    }
    if (!issuerCertificateForSign) {
      console.error(`[mdl-issue] Issuer certificate (X.509) not found. Received: ${typeof issuerCertificateForSign}, Expected: a PEM string`);
      throw new Error(`Issuer certificate (X.509) not found. Received: ${typeof issuerCertificateForSign}, Expected: a PEM string`);
    }
    console.log(`[mdl-issue] Issuer X.509 certificate loaded (length: ${issuerCertificateForSign.length} chars)`);
  } else {
    console.log("[mdl-issue] Using JWK for mDL signing (fallback to X.509 keys)");
    issuerPrivateKeyForSign = privateKeyPemX509;
    issuerCertificateForSign = certificatePemX509;
  }

  // Step 6: Create Document using @auth0/mdl library
  // Based on https://github.com/auth0-lab/mdl documentation
  console.log(`[mdl-issue] Creating Document with docType: ${docType}`);
  
  const validFrom = new Date();
  const validUntil = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  console.log(`[mdl-issue] Validity period: ${validFrom.toISOString()} to ${validUntil.toISOString()}`);
  
  try {
    console.log(`[mdl-issue] Adding ${Object.keys(mDLClaimsMapped).length} claims to namespace: ${namespace}`);
    
    // Create and sign document using method chaining as shown in the library docs
    // The sign() method expects { issuerPrivateKey, issuerCertificate } in PEM format
    // and returns the signed document (chainable, async)
    const document = await new Document(docType)
      .addIssuerNameSpace(namespace, mDLClaimsMapped);
    
    console.log(`[mdl-issue] ✅ Added issuer namespace with ${Object.keys(mDLClaimsMapped).length} claims`);
    
    document.useDigestAlgorithm('SHA-256');
    console.log(`[mdl-issue] ✅ Set digest algorithm to SHA-256`);
    
    document.addValidityInfo({
      signed: validFrom, // Date object, not ISO string
      validFrom: validFrom,
      validUntil: validUntil
    });
    console.log(`[mdl-issue] ✅ Added validity info`);
    
    document.addDeviceKeyInfo({ deviceKey: devicePublicKeyJwk });
    console.log(`[mdl-issue] ✅ Added device key info`);
    
    // Log what we're passing to sign() for debugging
    console.log(`[mdl-issue] Preparing to sign document...`);
    console.log(`[mdl-issue] issuerPrivateKey (PEM) type: ${typeof issuerPrivateKeyForSign}, length: ${issuerPrivateKeyForSign?.length || 'N/A'}`);
    console.log(`[mdl-issue] issuerCertificate (PEM) type: ${typeof issuerCertificateForSign}, length: ${issuerCertificateForSign?.length || 'N/A'}`);
    
    // CRITICAL: @auth0/mdl library expects issuerPrivateKey as JWK object, not PEM string
    // The library only accepts PEM for issuerCertificate, but issuerPrivateKey must be JWK
    // Reference: https://github.com/auth0-lab/mdl/blob/main/src/mdoc/model/Document.ts
    console.log(`[mdl-issue] Converting issuer private key from PEM to JWK format...`);
    const { importPKCS8, exportJWK } = await import('jose');
    const issuerPrivateKeyObj = await importPKCS8(issuerPrivateKeyForSign, 'ES256');
    const issuerPrivateKeyJwk = await exportJWK(issuerPrivateKeyObj);
    
    // Add key operations and usage flags as per jose library best practices
    issuerPrivateKeyJwk.key_ops = ['sign'];
    issuerPrivateKeyJwk.use = 'sig';
    issuerPrivateKeyJwk.ext = true;
    
    console.log(`[mdl-issue] ✅ Converted issuer private key to JWK format: kty=${issuerPrivateKeyJwk.kty}, crv=${issuerPrivateKeyJwk.crv || 'N/A'}`);
    console.log(`[mdl-issue] JWK has kid: ${!!issuerPrivateKeyJwk.kid}`);
    
    const signOptions = {
      issuerPrivateKey: issuerPrivateKeyJwk, // JWK object (required by library)
      issuerCertificate: issuerCertificateForSign, // PEM format string (library handles this)
      alg: 'ES256' // Algorithm for signing
    };
    console.log(`[mdl-issue] Sign options prepared: issuerPrivateKey (JWK), issuerCertificate (PEM), alg: ES256`);
    console.log(`[mdl-issue] Signing document with issuer certificate (alg: ES256)...`);
    
    // The sign() method returns a new IssuerSignedDocument instance
    // We must use this signed instance for the MDoc
    const signedDocument = await document.sign(signOptions);
    
    console.log("[mdl-issue] ✅ Document signed successfully");
    
    // OIDC4VCI v1.0 A.2.4 Credential Response:
    // "The value of the credential claim in the Credential Response MUST be a string that is the 
    // base64url-encoded representation of the CBOR-encoded IssuerSigned structure"
    // 
    // CRITICAL: We must use the library's prepare() method to get the proper CBOR-encodable structure.
    // The prepare() method converts:
    //   - issuerAuth (IssuerAuth class) -> COSE_Sign1 array via getContentForEncoding()
    //   - nameSpaces -> proper Map structure with CBOR-tagged items
    // Direct cbor.encode() on issuerSigned fails because it serializes the IssuerAuth class
    // as a JS object with property names instead of a COSE_Sign1 Tag 18 array.
    console.log(`[mdl-issue] Preparing IssuerSigned structure for CBOR encoding...`);
    
    const issuerSigned = signedDocument.issuerSigned;
    if (!issuerSigned || !issuerSigned.issuerAuth || !issuerSigned.nameSpaces) {
        throw new Error("Signed document does not contain valid IssuerSigned structure");
    }
    
    // Use the library's prepare() method which returns a Map with properly structured data:
    // - 'docType' -> string
    // - 'issuerSigned' -> { nameSpaces: Map, issuerAuth: [protectedHeaders, unprotectedHeaders, payload, signature] }
    const preparedDoc = signedDocument.prepare();
    console.log(`[mdl-issue] ✅ Document prepared for encoding`);
    
    // Extract just the issuerSigned portion from the prepared document
    // The prepare() method returns: Map { 'docType' -> ..., 'issuerSigned' -> ... }
    const preparedIssuerSigned = preparedDoc.get('issuerSigned');
    if (!preparedIssuerSigned) {
        throw new Error("Prepared document does not contain issuerSigned structure");
    }
    
    console.log(`[mdl-issue] IssuerSigned structure extracted from prepared document`);
    console.log(`[mdl-issue] issuerAuth is array: ${Array.isArray(preparedIssuerSigned.issuerAuth)}`);
    console.log(`[mdl-issue] nameSpaces is Map: ${preparedIssuerSigned.nameSpaces instanceof Map}`);

    // Normalize issuerAuth headers from @auth0/mdl so that optional COSE fields (e.g., 4/kid)
    // are omitted rather than present with `undefined` values.
    normalizeIssuerAuthHeaders(preparedIssuerSigned);

    // Encode the properly prepared IssuerSigned structure using the library's cborEncode
    // which uses cbor-x with the correct options for ISO 18013-5 compliance
    // Note: cborEncode is exported from @auth0/mdl/lib/cbor, not the main module
    const { cborEncode } = await import('@auth0/mdl/lib/cbor/index.js');
    console.log(`[mdl-issue] Encoding IssuerSigned to CBOR using @auth0/mdl cborEncode...`);
    const encoded = cborEncode(preparedIssuerSigned);
    console.log(`[mdl-issue] ✅ IssuerSigned encoded to CBOR (${encoded.length} bytes)`);
    
    const encodedMobileDocument = Buffer.from(encoded).toString("base64url");
    console.log(`[mdl-issue] ✅ mDL Credential generated successfully using @auth0/mdl library`);
    console.log(`[mdl-issue] Base64URL length: ${encodedMobileDocument.length} characters`);
    console.log(`[mdl-issue] Base64URL preview (first 100 chars): ${encodedMobileDocument.substring(0, 100)}...`);
    
    return encodedMobileDocument;
  } catch (error) {
    console.error(`[mdl-issue] ❌ Error during mDL credential generation:`, error.message);
    console.error(`[mdl-issue] Error stack:`, error.stack);
    throw new Error(`Failed to generate mDL with @auth0/mdl library: ${error.message}. Received error: ${error.message}, Expected: successful credential generation`);
  }
}

export async function handleCredentialGenerationBasedOnFormatDeferred(
  sessionObject,
  serverURL,
) {
  const resolvedServerURL =
    serverURL ?? process.env.SERVER_URL ?? "http://localhost:3000";
  const requestBody = sessionObject.requestBody;
  const vct = requestBody.vct;
  let { signer, verifier } = await createSignerVerifierX509(
    privateKeyPemX509,
    certificatePemX509,
  );
  console.log("vc+sd-jwt ", vct);

  // Same cnf semantics as handleCredentialGenerationBasedOnFormat (jwt PoP vs attestation attested_keys).
  const credentialProofKindDeferred = requestBody.credentialRequestProofKind || "jwt";
  let cnf;
  if (credentialProofKindDeferred === "attestation") {
    if (!requestBody._credentialBindingCnf) {
      throw new Error(
        "Credential binding missing for attestation proof (internal error)."
      );
    }
    cnf = requestBody._credentialBindingCnf;
  } else {
    if (!requestBody.proofs || !requestBody.proofs.jwt) {
      const error = new Error("proof not found");
      error.status = 400;
      throw error;
    }

    const rawJwtProofDef = requestBody.proofs.jwt;
    const holderProofJwtDef = Array.isArray(rawJwtProofDef)
      ? rawJwtProofDef[0]
      : rawJwtProofDef;
    const decodedWithHeader = jwt.decode(holderProofJwtDef, {
      complete: true,
    });
    const holderJWKS = decodedWithHeader.header;

    cnf = await buildHolderCnfFromProofJwtHeader(holderJWKS);
    if (!cnf) {
      throw new Error(
        "Could not determine holder binding from proof JWT header (missing jwk, resolvable kid, or x5c)"
      );
    }
  }

  const isHaip = sessionObject ? sessionObject.isHaip : false;
  // Determine effective signature type (same logic as main function)
  const effectiveSignatureType =
    sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
      ? "x509"
      : sessionObject.signatureType || "kid-jwk";
  if (!isHaip) {
    if (effectiveSignatureType === "x509") {
      ({ signer, verifier } = await createSignerVerifierX509(
        privateKeyPemX509,
        certificatePemX509,
      ));
    } else {
      let privateJwkForSigning;
      let publicJwkForSigning;

      if (
        effectiveSignatureType === "did:web" ||
        effectiveSignatureType === "did:jwk"
      ) {
        const { privateJwk, publicJwk } =
          getIssuerJwkPairAlignedWithDidDocument();
        privateJwkForSigning = privateJwk;
        publicJwkForSigning = publicJwk;
        console.log(
          `${effectiveSignatureType} signature type selected for deferred issuance. Using DID-aligned key pair from ./didjwks/`,
        );
      } else {
        privateJwkForSigning = pemToJWK(privateKey, "private");
        publicJwkForSigning = pemToJWK(publicKeyPem, "public");
      }

      ({ signer, verifier } = await createSignerVerifier(
        privateJwkForSigning,
        publicJwkForSigning,
      ));
    }
  }

  const sdjwt = new SDJwtVcInstance({
    signer,
    verifier,
    signAlg: "ES256",
    hasher: digest,
    hashAlg: "sha-256",
    saltGenerator: generateSalt,
  });

  const credType = vct;
  let credPayload = {};

  // Determine issuer identifier based on signature type
  // For did:web signature type, use did:web identifier
  // For did:jwk signature type, use did:jwk identifier
  // Otherwise use serverURL
  let issuerIdentifier = resolvedServerURL;
  if (effectiveSignatureType === "did:web") {
    issuerIdentifier = computeDidWebFromServerURL(resolvedServerURL);
  } else if (effectiveSignatureType === "did:jwk") {
    issuerIdentifier = await computeDidJwkFromPublic();
  }

  let issuerName = resolvedServerURL;
  const match = resolvedServerURL.match(/^(?:https?:\/\/)?([^/]+)/);
  if (match) {
    issuerName = match[1];
  }

  // Determine credential payload based on type
  switch (credType) {
    case "VerifiableIdCardJwtVc":
    case "VerifiablePIDSDJWT":
    case "VerifiablePIDSDJWTAttestation":
    case "urn:eu.europa.ec.eudi:pid:1":
    case "test-cred-config": // For testing purposes
      credPayload = getPIDSDJWTData();
      break;
    case "VerifiableePassportCredentialSDJWT":
      credPayload = getEPassportSDJWTData();
      break;
    case "VerifiableStudentIDSDJWT":
      credPayload = getStudentIDSDJWTData();
      break;
    case "ferryBoardingPassCredential":
    case "VerifiableFerryBoardingPassCredentialSDJWT":
      credPayload = await getFerryBoardingPassSDJWTData();
      break;
    case "VerifiablePortableDocumentA1SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "PaymentWalletAttestation":
      credPayload = createPaymentWalletAttestationPayload(issuerName);
      break;
    case "VerifiablevReceiptSDJWT":
      credPayload = sessionObject
        ? getVReceiptSDJWTDataWithPayload(sessionObject.credentialPayload)
        : getVReceiptSDJWTData();
      break;
    case "VerifiablePortableDocumentA2SDJWT":
      credPayload = getGenericSDJWTData();
      break;
    case "eu.europa.ec.eudi.photoid.1":
      credPayload = createPhotoIDAttestationPayload(issuerName);
      break;
    case "eu.europa.ec.eudi.pcd.1":
      credPayload = createPCDAttestationPayload(issuerName);
      break;
    default:
      throw new Error(`Unsupported credential type: ${credType}`);
  }

  //TODO this should be update to check format before deciding on the typ of the header
  // Prepare issuance headers (DIIP v5: typ MUST be dc+sd-jwt for SD-JWT credentials)
  let headerOptions;
  if (effectiveSignatureType === "x509") {
    headerOptions = {
      header: {
        typ: SDJWT_CREDENTIAL_TYP_HEADER,
        x5c: [pemToBase64Der(certificatePemX509)],
      },
    };
  } else if (effectiveSignatureType === "did:web") {
    const controller = computeDidWebFromServerURL(resolvedServerURL);
    headerOptions = {
      header: {
        typ: SDJWT_CREDENTIAL_TYP_HEADER,
        kid: `${controller}#keys-1`,
      },
    };
  } else if (effectiveSignatureType === "did:jwk") {
    const { kid } = computeDidJwkIssuerDidAndKidFromDidKeys();
    headerOptions = {
      header: {
        typ: SDJWT_CREDENTIAL_TYP_HEADER,
        kid,
      },
    };
  } else {
    headerOptions = {
      header: {
        typ: SDJWT_CREDENTIAL_TYP_HEADER,
        kid: "aegean#authentication-key",
      },
    };
  }

  const now = new Date();
  const expiryDate = new Date(now);
  expiryDate.setMonth(now.getMonth() + 6);
  // Issue credential
  const credential = await sdjwt.issue(
    {
      iss: issuerIdentifier,
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000),
      exp: Math.floor(expiryDate.getTime() / 1000),
      vct: credType,
      ...credPayload.claims,
      cnf,
    },
    credPayload.disclosureFrame,
    headerOptions,
  );

  return credential;
}
