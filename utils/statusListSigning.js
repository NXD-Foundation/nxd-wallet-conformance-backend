import fs from "fs";
import crypto from "crypto";
import zlib from "zlib";
import base64url from "base64url";
import * as jose from "jose";
import {
  computeDidJwkIssuerDidAndKidFromDidKeys,
  loadDidIssuerPems,
} from "../utils/issuerDidKeys.js";

const defaultServerURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;

const fallbackPrivateKey = fs.readFileSync("./private-key.pem", "utf-8");
let certificatePemX509 = null;
let privateKeyPemX509 = null;
let privateKeyPemDidWeb = null;
try {
  certificatePemX509 = fs.readFileSync("./x509EC/client_certificate.crt", "utf8");
  privateKeyPemX509 = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
} catch {
  // optional, only required in x509 mode
}
try {
  privateKeyPemDidWeb = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
} catch {
  // optional, used when did:web/did:jwk is active
}

export function computeDidWebFromServer(serverURL = defaultServerURL) {
  let controller = serverURL;
  if (proxyPath) {
    controller = serverURL.replace("/" + proxyPath, "") + ":" + proxyPath;
  }
  controller = controller.replace("https://", "").replace("http://", "");
  const did = `did:web:${controller}`;
  const kid = `${did}#keys-1`;
  return { did, kid };
}

export async function computeDidJwkFromPublic() {
  return computeDidJwkIssuerDidAndKidFromDidKeys();
}

export function certToBase64(certPem) {
  return certPem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "");
}

export function statusesToCompressedBuffer(statuses, bits) {
  const bitsArray = [];
  for (let i = 0; i < statuses.length; i++) {
    const status = statuses[i];
    for (let j = 0; j < bits; j++) {
      bitsArray.push((status >> j) & 1);
    }
  }

  const bytes = [];
  for (let i = 0; i < bitsArray.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8 && i + j < bitsArray.length; j++) {
      byte |= bitsArray[i + j] << j;
    }
    bytes.push(byte);
  }

  return zlib.deflateSync(Buffer.from(bytes));
}

export function getEffectiveSignatureType(sessionObject = null) {
  if (sessionObject) {
    return sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
      ? "x509"
      : sessionObject.signatureType;
  }
  return process.env.ISSUER_SIGNATURE_TYPE || "did:web";
}

async function getKeyLikeFromPem(pem) {
  try {
    return await jose.importPKCS8(pem, "ES256");
  } catch (e) {
    try {
      return crypto.createPrivateKey({ key: pem, format: "pem" });
    } catch (e2) {
      console.error("Failed to load private key (PKCS#8/SEC1)", e2);
      throw e;
    }
  }
}

export async function signStatusListToken(
  statusListId,
  statusList,
  sessionObject = null,
  serverURL = defaultServerURL
) {
  const compressedBuffer = statusesToCompressedBuffer(
    statusList.statuses,
    statusList.bits
  );
  const compressedBase64 = base64url.encode(compressedBuffer);
  const effectiveSignatureType = getEffectiveSignatureType(sessionObject);

  let issuerForPayload;
  let protectedHeader;
  const configuredIss = statusList.iss;
  const configuredKid = statusList.kid;
  const configuredX5c = statusList.x5c;

  if (configuredX5c) {
    issuerForPayload = configuredIss || serverURL;
    protectedHeader = { alg: "ES256", typ: "statuslist+jwt", x5c: [configuredX5c] };
  } else if (configuredKid) {
    issuerForPayload = configuredIss || configuredKid.split("#")[0];
    protectedHeader = { alg: "ES256", typ: "statuslist+jwt", kid: configuredKid };
  } else if (effectiveSignatureType === "x509" && certificatePemX509 && privateKeyPemX509) {
    issuerForPayload = serverURL;
    protectedHeader = {
      alg: "ES256",
      typ: "statuslist+jwt",
      x5c: [certToBase64(certificatePemX509)],
    };
  } else if (effectiveSignatureType === "did:jwk") {
    const { did, kid } = await computeDidJwkFromPublic();
    issuerForPayload = did;
    protectedHeader = { alg: "ES256", typ: "statuslist+jwt", kid };
  } else {
    const { did, kid } = computeDidWebFromServer(serverURL);
    issuerForPayload = did;
    protectedHeader = { alg: "ES256", typ: "statuslist+jwt", kid };
  }

  const payload = {
    iss: issuerForPayload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400,
    sub: `${serverURL}/status-list/${statusListId}`,
    status_list: {
      bits: statusList.bits,
      lst: compressedBase64,
    },
  };

  let pemToUse = fallbackPrivateKey;
  if (protectedHeader.x5c && privateKeyPemX509) {
    pemToUse = privateKeyPemX509;
  } else if (
    privateKeyPemDidWeb &&
    (effectiveSignatureType === "did:web" || effectiveSignatureType === "did:jwk")
  ) {
    pemToUse = privateKeyPemDidWeb;
  }

  const privateKeyForSign = await getKeyLikeFromPem(pemToUse);
  return new jose.SignJWT(payload)
    .setProtectedHeader(protectedHeader)
    .sign(privateKeyForSign);
}
