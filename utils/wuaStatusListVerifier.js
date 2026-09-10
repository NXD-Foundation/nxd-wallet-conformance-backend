/**
 * Issuer-side IETF Token Status List (draft-20) consumer for CS-04 WIA/KA revocation.
 *
 * Fetches `statuslist+jwt`, verifies it with the Wallet Provider key that already
 * authenticated the referenced WIA/KA when that key matches, otherwise with the
 * Status List Token's own protected-header `x5c` or `jwk` (IETF Status List
 * issuer keys; EUDI reference wallets often sign the list independently of the
 * WIA leaf). Inflates the ZLIB bitstring and reads the LSB-first status value
 * at `idx` (`bits` 1, 2, 4, or 8). Fail-closed for WUA-required issuance.
 */

import zlib from "node:zlib";
import * as jose from "jose";
import { lookup } from "node:dns/promises";
import { fetchDocument } from "../trust/fetch.js";
import { TrustListError } from "../trust/errors.js";

export const WUA_STATUS_LIST_DRAFT = "draft-ietf-oauth-status-list-20";
export const STATUS_LIST_JWT_TYP = "statuslist+jwt";
export const STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt";
export const STATUS_VALID = 0x00;
export const STATUS_INVALID = 0x01;
export const STATUS_SUSPENDED = 0x02;
export const STATUS_LIST_BITS = 1;
export const ALLOWED_STATUS_LIST_BITS = new Set([1, 2, 4, 8]);

const SPEC_REFS = {
  CS04: "CS-04 §7.2 / §8.2",
  DRAFT20: "draft-ietf-oauth-status-list-20",
};

const ASYMMETRIC_ALGS = new Set(["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"]);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 2_000_000;
const COMPACT_JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const PUBLIC_JWK_FIELDS = ["kty", "crv", "x", "y", "n", "e", "kid", "alg", "use", "key_ops"];

let injectedFetchImpl = null;
let injectedResolveHostname = null;

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  return present.length ? `${message}${message.endsWith(".") ? "" : "."} See ${present.join(" and ")}.` : message;
}

export class WuaStatusListValidationError extends Error {
  constructor(message, { kind = null, reason = "invalid_status_list", statusState = "invalid" } = {}) {
    super(message);
    this.name = "WuaStatusListValidationError";
    this.kind = kind;
    this.reason = reason;
    this.statusState = statusState;
  }
}

export function setWuaStatusListFetchForTests(fetchImpl = null) {
  injectedFetchImpl = fetchImpl;
}

export function setWuaStatusListResolveHostnameForTests(resolveHostname = null) {
  injectedResolveHostname = resolveHostname;
}

export function resetWuaStatusListVerifierForTests() {
  injectedFetchImpl = null;
  injectedResolveHostname = null;
}

export function publicJwkOnly(jwk) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) return null;
  const out = {};
  for (const field of PUBLIC_JWK_FIELDS) {
    if (jwk[field] !== undefined) out[field] = jwk[field];
  }
  return out.kty ? out : null;
}

function kindLabel(kind) {
  if (kind === "wia") return "WIA";
  if (kind === "ka") return "KA";
  return "WUA";
}

function fail(message, options = {}) {
  throw new WuaStatusListValidationError(
    withSpecRef(message, SPEC_REFS.CS04, SPEC_REFS.DRAFT20),
    options
  );
}

function derBase64ToPem(derBase64) {
  const b64 = String(derBase64 || "").replace(/\s+/g, "");
  const lines = b64.match(/.{1,64}/g) || [b64];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

function jwkFingerprint(jwk) {
  const pub = publicJwkOnly(jwk);
  if (!pub) return null;
  return JSON.stringify({
    kty: pub.kty,
    crv: pub.crv,
    x: pub.x,
    y: pub.y,
    n: pub.n,
    e: pub.e,
  });
}

async function jwkFromStatusListHeader(header) {
  const alg = header?.alg;
  if (Array.isArray(header?.x5c) && header.x5c[0]) {
    const key = await jose.importX509(derBase64ToPem(header.x5c[0]), alg);
    return publicJwkOnly(await jose.exportJWK(key));
  }
  if (header?.jwk) return publicJwkOnly(header.jwk);
  return null;
}

export function encodeStatusListBytes(statuses, { bits = STATUS_LIST_BITS } = {}) {
  if (!ALLOWED_STATUS_LIST_BITS.has(bits)) {
    throw new WuaStatusListValidationError("Status List bits must be 1, 2, 4, or 8", {
      reason: "unsupported_bits",
    });
  }
  const count = Array.isArray(statuses) ? statuses.length : 0;
  const byteLength = Math.max(Math.ceil((Math.max(count, 1) * bits) / 8), 1);
  const bytes = Buffer.alloc(byteLength, 0);
  const mask = (1 << bits) - 1;
  for (let i = 0; i < count; i++) {
    const value = Number(statuses[i]) & mask;
    if (!value) continue;
    const bitOffset = i * bits;
    bytes[Math.floor(bitOffset / 8)] |= value << (bitOffset % 8);
  }
  return bytes;
}

export function compressStatusListBytes(bytes) {
  return zlib.deflateSync(bytes, { level: 9 }).toString("base64url");
}

export function encodeStatusListLst(statuses, options) {
  return compressStatusListBytes(encodeStatusListBytes(statuses, options));
}

export function inflateStatusListLst(lst) {
  if (typeof lst !== "string" || !lst.length) {
    fail("Status List Token lst is missing", { reason: "malformed_lst" });
  }
  try {
    return zlib.inflateSync(Buffer.from(lst, "base64url"));
  } catch (error) {
    fail(`Status List Token lst is not valid ZLIB/DEFLATE data (${error.message})`, {
      reason: "malformed_lst",
    });
  }
}

export function readStatusBit(bytes, idx, bits = STATUS_LIST_BITS) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) return null;
  if (!Number.isInteger(idx) || idx < 0) return null;
  if (!ALLOWED_STATUS_LIST_BITS.has(bits)) return null;
  const bitOffset = idx * bits;
  const byteIndex = Math.floor(bitOffset / 8);
  if (byteIndex >= bytes.length) return null;
  return (bytes[byteIndex] >> (bitOffset % 8)) & ((1 << bits) - 1);
}

export function parseReferencedTokenStatus(statusContainer, { required = false, kind = null } = {}) {
  const label = kindLabel(kind);
  if (!statusContainer || typeof statusContainer !== "object") {
    if (required) {
      fail(`${label} status object is missing`, { kind, reason: "incomplete_reference" });
    }
    return null;
  }
  const uri = statusContainer.status?.status_list?.uri;
  const idx = statusContainer.status?.status_list?.idx;
  const incomplete =
    typeof uri !== "string" ||
    !uri.trim() ||
    !Number.isInteger(idx) ||
    idx < 0;
  if (incomplete) {
    if (required) {
      fail(
        `${label} status_list must include an HTTPS uri and a non-negative integer idx`,
        { kind, reason: "incomplete_reference" }
      );
    }
    return { incomplete: true, uri: uri || null, idx: Number.isInteger(idx) ? idx : null, exp: statusContainer.exp };
  }
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    if (required) {
      fail(`${label} status_list.uri must be an absolute URI`, { kind, reason: "invalid_uri" });
    }
    return { incomplete: true, uri, idx, exp: statusContainer.exp };
  }
  if (parsed.protocol !== "https:") {
    if (required) {
      fail(`${label} status_list.uri must use HTTPS`, { kind, reason: "invalid_uri" });
    }
    return { incomplete: true, uri, idx, exp: statusContainer.exp };
  }
  return {
    uri,
    idx,
    exp: typeof statusContainer.exp === "number" ? statusContainer.exp : null,
    incomplete: false,
  };
}

export function buildWiaStatusListEvidence({ uri, idx, exp = null, verificationJwk } = {}) {
  const jwk = publicJwkOnly(verificationJwk);
  if (!jwk || typeof uri !== "string" || !Number.isInteger(idx) || idx < 0) return null;
  return { uri, idx, exp: typeof exp === "number" ? exp : null, verificationJwk: jwk };
}

export function applyWiaStatusEvidenceToSession(session, evidence) {
  if (!session || !evidence) return session;
  const next = buildWiaStatusListEvidence(evidence);
  if (!next) return session;
  session.wiaStatusList = next;
  session.clientStatusPresent = true;
  if (evidence.wiaCnfJkt) session.wiaCnfJkt = evidence.wiaCnfJkt;
  return session;
}

function mediaTypeMatches(contentType) {
  const value = String(contentType || "").split(";")[0].trim().toLowerCase();
  return value === STATUS_LIST_MEDIA_TYPE;
}

function resolveTimeoutMs() {
  const raw = Number(process.env.WUA_STATUS_LIST_TIMEOUT_MS);
  return Number.isInteger(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
}

function resolveMaxBytes() {
  const raw = Number(process.env.WUA_STATUS_LIST_MAX_BYTES);
  return Number.isInteger(raw) && raw > 0 ? raw : DEFAULT_MAX_BYTES;
}

async function fetchStatusListJwt(uri, options) {
  const fetchImpl = options.fetchImpl || injectedFetchImpl || globalThis.fetch;
  const resolveHostname = options.resolveHostname || injectedResolveHostname || lookup;
  try {
    const result = await fetchDocument(uri, {
      fetchImpl,
      resolveHostname,
      timeoutMs: options.timeoutMs ?? resolveTimeoutMs(),
      maxBytes: options.maxBytes ?? resolveMaxBytes(),
      allowInsecureHttp: options.allowInsecureHttp === true,
      allowPrivateAddresses: options.allowPrivateAddresses === true,
      allowedHosts: options.allowedHosts || null,
      headers: { Accept: STATUS_LIST_MEDIA_TYPE },
      followRedirects: true,
    });
    if (!mediaTypeMatches(result.contentType)) {
      fail(`Status List Token Content-Type must be ${STATUS_LIST_MEDIA_TYPE}`, {
        kind: options.kind,
        reason: "invalid_media_type",
      });
    }
    const jwt = Buffer.from(result.bytes).toString("utf8").trim();
    if (!COMPACT_JWT_RE.test(jwt)) {
      fail("Status List Token body must be a compact JWT", {
        kind: options.kind,
        reason: "invalid_token",
      });
    }
    return jwt;
  } catch (error) {
    if (error instanceof WuaStatusListValidationError) throw error;
    const message = error instanceof TrustListError ? error.message : error?.message || String(error);
    fail(`${kindLabel(options.kind)} Status List Token fetch failed: ${message}`, {
      kind: options.kind,
      reason: "fetch_failed",
      statusState: "unavailable",
    });
  }
}

async function verifyJwtWithJwk(jwt, jwk, alg, clockTolerance) {
  const key = await jose.importJWK(jwk, alg);
  const { payload } = await jose.jwtVerify(jwt, key, {
    algorithms: [alg],
    typ: STATUS_LIST_JWT_TYP,
    clockTolerance,
  });
  return payload;
}

async function verifyStatusListJwt(jwt, verificationJwk, { uri, kind, now, clockTolerance = 60 }) {
  const header = jose.decodeProtectedHeader(jwt);
  const alg = header?.alg;
  if (!alg || !ASYMMETRIC_ALGS.has(alg) || alg === "none" || String(alg).startsWith("HS")) {
    fail(`${kindLabel(kind)} Status List Token must use an asymmetric alg`, {
      kind,
      reason: "invalid_token",
    });
  }
  if (header.typ && header.typ !== STATUS_LIST_JWT_TYP) {
    fail(`${kindLabel(kind)} Status List Token typ must be ${STATUS_LIST_JWT_TYP}`, {
      kind,
      reason: "invalid_token",
    });
  }

  const candidates = [];
  const seen = new Set();
  const addCandidate = (jwk) => {
    const pub = publicJwkOnly(jwk);
    const fp = jwkFingerprint(pub);
    if (!pub || !fp || seen.has(fp)) return;
    seen.add(fp);
    candidates.push(pub);
  };
  addCandidate(verificationJwk);
  try {
    addCandidate(await jwkFromStatusListHeader(header));
  } catch (error) {
    fail(`${kindLabel(kind)} Status List Token header key material is invalid (${error.message})`, {
      kind,
      reason: "signature_invalid",
    });
  }
  if (!candidates.length) {
    fail(`${kindLabel(kind)} Status List Token cannot be verified without the Wallet Provider public key`, {
      kind,
      reason: "signature_invalid",
    });
  }

  let payload;
  let usedJwk = null;
  let lastError = null;
  for (const jwk of candidates) {
    try {
      payload = await verifyJwtWithJwk(jwt, jwk, alg, clockTolerance);
      usedJwk = jwk;
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!payload) {
    fail(`${kindLabel(kind)} Status List Token signature or claims are invalid (${lastError?.message || "signature verification failed"})`, {
      kind,
      reason: /exp|timestamp|current time/i.test(lastError?.message || "") ? "expired" : "signature_invalid",
    });
  }
  if (payload.sub !== uri) {
    fail(`${kindLabel(kind)} Status List Token sub must equal the referenced uri`, {
      kind,
      reason: "sub_mismatch",
    });
  }
  if (typeof payload.iat !== "number") {
    fail(`${kindLabel(kind)} Status List Token missing iat`, { kind, reason: "invalid_token" });
  }
  // draft-20 §5.1: iat is REQUIRED; exp is RECOMMENDED. §8.3: check exp only if present.
  const current = now ?? Math.floor(Date.now() / 1000);
  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number") {
      fail(`${kindLabel(kind)} Status List Token exp must be a number`, { kind, reason: "invalid_token" });
    }
    if (payload.exp < current - clockTolerance) {
      fail(`${kindLabel(kind)} Status List Token has expired`, { kind, reason: "expired" });
    }
  }
  return { payload, verificationJwk: usedJwk };
}

function evaluateBit(payload, idx, kind) {
  const statusList = payload.status_list;
  if (!statusList || typeof statusList !== "object") {
    fail(`${kindLabel(kind)} Status List Token missing status_list`, { kind, reason: "invalid_token" });
  }
  if (!ALLOWED_STATUS_LIST_BITS.has(statusList.bits)) {
    fail(`${kindLabel(kind)} Status List Token bits must be 1, 2, 4, or 8`, {
      kind,
      reason: "unsupported_bits",
    });
  }
  const bytes = inflateStatusListLst(statusList.lst);
  const bit = readStatusBit(bytes, idx, statusList.bits);
  if (bit == null) {
    fail(`${kindLabel(kind)} status_list.idx is outside the published bitstring`, {
      kind,
      reason: "idx_out_of_range",
    });
  }
  if (bit === STATUS_INVALID) {
    fail(`${kindLabel(kind)} has been revoked`, {
      kind,
      reason: "revoked",
      statusState: "revoked",
    });
  }
  if (bit !== STATUS_VALID) {
    fail(`${kindLabel(kind)} status bit is not VALID`, {
      kind,
      reason: "unexpected_status",
      statusState: "invalid",
    });
  }
  return { status: STATUS_VALID, bits: statusList.bits };
}

/**
 * Fetch, verify, and evaluate a referenced Token Status List.
 * @returns {Promise<{ ok: true, uri: string, idx: number, status: number, sub: string }>}
 */
export async function evaluateWuaStatusList({
  uri,
  idx,
  verificationJwk,
  kind = null,
  fetchImpl,
  resolveHostname,
  timeoutMs,
  maxBytes,
  allowInsecureHttp,
  allowPrivateAddresses,
  allowedHosts,
  now,
  clockTolerance,
} = {}) {
  const required = parseReferencedTokenStatus(
    { status: { status_list: { uri, idx } } },
    { required: true, kind }
  );
  const jwt = await fetchStatusListJwt(required.uri, {
    kind,
    fetchImpl,
    resolveHostname,
    timeoutMs,
    maxBytes,
    allowInsecureHttp,
    allowPrivateAddresses,
    allowedHosts,
  });
  const { payload, verificationJwk: statusListVerificationJwk } = await verifyStatusListJwt(jwt, verificationJwk, {
    uri: required.uri,
    kind,
    now,
    clockTolerance,
  });
  const bit = evaluateBit(payload, required.idx, kind);
  return {
    ok: true,
    kind,
    uri: required.uri,
    idx: required.idx,
    status: bit.status,
    sub: payload.sub,
    exp: payload.exp,
    ttl: payload.ttl,
    verificationJwk: statusListVerificationJwk,
  };
}

export function statusListLogDetails(resultOrError, extra = {}) {
  if (resultOrError instanceof WuaStatusListValidationError) {
    return {
      kind: resultOrError.kind,
      reason: resultOrError.reason,
      statusState: resultOrError.statusState,
      ...extra,
    };
  }
  if (resultOrError && resultOrError.ok) {
    return {
      kind: resultOrError.kind,
      uri: resultOrError.uri,
      idx: resultOrError.idx,
      status: resultOrError.status,
      ...extra,
    };
  }
  return extra;
}
