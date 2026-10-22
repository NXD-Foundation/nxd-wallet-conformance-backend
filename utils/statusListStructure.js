/**
 * RFC004 / IETF Token Status List — structural parsing only.
 * No trust-anchor or list-signer validation (APTITUDE has no trust framework wired).
 */

import zlib from "node:zlib";
import jwt from "jsonwebtoken";

export const STATUS_LIST_JWT_TYP = "statuslist+jwt";
export const STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt";
export const STATUS_VALID = 0x00;
export const STATUS_INVALID = 0x01;
export const STATUS_SUSPENDED = 0x02;
export const STATUS_LIST_BITS = 1;
export const ALLOWED_STATUS_LIST_BITS = new Set([1, 2, 4, 8]);

export class StatusListStructureError extends Error {
  constructor(message, { reason = "invalid_status_list" } = {}) {
    super(message);
    this.name = "StatusListStructureError";
    this.reason = reason;
  }
}

function fail(message, options = {}) {
  throw new StatusListStructureError(message, options);
}

function kindLabel(kind) {
  if (kind === "wia") return "WIA";
  if (kind === "ka") return "KA";
  return "WUA";
}

export function encodeStatusListBytes(statuses, { bits = STATUS_LIST_BITS } = {}) {
  if (!ALLOWED_STATUS_LIST_BITS.has(bits)) {
    throw new StatusListStructureError("Status List bits must be 1, 2, 4, or 8", {
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
      fail(`${label} status object is missing`, { reason: "incomplete_reference" });
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
        { reason: "incomplete_reference" }
      );
    }
    return {
      incomplete: true,
      uri: uri || null,
      idx: Number.isInteger(idx) ? idx : null,
      exp: statusContainer.exp,
    };
  }
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    if (required) {
      fail(`${label} status_list.uri must be an absolute URI`, { reason: "invalid_uri" });
    }
    return { incomplete: true, uri, idx, exp: statusContainer.exp };
  }
  if (parsed.protocol !== "https:") {
    if (required) {
      fail(`${label} status_list.uri must use HTTPS`, { reason: "invalid_uri" });
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

/**
 * Decode a Status List JWT payload without trust-anchor signature enforcement.
 */
export function decodeStatusListTokenStructure(compactJwt) {
  if (typeof compactJwt !== "string" || !compactJwt.includes(".")) {
    fail("Status List Token must be a compact JWT", { reason: "malformed_jwt" });
  }
  const decoded = jwt.decode(compactJwt, { complete: true });
  if (!decoded?.payload || typeof decoded.payload !== "object") {
    fail("Status List Token payload is missing", { reason: "malformed_jwt" });
  }
  if (decoded.header?.typ && decoded.header.typ !== STATUS_LIST_JWT_TYP) {
    fail(`Status List Token typ must be ${STATUS_LIST_JWT_TYP}`, { reason: "invalid_typ" });
  }
  const bits = decoded.payload.bits;
  if (bits !== undefined && !ALLOWED_STATUS_LIST_BITS.has(bits)) {
    fail("Status List Token bits must be 1, 2, 4, or 8", { reason: "unsupported_bits" });
  }
  const effectiveBits = bits ?? STATUS_LIST_BITS;
  const lst = decoded.payload.lst;
  if (typeof lst !== "string" || !lst.length) {
    fail("Status List Token lst is missing", { reason: "malformed_lst" });
  }
  const bytes = inflateStatusListLst(lst);
  return { bits: effectiveBits, bytes, payload: decoded.payload, header: decoded.header };
}

export function readReferencedStatusFromList(compactJwt, idx) {
  const { bits, bytes } = decodeStatusListTokenStructure(compactJwt);
  return readStatusBit(bytes, idx, bits);
}
