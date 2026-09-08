/**
 * Wallet Provider Token Status List publisher for CS-04 WIA/KA revocation.
 *
 * Wire format: IETF OAuth Token Status List draft-ietf-oauth-status-list-20
 * (JWT, bits=1, ZLIB/DEFLATE, LSB-first packing).
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { importPKCS8, SignJWT } from "jose";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WALLET_PROVIDER_KEY_PATH = path.resolve(__dirname, "../../x509EC/ec_private_pkcs8.key");
const WALLET_PROVIDER_CERT_PATH = path.resolve(__dirname, "../../x509EC/client_certificate.crt");

export const WUA_STATUS_LIST_DRAFT = "draft-ietf-oauth-status-list-20";
export const WUA_STATUS_LIST_KINDS = Object.freeze(["wia", "ka"]);
export const DEFAULT_STATUS_LIST_ID = "1";
export const STATUS_VALID = 0x00;
export const STATUS_INVALID = 0x01;
export const STATUS_LIST_BITS = 1;
export const DEFAULT_STATUS_TOKEN_TTL_SECONDS = 3600;
export const MIN_STATUS_MAINTENANCE_DAYS = 31;
export const CS01_ATTESTATION_TTL_SECONDS = 23 * 60 * 60;
export const DEFAULT_STATUS_MAINTENANCE_SECONDS = 32 * 24 * 60 * 60;
export const MIN_STATUS_MAINTENANCE_SECONDS =
  MIN_STATUS_MAINTENANCE_DAYS * 24 * 60 * 60 + CS01_ATTESTATION_TTL_SECONDS;
export const STATUS_LIST_JWT_TYP = "statuslist+jwt";
export const STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt";

const TEST_PROVIDER_URL = "https://wallet-provider.test/wallet-client";

export class WuaStatusListError extends Error {
  constructor(message, { status = 500, errorCode = "server_error" } = {}) {
    super(message);
    this.name = "WuaStatusListError";
    this.status = status;
    this.errorCode = errorCode;
  }
}

let storage = null;
let nowFn = () => Math.floor(Date.now() / 1000);
let signingMaterial = null;

export function createMemoryStatusListStorage() {
  const nextByList = new Map();
  const entriesByList = new Map();

  function listKey(kind, listId) {
    return `${kind}:${listId}`;
  }

  return {
    async allocate(kind, listId, metadata) {
      const key = listKey(kind, listId);
      const idx = nextByList.get(key) || 0;
      nextByList.set(key, idx + 1);
      const entries = entriesByList.get(key) || new Map();
      entries.set(idx, { status: STATUS_VALID, ...metadata });
      entriesByList.set(key, entries);
      return idx;
    },
    async allocatedCount(kind, listId) {
      return nextByList.get(listKey(kind, listId)) || 0;
    },
    async getEntry(kind, listId, idx) {
      const entries = entriesByList.get(listKey(kind, listId));
      return entries?.get(idx) || null;
    },
    async putEntry(kind, listId, idx, entry) {
      const key = listKey(kind, listId);
      const entries = entriesByList.get(key) || new Map();
      entries.set(idx, entry);
      entriesByList.set(key, entries);
    },
    async listEntries(kind, listId) {
      const entries = entriesByList.get(listKey(kind, listId));
      if (!entries) return [];
      return Array.from(entries.entries());
    },
  };
}

export function setWuaStatusListStorageForTests(nextStorage = null) {
  storage = nextStorage || createMemoryStatusListStorage();
}

export function setWuaStatusListClockForTests(clock = null) {
  nowFn = clock || (() => Math.floor(Date.now() / 1000));
}

export function resetWuaStatusListForTests() {
  storage = createMemoryStatusListStorage();
  nowFn = () => Math.floor(Date.now() / 1000);
  signingMaterial = null;
}

function isTestEnv(env = process.env) {
  return env.NODE_ENV === "test";
}

async function getStorage() {
  if (storage) return storage;
  if (isTestEnv()) {
    storage = createMemoryStatusListStorage();
    return storage;
  }
  const { createRedisStatusListStorage } = await import("./cache.js");
  storage = createRedisStatusListStorage();
  return storage;
}

function trimTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

export function resolveWalletProviderUrl(env = process.env) {
  const configured = env.WALLET_PROVIDER_URL;
  if (configured) return trimTrailingSlash(configured);
  if (isTestEnv(env)) return TEST_PROVIDER_URL;
  return null;
}

export function isWuaStatusListKind(kind) {
  return WUA_STATUS_LIST_KINDS.includes(kind);
}

export function assertStatusListCoordinates(kind, listId = DEFAULT_STATUS_LIST_ID) {
  if (!isWuaStatusListKind(kind)) {
    throw new WuaStatusListError(`Unknown status-list kind '${kind}'`, {
      status: 404,
      errorCode: "not_found",
    });
  }
  if (String(listId) !== DEFAULT_STATUS_LIST_ID) {
    throw new WuaStatusListError(`Unknown status-list id '${listId}'`, {
      status: 404,
      errorCode: "not_found",
    });
  }
}

export function statusListTokenUri(kind, listId = DEFAULT_STATUS_LIST_ID, env = process.env) {
  assertStatusListCoordinates(kind, listId);
  const base = resolveWalletProviderUrl(env);
  if (!base) {
    throw new WuaStatusListError(
      "WALLET_PROVIDER_URL is required to advertise Token Status List URIs",
      { status: 500, errorCode: "server_error" },
    );
  }
  return `${base}/status-lists/${kind}/${listId}`;
}

export function resolveStatusTokenTtlSeconds(env = process.env) {
  const raw = env.WALLET_STATUS_LIST_TTL;
  if (raw == null || raw === "") return DEFAULT_STATUS_TOKEN_TTL_SECONDS;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new WuaStatusListError("WALLET_STATUS_LIST_TTL must be a positive integer number of seconds", {
      status: 500,
      errorCode: "server_error",
    });
  }
  return parsed;
}

export function resolveStatusMaintenanceSeconds(env = process.env) {
  const raw = env.WALLET_STATUS_MAINTENANCE_SECONDS;
  const value =
    raw == null || raw === "" ? DEFAULT_STATUS_MAINTENANCE_SECONDS : Number(raw);
  if (!Number.isInteger(value) || value < MIN_STATUS_MAINTENANCE_SECONDS) {
    throw new WuaStatusListError(
      `Status maintenance period must be an integer of at least ${MIN_STATUS_MAINTENANCE_SECONDS} seconds (31 days plus CS-01 attestation TTL)`,
      { status: 500, errorCode: "server_error" },
    );
  }
  return value;
}

export function assertWuaStatusListPublisherConfig(profile, env = process.env) {
  if (profile !== "webuild-cs01") return;
  const raw = env.WALLET_PROVIDER_URL;
  if (!raw) {
    throw new WuaStatusListError(
      "WALLET_PROVIDER_URL is required in webuild-cs01 mode so issuers can fetch WIA/KA status lists",
      { status: 500, errorCode: "invalid_configuration" },
    );
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new WuaStatusListError("WALLET_PROVIDER_URL must be an absolute URL", {
      status: 500,
      errorCode: "invalid_configuration",
    });
  }
  if (parsed.protocol !== "https:") {
    throw new WuaStatusListError("WALLET_PROVIDER_URL must use HTTPS in webuild-cs01 mode", {
      status: 500,
      errorCode: "invalid_configuration",
    });
  }
  if (!env.WALLET_STATUS_ADMIN_TOKEN) {
    throw new WuaStatusListError(
      "WALLET_STATUS_ADMIN_TOKEN is required in webuild-cs01 mode to protect status-list revocation",
      { status: 500, errorCode: "invalid_configuration" },
    );
  }
}

export function describeWuaStatusListPublisher(env = process.env) {
  const base = resolveWalletProviderUrl(env);
  return {
    draft: WUA_STATUS_LIST_DRAFT,
    configured: Boolean(env.WALLET_PROVIDER_URL),
    mediaType: STATUS_LIST_MEDIA_TYPE,
    wia: base ? `${base}/status-lists/wia/${DEFAULT_STATUS_LIST_ID}` : null,
    ka: base ? `${base}/status-lists/ka/${DEFAULT_STATUS_LIST_ID}` : null,
  };
}

export function encodeStatusListBytes(statuses, { bits = STATUS_LIST_BITS } = {}) {
  if (bits !== STATUS_LIST_BITS) {
    throw new WuaStatusListError("Wallet Provider status lists currently support bits=1 only");
  }
  const count = Array.isArray(statuses) ? statuses.length : 0;
  const bitCount = Math.max(Math.ceil(Math.max(count, 1) / 8) * 8, 8);
  const bytes = Buffer.alloc(bitCount / 8, 0);
  for (let i = 0; i < count; i++) {
    const value = Number(statuses[i]) & 1;
    if (value) {
      bytes[Math.floor(i / 8)] |= 1 << (i % 8);
    }
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
  return zlib.inflateSync(Buffer.from(lst, "base64url"));
}

export function readStatusBit(bytes, idx) {
  if (!Number.isInteger(idx) || idx < 0) return null;
  const byteIndex = Math.floor(idx / 8);
  if (byteIndex >= bytes.length) return null;
  return (bytes[byteIndex] >> (idx % 8)) & 1;
}

function pemCertificateToX5c(certPem) {
  return certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

function loadWalletProviderFixtureMaterial() {
  if (signingMaterial) return signingMaterial;
  const privateKeyPem = fs.readFileSync(WALLET_PROVIDER_KEY_PATH, "utf8");
  const certPem = fs.readFileSync(WALLET_PROVIDER_CERT_PATH, "utf8");
  signingMaterial = {
    privateKeyPem,
    x5c: [pemCertificateToX5c(certPem)],
    certPem,
  };
  return signingMaterial;
}

async function loadStatuses(kind, listId) {
  const store = await getStorage();
  const count = await store.allocatedCount(kind, listId);
  const statuses = new Array(count).fill(STATUS_VALID);
  const entries = await store.listEntries(kind, listId);
  for (const [idx, entry] of entries) {
    if (idx >= 0 && idx < count) statuses[idx] = entry.status === STATUS_INVALID ? STATUS_INVALID : STATUS_VALID;
  }
  return statuses;
}

export async function allocateWuaStatusListEntry({
  kind,
  listId = DEFAULT_STATUS_LIST_ID,
  now = nowFn(),
  jti = null,
  env = process.env,
} = {}) {
  assertStatusListCoordinates(kind, listId);
  const uri = statusListTokenUri(kind, listId, env);
  const maintenanceExp = now + resolveStatusMaintenanceSeconds(env);
  const store = await getStorage();
  const idx = await store.allocate(kind, listId, {
    status: STATUS_VALID,
    jti,
    maintenanceExp,
    allocatedAt: now,
  });
  return {
    kind,
    listId,
    idx,
    uri,
    exp: maintenanceExp,
    status: STATUS_VALID,
  };
}

export async function getWuaStatusListEntry({
  kind,
  listId = DEFAULT_STATUS_LIST_ID,
  idx,
} = {}) {
  assertStatusListCoordinates(kind, listId);
  const store = await getStorage();
  return store.getEntry(kind, listId, idx);
}

export async function bindWuaStatusListAttestationJti({
  kind,
  listId = DEFAULT_STATUS_LIST_ID,
  idx,
  jti,
} = {}) {
  assertStatusListCoordinates(kind, listId);
  if (!Number.isInteger(idx) || idx < 0) {
    throw new WuaStatusListError("status-list idx must be a non-negative integer", {
      status: 400,
      errorCode: "invalid_request",
    });
  }
  const store = await getStorage();
  const entry = await store.getEntry(kind, listId, idx);
  if (!entry) {
    throw new WuaStatusListError(`No status-list entry at ${kind}/${listId} idx=${idx}`, {
      status: 404,
      errorCode: "not_found",
    });
  }
  await store.putEntry(kind, listId, idx, { ...entry, jti });
}

export async function revokeWuaStatusListEntry({
  kind,
  listId = DEFAULT_STATUS_LIST_ID,
  idx,
  now = nowFn(),
} = {}) {
  assertStatusListCoordinates(kind, listId);
  const parsedIdx = Number(idx);
  if (!Number.isInteger(parsedIdx) || parsedIdx < 0) {
    throw new WuaStatusListError("status-list idx must be a non-negative integer", {
      status: 400,
      errorCode: "invalid_request",
    });
  }
  const store = await getStorage();
  const entry = await store.getEntry(kind, listId, parsedIdx);
  if (!entry) {
    throw new WuaStatusListError(`No status-list entry at ${kind}/${listId} idx=${parsedIdx}`, {
      status: 404,
      errorCode: "not_found",
    });
  }
  const next = {
    ...entry,
    status: STATUS_INVALID,
    revokedAt: entry.revokedAt || now,
  };
  await store.putEntry(kind, listId, parsedIdx, next);
  return {
    kind,
    listId,
    idx: parsedIdx,
    status: STATUS_INVALID,
    alreadyRevoked: entry.status === STATUS_INVALID,
    jti: next.jti || null,
    maintenanceExp: next.maintenanceExp,
  };
}

export async function signStatusListToken({
  kind,
  listId = DEFAULT_STATUS_LIST_ID,
  env = process.env,
  now = nowFn(),
} = {}) {
  assertStatusListCoordinates(kind, listId);
  const uri = statusListTokenUri(kind, listId, env);
  const ttl = resolveStatusTokenTtlSeconds(env);
  const statuses = await loadStatuses(kind, listId);
  const lst = encodeStatusListLst(statuses);
  const material = loadWalletProviderFixtureMaterial();
  const key = await importPKCS8(material.privateKeyPem, "ES256");
  return new SignJWT({
    sub: uri,
    iat: now,
    exp: now + ttl,
    ttl,
    status_list: {
      bits: STATUS_LIST_BITS,
      lst,
    },
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: STATUS_LIST_JWT_TYP,
      x5c: material.x5c,
    })
    .sign(key);
}

export function timingSafeEqualString(left, right) {
  const a = Buffer.from(String(left || ""), "utf8");
  const b = Buffer.from(String(right || ""), "utf8");
  if (!a.length || a.length !== b.length) {
    crypto.timingSafeEqual(b.length ? b : Buffer.from("x"), b.length ? b : Buffer.from("x"));
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

export function authorizeStatusListAdmin(req, env = process.env) {
  const expected = env.WALLET_STATUS_ADMIN_TOKEN;
  if (!expected) {
    throw new WuaStatusListError("WALLET_STATUS_ADMIN_TOKEN is not configured", {
      status: 500,
      errorCode: "server_error",
    });
  }
  const header = req.get?.("authorization") || req.headers?.authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(String(header));
  const presented = match?.[1] || "";
  if (!timingSafeEqualString(presented, expected)) {
    throw new WuaStatusListError("invalid or missing status-list admin token", {
      status: 401,
      errorCode: "unauthorized",
    });
  }
}

export async function allocateWuaStatusMaintenance({ kind, now = nowFn(), env = process.env } = {}) {
  const entry = await allocateWuaStatusListEntry({ kind, now, env });
  return {
    status: {
      status_list: {
        idx: entry.idx,
        uri: entry.uri,
      },
    },
    exp: entry.exp,
    idx: entry.idx,
    uri: entry.uri,
  };
}
