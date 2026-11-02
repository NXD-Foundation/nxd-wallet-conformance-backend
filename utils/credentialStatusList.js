import fs from "node:fs";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { SignJWT } from "jose";

export const CREDENTIAL_STATUS_LIST_PATH = "/credential-status";
const LIST_SIZE = 131072;
const TTL = 300;
const state = {
  lists: new Map(),
  used: new Map(),
  activeIds: [],
};

function list(id) {
  if (!state.lists.has(id)) state.lists.set(id, { statuses: new Uint8Array(LIST_SIZE), iat: 0 });
  return state.lists.get(id);
}

function openList() {
  const id = crypto.randomUUID();
  state.lists.set(id, { statuses: new Uint8Array(LIST_SIZE), iat: 0 });
  state.used.set(id, new Set());
  state.activeIds.push(id);
  return id;
}

function chooseListId() {
  const open = state.activeIds.filter((id) => state.used.get(id).size < LIST_SIZE);
  if (open.length === 0) return openList();
  return open[crypto.randomInt(0, open.length)];
}

function unusedIndex(taken) {
  let idx = crypto.randomInt(0, LIST_SIZE);
  if (!taken.has(idx)) return idx;
  for (let step = 0; step < LIST_SIZE; step += 1) {
    idx = (idx + 1) % LIST_SIZE;
    if (!taken.has(idx)) return idx;
  }
  throw new Error("status list is full");
}

export function allocateCredentialStatus({ issuer, baseUrl }) {
  const id = chooseListId();
  const taken = state.used.get(id);
  const idx = unusedIndex(taken);
  taken.add(idx);
  list(id).statuses[idx] = 0;
  return {
    status: { status_list: { uri: credentialStatusListUri(baseUrl, id), idx } },
    issuer,
    listId: id,
    idx,
  };
}

export function allocateIssuedCredentialStatus({ baseUrl, revoked = false } = {}) {
  const allocated = allocateCredentialStatus({ baseUrl });
  if (revoked === true) revokeCredentialStatus(allocated.listId, allocated.idx);
  return allocated.status;
}

export function revokeCredentialStatus(listId, idx) {
  const n = Number(idx);
  if (!Number.isInteger(n) || n < 0 || n >= LIST_SIZE) throw Object.assign(new Error("invalid status-list index"), { status: 400 });
  const entry = list(listId);
  if (!state.used.has(listId)) state.used.set(listId, new Set());
  state.used.get(listId).add(n);
  entry.statuses[n] = 1;
  return { listId, idx: n, status: 1 };
}

function credentialStatusListUri(baseUrl, listId) {
  return `${String(baseUrl).replace(/\/$/, "")}${CREDENTIAL_STATUS_LIST_PATH}/${listId}`;
}

function encodedList(entry) {
  const bytes = Buffer.alloc(Math.ceil(entry.statuses.length / 8));
  for (let i = 0; i < entry.statuses.length; i += 1) if (entry.statuses[i]) bytes[Math.floor(i / 8)] |= 1 << (i % 8);
  return zlib.deflateSync(bytes, { level: 9 }).toString("base64url");
}

export async function signCredentialStatusList(listId, { issuer, privateKeyPath = "./private-key.pem", now = Math.floor(Date.now() / 1000) } = {}) {
  const entry = list(listId);
  const uri = credentialStatusListUri(issuer || process.env.SERVER_URL || "http://localhost:3000", listId);
  const key = crypto.createPrivateKey(fs.readFileSync(privateKeyPath, "utf8"));
  entry.iat = now;
  return new SignJWT({ sub: uri, iat: now, exp: now + TTL, ttl: TTL, status_list: { bits: 1, lst: encodedList(entry) } })
    .setProtectedHeader({ alg: "ES256", typ: "statuslist+jwt", kid: "aegean#authentication-key" }).sign(key);
}

export function readCredentialStatusToken(token, idx) {
  const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  if (payload.status_list?.bits !== 1) throw new Error("unsupported status-list bits");
  const bytes = zlib.inflateSync(Buffer.from(payload.status_list.lst, "base64url"));
  if (!Number.isInteger(idx) || idx < 0 || idx >= bytes.length * 8) throw new Error("status-list index out of range");
  return { status: (bytes[Math.floor(idx / 8)] >> (idx % 8)) & 1, payload };
}

export function resetCredentialStatusListsForTests() {
  state.lists.clear();
  state.used.clear();
  state.activeIds.length = 0;
}

export function statusListStoreForTests() { return state.lists; }
