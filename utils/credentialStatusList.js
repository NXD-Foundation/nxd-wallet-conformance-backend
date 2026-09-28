import fs from "node:fs";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { SignJWT } from "jose";

const lists = new Map();
const LIST_SIZE = 131072;
const TTL = 300;

function list(id) {
  if (!lists.has(id)) lists.set(id, { statuses: new Uint8Array(LIST_SIZE), iat: 0 });
  return lists.get(id);
}

export function allocateCredentialStatus({ issuer, baseUrl }) {
  const id = crypto.randomUUID();
  const idx = crypto.randomInt(0, LIST_SIZE);
  const entry = list(id);
  entry.statuses[idx] = 0;
  return { status: { status_list: { uri: `${String(baseUrl).replace(/\/$/, "")}/status-lists/credentials/${id}`, idx } }, issuer, listId: id, idx };
}

export function revokeCredentialStatus(listId, idx) {
  const n = Number(idx);
  if (!Number.isInteger(n) || n < 0 || n >= LIST_SIZE) throw Object.assign(new Error("invalid status-list index"), { status: 400 });
  const entry = list(listId);
  entry.statuses[n] = 1;
  return { listId, idx: n, status: 1 };
}

function encodedList(entry) {
  const bytes = Buffer.alloc(Math.ceil(entry.statuses.length / 8));
  for (let i = 0; i < entry.statuses.length; i += 1) if (entry.statuses[i]) bytes[Math.floor(i / 8)] |= 1 << (i % 8);
  return zlib.deflateSync(bytes, { level: 9 }).toString("base64url");
}

export async function signCredentialStatusList(listId, { issuer, privateKeyPath = "./private-key.pem", now = Math.floor(Date.now() / 1000) } = {}) {
  const entry = list(listId);
  const uri = `${String(issuer || process.env.SERVER_URL || "http://localhost:3000").replace(/\/$/, "")}/status-lists/credentials/${listId}`;
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

export function statusListStoreForTests() { return lists; }
