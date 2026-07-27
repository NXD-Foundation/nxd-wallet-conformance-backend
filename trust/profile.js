import fs from "node:fs/promises";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

export const SUPPORTED_LIST_TYPES = Object.freeze([
  "pid-provider",
  "wallet-provider",
  "wrpac-provider",
  "wrprc-provider",
  "pub-eaa-provider",
  "eaa-provider",
  "qeaa-provider",
  "ebwoid-provider",
]);

const REQUIRED = ["id", "formats", "listTypes", "freshness"];

export function validateTrustProfile(profile) {
  if (!profile || typeof profile !== "object") {
    throw new TrustListError("Trust profile must be an object", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  for (const field of REQUIRED) {
    if (!(field in profile)) {
      throw new TrustListError(`Trust profile is missing ${field}`, TRUST_REASON_CODES.LIST_PROFILE_INVALID);
    }
  }
  if (!profile.formats?.preferred || !profile.formats?.fallback) {
    throw new TrustListError("Trust profile must define preferred and fallback formats", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  if (!SUPPORTED_LIST_TYPES.every((type) => profile.listTypes[type])) {
    throw new TrustListError("Trust profile must map all WP4 list types", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  if (!Number.isFinite(profile.freshness.maxStaleSeconds) || profile.freshness.maxStaleSeconds < 0) {
    throw new TrustListError("Trust profile freshness.maxStaleSeconds must be non-negative", TRUST_REASON_CODES.LIST_PROFILE_INVALID);
  }
  return profile;
}

export async function loadTrustProfile(path) {
  return validateTrustProfile(JSON.parse(await fs.readFile(path, "utf8")));
}

export function listTypeProfile(profile, listType) {
  const selected = profile.listTypes[listType];
  if (!selected) {
    throw new TrustListError(`Unsupported list type: ${listType}`, TRUST_REASON_CODES.UNSUPPORTED_LIST_TYPE);
  }
  return selected;
}
