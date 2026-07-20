import fs from "fs";
import { resolveCs07VerifierOrigin } from "./cs07DcApi.js";

const DEFAULT_PATH = "./data/dc-api-config.json";
const WORKFLOWS = new Set(["presentation", "cs03-inline-signing"]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertObject(value, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
}

export function validateCs07Config(config, { env = process.env } = {}) {
  assertObject(config, "CS-07 configuration must be an object");
  assertObject(config.profiles, "CS-07 configuration must contain profiles");
  if (typeof config.default_profile !== "string" || !config.profiles[config.default_profile]) {
    throw new Error("CS-07 configuration default_profile must reference a profile");
  }
  for (const [id, profile] of Object.entries(config.profiles)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) {
      throw new Error(`Invalid CS-07 profile identifier "${id}"`);
    }
    assertObject(profile, `CS-07 profile "${id}" must be an object`);
    if (!WORKFLOWS.has(profile.workflow || "presentation")) {
      throw new Error(`Unknown CS-07 workflow for profile "${id}"`);
    }
    assertObject(profile.dcql_query, `CS-07 profile "${id}" must contain dcql_query`);
    if (!Array.isArray(profile.dcql_query.credentials) || profile.dcql_query.credentials.length === 0) {
      throw new Error(`CS-07 profile "${id}" must contain non-empty DCQL credentials`);
    }
    for (const credential of profile.dcql_query.credentials) {
      if (!credential || typeof credential.id !== "string" || !credential.id || typeof credential.format !== "string") {
        throw new Error(`CS-07 profile "${id}" contains an invalid DCQL credential`);
      }
    }
  }
  const parties = config.relying_parties || {};
  config.relying_parties = parties;
  assertObject(parties, "CS-07 relying_parties must be an object");
  for (const [origin, party] of Object.entries(parties)) {
    const canonical = resolveCs07VerifierOrigin({ serverURL: origin, env });
    if (canonical !== origin) throw new Error(`CS-07 relying-party origin must be canonical: "${origin}"`);
    assertObject(party, `CS-07 relying party "${origin}" must be an object`);
    if (!Array.isArray(party.profiles) || party.profiles.length === 0) {
      throw new Error(`CS-07 relying party "${origin}" must authorize profiles`);
    }
    for (const profileId of party.profiles) {
      if (typeof profileId !== "string" || !config.profiles[profileId]) {
        throw new Error(`CS-07 relying party "${origin}" references unknown profile`);
      }
    }
  }
  return config;
}

export function loadCs07Config({ path = process.env.DC_API_CONFIG_PATH || DEFAULT_PATH, env = process.env } = {}) {
  let config;
  try {
    config = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`Unable to load CS-07 configuration: ${error.message}`);
  }
  return validateCs07Config(config, { env });
}

export function resolveCs07Profile(config, { profileId, origin }) {
  const selectedId = profileId || config.default_profile;
  const profile = config.profiles[selectedId];
  if (!profile) throw new Error(`Unknown CS-07 profile "${selectedId}"`);
  const party = config.relying_parties[origin];
  if (!party || !party.profiles.includes(selectedId)) {
    throw new Error(`Origin is not authorized for CS-07 profile "${selectedId}"`);
  }
  return { id: selectedId, ...clone(profile) };
}
