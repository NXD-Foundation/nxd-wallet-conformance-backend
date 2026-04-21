/**
 * Same field set and rules as `normalizeVerifierInfo` in repo `utils/routeUtils.js`
 * (kept local so the wallet does not import the full issuer route stack).
 */
const VERIFIER_INFO_KEYS = [
  "verifier_id",
  "service_description",
  "rp_registrar_uri",
  "registration_certificate",
  "intended_use",
  "purpose",
  "privacy_policy_uri",
];

function cloneJsonValue(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

export function normalizeVerifierInfo(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return null;
  }

  const normalized = {};
  for (const key of VERIFIER_INFO_KEYS) {
    const value = input[key];
    if (value === undefined || value === null || value === "") continue;
    if (key === "registration_certificate" && typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed.startsWith("[")) {
        normalized[key] = JSON.parse(trimmed);
      } else {
        normalized[key] = [trimmed];
      }
      continue;
    }
    normalized[key] = cloneJsonValue(value);
  }

  return Object.keys(normalized).length > 0 ? normalized : null;
}
