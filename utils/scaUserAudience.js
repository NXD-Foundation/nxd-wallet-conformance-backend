/** Issuer-controlled SCA-User RP URL (Rulebook sections 4.1 and 5.1). */
export function resolveScaUserRpUrl(env = process.env) {
  const value = env.RP_URL;
  let url;
  try { url = new URL(value); } catch { throw new Error("RP_URL must be an explicitly configured HTTPS RP URL"); }
  if (typeof value !== "string" || value !== value.trim() || url.protocol !== "https:" || url.username || url.password || url.hash || value.includes("#")) {
    throw new Error("RP_URL must be an explicitly configured HTTPS RP URL without userinfo or fragment");
  }
  // Preserve the configured audience exactly; do not normalize paths or trailing slashes.
  return value;
}
