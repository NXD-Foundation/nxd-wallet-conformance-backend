/**
 * DCQL claim entries use `path` as segment array (per verifier vpHeplers), JSON Pointer, or dotted string.
 * @param {unknown} claim
 * @returns {string[] | null}
 */
export function dcqlClaimEntryToSegments(claim) {
  if (claim == null) return null;
  if (typeof claim === "string") {
    const p = claim.trim();
    if (!p) return null;
    if (p.startsWith("/")) return p.split("/").filter(Boolean);
    if (p.includes(".")) return p.split(".").filter(Boolean);
    return [p];
  }
  if (typeof claim === "object" && claim.path != null) {
    const p = claim.path;
    if (Array.isArray(p)) return p.filter((s) => typeof s === "string" && s.length > 0);
    if (typeof p === "string") return dcqlClaimEntryToSegments(p);
  }
  return null;
}

/** @param {unknown} claims */
export function normalizeDcqlClaimsToSegmentLists(claims) {
  if (!Array.isArray(claims)) return [];
  const out = [];
  for (const c of claims) {
    const segs = dcqlClaimEntryToSegments(c);
    if (segs?.length) out.push(segs);
  }
  return out;
}
