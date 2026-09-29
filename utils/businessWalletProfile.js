export function classifyBusinessWalletAttestation(payload, requestedProfile = "auto") {
  if (!payload || typeof payload !== "object" || !["auto", "cs04", "cs05"].includes(requestedProfile)) {
    throw new Error("Invalid wallet attestation profile or payload");
  }
  // Call only after verifying the attestation signature at protocol boundaries.
  // The OAuth validator may classify before verification to select validation
  // rules, but CS-05 subsequently forces cryptographic verification.
  const hasEbwoid = Object.prototype.hasOwnProperty.call(payload || {}, "ebwoid_id");
  const hasLegalName = Object.prototype.hasOwnProperty.call(payload || {}, "legal_name");
  const claimsSuggestBusiness = hasEbwoid || hasLegalName;

  if (requestedProfile === "cs04" && claimsSuggestBusiness) {
    throw new Error("Business wallet claims are not allowed in a CS-04 session");
  }
  const resolvedProfile = requestedProfile === "auto"
    ? (claimsSuggestBusiness ? "cs05" : "cs04")
    : requestedProfile;

  if (resolvedProfile === "cs05") {
    if (typeof payload?.ebwoid_id !== "string" || !payload.ebwoid_id.trim()) throw new Error("BWIA ebwoid_id is required");
    if (typeof payload?.legal_name !== "string" || !payload.legal_name.trim()) throw new Error("BWIA legal_name is required");
    if (typeof payload?.wallet_name !== "string" || !payload.wallet_name.trim()) throw new Error("BWIA wallet_name is required");
    if (typeof payload?.wallet_version !== "string" || !payload.wallet_version.trim()) throw new Error("BWIA wallet_version is required");
    if (!payload?.wallet_solution_certification_information || typeof payload.wallet_solution_certification_information !== "object") {
      throw new Error("BWIA wallet_solution_certification_information is required");
    }
    if (!payload?.client_status?.status?.status_list) throw new Error("BWIA client_status is required");
  }
  return { requestedProfile, resolvedProfile, businessIdentity: resolvedProfile === "cs05" ? {
    ebwoidId: payload.ebwoid_id,
    legalName: payload.legal_name,
  } : null };
}
