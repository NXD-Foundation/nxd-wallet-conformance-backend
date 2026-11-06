// Pilot assignments; payment/SCA and credentials awaiting a role are deliberately
// absent until their applicable rulebook and onboarding are agreed.
export const issuerProfiles = Object.freeze({
  pid: Object.freeze({ role: "pid-provider", credentialConfigurationIds: Object.freeze([
    "VerifiablePIDSDJWT", "VerifiablePIDSDJWTWUA", "VerifiablePIDSDJWTAttestation",
    "urn:eu.europa.ec.eudi:pid:1", "urn:eudi:pid:1", "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
    "urn:eudi:pid:lsp:1", "urn:eudi:pid:lsp:1:mso_mdoc",
  ]) }),
  eaa: Object.freeze({ role: "eaa-provider", credentialConfigurationIds: Object.freeze([
    "VerifiableStudentIDSDJWT", "VerifiableFerryBoardingPassCredentialSDJWT", "VerifiableReceipt", "LoyaltyCard",
  ]) }),
  "pub-eaa": Object.freeze({ role: "pub-eaa-provider", credentialConfigurationIds: Object.freeze([
    "VerifiablePortableDocumentA1SDJWT", "VerifiablePortableDocumentA2SDJWT",
    "VerifiableePassportCredentialSDJWT", "PhotoID", "PCD",
  ]) }),
  qeaa: Object.freeze({ role: "qeaa-provider", credentialConfigurationIds: Object.freeze([]) }),
});

export function getIssuerProfile(id) {
  return Object.hasOwn(issuerProfiles, id) ? issuerProfiles[id] : null;
}

export function profileIssuerUrl(base, id) {
  if (!getIssuerProfile(id)) throw new Error(`Unknown issuer profile: ${id}`);
  return `${base.replace(/\/+$/, "")}/issuer/${id}`;
}

export function assertProfileCredential(id, credentialConfigurationId) {
  const profile = getIssuerProfile(id);
  if (!profile) throw new Error(`Unknown issuer profile: ${id}`);
  if (!profile.credentialConfigurationIds.includes(credentialConfigurationId)) {
    throw new Error(`Credential configuration is not permitted for issuer profile ${id}`);
  }
}

export function sessionIssuerUrl(base, session) {
  return session?.issuerProfile ? profileIssuerUrl(base, session.issuerProfile) : base;
}
