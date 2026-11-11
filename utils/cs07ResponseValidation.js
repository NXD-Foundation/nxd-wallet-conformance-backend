import {
  resolveCs02ResponseOptions,
  validateCs02SdJwtEntriesInVpToken,
} from "./cs02VerifierResponse.js";

/**
 * Validate the non-CS-03 presentations carried by a decrypted CS-07 response.
 * This keeps the DC API transport layer independent of SD-JWT versus mdoc.
 */
export async function validateCs07CredentialPresentations({ vpToken, session, options = {} } = {}) {
  const skipCredentialStatus = session?.transport_profile === "cs07-dc-api" &&
    session.credentialStatusCheck === "skip";
  const cs02Options = options.cs02 || resolveCs02ResponseOptions();
  const trustDecisions = await validateCs02SdJwtEntriesInVpToken(
    vpToken,
    session?.dcql_query,
    {
      session,
      skipCredentialStatus,
      computeSdHash: options.computeSdHash,
      issuerVerificationKey: options.issuerVerificationKey,
      issuerVerificationJwk: options.issuerVerificationJwk,
      issuerJwks: options.issuerJwks,
      resolveIssuerVerificationKey: options.resolveIssuerVerificationKey,
      rejectUnsolicitedDisclosures: options.rejectUnsolicitedDisclosures,
      trustPolicyOptions: options.trustPolicyOptions,
      env: options.env,
      log: options.log,
    },
    skipCredentialStatus ? { ...cs02Options, strict: true } : cs02Options,
  );
  const verifiedCredentialIds = (session?.dcql_query?.credentials || [])
    .map((credential) => credential.id)
    .filter((id) => id && vpToken?.[id] != null);
  return {
    verifiedCredentialIds,
    verification: "dcql_and_credential_binding_validated",
    ...(trustDecisions.some((entry) => entry.credentialStatusSkipped) ? { credentialStatus: "skipped" } : {}),
    ...(trustDecisions.some((entry) => entry.trust) ? { trustDecisions } : {}),
  };
}
