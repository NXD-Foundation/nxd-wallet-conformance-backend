import {
  resolveCs02ResponseOptions,
  validateCs02SdJwtEntriesInVpToken,
} from "./cs02VerifierResponse.js";

/**
 * Validate the non-CS-03 presentations carried by a decrypted CS-07 response.
 * This keeps the DC API transport layer independent of SD-JWT versus mdoc.
 */
export async function validateCs07CredentialPresentations({ vpToken, session, options = {} } = {}) {
  const trustDecisions = await validateCs02SdJwtEntriesInVpToken(
    vpToken,
    session?.dcql_query,
    {
      session,
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
    options.cs02 || resolveCs02ResponseOptions(),
  );
  const verifiedCredentialIds = (session?.dcql_query?.credentials || [])
    .map((credential) => credential.id)
    .filter((id) => id && vpToken?.[id] != null);
  return {
    verifiedCredentialIds,
    verification: "dcql_and_credential_binding_validated",
    ...(trustDecisions.some((entry) => entry.trust) ? { trustDecisions } : {}),
  };
}
