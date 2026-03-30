/**
 * OID4VCI JWT proof header validation helpers.
 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 */
export class ProofJwtHeaderValidator {
  /**
   * x5c MUST NOT be present when kid or jwk is present (OID4VCI JWT proof header).
   *
   * @param {object} header - JWS protected header
   * @param {{ invalidProofMessage: string, specRef?: string }} options
   * @throws {Error} when header violates mutual exclusivity
   */
  static assertX5cExclusiveWithKidOrJwk(header, options) {
    const invalidProofMessage = options?.invalidProofMessage ?? "Invalid proof header";
    const specRef = options?.specRef ?? "";
    const hasX5c = Array.isArray(header?.x5c) && header.x5c.length > 0;
    if (hasX5c && (header.jwk || header.kid)) {
      const suffix = specRef ? ` See ${specRef}` : "";
      throw new Error(
        `${invalidProofMessage}: x5c MUST NOT be present when kid or jwk is present.${suffix}`
      );
    }
  }
}
