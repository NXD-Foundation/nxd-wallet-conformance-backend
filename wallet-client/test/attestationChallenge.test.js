import { expect } from "chai";
import {
  ATTESTATION_CHALLENGE_HEADER,
  AttestationChallengeError,
  createAttestationChallengeState,
  extractAttestationChallenge,
  fetchAttestationChallenge,
  parseAttestationOAuthError,
  shouldRetryWithAttestationChallenge,
} from "../src/lib/attestationChallenge.js";

describe("wallet-client attestationChallenge", () => {
  it("extractAttestationChallenge reads case-insensitive Fetch Headers", () => {
    const headers = new Headers({
      [ATTESTATION_CHALLENGE_HEADER]: "challenge-from-header",
    });
    expect(extractAttestationChallenge(headers)).to.equal("challenge-from-header");
    expect(extractAttestationChallenge({ "oauth-client-attestation-challenge": "lower-case" })).to.equal(
      "lower-case",
    );
    expect(extractAttestationChallenge(null)).to.equal(null);
  });

  it("createAttestationChallengeState tracks and replaces challenge values", () => {
    const state = createAttestationChallengeState("initial-challenge");
    expect(state.consume()).to.equal("initial-challenge");
    state.set("next-challenge");
    expect(state.current).to.equal("next-challenge");
    state.updateFromResponse({ [ATTESTATION_CHALLENGE_HEADER]: "response-challenge" });
    expect(state.current).to.equal("response-challenge");
  });

  it("parseAttestationOAuthError detects use_attestation_challenge", () => {
    const parsed = parseAttestationOAuthError(
      JSON.stringify({ error: "use_attestation_challenge", error_description: "retry" }),
    );
    expect(parsed.isUseAttestationChallenge).to.equal(true);
    expect(parsed.error).to.equal("use_attestation_challenge");
  });

  it("shouldRetryWithAttestationChallenge requires error and header challenge", () => {
    const headers = new Headers({ [ATTESTATION_CHALLENGE_HEADER]: "retry-challenge" });
    const retry = shouldRetryWithAttestationChallenge(
      { ok: false, headers },
      JSON.stringify({ error: "use_attestation_challenge" }),
    );
    expect(retry.shouldRetry).to.equal(true);
    expect(retry.challenge).to.equal("retry-challenge");

    const noRetry = shouldRetryWithAttestationChallenge(
      { ok: false, headers },
      JSON.stringify({ error: "invalid_client" }),
    );
    expect(noRetry.shouldRetry).to.equal(false);
  });

  it("fetchAttestationChallenge POSTs challenge_endpoint and returns attestation_challenge", async () => {
    const fetchImpl = async (url, init) => {
      expect(url).to.equal("https://issuer.example.com/challenge");
      expect(init.method).to.equal("POST");
      expect(init.headers.Accept).to.equal("application/json");
      return {
        ok: true,
        async json() {
          return { attestation_challenge: "AYjcyMzY3ZDhiNmJkNTZ" };
        },
      };
    };

    const challenge = await fetchAttestationChallenge("https://issuer.example.com/challenge", {
      fetchImpl,
    });
    expect(challenge).to.equal("AYjcyMzY3ZDhiNmJkNTZ");
  });

  it("fetchAttestationChallenge rejects missing attestation_challenge", async () => {
    const fetchImpl = async () => ({
      ok: true,
      async json() {
        return {};
      },
    });

    let thrown = null;
    try {
      await fetchAttestationChallenge("https://issuer.example.com/challenge", { fetchImpl });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).to.be.instanceOf(AttestationChallengeError);
    expect(thrown.errorCode).to.equal("missing_attestation_challenge");
  });
});
