import { expect } from "chai";
import { normalizeCredentialOfferDeepLink } from "../src/lib/credentialOfferScheme.js";

describe("credentialOfferScheme", () => {
  it("normalizes eu-eaa-offer:// to openid-credential-offer://", () => {
    const inUri =
      "eu-eaa-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2F.offer.json";
    const out = normalizeCredentialOfferDeepLink(inUri);
    expect(out.startsWith("openid-credential-offer://")).to.equal(true);
    const u = new URL(out);
    expect(u.protocol).to.equal("openid-credential-offer:");
    expect(u.searchParams.get("credential_offer_uri")).to.equal("https://issuer.example/.offer.json");
  });

  it("still normalizes haip and haip-vci", () => {
    expect(
      normalizeCredentialOfferDeepLink("haip://?credential_offer=%7B%22issuer%22%3A%22x%22%7D"),
    ).to.match(/^openid-credential-offer:\/\//);
    expect(
      normalizeCredentialOfferDeepLink("haip-vci://?credential_offer=%7B%22issuer%22%3A%22x%22%7D"),
    ).to.match(/^openid-credential-offer:\/\//);
  });
});
