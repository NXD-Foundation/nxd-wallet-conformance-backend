import { expect } from "chai";
import {
  assertAuthorizationDetailsSupportForCredentialRequest,
} from "../wallet-client/src/lib/scopeResolution.js";

describe("scope-less credential authorization", () => {
  it("requires advertised openid_credential authorization details support", () => {
    const request = {
      configurationId: "pid",
      issuerMeta: { credential_configurations_supported: { pid: {} } },
    };
    expect(() => assertAuthorizationDetailsSupportForCredentialRequest(request)).to.throw(
      /issuer_metadata_incomplete[\s\S]*authorization_details_types_supported/i,
    );
    expect(() => assertAuthorizationDetailsSupportForCredentialRequest({
      ...request,
      authorizationServerMeta: {
        authorization_details_types_supported: ["openid_credential"],
      },
    })).to.not.throw();
  });
});
