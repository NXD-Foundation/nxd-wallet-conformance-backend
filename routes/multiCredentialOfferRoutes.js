import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";

import {
  storePreAuthSession,
  getPreAuthSession,
} from "../services/cacheServiceRedis.js";

import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import {
  getCredentialOfferSchemeFromRequest,
  createCredentialOfferConfig,
} from "../utils/routeUtils.js";

/**
 * Multi-credential offer helpers (RFC001 / OID4VCI 1.0 aligned).
 *
 * IMPORTANT — These endpoints are NOT a "Batch Credential Endpoint".
 *   OID4VCI 1.0 removed the separate `batch_credential_endpoint` (draft-14)
 *   and RFC001 is constrained to OID4VCI 1.0. Multi-credential issuance is
 *   performed against the standard `POST /credential` endpoint by sending
 *   multiple `proofs.jwt[]` entries together with a `credential_configuration_id`
 *   or `credential_identifier`. See OID4VCI 1.0 §7 "Credential Request"
 *   ("proofs" object) and RFC001 §7.5.
 *
 * What this router does:
 *   - Produces a **credential offer** that advertises more than one
 *     `credential_configuration_ids` entry. This is fully spec-aligned (the
 *     Credential Offer may list multiple configuration ids). The wallet will
 *     then use the standard /credential endpoint to request each credential.
 *
 * Paths are kept stable (`/offer-no-code-batch`, `/credential-offer-no-code-batch/:id`)
 * for backwards compatibility with existing test harnesses (`testCaseRequests.yml`)
 * and wallet fixtures. The naming of this module/router was renamed from
 * `batchRequestRoutes` to avoid suggesting a non-existent RFC001 batch endpoint.
 */

const multiCredentialOfferRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************

/**
 * Pre-authorised flow — credential offer advertising multiple credentials.
 * RFC001 / OID4VCI 1.0: the wallet will subsequently use POST /credential
 * with `proofs.jwt[]` to obtain each credential.
 */
multiCredentialOfferRouter.get(["/offer-no-code-batch"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "CombinedCredentials";

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      flowType: "pre-auth",
    });
  }
  let encodedCredentialOfferUri = encodeURIComponent(
    `${serverURL}/credential-offer-no-code-batch/${uuid}?type=${credentialType}`
  );
  const scheme = getCredentialOfferSchemeFromRequest(req);
  let credentialOffer = `${scheme}?credential_offer_uri=${encodedCredentialOfferUri}`;
  let code = qr.image(credentialOffer, {
    type: "png",
    ec_level: "H",
    size: 10,
    margin: 10,
  });
  let mediaType = "PNG";
  let encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
  res.json({
    qr: encodedQR,
    deepLink: credentialOffer,
    sessionId: uuid,
  });
});

/**
 * Pre-authorised flow — credential offer document (by reference), listing
 * multiple `credential_configuration_ids`. Spec-aligned: the Credential Offer
 * document allows multiple entries in `credential_configuration_ids`.
 */
multiCredentialOfferRouter.get(
  ["/credential-offer-no-code-batch/:id"],
  (req, res) => {
    const multiIds = ["urn:eu.europa.ec.eudi:pid:1", "PhotoID"];
    const config = createCredentialOfferConfig(
      multiIds,
      req.params.id,
      false,
      "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    );
    res.json(config);
  }
);

export default multiCredentialOfferRouter;
