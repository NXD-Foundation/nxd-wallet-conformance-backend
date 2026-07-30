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
  isValidSessionId,
  sendErrorResponse,
} from "../utils/routeUtils.js";

/**
 * Multi-credential offer helpers (RFC001 / OID4VCI 1.0 aligned).
 *
 * IMPORTANT — These endpoints are NOT a "Batch Credential Endpoint".
 *   OID4VCI 1.0 removed the separate `batch_credential_endpoint` (draft-14)
 *   and RFC001 is constrained to OID4VCI 1.0. When a Credential Offer lists
 *   multiple `credential_configuration_ids`, the wallet obtains each
 *   credential through consecutive standard `POST /credential` requests.
 *   A single `/credential` response may still contain multiple credentials
 *   only when they share the same configuration and dataset (multi-key batch).
 *
 * What this router does:
 *   - Produces a credential offer that advertises more than one
 *     `credential_configuration_ids` entry. The wallet then uses the standard
 *     `/credential` endpoint once per offered configuration.
 *
 * Dynamic offers created via `POST /offer-no-code-batch` store the offered
 * configuration ids in the pre-auth session. Legacy GET `/offer-no-code-batch`
 * keeps a hard-coded fallback when no session state is present.
 */

const multiCredentialOfferRouter = express.Router();

const serverURL = process.env.SERVER_URL || "http://localhost:3000";

const LEGACY_BATCH_CONFIGURATION_IDS = [
  "urn:eu.europa.ec.eudi:pid:1",
  "PhotoID",
];

const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************

/**
 * Pre-authorised flow — credential offer advertising multiple credentials.
 * Legacy GET entrypoint; prefer `POST /offer-no-code-batch` for dynamic ids.
 */
multiCredentialOfferRouter.get(["/offer-no-code-batch"], async (req, res) => {
  const uuid = req.query.sessionId ? req.query.sessionId : uuidv4();
  const credentialType = req.query.credentialType
    ? req.query.credentialType
    : "CombinedCredentials";
  const signatureType = req.query.signatureType || undefined;

  let existingPreAuthSession = await getPreAuthSession(uuid);
  if (!existingPreAuthSession) {
    storePreAuthSession(uuid, {
      status: "pending",
      resulut: null,
      persona: null,
      accessToken: null,
      flowType: "pre-auth",
      ...(signatureType ? { signatureType } : {}),
    });
  }
  let encodedCredentialOfferUri = encodeURIComponent(
    `${serverURL}/credential-offer-no-code-batch/${uuid}?type=${credentialType}`,
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
 * multiple `credential_configuration_ids`.
 */
multiCredentialOfferRouter.get(
  ["/credential-offer-no-code-batch/:id"],
  async (req, res) => {
    const sessionId = req.params.id;

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(
        res,
        "invalid_request",
        "Invalid session ID",
        400,
      );
    }

    const sessionData = await getPreAuthSession(sessionId);
    const multiIds =
      Array.isArray(sessionData?.offeredConfigurationIds) &&
      sessionData.offeredConfigurationIds.length > 0
        ? sessionData.offeredConfigurationIds
        : LEGACY_BATCH_CONFIGURATION_IDS;

    const config = createCredentialOfferConfig(
      multiIds,
      sessionId,
      false,
      "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    );
    res.json(config);
  },
);

export default multiCredentialOfferRouter;
