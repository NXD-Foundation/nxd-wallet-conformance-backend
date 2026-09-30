import express from "express";
import { v4 as uuidv4 } from "uuid";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import {
  URL_SCHEMES,
  getSignatureType,
  createCodeFlowSession,
  createPreAuthSessionData,
  createCredentialOfferConfig,
  generateQRCode,
} from "../../utils/routeUtils.js";
import {
  getCodeFlowSession,
  getPreAuthSession,
  storeCodeFlowSession,
  storePreAuthSession,
} from "../../services/cacheServiceRedis.js";
import { issuanceSessionProps } from "../../utils/trustFrameworkPolicy.js";
import { offeredCredentialConfigurationIds } from "../../utils/dcApiIssuance.js";
import { getDcApiIssuanceProgress } from "../../services/cacheServiceRedis.js";

const router = express.Router();
const PROTOCOL = "openid4vci-v1";
const SCENARIOS = {
  "pid-pre-authorized": { flow: "pre_authorized_code", txCodeRequired: false },
  "pid-pre-authorized-tx-code": { flow: "pre_authorized_code", txCodeRequired: true },
  "pid-authorization-code": { flow: "authorization_code", txCodeRequired: false },
};
const ISSUER_CONFIG = JSON.parse(fs.readFileSync("./data/issuer-config.json", "utf8"));
const PAYLOAD_MAX_BYTES = 32 * 1024;
const OFFER_MAX_BYTES = 100 * 1024;
const RESERVED_CLAIMS = new Set(["iss", "iat", "nbf", "exp", "vct", "cnf", "status", "status_reference", "_sd", "_sd_alg", "credentialSubject", "@context", "type", "issuer", "validFrom", "validUntil"]);
const SD_JWT_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt"]);
const CALLER_PAYLOAD_CONFIGURATIONS = new Set([
  "VerifiablePIDSDJWT", "VerifiablePIDSDJWTAttestation", "VerifiablePIDSDJWTWUA",
  "VerifiableePassportCredentialSDJWT", "VerifiableStudentIDSDJWT",
  "VerifiableFerryBoardingPassCredentialSDJWT", "ferryBoardingPassCredential",
  "VerifiablePortableDocumentA1SDJWT", "VerifiablePortableDocumentA2SDJWT",
  "VerifiablevReceiptSDJWT", "LoyaltyCard",
  "eu.europa.ec.eudi.photoid.1", "PhotoID", "eu.europa.ec.eudi.pcd.1",
  "urn:eu.europa.ec.eudi:pid:1", "urn:eudi:pid:1", "urn:eudi:pid:lsp:1", "test-cred-config",
]);

function validateJsonValue(value, depth = 0) {
  if (depth > 16) throw new Error("Credential payload nesting exceeds 16 levels");
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error("Credential payload numbers must be finite"); return; }
  if (Array.isArray(value)) { for (const child of value) validateJsonValue(child, depth + 1); return; }
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("Credential payload must contain only JSON values");
  for (const child of Object.values(value)) validateJsonValue(child, depth + 1);
}

export function resolveCredentials(body = {}) {
  const supported = ISSUER_CONFIG.credential_configurations_supported || {};
  if (Object.hasOwn(body, "credentials") && !Array.isArray(body.credentials)) {
    throw new Error("credentials must be an array");
  }
  if (Array.isArray(body.credentials)) {
    if (!body.credentials.length || body.credentials.length > 16) throw new Error("credentials must contain between 1 and 16 entries");
    if (body.credentialType || body.credentialFormat) throw new Error("credentials cannot be combined with credentialType or credentialFormat");
    const seen = new Set();
    return body.credentials.map((entry) => {
      const id = entry?.credential_configuration_id;
      const config = supported[id];
      if (typeof id !== "string" || !config || seen.has(id)) throw new Error(`Unknown or duplicate credential configuration: ${id}`);
      seen.add(id);
      if (!SD_JWT_FORMATS.has(config.format) || !CALLER_PAYLOAD_CONFIGURATIONS.has(id)) throw new Error(`Caller payloads are supported only for credential configurations with SD-JWT generation support: ${id}`);
      const payload = entry.payload;
      if (!payload || typeof payload !== "object" || Array.isArray(payload) || Object.keys(payload).length === 0 || Object.getPrototypeOf(payload) !== Object.prototype) throw new Error(`Payload for ${id} must be a non-empty JSON object`);
      validateJsonValue(payload);
      const payloadBytes = Buffer.byteLength(JSON.stringify(payload));
      if (payloadBytes > PAYLOAD_MAX_BYTES) throw new Error(`Payload for ${id} exceeds 32 KiB`);
      const forbidden = Object.keys(payload).filter((key) => RESERVED_CLAIMS.has(key));
      if (forbidden.length) throw new Error(`Payload for ${id} contains issuer-owned claims: ${forbidden.join(", ")}`);
      return { id, payload };
    });
  }
  const selected = resolveCredentialSelection(body);
  return [{ id: selected.credentialType, payload: null }];
}

export function resolveCredentialSelection(body = {}) {
  const credentialType = body.credentialType || "VerifiablePortableDocumentA2SDJWT";
  const supported = ISSUER_CONFIG.credential_configurations_supported || {};
  const configurationId = supported[credentialType] ? credentialType : Object.keys(supported).find((id) => supported[id]?.vct === credentialType);
  const config = configurationId ? supported[configurationId] : null;
  if (!config) throw new Error(`Unsupported credential configuration: ${credentialType}`);
  const requestedFormat = body.credentialFormat;
  if (requestedFormat && ![config.format, config.format === "dc+sd-jwt" ? "sd-jwt" : undefined].includes(requestedFormat)) {
    throw new Error(`Credential format ${requestedFormat} is incompatible with ${credentialType}`);
  }
  return { credentialType: configurationId, credentialFormat: config.format };
}

export function issuanceTtlSeconds(flow) {
  const raw = flow === "authorization_code" ? process.env.VCI_CODE_FLOW_TIMEOUT : process.env.VCI_PRE_AUTH_TIMEOUT;
  if (raw == null || raw === "") return 180;
  const ttl = Number(raw);
  if (!Number.isSafeInteger(ttl) || ttl <= 0) throw new Error("Issuance session TTL must be a positive integer");
  return ttl;
}

function scenarioConfig(body) {
  const scenario = body?.scenario || "pid-pre-authorized";
  const selected = SCENARIOS[scenario];
  if (!selected) return null;
  return { scenario, ...selected };
}

function removeCallerPayloadsFromOffer(offer) {
  delete offer.credentialPayload;
  delete offer.credentialPayloads;
  return offer;
}

export async function createOfferHandler(req, res, dependencies = {}) {
  if (Buffer.byteLength(JSON.stringify(req.body || {})) > OFFER_MAX_BYTES) return res.status(413).json({ error: "invalid_request", error_description: "Request body exceeds 100 KiB" });
  const selected = scenarioConfig(req.body);
  if (!selected) return res.status(400).json({ error: "invalid_request", error_description: "Unknown issuance scenario" });
  const sessionId = uuidv4();
  let credentials;
  try { credentials = resolveCredentials(req.body); }
  catch (error) { return res.status(400).json({ error: "invalid_request", error_description: error.message }); }
  const credentialType = credentials[0].id;
  const credentialIds = credentials.map(({ id }) => id);
  const requestedSignatureType = req.body?.signatureType || getSignatureType({ query: {} });
  const signatureType = requestedSignatureType === "did-web" ? "did:web" : requestedSignatureType;
  if (!["x509", "did:web", "did:jwk", "kid-jwk", "jwk", "jwt"].includes(signatureType)) return res.status(400).json({ error: "invalid_request", error_description: "Unsupported signatureType" });
  let issuanceProps;
  try {
    issuanceProps = issuanceSessionProps({ ...(req.query || {}), ...(req.body || {}) });
  } catch (error) {
    return res.status(400).json({ error: "invalid_request", error_description: error.message });
  }
  try {
    const persistPreAuth = dependencies.storePreAuthSession || storePreAuthSession;
    const persistCode = dependencies.storeCodeFlowSession || storeCodeFlowSession;
    const readPreAuth = dependencies.getPreAuthSession || getPreAuthSession;
    const readCode = dependencies.getCodeFlowSession || getCodeFlowSession;
    const ttlSeconds = issuanceTtlSeconds(selected.flow);
    const statusToken = randomBytes(32).toString("base64url");
    const statusTokenHash = createHash("sha256").update(statusToken).digest("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    const issuanceData = {
      dcApi: true,
      dcApiScenario: selected.scenario,
      credentialType,
      requestedCredentialConfigurationIds: credentialIds,
      credentialPayloads: Object.fromEntries(credentials.filter(({ payload }) => payload).map(({ id, payload }) => [id, payload])),
      ...(credentials[0].payload && credentials.length === 1 ? { credentialPayload: credentials[0].payload } : {}),
      dcApiState: { expiresAt, statusToken, statusTokenHash, credentialConfigurationIds: credentialIds, issuedCredentialConfigurationIds: [], notifications: {} },
      ...issuanceProps,
    };
    let offer;
    let fallback;
    if (selected.flow === "authorization_code") {
      const clientIdScheme = signatureType === "x509" ? "x509_san_dns" : signatureType === "did:web" ? "did:web" : "redirect_uri";
      const session = createCodeFlowSession(clientIdScheme, "code", true, false, signatureType, issuanceData);
      await persistCode(sessionId, session);
      if (!await readCode(sessionId)) { const error = new Error("Unable to persist issuance session"); error.status = 503; throw error; }
      offer = createCredentialOfferConfig(credentialType, sessionId, false, "authorization_code");
      if (credentialIds.length > 1) delete offer.grants.authorization_code.scope;
      const offerUrl = `${process.env.SERVER_URL || "http://localhost:3000"}/vci/dc-api/offer/${sessionId}`;
      const deepLink = `${URL_SCHEMES.STANDARD}?credential_offer_uri=${encodeURIComponent(offerUrl)}`;
      fallback = { deepLink, qr: await generateQRCode(deepLink, sessionId) };
    } else {
      const session = createPreAuthSessionData({ signatureType, credentialType, txCodeRequired: selected.txCodeRequired, additionalProps: issuanceData });
      session.requestedCredentialConfigurationIds = credentialIds;
      await persistPreAuth(sessionId, session);
      if (!await readPreAuth(sessionId)) { const error = new Error("Unable to persist issuance session"); error.status = 503; throw error; }
      const endpointPath = "/vci/dc-api/offer";
      offer = createCredentialOfferConfig(credentialType, sessionId, selected.txCodeRequired);
      offer.credential_configuration_ids = credentialIds;
      const offerUrl = `${process.env.SERVER_URL || "http://localhost:3000"}${endpointPath}/${sessionId}`;
      const deepLink = `${URL_SCHEMES.STANDARD}?credential_offer_uri=${encodeURIComponent(offerUrl)}`;
      fallback = { deepLink, qr: await generateQRCode(deepLink, sessionId) };
    }
    removeCallerPayloadsFromOffer(offer);
    offer.credential_configuration_ids = credentialIds;
    const statusEndpoint = `/vci/dc-api/session/${encodeURIComponent(sessionId)}`;
    offer.statusEndpoint = statusEndpoint;
    offer.statusToken = statusToken;
    res.set("Cache-Control", "no-store").json({
      sessionId, expiresAt, credentialOffer: offer,
      digital: { requests: [{ protocol: PROTOCOL, data: offer }] },
      fallback, statusEndpoint, statusToken,
      ...(selected.txCodeRequired ? { transactionCode: (await readPreAuth(sessionId)).expectedTxCode } : {}),
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.status === 503 ? "temporarily_unavailable" : "server_error", error_description: error.message });
  }
}

export async function sessionHandler(req, res, dependencies = {}) {
  try {
    const id = req.params.id;
    const readPreAuth = dependencies.getPreAuthSession || getPreAuthSession;
    const readCode = dependencies.getCodeFlowSession || getCodeFlowSession;
    const session = await readPreAuth(id) || await readCode(id);
    if (!session || session.dcApi !== true || !session.dcApiState) return res.status(404).json({ error: "not_found" });
    const presented = String(req.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const presentedHash = createHash("sha256").update(presented).digest();
    const expectedHash = Buffer.from(session.dcApiState.statusTokenHash, "hex");
    if (!presented || presentedHash.length !== expectedHash.length || !timingSafeEqual(presentedHash, expectedHash)) return res.status(401).json({ error: "unauthorized" });
    if (Number(session.dcApiState.expiresAt || 0) <= Math.floor(Date.now() / 1000)) return res.status(410).json({ error: "expired" });
    const flowType = session.flowType === "code" ? "code" : "pre-auth";
    const readProgress = dependencies.getDcApiIssuanceProgress || getDcApiIssuanceProgress;
    const progress = await readProgress(id, flowType);
    const selected = offeredCredentialConfigurationIds(session);
    const issued = progress.issuedCredentialConfigurationIds.length ? progress.issuedCredentialConfigurationIds : (session.dcApiState.issuedCredentialConfigurationIds || []);
    const status = progress.status === "failed" || session.status === "failed" ? "failed" : issued.length >= selected.length ? "issued" : issued.length ? "partial" : "pending";
    res.set("Cache-Control", "no-store").json({
      sessionId: id,
      status,
      expiresAt: session.dcApiState.expiresAt,
      credentialConfigurationIds: selected,
      issuedCredentialConfigurationIds: issued,
      notifications: Object.fromEntries(Object.entries({ ...(session.dcApiState.notifications || {}), ...progress.notifications }).map(([notificationId, entry]) => [notificationId, { credentialConfigurationId: entry.credentialConfigurationId, event: entry.event }])),
      flow: session.flowType || undefined,
      dcApi: session.dcApi === true,
      dcApiScenario: session.dcApiScenario,
    });
  } catch (error) {
    res.status(500).json({ error: "server_error", error_description: error.message });
  }
}

const allowedOrigins = new Set((process.env.DC_API_ISSUER_ORIGINS || process.env.DC_API_DEMO_ORIGINS || "http://localhost:4173").split(",").map((origin) => origin.trim()).filter(Boolean));
router.use("/vci/dc-api", (req, res, next) => {
  const origin = req.get("Origin");
  const ownOrigin = (() => { try { return new URL(process.env.SERVER_URL || "http://localhost:3000").origin; } catch { return ""; } })();
  const permitted = origin && (origin === ownOrigin || allowedOrigins.has(origin));
  if (permitted) {
    res.set({ "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "POST, GET, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", Vary: "Origin" });
  }
  if (req.method === "OPTIONS") return permitted ? res.sendStatus(204) : res.sendStatus(403);
  if (origin && !permitted) return res.status(403).json({ error: "origin_not_allowed" });
  return next();
});
router.post("/vci/dc-api/offer", createOfferHandler);
router.get("/vci/dc-api/session/:id", sessionHandler);
export async function credentialOfferHandler(req, res, dependencies = {}) {
  try {
    const readPreAuth = dependencies.getPreAuthSession || getPreAuthSession;
    const readCode = dependencies.getCodeFlowSession || getCodeFlowSession;
    const session = await readPreAuth(req.params.id) || await readCode(req.params.id);
    if (!session || session.dcApi !== true || Number(session.dcApiState?.expiresAt || 0) <= Math.floor(Date.now() / 1000)) return res.status(404).json({ error: "not_found" });
    const grant = session.flowType === "code" ? "authorization_code" : "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    const offer = createCredentialOfferConfig(session.credentialType, req.params.id, session.txCodeRequired === true, grant);
    removeCallerPayloadsFromOffer(offer);
    const credentialIds = offeredCredentialConfigurationIds(session);
    offer.credential_configuration_ids = credentialIds;
    if (grant === "authorization_code" && credentialIds.length > 1) delete offer.grants.authorization_code.scope;
    offer.statusEndpoint = `/vci/dc-api/session/${encodeURIComponent(req.params.id)}`;
    offer.statusToken = session.dcApiState.statusToken;
    res.set("Cache-Control", "no-store").json(offer);
  } catch (error) { res.status(500).json({ error: "server_error", error_description: error.message }); }
}
router.get("/vci/dc-api/offer/:id", credentialOfferHandler);

export { PROTOCOL, SCENARIOS };
export default router;
