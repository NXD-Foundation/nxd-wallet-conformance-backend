import express from "express";
import { v4 as uuidv4 } from "uuid";
import fs from "node:fs";
import {
  URL_SCHEMES,
  getSignatureType,
  createCodeFlowSession,
  createPreAuthSessionData,
  createCredentialOfferConfig,
  createCodeFlowCredentialOfferResponse,
  createPreAuthCredentialOfferUri,
  generateQRCode,
} from "../../utils/routeUtils.js";
import {
  getCodeFlowSession,
  getPreAuthSession,
  storeCodeFlowSession,
  storePreAuthSession,
} from "../../services/cacheServiceRedis.js";

const router = express.Router();
const PROTOCOL = "openid4vci-v1";
const SCENARIOS = {
  "pid-pre-authorized": { flow: "pre_authorized_code", txCodeRequired: false },
  "pid-pre-authorized-tx-code": { flow: "pre_authorized_code", txCodeRequired: true },
  "pid-authorization-code": { flow: "authorization_code", txCodeRequired: false },
};
const ISSUER_CONFIG = JSON.parse(fs.readFileSync("./data/issuer-config.json", "utf8"));

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

export async function createOfferHandler(req, res) {
  const selected = scenarioConfig(req.body);
  if (!selected) return res.status(400).json({ error: "invalid_request", error_description: "Unknown issuance scenario" });
  const sessionId = uuidv4();
  let selection;
  try { selection = resolveCredentialSelection(req.body); }
  catch (error) { return res.status(400).json({ error: "invalid_request", error_description: error.message }); }
  const credentialType = selection.credentialType;
  const signatureType = getSignatureType({ query: {} });
  try {
    const ttlSeconds = issuanceTtlSeconds(selected.flow);
    let offer;
    let fallback;
    if (selected.flow === "authorization_code") {
      const clientIdScheme = signatureType === "x509" ? "x509_san_dns" : signatureType === "did-web" ? "did:web" : "redirect_uri";
      await storeCodeFlowSession(sessionId, createCodeFlowSession(clientIdScheme, "code", true, false, signatureType, {
        dcApi: true, dcApiScenario: selected.scenario, credentialType,
      }));
      offer = createCredentialOfferConfig(credentialType, sessionId, false, "authorization_code");
      const deepLink = createCodeFlowCredentialOfferResponse(sessionId, credentialType, clientIdScheme, true, URL_SCHEMES.STANDARD);
      fallback = { deepLink, qr: await generateQRCode(deepLink, sessionId) };
    } else {
      const session = createPreAuthSessionData({ signatureType, credentialType, txCodeRequired: selected.txCodeRequired, additionalProps: { dcApi: true, dcApiScenario: selected.scenario } });
      await storePreAuthSession(sessionId, session);
      const endpointPath = selected.txCodeRequired ? "/credential-offer-tx-code" : "/credential-offer-no-code";
      offer = createCredentialOfferConfig(credentialType, sessionId, selected.txCodeRequired);
      const deepLink = createPreAuthCredentialOfferUri(sessionId, credentialType, endpointPath);
      fallback = { deepLink, qr: await generateQRCode(deepLink, sessionId) };
    }
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    res.set("Cache-Control", "no-store").json({
      sessionId, expiresAt, credentialOffer: offer,
      digital: { requests: [{ protocol: PROTOCOL, data: offer }] },
      fallback, statusEndpoint: `/vci/dc-api/session/${encodeURIComponent(sessionId)}`,
    });
  } catch (error) {
    res.status(500).json({ error: "server_error", error_description: error.message });
  }
}

export async function sessionHandler(req, res) {
  try {
    const id = req.params.id;
    const session = await getPreAuthSession(id) || await getCodeFlowSession(id);
    if (!session) return res.status(404).json({ error: "not_found" });
    res.set("Cache-Control", "no-store").json({
      sessionId: id,
      status: session.status || "pending",
      flow: session.flowType || undefined,
      dcApi: session.dcApi === true,
      dcApiScenario: session.dcApiScenario,
    });
  } catch (error) {
    res.status(500).json({ error: "server_error", error_description: error.message });
  }
}

const allowedOrigins = new Set((process.env.DC_API_ISSUER_ORIGINS || process.env.DC_API_DEMO_ORIGINS || "http://localhost:4173").split(",").map((origin) => origin.trim()).filter(Boolean));
router.use((req, res, next) => {
  const origin = req.get("Origin");
  if (origin && allowedOrigins.has(origin)) {
    res.set({ "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "POST, GET, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", Vary: "Origin" });
  }
  if (req.method === "OPTIONS") return origin && allowedOrigins.has(origin) ? res.sendStatus(204) : res.sendStatus(403);
  return next();
});
router.post("/vci/dc-api/offer", createOfferHandler);
router.get("/vci/dc-api/session/:id", sessionHandler);

export { PROTOCOL, SCENARIOS };
export default router;
