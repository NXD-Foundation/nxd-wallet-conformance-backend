import fetch from "node-fetch";
import { createDPoP } from "./crypto.js";
import { isDpopBoundAccessToken, computeAthForDpop } from "../../utils/tokenUtils.js";

/**
 * OIDC4VCI credential response may include `notification_id` at the top level.
 */
export function extractNotificationId(credentialResponse) {
  if (!credentialResponse || typeof credentialResponse !== "object" || Array.isArray(credentialResponse)) {
    return undefined;
  }
  const id = credentialResponse.notification_id;
  if (id === undefined || id === null) return undefined;
  return String(id);
}

/**
 * Prefer issuer metadata `notification_endpoint`; otherwise default under `apiBase`.
 */
export function resolveNotificationEndpoint(issuerMeta, apiBase) {
  const ep = issuerMeta?.notification_endpoint;
  if (typeof ep === "string" && ep.length > 0) return ep;
  const base = String(apiBase || "").replace(/\/$/, "");
  return `${base}/notification`;
}

/**
 * POST { notification_id, event: "credential_accepted" } to the issuer notification endpoint.
 * Retries once on 5xx. Logs 4xx and other failures; does not throw (wallet-side event only).
 */
export async function postCredentialAcceptedNotification({
  notificationEndpoint,
  notificationId,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
}) {
  if (!notificationEndpoint || !notificationId || !accessToken) return;

  const body = JSON.stringify({
    notification_id: notificationId,
    event: "credential_accepted",
  });

  let dpopJwt = null;
  try {
    if (
      dpopPrivateJwk &&
      dpopPublicJwk &&
      isDpopBoundAccessToken(tokenBody, accessToken)
    ) {
      dpopJwt = await createDPoP({
        privateJwk: dpopPrivateJwk,
        publicJwk: dpopPublicJwk,
        htu: notificationEndpoint,
        htm: "POST",
        ath: computeAthForDpop(accessToken),
        alg: "ES256",
      });
    }
  } catch (e) {
    console.warn("[credential-notification] DPoP for /notification failed:", e?.message);
  }

  const headers = {
    "content-type": "application/json",
    Authorization: `Bearer ${accessToken}`,
    ...(dpopJwt ? { DPoP: dpopJwt } : {}),
  };

  async function attempt() {
    return fetch(notificationEndpoint, { method: "POST", headers, body });
  }

  try {
    let res = await attempt();
    if (res.status >= 500 && res.status < 600) {
      console.warn("[credential-notification] server error", res.status, ", retrying once");
      await new Promise((r) => setTimeout(r, 250));
      res = await attempt();
    }
    if (res.status >= 400 && res.status < 500) {
      const t = await res.text().catch(() => "");
      console.warn("[credential-notification] client error", res.status, t.slice(0, 400));
      return;
    }
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      console.warn("[credential-notification] notification failed", res.status, t.slice(0, 400));
      return;
    }
    console.log("[credential-notification] posted credential_accepted for", notificationId);
  } catch (err) {
    console.warn("[credential-notification] request error:", err?.message || err);
  }
}
