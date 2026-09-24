import { walletRedisClient } from "./cache.js";
import { createWalletContext } from "../../../utils/sessionContext.js";

const PENDING_PREFIX = "wallet:oauth-pending:";
const SESSION_PREFIX = "wallet:test-session:";

function sessionTtlSeconds(env = process.env) {
  const parsed = parseInt(env.WALLET_TEST_SESSION_TTL || "86400", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 86400;
}

export function pendingKeyForState(state) {
  return `${PENDING_PREFIX}${state}`;
}

export function sessionKeyForId(sessionId) {
  return `${SESSION_PREFIX}${sessionId}`;
}

export async function savePendingAuthorization({
  sessionId,
  state,
  pendingContext,
  authorizationUrl,
  expiresAt,
  ttlSeconds,
  trustFrameworkSessionProps = {},
  previousSession = null,
}) {
  const pendingPayload = {
    sessionId,
    state,
    authorizationUrl,
    expiresAt,
    consumed: false,
    pendingContext,
  };
  await walletRedisClient.setEx(
    pendingKeyForState(state),
    ttlSeconds,
    JSON.stringify(pendingPayload),
  );

  const legacySession = {
    sessionId,
    status: "AUTHORIZATION_REQUIRED",
    authorizationUrl,
    expiresAt,
    ...(trustFrameworkSessionProps || {}),
    updatedAt: new Date().toISOString(),
  };
  const payload = createWalletContext({
    sessionContext: previousSession?.sessionContext,
    id: sessionId,
    flow: "issuance",
    status: "AUTHORIZATION_REQUIRED",
    trustPolicy: legacySession.trustPolicy ?? previousSession?.trustPolicy,
  })
    .withWalletSession(legacySession)
    .toSession(legacySession);

  await walletRedisClient.setEx(
    sessionKeyForId(sessionId),
    sessionTtlSeconds(),
    JSON.stringify(payload),
  );
  return payload;
}

export async function consumePendingByState(state) {
  const key = pendingKeyForState(state);
  const raw = await walletRedisClient.getDel(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function getWalletTestSession(sessionId) {
  const raw = await walletRedisClient.get(sessionKeyForId(sessionId));
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function updateWalletTestSession(sessionId, status, extra = {}, previous = null) {
  let existing = previous;
  if (!existing) {
    existing = await getWalletTestSession(sessionId);
  }
  const legacySession = {
    ...(existing || {}),
    sessionId,
    status,
    ...(extra || {}),
    updatedAt: new Date().toISOString(),
  };
  delete legacySession.sessionContext;

  const payload = createWalletContext({
    sessionContext: existing?.sessionContext,
    id: sessionId,
    flow: existing?.sessionContext?.flow || "issuance",
    status,
    trustPolicy: legacySession.trustPolicy ?? existing?.trustPolicy,
  })
    .withWalletSession(legacySession)
    .toSession(legacySession);

  await walletRedisClient.setEx(
    sessionKeyForId(sessionId),
    sessionTtlSeconds(),
    JSON.stringify(payload),
  );
  return payload;
}

export function renderCallbackHtml({ success, title, message }) {
  const safeTitle = String(title || (success ? "Authentication complete" : "Authentication failed"));
  const safeMessage = String(
    message || (success ? "You can close this tab and return to the test." : "Please return to the test for details."),
  );
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(safeTitle)}</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; }
    .ok { color: #0a6; }
    .err { color: #b00; }
  </style>
</head>
<body>
  <h1 class="${success ? "ok" : "err"}">${escapeHtml(safeTitle)}</h1>
  <p>${escapeHtml(safeMessage)}</p>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function issuersMatch(expectedIssuer, callbackIss) {
  if (!callbackIss) return true;
  if (!expectedIssuer) return false;
  try {
    const expected = new URL(expectedIssuer);
    const actual = new URL(callbackIss);
    return expected.origin === actual.origin;
  } catch {
    return String(expectedIssuer).replace(/\/$/, "") === String(callbackIss).replace(/\/$/, "");
  }
}
