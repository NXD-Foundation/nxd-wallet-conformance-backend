import { calculateJwkThumbprint } from "jose";
import { createDPoP } from "./crypto.js";

/** Serializable, transaction-local state; AS and resource nonces never overlap. */
export function createDpopNonceState() {
  return { nonces: {}, authorizationServer: null, resourceServer: null };
}

function isValidNonce(nonce) {
  return typeof nonce === "string" && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(nonce);
}

function responseNonce(headers) {
  if ((headers?.raw?.()["dpop-nonce"]?.length || 0) > 1) return null;
  return headers?.get?.("dpop-nonce");
}

async function scopeFor(state, namespace, url, publicJwk) {
  const server = namespace === "as" ? state.authorizationServer : state.resourceServer;
  const key = publicJwk ? await calculateJwkThumbprint(publicJwk) : "unbound";
  return JSON.stringify([namespace, server || new URL(url).origin, key]);
}

export async function captureDpopNonce({ state, namespace = "resource", url, publicJwk, headers }) {
  const nonce = responseNonce(headers);
  if (isValidNonce(nonce)) {
    state.nonces[await scopeFor(state, namespace, url, publicJwk)] = nonce;
  }
}

// Split challenges/parameters only at commas outside quoted strings.
export function isDpopNonceChallenge(value = "") {
  if (typeof value !== "string") return false;
  const parts = value.match(/(?:[^," ]| +|"(?:\\.|[^"\\])*")+/g) || [];
  let scheme = null;
  for (const part of parts) {
    let parameter = part.trim();
    const start = parameter.match(/^([A-Za-z][A-Za-z0-9_-]*)\s+(.+)$/);
    if (start && !start[2].startsWith("=")) {
      scheme = start[1].toLowerCase();
      parameter = start[2];
    } else if (/^[A-Za-z][A-Za-z0-9_-]*$/.test(parameter)) {
      scheme = parameter.toLowerCase();
    }
    if (scheme === "dpop" && /^error\s*=\s*(?:"use_dpop_nonce"|use_dpop_nonce)$/i.test(parameter)) return true;
  }
  return false;
}

/** Replay only explicit nonce challenges, generating a fresh proof for every send. */
export async function requestWithDpopNonce({
  url, namespace = "resource", state = createDpopNonceState(),
  privateJwk, publicJwk, ath = null, alg = "ES256", htm = "POST",
  enabled = Boolean(privateJwk && publicJwk), signer = createDPoP,
  send, log = () => {}, budget = { sends: 0, nonceRetries: 0 },
}) {
  if (enabled && (!privateJwk || !publicJwk)) throw new Error("dpop_nonce_error: DPoP binding key material is missing");
  const scope = await scopeFor(state, namespace, url, publicJwk);
  while (true) {
    if (budget.sends >= 5) throw new Error("dpop_nonce_error: request retry budget exhausted");
    const proof = enabled ? await signer({
      privateJwk, publicJwk, htu: url, htm, ath, alg, nonce: state.nonces[scope],
    }) : null;
    budget.sends++;
    const response = await send(proof);
    await captureDpopNonce({ state, namespace, url, publicJwk, headers: response.headers });
    if (response.ok) return response;
    let body = null;
    const headerChallenge = response.status === 401 && isDpopNonceChallenge(response.headers?.get?.("www-authenticate"));
    if (!headerChallenge && (response.status === 400 || response.status === 401)) {
      // Real HTTP responses are cloned so callers can still consume their bodies.
      const text = response._responseText ?? response.bodyText ?? await (response.clone ? response.clone() : response).text().catch(() => "");
      try { body = JSON.parse(text); } catch {}
    }
    const challenged = namespace === "as"
      ? response.status === 400 && body?.error === "use_dpop_nonce"
      : headerChallenge || (response.status === 401 && body?.error === "use_dpop_nonce");
    if (!challenged) return response;
    if (!enabled || !privateJwk || !publicJwk) throw new Error("dpop_nonce_error: challenge without a DPoP binding");
    const nonce = responseNonce(response.headers);
    if (!isValidNonce(nonce)) throw new Error("dpop_nonce_error: challenge missing a valid DPoP-Nonce header");
    if (budget.nonceRetries >= 2) throw new Error("dpop_nonce_error: nonce retries exhausted");
    budget.nonceRetries++;
    log("DPoP nonce retry", { stage: new URL(url).pathname, namespace, status: response.status, noncePresent: true, retry: budget.nonceRetries });
    // Release rejected response streams without consuming the returned response.
    if (response.body?.destroy) response.body.destroy();
  }
}
