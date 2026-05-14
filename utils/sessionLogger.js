import { storeSessionLog } from "../services/cacheServiceRedis.js";

// Operation context tracking for better log organization (per session)
const sessionOperationCounters = new Map();

function summarizeHeaders(headers) {
  if (!headers || typeof headers !== "object") return {};
  const out = {};
  const allowList = new Set([
    "content-type",
    "content-length",
    "accept",
    "host",
    "user-agent",
    "authorization",
    "dpop",
    "oauth-client-attestation",
    "oauth-client-attestation-pop",
    "location",
  ]);
  for (const [key, value] of Object.entries(headers)) {
    const normalizedKey = String(key).toLowerCase();
    if (!allowList.has(normalizedKey)) continue;
    const stringValue = Array.isArray(value) ? value.join(",") : String(value);
    if (
      normalizedKey === "authorization" ||
      normalizedKey === "dpop" ||
      normalizedKey === "oauth-client-attestation" ||
      normalizedKey === "oauth-client-attestation-pop"
    ) {
      out[normalizedKey] = summarizeSensitiveString(stringValue);
    } else {
      out[normalizedKey] = summarizeString(stringValue, 160);
    }
  }
  return out;
}

function summarizeSensitiveString(value) {
  if (typeof value !== "string" || !value) return value;
  return {
    present: true,
    length: value.length,
    preview: value.length <= 24 ? value : `${value.slice(0, 12)}...${value.slice(-8)}`,
  };
}

function summarizeString(value, maxLength = 240) {
  if (typeof value !== "string") return value;
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength)}...`;
}

function summarizeBody(body) {
  if (body == null) return { present: false };
  if (typeof body === "string") {
    return {
      present: true,
      kind: "string",
      length: body.length,
      preview: summarizeString(body, 240),
    };
  }
  if (Array.isArray(body)) {
    return {
      present: true,
      kind: "array",
      length: body.length,
      preview: body.slice(0, 3),
    };
  }
  if (typeof body === "object") {
    const preview = {};
    for (const [key, value] of Object.entries(body).slice(0, 12)) {
      if (typeof value === "string") {
        if (
          key.toLowerCase().includes("token") ||
          key.toLowerCase().includes("proof") ||
          key.toLowerCase().includes("jwt") ||
          key.toLowerCase().includes("qr")
        ) {
          preview[key] = summarizeSensitiveString(value);
        } else {
          preview[key] = summarizeString(value, 160);
        }
      } else {
        preview[key] = value;
      }
    }
    return {
      present: true,
      kind: "object",
      keys: Object.keys(body),
      preview,
    };
  }
  return {
    present: true,
    kind: typeof body,
    preview: body,
  };
}

/**
 * Creates an enhanced session logger that provides structured logging
 * with step numbers, categorization, and full request/response data.
 * 
 * @param {string} sessionId - The session ID for this logger
 * @returns {Function} A logger function that accepts (message, data) or (...args)
 * 
 * @example
 * const slog = makeSessionLogger(sessionId);
 * slog("[ISSUANCE] [START] Pre-authorized flow", { configurationId: "..." });
 * slog("[HTTP] [REQUEST] POST token", { url: "...", body: {...} });
 */
export function makeSessionLogger(sessionId) {
  if (!sessionId) {
    return function sessionLog(...args) {
      try { console.log(...args); } catch {}
    };
  }
  
  // Initialize per-session counter if needed
  if (!sessionOperationCounters.has(sessionId)) {
    sessionOperationCounters.set(sessionId, 0);
  }
  
  return function sessionLog(...args) {
    try { console.log(...args); } catch {}
    try {
      // Separate string messages from structured data
      const messages = [];
      let data = null;
      
      // If last arg is a plain object (not null, not array, not Date, etc.), treat it as structured data
      if (args.length > 0) {
        const lastArg = args[args.length - 1];
        if (lastArg && typeof lastArg === 'object' && !Array.isArray(lastArg) && 
            !(lastArg instanceof Date) && !(lastArg instanceof Error) && 
            Object.prototype.toString.call(lastArg) === '[object Object]') {
          // Last argument is structured data
          data = lastArg;
          // Process remaining args as messages
          for (let i = 0; i < args.length - 1; i++) {
            const arg = args[i];
            if (typeof arg === 'string') {
              messages.push(arg);
            } else {
              try { messages.push(JSON.stringify(arg)); } catch { messages.push(String(arg)); }
            }
          }
        } else {
          // No structured data, convert all args to messages
          for (const arg of args) {
            if (typeof arg === 'string') {
              messages.push(arg);
            } else {
              try { messages.push(JSON.stringify(arg)); } catch { messages.push(String(arg)); }
            }
          }
        }
      }
      
      const message = messages.join(' ');
      const counter = sessionOperationCounters.get(sessionId);
      sessionOperationCounters.set(sessionId, counter + 1);
      
      // Determine log level from message prefix
      let level = 'info';
      if (message.includes('[ERROR]') || message.includes('error')) {
        level = 'error';
      } else if (message.includes('[WARN]') || message.includes('warning')) {
        level = 'warn';
      } else if (message.includes('[DEBUG]')) {
        level = 'debug';
      }
      
      // Include step in metadata
      const metadata = { ...(data || {}), step: counter };
      
      storeSessionLog(sessionId, level, message, metadata).catch(() => {});
    } catch {}
  };
}

/**
 * Helper to log HTTP requests with full details
 */
export function logHttpRequest(slog, method, url, headers, body, requestId = null) {
  const reqId = requestId || `req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  slog(`[HTTP] [REQUEST] ${method} ${url}`, {
    event: "http.request",
    phase: inferPhaseFromUrl(url),
    kind: "http",
    requestId: reqId,
    method,
    url,
    headers: summarizeHeaders(headers),
    body: summarizeBody(body),
  });
  return reqId;
}

/**
 * Helper to log HTTP responses with full details
 */
export function logHttpResponse(slog, requestId, url, status, statusText, headers, body) {
  slog(`[HTTP] [RESPONSE] ${url}`, {
    event: "http.response",
    phase: inferPhaseFromUrl(url),
    kind: "http",
    requestId,
    url,
    status,
    statusText,
    headers: summarizeHeaders(headers),
    body: summarizeBody(body),
  });
}

function inferPhaseFromUrl(url = "") {
  const normalized = String(url);
  if (normalized.includes("/vci/offer") || normalized.includes("/offer")) return "offer";
  if (normalized.includes("/par")) return "par";
  if (normalized.includes("/authorize")) return "authorize";
  if (normalized.includes("/token")) return "token";
  if (normalized.includes("/nonce")) return "nonce";
  if (normalized.includes("/credential")) return "credential";
  if (normalized.includes("/logs")) return "internal";
  if (normalized.includes("/vp") || normalized.includes("openid4vp")) return "vp";
  return "internal";
}
