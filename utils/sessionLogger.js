import { storeSessionLog } from "../services/cacheServiceRedis.js";

// Operation context tracking for better log organization (per session)
const sessionOperationCounters = new Map();

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
      const metadata = data || {};
      metadata.step = counter;
      
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
    requestId: reqId,
    method,
    url,
    headers: headers || {},
    body: body || {}
  });
  return reqId;
}

/**
 * Helper to log HTTP responses with full details
 */
export function logHttpResponse(slog, requestId, url, status, statusText, headers, body) {
  slog(`[HTTP] [RESPONSE] ${url}`, {
    requestId,
    url,
    status,
    statusText,
    headers: headers || {},
    body: body || {}
  });
}
