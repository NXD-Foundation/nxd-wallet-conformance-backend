import { AsyncLocalStorage } from "node:async_hooks";

const storage = new AsyncLocalStorage();

function normalize(input) {
  if (!input) return null;
  if (typeof input === "string") return { sessionId: input };
  const correlation = input.correlation || input.sessionContext?.correlation || {};
  return {
    sessionId: input.sessionId || input.id || correlation.sessionId || null,
    domain: input.domain || correlation.domain || null,
    flow: input.flow || correlation.flow || null,
    operationId: input.operationId || correlation.operationId || null,
  };
}

export function runWithSessionLogContext(input, fn) {
  const context = normalize(input);
  return context?.sessionId ? storage.run(context, fn) : fn();
}

export function enterSessionLogContext(input) {
  const context = normalize(input);
  if (context?.sessionId) storage.enterWith(context);
}

export function clearSessionLogContext() {
  storage.enterWith(null);
}

export function getSessionLogContext() {
  return storage.getStore() || null;
}
