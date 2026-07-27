import {
  getSessionLogContext,
  runWithSessionLogContext,
} from "../../../utils/sessionLogContext.js";

const sessionOperationCounters = new Map();
const originalConsole = {
  log: console.log.bind(console),
  warn: console.warn.bind(console),
  error: console.error.bind(console),
};

let appendSessionLogSink = null;
let appendGlobalLogSink = null;
let processHandlersInstalled = false;
let consoleInstalled = false;
let mirroringInProgress = false;

function isPlainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date) &&
    !(value instanceof Error) &&
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

function normalizeArgs(args) {
  const messages = [];
  let data;

  if (args.length > 0 && isPlainObject(args[args.length - 1])) {
    data = args[args.length - 1];
    args = args.slice(0, -1);
  }

  for (const arg of args) {
    if (typeof arg === "string") {
      messages.push(arg);
      continue;
    }
    if (arg instanceof Error) {
      messages.push(arg.stack || arg.message || String(arg));
      continue;
    }
    try {
      messages.push(JSON.stringify(arg));
    } catch {
      messages.push(String(arg));
    }
  }

  return {
    message: messages.join(" "),
    data,
  };
}

function buildLogEntry(level, args, sessionId, context = {}) {
  const { message, data } = normalizeArgs(args);
  const entry = {
    level,
    message,
    timestamp: new Date().toISOString(),
  };

  if (typeof sessionId === "string" && sessionId.length > 0) {
    const currentStep = sessionOperationCounters.get(sessionId) || 0;
    sessionOperationCounters.set(sessionId, currentStep + 1);
    entry.step = currentStep;
  }

  if (typeof data !== "undefined") {
    entry.data = data;
  }
  if (context.domain) entry.domain = context.domain;
  if (context.flow) entry.flow = context.flow;
  if (context.operationId) entry.operationId = context.operationId;

  return entry;
}

function mirrorConsole(level, args) {
  if (mirroringInProgress) return;
  mirroringInProgress = true;
  try {
    const context = getSessionLogContext() || {};
    const sessionId = context.sessionId;
    const entry = buildLogEntry(level, args, sessionId, context);

    if (appendGlobalLogSink) {
      Promise.resolve(appendGlobalLogSink(entry)).catch(() => {});
    }
    if (sessionId && appendSessionLogSink) {
      Promise.resolve(appendSessionLogSink(sessionId, entry)).catch(() => {});
    }
  } finally {
    mirroringInProgress = false;
  }
}

function installConsoleMirroring() {
  if (consoleInstalled) return;
  consoleInstalled = true;

  console.log = (...args) => {
    originalConsole.log(...args);
    mirrorConsole("info", args);
  };
  console.warn = (...args) => {
    originalConsole.warn(...args);
    mirrorConsole("warn", args);
  };
  console.error = (...args) => {
    originalConsole.error(...args);
    mirrorConsole("error", args);
  };
}

export function registerLogSinks({ appendSessionLog, appendGlobalLog } = {}) {
  if (appendSessionLog) appendSessionLogSink = appendSessionLog;
  if (appendGlobalLog) appendGlobalLogSink = appendGlobalLog;
}

export function runWithLogContext(sessionId, fn) {
  if (!sessionId) return fn();
  return runWithSessionLogContext({ sessionId, domain: "wallet" }, fn);
}

export function makeSessionLogger(sessionId) {
  return (...args) => runWithLogContext(sessionId, () => console.log(...args));
}

export function logInfo(sessionId, ...args) {
  return runWithLogContext(sessionId, () => console.log(...args));
}

export function logWarn(sessionId, ...args) {
  return runWithLogContext(sessionId, () => console.warn(...args));
}

export function logError(sessionId, ...args) {
  return runWithLogContext(sessionId, () => console.error(...args));
}

export function installProcessLogHandlers() {
  if (processHandlersInstalled) return;
  processHandlersInstalled = true;

  process.on("unhandledRejection", (reason) => {
    console.error("[process] unhandledRejection:", reason);
  });
  process.on("uncaughtException", (error) => {
    console.error("[process] uncaughtException:", error);
  });
}

installConsoleMirroring();
