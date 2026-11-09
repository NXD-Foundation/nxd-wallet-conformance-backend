import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import net from "node:net";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CASES,
  caseRequest,
  checkInvocationLink,
  classifyWalletFailure,
  judgeIssueStatus,
  judgeVerificationStatus,
  walletSessionBody,
} from "./preShipItbCases.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CASE_TIMEOUT_MS = 180_000;
const children = [];

function selectedCases() {
  const arg = process.argv.find((item) => item.startsWith("--case="));
  const raw = arg ? arg.slice("--case=".length) : process.env.PRE_SHIP_CASES;
  if (!raw) return CASES;
  const ids = raw.split(",").map((id) => id.trim()).filter(Boolean);
  const selected = CASES.filter((entry) => ids.includes(entry.id));
  const missing = ids.filter((id) => !CASES.some((entry) => entry.id === id));
  if (missing.length > 0 || selected.length === 0) {
    throw new Error(`Unknown case ${missing.join(", ") || raw}. Known cases: ${CASES.map((entry) => entry.id).join(", ")}`);
  }
  return selected;
}

function portOpen(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    const done = (open) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(open);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

async function readJson(response) {
  const text = await response.text();
  if (text.trimStart().startsWith("<")) {
    throw new Error(`HTML response from ${response.url}; the tunnel returned a browser page instead of JSON`);
  }
  return text ? JSON.parse(text) : {};
}

async function requestJson(url, options = {}) {
  const { timeoutMs = CASE_TIMEOUT_MS, ...fetchOptions } = options;
  const response = await fetch(url, {
    ...fetchOptions,
    headers: {
      accept: "application/json",
      "ngrok-skip-browser-warning": "true",
      ...(fetchOptions.headers || {}),
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body = await readJson(response);
  return { httpStatus: response.status, body };
}

async function waitFor(label, probe, timeoutMs = 30_000) {
  const started = Date.now();
  let lastError = "not ready";
  while (Date.now() - started < timeoutMs) {
    try {
      if (await probe()) return;
    } catch (error) {
      lastError = error.message || String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`${label} did not become ready: ${lastError}`);
}

function track(child) {
  children.push(child);
  return child;
}

async function ngrokConfigPath() {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { stdout, stderr } = await promisify(execFile)("ngrok", ["config", "check"]);
  const match = `${stdout}\n${stderr}`.match(/Valid configuration file at (.+)/);
  if (!match) throw new Error("ngrok config check did not report a configuration file");
  return match[1].trim();
}

async function readTunnels() {
  const response = await fetch("http://127.0.0.1:4040/api/tunnels", { signal: AbortSignal.timeout(2_000) });
  const body = await response.json();
  const found = {};
  for (const tunnel of body.tunnels || []) {
    const addr = String(tunnel.config?.addr || "");
    const publicUrl = String(tunnel.public_url || "");
    if (!publicUrl.startsWith("https://")) continue;
    if (addr.endsWith(":3000")) found.issuer = publicUrl;
    if (addr.endsWith(":4000")) found.wallet = publicUrl;
  }
  return found;
}

async function startNgrok() {
  const directory = await mkdtemp(path.join(tmpdir(), "pre-ship-ngrok-"));
  const configPath = path.join(directory, "tunnels.yml");
  await writeFile(configPath, [
    "version: 2",
    "tunnels:",
    "  issuer:",
    "    proto: http",
    "    addr: 3000",
    "  wallet:",
    "    proto: http",
    "    addr: 4000",
    "",
  ].join("\n"));
  const userConfig = await ngrokConfigPath();
  const logPath = path.join(directory, "ngrok.log");
  track(spawn("ngrok", [
    "start", "issuer", "wallet",
    "--config", userConfig,
    "--config", configPath,
    "--log", logPath,
  ], { stdio: "ignore" }));
  try {
    await waitFor("ngrok", async () => {
      const tunnels = await readTunnels();
      return Boolean(tunnels.issuer && tunnels.wallet);
    });
  } catch (error) {
    const log = await readFile(logPath, "utf8").catch(() => "");
    throw new Error(`${error.message}\n${log.split("\n").slice(-20).join("\n")}`);
  }
  return readTunnels();
}

async function resolveUrls() {
  const fromEnv = {
    issuer: process.env.ISSUER?.replace(/\/$/, ""),
    wallet: process.env.WALLET?.replace(/\/$/, ""),
  };
  if (fromEnv.issuer && fromEnv.wallet) return fromEnv;
  if (fromEnv.issuer || fromEnv.wallet) {
    throw new Error("Set both ISSUER and WALLET, or neither to start ngrok for ports 3000 and 4000");
  }
  let tunnels = {};
  if (await portOpen(4040)) {
    tunnels = await readTunnels();
    if (tunnels.issuer && tunnels.wallet) return tunnels;
    throw new Error("ngrok is already running without HTTPS tunnels for both port 3000 and port 4000. Stop it, or set ISSUER and WALLET.");
  }
  console.log("Starting ngrok for issuer :3000 and wallet :4000");
  tunnels = await startNgrok();
  console.log(`ISSUER=${tunnels.issuer}`);
  console.log(`WALLET=${tunnels.wallet}`);
  return tunnels;
}

function spawnService(command, args, env, cwd) {
  const child = track(spawn(command, args, {
    cwd,
    env,
    stdio: "inherit",
  }));
  child.on("exit", (code) => {
    if (code && code !== 0 && !shuttingDown) {
      console.error(`${command} exited with ${code}`);
    }
  });
  return child;
}

let shuttingDown = false;
let startedRedisContainer = false;

function stopChildren() {
  shuttingDown = true;
  for (const child of children) {
    if (child.exitCode == null && child.signalCode == null) child.kill("SIGTERM");
  }
  if (startedRedisContainer) {
    spawn("docker", ["stop", "pre-ship-redis"], { stdio: "ignore" });
  }
}

async function ensureRedis() {
  if (await portOpen(6379)) return;
  console.log("Starting Redis test container pre-ship-redis on 127.0.0.1:6379");
  await new Promise((resolve) => {
    const removal = spawn("docker", ["rm", "-f", "pre-ship-redis"], { stdio: "ignore" });
    removal.once("exit", () => resolve());
    removal.once("error", () => resolve());
  });
  const child = track(spawn("docker", [
    "run", "--rm", "--name", "pre-ship-redis",
    "-p", "127.0.0.1:6379:6379",
    "redis:7-alpine",
  ], { stdio: "inherit" }));
  startedRedisContainer = true;
  let earlyFailure = null;
  child.once("error", (error) => {
    earlyFailure = error.message || String(error);
  });
  child.once("exit", (code) => {
    if (code && code !== 0) earlyFailure = `docker exited with ${code}`;
  });
  const started = Date.now();
  while (Date.now() - started < 120_000) {
    if (earlyFailure) {
      throw new Error(`Redis is not accepting connections on localhost:6379, and the test container did not start. ${earlyFailure}`);
    }
    if (await portOpen(6379)) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Redis is not accepting connections on localhost:6379, and the test container did not become ready");
}

async function ensureIssuer(issuer) {
  const ready = async () => {
    const response = await requestJson(`${issuer}/.well-known/openid-credential-issuer`, { timeoutMs: 3_000 });
    return response.httpStatus === 200 && response.body && typeof response.body === "object";
  };
  try {
    if (await ready()) return;
  } catch {
    // The public origin is not serving yet.
  }
  if (await portOpen(3000)) {
    throw new Error(`Port 3000 is in use, and ${issuer} is not serving issuer metadata. Stop that process or start it with SERVER_URL=${issuer}`);
  }
  console.log("Starting issuer");
  spawnService("node", ["server.js"], {
    ...process.env,
    SERVER_URL: issuer,
    VERIFIER_CS02_COMPATIBILITY: "",
    CS02_COMPATIBILITY: "",
  }, root);
  await waitFor("issuer", ready);
}

async function ensureWallet(wallet) {
  const ready = async () => {
    const response = await requestJson(`${wallet}/health`, { timeoutMs: 3_000 });
    return response.httpStatus === 200 && response.body?.status === "ok" && response.body?.cs01Mode === true;
  };
  try {
    if (await ready()) return;
  } catch {
    // The public origin is not serving yet.
  }
  if (await portOpen(4000)) {
    throw new Error(`Port 4000 is in use, and ${wallet}/health is not the CS-01 wallet. Restart wallet-client with WALLET_PROFILE=webuild-cs01 and WALLET_PROVIDER_URL=${wallet}`);
  }
  console.log("Starting wallet-client");
  const env = { ...process.env };
  delete env.WALLET_AUTH_HANDOFF;
  spawnService("node", ["src/server.js"], {
    ...env,
    WALLET_PROFILE: "webuild-cs01",
    WALLET_CLIENT_ID: "wallet-client",
    WALLET_ATTESTATION_SOURCE: "local-key",
    WALLET_PROVIDER_URL: wallet,
    WALLET_STATUS_ADMIN_TOKEN: process.env.WALLET_STATUS_ADMIN_TOKEN || "dev-status-admin",
    PORT: "4000",
  }, path.join(root, "wallet-client"));
  await waitFor("wallet", ready);
}

async function failureExcerpt(issuer, wallet, sessionId) {
  const parts = [];
  for (const [label, url] of [["issuer", `${issuer}/logs/${sessionId}`], ["wallet", `${wallet}/logs/${sessionId}`]]) {
    try {
      const response = await requestJson(url);
      const logs = Array.isArray(response.body?.logs) ? response.body.logs : [];
      const last = logs.slice(-3).map((entry) => (typeof entry === "string" ? entry : JSON.stringify(entry))).join(" | ");
      if (last) parts.push(`${label}: ${last}`);
    } catch {
      // Logs are evidence, not a second verdict.
    }
  }
  return parts.join("\n");
}

async function runCase(testCase, { issuer, wallet }) {
  const sessionId = randomUUID();
  const started = Date.now();
  try {
    const created = await requestJson(`${issuer}${testCase.path}?${caseRequest(testCase, sessionId)}`);
    if (created.httpStatus !== 200 || !created.body?.deepLink) {
      return { id: testCase.id, result: "fail", detail: `offer HTTP ${created.httpStatus}`, sessionId, ms: Date.now() - started };
    }
    if (testCase.kind === "present") {
      const link = checkInvocationLink({
        deepLink: created.body.deepLink,
        sessionId,
        issuer,
        scheme: testCase.scheme,
        method: testCase.method,
        requestPath: testCase.requestPath,
      });
      if (!link.ok) return { id: testCase.id, result: "fail", detail: link.reason, sessionId, ms: Date.now() - started };
    }
    const pin = testCase.pin ? created.body.txCode : undefined;
    if (testCase.pin && !pin) {
      return { id: testCase.id, result: "fail", detail: "offer did not return txCode", sessionId, ms: Date.now() - started };
    }
    const walletResponse = await requestJson(`${wallet}/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(walletSessionBody({
        deepLink: created.body.deepLink,
        sessionId,
        issuer,
        pin,
      })),
    });
    if (walletResponse.httpStatus !== 200 || walletResponse.body?.status !== "ok") {
      const text = walletResponse.body?.error_description || walletResponse.body?.error || JSON.stringify(walletResponse.body);
      const classified = classifyWalletFailure(testCase, text);
      const excerpt = await failureExcerpt(issuer, wallet, sessionId);
      return { id: testCase.id, ...classified, detail: [classified.detail, excerpt].filter(Boolean).join("\n"), sessionId, ms: Date.now() - started };
    }
    const statusUrl = testCase.kind === "issue"
      ? `${issuer}/issueStatus?${new URLSearchParams({ sessionId })}`
      : `${issuer}/verificationStatus?${new URLSearchParams({ sessionId })}`;
    const status = await requestJson(statusUrl);
    const judged = testCase.kind === "issue" ? judgeIssueStatus(status.body) : judgeVerificationStatus(status.body);
    if (judged.result !== "pass") {
      const excerpt = await failureExcerpt(issuer, wallet, sessionId);
      return { id: testCase.id, ...judged, detail: [judged.detail, excerpt].filter(Boolean).join("\n"), sessionId, ms: Date.now() - started };
    }
    return { id: testCase.id, result: "pass", sessionId, ms: Date.now() - started };
  } catch (error) {
    return { id: testCase.id, result: "fail", detail: error.message || String(error), sessionId, ms: Date.now() - started };
  }
}

function printResults(results) {
  console.log("\nPre-ship ITB results");
  for (const result of results) {
    const detail = result.detail ? ` ${result.detail.split("\n")[0]}` : "";
    console.log(`${result.result.padEnd(16)} ${result.id.padEnd(8)} ${result.sessionId || ""} ${result.ms || 0}ms${detail}`);
  }
}

async function main() {
  const cases = selectedCases();
  await ensureRedis();
  const urls = await resolveUrls();
  await ensureIssuer(urls.issuer);
  await ensureWallet(urls.wallet);
  const results = [];
  let stopPresentations = false;
  for (const testCase of cases) {
    if (stopPresentations && testCase.kind === "present") {
      results.push({ id: testCase.id, result: "skipped", detail: "stopped after a counterpart gap" });
      continue;
    }
    console.log(`\n${testCase.id} ${testCase.path}`);
    const outcome = await runCase(testCase, urls);
    results.push(outcome);
    console.log(`${outcome.result} ${outcome.sessionId || ""}`);
    if (outcome.result === "counterpart-stop") stopPresentations = true;
  }
  printResults(results);
  const failed = results.some((result) => result.result === "fail" || result.result === "counterpart-stop");
  process.exitCode = failed ? 1 : 0;
}

process.on("SIGINT", () => {
  stopChildren();
  process.exit(130);
});
process.on("SIGTERM", () => {
  stopChildren();
  process.exit(143);
});

main()
  .catch((error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  })
  .finally(() => {
    stopChildren();
  });
