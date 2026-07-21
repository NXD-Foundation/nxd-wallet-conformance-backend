#!/usr/bin/env node
/**
 * Zero-dependency static server for the CS-07 RP demo page.
 * Serves this directory so phones can load demo/index.html over an ngrok tunnel
 * separate from the verifier (usually already on :3000).
 *
 *   node clients/dc-api/serve.js
 *   DC_API_DEMO_PORT=4173 node clients/dc-api/serve.js
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.DC_API_DEMO_PORT || process.env.PORT || 4173);
const host = process.env.DC_API_DEMO_HOST || "0.0.0.0";

if (/^https?:\/\//i.test(host)) {
  console.error(
    "DC_API_DEMO_HOST must be a bind address (e.g. 0.0.0.0), not an ngrok URL.\n" +
      "  Run:  npm run dc-api:demo\n" +
      "  Then: ngrok http 4173\n" +
      "Paste the *verifier* ngrok URL into the demo page form, not into DC_API_DEMO_HOST.",
  );
  process.exit(1);
}

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".md": "text/markdown; charset=utf-8",
};

function safeJoin(base, requestPath) {
  const decoded = decodeURIComponent(requestPath.split("?")[0]);
  const resolved = path.normalize(path.join(base, decoded));
  if (!resolved.startsWith(base)) return null;
  return resolved;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return send(res, 405, "Method Not Allowed");
  }

  let urlPath = new URL(req.url || "/", `http://${req.headers.host}`).pathname;
  if (urlPath === "/") urlPath = "/demo/index.html";

  const filePath = safeJoin(root, urlPath);
  if (!filePath) return send(res, 403, "Forbidden");

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      return send(res, 404, "Not Found");
    }
    const type = TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream";
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Length": stat.size,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(port, host, () => {
  const local = `http://127.0.0.1:${port}/`;
  console.log(`CS-07 RP demo listening on ${local}`);
  console.log(`Open ${local}demo/ (or ${local}) on a secure origin.`);
  console.log("");
  console.log("Phone / ngrok:");
  console.log(`  ngrok http ${port}`);
  console.log("Then authorize that HTTPS origin on the verifier, e.g.:");
  console.log("  DC_API_RP_ORIGINS=https://abcd.ngrok-free.app npm run dev");
  console.log("Optional: DC_API_RP_PROFILES=pid-basic (defaults to default_profile)");
  console.log("Paste the verifier ngrok URL into the demo page.");
});
