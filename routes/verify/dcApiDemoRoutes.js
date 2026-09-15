import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const dcApiRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../clients/dc-api");
const dcApiDemoRouter = express.Router();

function sendDemoFile(res, relativePath, type) {
  res.set({
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Type": type,
  });
  return res.sendFile(path.join(dcApiRoot, relativePath));
}

dcApiDemoRouter.get(["/payment", "/payment/"], (_req, res) => {
  return sendDemoFile(res, "demo/payment.html", "text/html; charset=utf-8");
});

dcApiDemoRouter.get(["/demo", "/demo/", "/demo/index.html"], (_req, res) => {
  return sendDemoFile(res, "demo/index.html", "text/html; charset=utf-8");
});

dcApiDemoRouter.get("/demo/payment.html", (_req, res) => {
  return sendDemoFile(res, "demo/payment.html", "text/html; charset=utf-8");
});

dcApiDemoRouter.get(["/issuance", "/issuance/", "/demo/issuance.html"], (_req, res) => {
  return sendDemoFile(res, "demo/issuance.html", "text/html; charset=utf-8");
});

dcApiDemoRouter.get("/issuer-client.js", (_req, res) => {
  return sendDemoFile(res, "issuer-client.js", "text/javascript; charset=utf-8");
});

dcApiDemoRouter.get("/rp-client.js", (_req, res) => {
  return sendDemoFile(res, "rp-client.js", "text/javascript; charset=utf-8");
});

export default dcApiDemoRouter;
