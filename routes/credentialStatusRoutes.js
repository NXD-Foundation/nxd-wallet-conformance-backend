import express from "express";
import { CREDENTIAL_STATUS_LIST_PATH, revokeCredentialStatus, signCredentialStatusList } from "../utils/credentialStatusList.js";

export function credentialStatusRouter() {
  const router = express.Router();

  router.get(`${CREDENTIAL_STATUS_LIST_PATH}/:listId`, async (req, res) => {
    try {
      const token = await signCredentialStatusList(req.params.listId, {
        issuer: process.env.SERVER_URL || "http://localhost:3000",
      });
      res.set("Content-Type", "application/statuslist+jwt").set("Cache-Control", "public, max-age=300").send(Buffer.from(token));
    } catch (error) {
      res.status(404).json({ error: "not_found", error_description: error.message });
    }
  });

  router.post(`${CREDENTIAL_STATUS_LIST_PATH}/:listId/entries/:idx/revoke`, (req, res) => {
    const expected = process.env.ISSUER_STATUS_ADMIN_TOKEN;
    const presented = String(req.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!expected || presented !== expected) return res.status(401).json({ error: "unauthorized" });
    try {
      return res.json(revokeCredentialStatus(req.params.listId, req.params.idx));
    } catch (error) {
      return res.status(error.status || 400).json({ error: "invalid_request", error_description: error.message });
    }
  });

  return router;
}
