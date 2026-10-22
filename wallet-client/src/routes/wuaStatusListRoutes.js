import express from "express";
import {
  DEFAULT_STATUS_LIST_ID,
  STATUS_LIST_MEDIA_TYPE,
  WuaStatusListError,
  authorizeStatusListAdmin,
  resolveStatusTokenTtlSeconds,
  revokeWuaStatusListEntry,
  signStatusListToken,
} from "../lib/wuaStatusList.js";

function sendStatusListError(res, error) {
  const status = error?.status || 500;
  return res.status(status).json({
    error: error?.errorCode || "server_error",
    error_description: error?.message || String(error),
  });
}

function acceptsStatusListJwt(req) {
  const accept = req.get("Accept");
  if (!accept || accept === "*/*") return true;
  return /application\/statuslist\+jwt|\*\/\*|application\/\*/i.test(accept);
}

export function createWuaStatusListRouter() {
  const router = express.Router();

  router.use("/status-lists", (req, res, next) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }
    return next();
  });

  router.get("/status-lists/:kind/:listId", async (req, res) => {
    try {
      if (!acceptsStatusListJwt(req)) {
        return res.status(406).json({
          error: "not_acceptable",
          error_description: `Status lists are published as ${STATUS_LIST_MEDIA_TYPE}`,
        });
      }
      const { kind, listId } = req.params;
      const jwt = await signStatusListToken({ kind, listId });
      const ttl = resolveStatusTokenTtlSeconds();
      res.set("Content-Type", STATUS_LIST_MEDIA_TYPE);
      res.set("Cache-Control", `public, max-age=${ttl}`);
      return res.status(200).send(jwt);
    } catch (error) {
      if (error instanceof WuaStatusListError) return sendStatusListError(res, error);
      return sendStatusListError(res, error);
    }
  });

  router.post("/status-lists/:kind/:listId/entries/:idx/revoke", async (req, res) => {
    try {
      authorizeStatusListAdmin(req);
      const { kind, listId, idx } = req.params;
      const result = await revokeWuaStatusListEntry({
        kind,
        listId: listId || DEFAULT_STATUS_LIST_ID,
        idx: Number(idx),
      });
      return res.json(result);
    } catch (error) {
      if (error instanceof WuaStatusListError) return sendStatusListError(res, error);
      return sendStatusListError(res, error);
    }
  });

  return router;
}
