import express from "express";
import {
  getSessionLogs,
  clearSessionLogs,
  summarizeSessionLogs,
  logInfo,
  client, // Import the existing Redis client
} from "../services/cacheServiceRedis.js";
import { createErrorResponse } from "../utils/routeUtils.js";

const loggingRouter = express.Router();

function parseVerboseFlag(value) {
  if (value === true || value === 1) return true;
  const normalized = String(value ?? "").trim().toLowerCase();
  return normalized === "true" || normalized === "1";
}

function filterLogsForHumanView(logs = []) {
  return logs.filter((log) => {
    const kind = log?.kind || "protocol";
    const level = log?.level || "info";

    if (level === "warn" || level === "error") return true;
    if (kind === "protocol" || kind === "compliance") return true;
    return false;
  });
}

/**
 * SESSION LOGGING API ENDPOINTS
 *
 * This router provides endpoints to manage session-based logs stored in Redis.
 * All logs are associated with session IDs and have a 30-minute TTL.
 *
 * Available endpoints:
 * - GET /logs/sessions - List all session IDs that have logs
 * - GET /logs/:sessionId - Retrieve all logs for a session
 * - DELETE /logs/:sessionId - Clear logs for a session
 * - POST /logs/batch - Get logs for multiple sessions
 */

/**
 * Get logs for a specific session
 */
loggingRouter.get("/logs/:sessionId", async (req, res) => {
  try {
    // const sessionId = req.params.sessionId;
    const sessionId = req.query.sessionId || req.params.sessionId || req.params.id;
    await logInfo(sessionId, "Retrieving session logs", { endpoint: "/logs/:sessionId" });
    
    const rawLogs = await getSessionLogs(sessionId);
    const verbose = parseVerboseFlag(req.query.verbose);
    const logs = verbose ? rawLogs : filterLogsForHumanView(rawLogs);
    res.json({
      sessionId,
      summary: summarizeSessionLogs(rawLogs),
      verbose,
      logs,
      count: logs.length,
      totalCount: rawLogs.length,
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "GET /logs/:sessionId");
    res.status(500).json(errorResponse);
  }
});

/**
 * Clear logs for a specific session
 */
loggingRouter.delete("/logs/:sessionId", async (req, res) => {
  try {
    const sessionId = req.params.sessionId;
    await logInfo(sessionId, "Clearing session logs", { endpoint: "DELETE /logs/:sessionId" });
    
    const cleared = await clearSessionLogs(sessionId);
    res.json({
      sessionId,
      cleared,
      message: cleared ? "Logs cleared successfully" : "No logs found to clear"
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "DELETE /logs/:sessionId");
    res.status(500).json(errorResponse);
  }
});

/**
 * Get logs for multiple sessions (optional utility endpoint)
 */
loggingRouter.post("/logs/batch", async (req, res) => {
  try {
    const { sessionIds, verbose } = req.body;
    const includeVerbose = parseVerboseFlag(verbose);
    
    if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
      return res.status(400).json({ 
        error: "sessionIds must be a non-empty array" 
      });
    }
    
    const results = {};
    for (const sessionId of sessionIds) {
      try {
        const rawLogs = await getSessionLogs(sessionId);
        const logs = includeVerbose ? rawLogs : filterLogsForHumanView(rawLogs);
        results[sessionId] = {
          summary: summarizeSessionLogs(rawLogs),
          verbose: includeVerbose,
          logs,
          count: logs.length,
          totalCount: rawLogs.length,
        };
      } catch (error) {
        results[sessionId] = {
          error: error.message,
          logs: [],
          count: 0,
          totalCount: 0,
        };
      }
    }
    
    res.json({
      results,
      totalSessions: sessionIds.length
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "POST /logs/batch");
    res.status(500).json(errorResponse);
  }
});

/**
 * List all session IDs that currently have logs stored
 */
loggingRouter.get("/logs/sessions", async (req, res) => {
  try {
    // Get all keys matching the session-logs pattern
    const keys = await client.keys("session-logs:*");
    const sessionIds = keys.map(key => key.replace("session-logs:", ""));

    res.json({
      sessionIds,
      count: sessionIds.length,
      message: "List of sessions with available logs"
    });
  } catch (error) {
    const errorResponse = createErrorResponse(error, "GET /logs/sessions");
    res.status(500).json(errorResponse);
  }
});

export default loggingRouter;
