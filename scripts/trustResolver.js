#!/usr/bin/env node
import fs from "node:fs/promises";
import { loadTrustProfile } from "../trust/profile.js";
import { loadTrustSnapshot } from "../trust/loader.js";
import { createTrustResolver } from "../trust/resolver.js";

function option(args, name, fallback = null) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
}

export async function runTrustResolverCli(args = process.argv.slice(2)) {
  const profilePath = option(args, "--profile", "data/trust/webuild-wp4-pilot.json");
  const requestPath = option(args, "--request");
  const profile = await loadTrustProfile(profilePath);
  const snapshotPath = option(args, "--snapshot");
  const role = option(args, "--role", "pid-provider");
  const entityId = option(args, "--entity");
  const format = option(args, "--format");
  const request = requestPath
    ? JSON.parse(await fs.readFile(requestPath, "utf8"))
    : {
        framework: profile.id,
        role,
        operation: option(args, "--operation", "resolve-provider"),
        presentedIdentity: { entityId },
      };
  const snapshot = snapshotPath
    ? JSON.parse(await fs.readFile(snapshotPath, "utf8"))
    : await loadTrustSnapshot({ profile, format: format || profile.formats.preferred, listTypes: [request.role] });
  const resolver = createTrustResolver({ profile, snapshot });
  return resolver.resolve(request);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const result = await runTrustResolverCli();
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.trusted ? 0 : result.state === "indeterminate" ? 2 : 1;
  } catch (error) {
    console.error(JSON.stringify({ error: error.message, reasonCode: error.reasonCode || "TRUST_EVALUATION_INDETERMINATE" }));
    process.exitCode = 2;
  }
}
