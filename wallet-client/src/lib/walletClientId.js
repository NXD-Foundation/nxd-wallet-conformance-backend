import { getOrCreateWalletInstanceId } from "./cache.js";

/**
 * Stable OAuth `client_id` and WIA `sub` for this wallet install (RFC001 / HAIP).
 */
export async function resolveWalletInstanceClientId() {
  return getOrCreateWalletInstanceId();
}
