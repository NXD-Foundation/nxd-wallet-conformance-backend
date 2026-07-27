import { TrustListError, TRUST_REASON_CODES } from "./errors.js";

export async function fetchDocument(url, { fetchImpl = globalThis.fetch, timeoutMs = 10_000, maxBytes = 2_000_000, allowInsecureHttp = false } = {}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new TrustListError(`Invalid document URL: ${url}`, TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE);
  }
  if (parsed.protocol !== "https:" && !(allowInsecureHttp && parsed.protocol === "http:")) {
    throw new TrustListError("Trust-list URLs must use HTTP(S)", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { signal: controller.signal, redirect: "error" });
    if (!response.ok) {
      throw new TrustListError(`Trust-list fetch failed with HTTP ${response.status}`, TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url, status: response.status });
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > maxBytes) {
      throw new TrustListError("Trust-list response exceeds configured size limit", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url, maxBytes });
    }
    return { url, bytes: buffer, contentType: response.headers?.get?.("content-type") || "" };
  } catch (error) {
    if (error instanceof TrustListError) throw error;
    throw new TrustListError(`Trust-list fetch failed: ${error.message}`, TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url });
  } finally {
    clearTimeout(timer);
  }
}
