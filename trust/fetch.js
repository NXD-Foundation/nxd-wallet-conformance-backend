import { TrustListError, TRUST_REASON_CODES } from "./errors.js";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

function isPrivateAddress(address) {
  const mappedIpv4 = address.match(/^::ffff:(.+)$/i)?.[1];
  if (mappedIpv4 && isIP(mappedIpv4) === 4) return isPrivateAddress(mappedIpv4);
  const mappedHex = address.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHex) {
    const high = Number.parseInt(mappedHex[1], 16);
    const low = Number.parseInt(mappedHex[2], 16);
    return isPrivateAddress(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
  }
  if (address === "::1" || /^fe[89ab][0-9a-f]:/i.test(address) || address.startsWith("fc") || address.startsWith("fd")) return true;
  if (isIP(address) !== 4) return false;
  const [a, b] = address.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

async function assertSafeTarget(parsed, { resolveHostname = lookup, allowedHosts = null, allowPrivateAddresses = false }) {
  if (allowedHosts?.length && !allowedHosts.includes(parsed.hostname)) {
    throw new TrustListError("Trust-list URL host is not allowed by the profile", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { host: parsed.hostname });
  }
  const addresses = isIP(parsed.hostname) ? [{ address: parsed.hostname }] : await resolveHostname(parsed.hostname, { all: true });
  if (!allowPrivateAddresses && addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new TrustListError("Trust-list URL resolves to a private or reserved address", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { host: parsed.hostname });
  }
}

function headerValue(headers, name) {
  if (!headers || typeof headers.get !== "function") return "";
  return headers.get(name) || headers.get(name.toLowerCase()) || "";
}

export async function fetchDocument(url, { fetchImpl = globalThis.fetch, timeoutMs = 10_000, maxBytes = 2_000_000, allowInsecureHttp = false, resolveHostname = lookup, allowedHosts = null, allowPrivateAddresses = false, headers = null, followRedirects = false, maxRedirects = 5 } = {}) {
  const hopLimit = Number.isInteger(maxRedirects) && maxRedirects >= 0 ? maxRedirects : 5;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let currentUrl = String(url);
  try {
    for (let hops = 0; ; hops += 1) {
      let parsed;
      try {
        parsed = new URL(currentUrl);
      } catch {
        throw new TrustListError(`Invalid document URL: ${currentUrl}`, TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE);
      }
      if (parsed.protocol !== "https:" && !(allowInsecureHttp && parsed.protocol === "http:")) {
        throw new TrustListError("Trust-list URLs must use HTTP(S)", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE);
      }
      await assertSafeTarget(parsed, { resolveHostname, allowedHosts, allowPrivateAddresses });
      const requestInit = { signal: controller.signal, redirect: "error" };
      if (headers && typeof headers === "object") requestInit.headers = headers;
      const response = await fetchImpl(currentUrl, requestInit);
      const status = Number(response.status);
      if (followRedirects && status >= 300 && status < 400) {
        if (hops >= hopLimit) {
          throw new TrustListError("Trust-list fetch exceeded redirect limit", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url: currentUrl });
        }
        const location = headerValue(response.headers, "location");
        if (!location) {
          throw new TrustListError("Trust-list redirect is missing Location", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url: currentUrl, status });
        }
        try {
          currentUrl = new URL(location, parsed).href;
        } catch {
          throw new TrustListError("Trust-list redirect Location is invalid", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url: currentUrl, status, location });
        }
        continue;
      }
      if (!response.ok) {
        throw new TrustListError(`Trust-list fetch failed with HTTP ${response.status}`, TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url: currentUrl, status: response.status });
      }
      const buffer = Buffer.from(await response.arrayBuffer());
      if (buffer.length > maxBytes) {
        throw new TrustListError("Trust-list response exceeds configured size limit", TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url: currentUrl, maxBytes });
      }
      return { url: currentUrl, bytes: buffer, contentType: headerValue(response.headers, "content-type") };
    }
  } catch (error) {
    if (error instanceof TrustListError) throw error;
    throw new TrustListError(`Trust-list fetch failed: ${error.message}`, TRUST_REASON_CODES.REFERENCED_LIST_UNAVAILABLE, { url: currentUrl });
  } finally {
    clearTimeout(timer);
  }
}
