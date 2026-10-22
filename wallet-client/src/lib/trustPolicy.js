import { X509Certificate } from "node:crypto";

/** Certificate validity is independent of whether framework trust is configured. */
export function assertCertificateValidity(x5c) {
  if (!Array.isArray(x5c) || !x5c.length) throw new Error("Signing certificate chain is missing");
  for (const entry of x5c) {
    const cert = new X509Certificate(Buffer.from(entry, "base64"));
    const now = Date.now();
    if (now < Date.parse(cert.validFrom) || now > Date.parse(cert.validTo)) {
      throw new Error("Signing certificate is outside its validity period");
    }
  }
}

/** Signature verification must succeed before calling this framework-policy gate. */
export function handleUnestablishedTrust(context, env = process.env) {
  const mode = env.WALLET_TRUST_MODE ?? "warn";
  if (!["warn", "strict"].includes(mode)) throw new Error("Invalid WALLET_TRUST_MODE; expected warn or strict");
  const message = `[trust] ${context}: framework trust is not established`;
  if (mode === "strict") throw new Error(message);
  console.warn(`${message}; continuing in warn mode after signature verification`);
}
