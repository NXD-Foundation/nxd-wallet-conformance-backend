import fs from "fs";
import crypto from "node:crypto";
import fetch from "node-fetch";

export const CSC_X509_FORMAT = "https://cloudsignatureconsortium.org/2025/x509";
export const CSC_QES_TYPE = "https://cloudsignatureconsortium.org/2025/qes";

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

export function decodeCs03TransactionDataEntry(entry) {
  if (typeof entry !== "string") return null;
  const decoded = JSON.parse(Buffer.from(entry, "base64url").toString("utf8"));
  if (decoded?.type !== CSC_QES_TYPE) return null;
  return decoded;
}

export function extractCs03Request(payload) {
  const dcqlCredentials = Array.isArray(payload?.dcql_query?.credentials)
    ? payload.dcql_query.credentials
    : [];
  const cs03CredentialQueries = dcqlCredentials.filter(
    (cred) => cred?.format === CSC_X509_FORMAT,
  );
  if (cs03CredentialQueries.length === 0) return null;

  const transactionDataEntries = Array.isArray(payload?.transaction_data)
    ? payload.transaction_data
    : [];
  for (const entry of transactionDataEntries) {
    try {
      const qesRequest = decodeCs03TransactionDataEntry(entry);
      if (!qesRequest) continue;
      return {
        credentialQueries: cs03CredentialQueries,
        qesRequest,
      };
    } catch {
      // Ignore malformed non-CS03 entries here; generic request validation handles them elsewhere.
    }
  }
  return null;
}

export function loadLocalCs03Signer() {
  const metadata = readJson("./x509CS03/credential.json");
  return {
    ...metadata,
    certificatePem: fs.readFileSync(metadata.certificatePath, "utf8"),
    privateKeyPem: fs.readFileSync(metadata.privateKeyPath, "utf8"),
  };
}

export function selectMatchingCs03Signer({ credentialQueries, signer }) {
  if (!signer || signer.format !== CSC_X509_FORMAT) {
    throw new Error("No CSC X.509 signing credential available in wallet");
  }

  for (const query of credentialQueries) {
    const requestedPolicies = Array.isArray(query?.meta?.certificatePolicies)
      ? query.meta.certificatePolicies
      : [];
    if (requestedPolicies.length === 0) continue;
    const matchesPolicy = requestedPolicies.some((policy) =>
      signer.certificatePolicies.includes(policy),
    );
    if (!matchesPolicy) {
      throw new Error(
        `Wallet CS-03 signer does not match requested certificatePolicies: ${requestedPolicies.join(", ")}`,
      );
    }
  }

  return signer;
}

export async function fetchCs03Documents(signatureRequests) {
  const outputs = [];
  for (const request of signatureRequests || []) {
    if (!request?.href) {
      throw new Error("CS-03 signatureRequest.href is required");
    }
    const res = await fetch(request.href);
    if (!res.ok) {
      throw new Error(`Failed to fetch CS-03 document: ${request.href} (${res.status})`);
    }
    const arrayBuffer = await res.arrayBuffer();
    const bytes = Buffer.from(arrayBuffer);
    if (request.checksum) {
      const computed = `sha256-${crypto.createHash("sha256").update(bytes).digest("base64")}`;
      if (computed !== request.checksum) {
        throw new Error(
          `CS-03 document checksum mismatch for ${request.href}. Expected ${request.checksum}, got ${computed}`,
        );
      }
    }
    outputs.push({ request, bytes });
  }
  return outputs;
}

export function buildCs03SignatureObject({ signer, documents }) {
  const signatureObject = documents.map(({ bytes }) => {
    const signature = crypto
      .createSign("RSA-SHA256")
      .update(bytes)
      .end()
      .sign(signer.privateKeyPem, "base64");
    return signature;
  });

  return {
    signatureObject,
    signerCertificate: signer.certificatePem,
  };
}

export function buildInlineCs03VpToken({ credentialIds, qesResponse }) {
  return Object.fromEntries(
    credentialIds.map((credId) => [
      credId,
      {
        qes: qesResponse,
      },
    ]),
  );
}

export function buildOobCs03VpToken({ credentialIds }) {
  return Object.fromEntries(credentialIds.map((credId) => [credId, {}]));
}

function getAllowedHostsFromClientMetadata(clientMetadata) {
  const hosts = new Set();
  const candidates = [
    clientMetadata?.redirect_uris,
    clientMetadata?.response_uris,
    clientMetadata?.trusted_domains,
  ];

  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) continue;
    for (const value of candidate) {
      try {
        hosts.add(new URL(value).hostname);
      } catch {
        // ignore non-URL entries
      }
    }
  }

  return hosts;
}

export function validateCs03OobResponseUri({ responseURI, clientId, clientMetadata = null }) {
  let parsedResponseUri;
  try {
    parsedResponseUri = new URL(responseURI);
  } catch (error) {
    throw new Error(`Invalid CS-03 responseURI: ${error.message}`);
  }

  if (parsedResponseUri.protocol !== "https:") {
    throw new Error("CS-03 responseURI must use https");
  }

  const allowedHosts = new Set();
  if (typeof clientId === "string" && clientId.startsWith("x509_san_dns:")) {
    allowedHosts.add(clientId.slice("x509_san_dns:".length));
  } else if (typeof clientId === "string") {
    try {
      allowedHosts.add(new URL(clientId).hostname);
    } catch {
      // ignore non-URL non-x509 client ids for host extraction
    }
  }

  for (const host of getAllowedHostsFromClientMetadata(clientMetadata)) {
    allowedHosts.add(host);
  }

  if (allowedHosts.size === 0) {
    throw new Error(
      "Unable to verify CS-03 responseURI host against RP client_id or verified metadata",
    );
  }

  if (!allowedHosts.has(parsedResponseUri.hostname)) {
    throw new Error(
      `CS-03 responseURI host '${parsedResponseUri.hostname}' does not match RP client_id or verified metadata`,
    );
  }
}

export async function sendCs03OobResponse(responseURI, qesResponse, options = {}) {
  validateCs03OobResponseUri({
    responseURI,
    clientId: options.clientId,
    clientMetadata: options.clientMetadata || null,
  });

  const fetchImpl = options.fetchImpl || fetch;
  const res = await fetchImpl(responseURI, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(qesResponse),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `CS-03 responseURI POST failed ${res.status}${text ? `: ${text}` : ""}`,
    );
  }
}
