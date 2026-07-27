import http from "node:http";

function sendJson(response, status, body) {
  const data = JSON.stringify(body);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(data) });
  response.end(data);
}

export function createTrustResolverServer({ resolver, maxRequestBytes = 100_000 } = {}) {
  if (!resolver || typeof resolver.resolve !== "function") throw new TypeError("Trust resolver HTTP adapter requires a resolver");
  return http.createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== "/v1/trust/resolve") {
      sendJson(response, 404, { error: "not_found" });
      return;
    }
    const chunks = [];
    let size = 0;
    try {
      for await (const chunk of request) {
        size += chunk.length;
        if (size > maxRequestBytes) {
          sendJson(response, 413, { error: "request_too_large" });
          request.destroy();
          return;
        }
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const result = await resolver.resolve(body);
      sendJson(response, 200, result);
    } catch (error) {
      sendJson(response, 400, { trusted: false, state: "not_trusted", reasonCode: "INVALID_REQUEST", error: error.message });
    }
  });
}
