import zlib from "node:zlib";
import * as jose from "jose";
import { randomUUID } from "crypto";
import {
  CLIENT_ATTESTATION_JWT_TYP,
  CLIENT_ATTESTATION_POP_TYP,
} from "../../utils/oauthClientAttestation.js";
import {
  STATUS_LIST_JWT_TYP,
  STATUS_LIST_MEDIA_TYPE,
  encodeStatusListLst,
  setWuaStatusListFetchForTests,
  setWuaStatusListResolveHostnameForTests,
  resetWuaStatusListVerifierForTests,
} from "../../utils/wuaStatusListVerifier.js";

export const WIA_STATUS_LIST_URI = "https://wallet-provider.example/status-lists/wia/1";
export const KA_STATUS_LIST_URI = "https://wallet-provider.example/status-lists/ka/1";
export const PUBLIC_RESOLVE_HOSTNAME = async () => [{ address: "1.1.1.1" }];

export async function signStatusListToken({
  privateKey,
  uri,
  statuses = [0],
  bits = 1,
  typ = STATUS_LIST_JWT_TYP,
  sub,
  iat,
  exp,
  omitExp = false,
  ttl = 3600,
  alg = "ES256",
  extraClaims = {},
  lst,
  header = {},
} = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: sub === undefined ? uri : sub,
    iat: iat ?? now,
    ttl,
    status_list: {
      bits,
      lst: lst ?? encodeStatusListLst(statuses, { bits }),
    },
    ...extraClaims,
  };
  if (!omitExp) {
    payload.exp = exp ?? now + ttl;
  }
  if (bits !== 1) payload.status_list.bits = bits;
  if (lst !== undefined) payload.status_list.lst = lst;
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg, typ, ...header })
    .sign(privateKey);
}

export function stubStatusListFetch(jwtOrByUri, { contentType = STATUS_LIST_MEDIA_TYPE, status = 200 } = {}) {
  return async (url) => {
    const jwt = typeof jwtOrByUri === "function" ? jwtOrByUri(url) : jwtOrByUri;
    if (status !== 200) {
      return {
        ok: false,
        status,
        headers: { get: () => contentType },
        arrayBuffer: async () => Buffer.from(""),
      };
    }
    return {
      ok: true,
      status: 200,
      headers: {
        get: (name) => (String(name).toLowerCase() === "content-type" ? contentType : null),
      },
      arrayBuffer: async () => Buffer.from(jwt, "utf8"),
    };
  };
}

export function installStatusListTestHooks({ fetchImpl, resolveHostname = PUBLIC_RESOLVE_HOSTNAME } = {}) {
  setWuaStatusListFetchForTests(fetchImpl);
  setWuaStatusListResolveHostnameForTests(resolveHostname);
}

export function resetStatusListTestHooks() {
  resetWuaStatusListVerifierForTests();
}

export async function installValidStatusListForKey({ privateKey, uri, statuses = [0] }) {
  const jwt = await signStatusListToken({ privateKey, uri, statuses });
  installStatusListTestHooks({ fetchImpl: stubStatusListFetch(jwt) });
  return jwt;
}

export async function signWia({
  privateKey,
  publicJwk,
  clientId = "wua-test-client",
  uri = WIA_STATUS_LIST_URI,
  idx = 0,
  clientStatusExpOffsetSeconds = 86400 * 60,
} = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    sub: clientId,
    iat: now,
    exp: now + 3600,
    cnf: { jwk: publicJwk },
    client_status: {
      status: { status_list: { uri, idx } },
      exp: now + clientStatusExpOffsetSeconds,
    },
  })
    .setProtectedHeader({ alg: "ES256", typ: CLIENT_ATTESTATION_JWT_TYP, jwk: publicJwk })
    .sign(privateKey);
}

export async function signPop({ walletPrivateKey, clientId, audience }) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    iss: clientId,
    aud: audience,
    iat: now,
    exp: now + 300,
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: "ES256", typ: CLIENT_ATTESTATION_POP_TYP })
    .sign(walletPrivateKey);
}

export function deflateLst(bytes) {
  return zlib.deflateSync(bytes, { level: 9 }).toString("base64url");
}
