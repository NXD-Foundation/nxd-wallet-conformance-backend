#!/usr/bin/env node
import fs from 'node:fs/promises';
import { KEY_MATERIAL_PATHS } from '../utils/keyMaterialPaths.js';
import path from 'node:path';
import https from 'node:https';
import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { provisionWrprcs, activateQuarantinedWrprcs, registrarDatasetForRegistration, RAIDiam_ENTITY, RAIDiam_SERVICE } from '../utils/raidiamProvisioning.js';
import { verifyWrprc, assertQueryScope, assertRegistrarDataset } from '../utils/wrprc.js';
import { checkAccessCertificateTrust } from '../utils/trustFrameworkPolicy.js';

export function resolveProvisioningWrpacPath(env = process.env, root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')) {
  return path.resolve(root, env.RAIDIAM_WRPAC || env.TRUST_WRPAC_CERT_PATH || KEY_MATERIAL_PATHS.verifierTrustWrpacCertificate);
}

export async function main(env = process.env, argv = process.argv.slice(2)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const entityId = env.RAIDIAM_RPID || RAIDiam_ENTITY;
  const serviceId = env.RAIDIAM_SID || RAIDiam_SERVICE;
  const bodiesDir = path.join(root, 'data/trust/intended_uses');
  const bodies = await Promise.all((await fs.readdir(bodiesDir)).filter(f => f.endsWith('.json')).sort().map(async file => ({ scenario: file.slice(0, -5), body: JSON.parse(await fs.readFile(path.join(bodiesDir, file), 'utf8')) })));
  if (argv.includes('--dry-run')) {
    console.log(JSON.stringify({ entityId, serviceId, scenarios: bodies.map(b => b.scenario), privacyUrl: 'https://www.aegean.gr/', networkRequests: false }, null, 2));
    return true;
  }
  const activateOnly = argv.length === 1 && argv[0] === '--activate-quarantined';
  if (argv.length && !activateOnly) throw new Error('Only --dry-run or --activate-quarantined is supported');
  const access = new X509Certificate(await fs.readFile(resolveProvisioningWrpacPath(env, root)));
  // The WRPAC supplies the fixed relying-party entity/service identity.
  const subject = access.subject.split('\n');
  if (!subject.includes(`organizationIdentifier=${entityId}`) || !subject.includes(`OU=${serviceId}`)) throw new Error('WRPAC entity/service identity mismatch');
  if (Date.parse(access.validFrom) > Date.now() || Date.parse(access.validTo) <= Date.now()) throw new Error('Local certificate is outside its validity period');
  const registryUrl = env.RAIDIAM_REGISTRY_URI || `https://data.sandbox.eudi.raidiam.io/wrp/${entityId}/services/${serviceId}`;
  const verify = async (token, bindings) => {
    const result = await verifyWrprc(token, { ...bindings, checkTrust: async input => {
      const decision = await checkAccessCertificateTrust({ session: { trustPolicy: { mode: 'webuild', profile: 'webuild-wp4-pilot' } }, ...input });
      if (!decision?.trusted) {
        const reason = /^[A-Z0-9_]+$/.test(decision?.reasonCode || '') ? decision.reasonCode : 'UNKNOWN';
        throw new Error(`WRPRC: registrar trust rejected (${reason})`);
      }
      return decision;
    } });
    assertQueryScope({ credentials: bindings.declaration.credentials }, result.intendedUse);
    const dataset = registrarDatasetForRegistration({ entityId, serviceId, intendedUseId: bindings.intendedUseId, body: bindings.declaration, registration: result.payload, registryUrl });
    assertRegistrarDataset(dataset, { registration: result.payload, intendedUse: result.intendedUse, ...bindings });
    return result;
  };
  if (activateOnly) {
    const result = await activateQuarantinedWrprcs({ bodies, manifestPath: env.TRUST_WRPRC_MANIFEST_PATH || path.join(root, 'certs/raidiam/registration/manifest.json'), verify, entityId, serviceId, registryUrl });
    for (const item of result.results) console.log(`${item.scenario}: ${item.status}${item.error ? ` (${item.error})` : ''}`);
    return result.ok;
  }
  const transportDir = path.join(root, 'certs/raidiam/Trust_Registry_API authentication');
  const cert = await fs.readFile(env.RAIDIAM_TRANSPORT_CERT || path.join(transportDir, 'trust_api_call.pem'));
  const key = await fs.readFile(env.RAIDIAM_TRANSPORT_KEY || path.join(transportDir, `${serviceId}-rtstransport.key`));
  const transport = new X509Certificate(cert);
  if (!transport.subject.split('\n').includes(`CN=${serviceId}`)) throw new Error('Transport certificate service mismatch');
  for (const certificate of [access, transport]) if (Date.parse(certificate.validFrom) > Date.now() || Date.parse(certificate.validTo) <= Date.now()) throw new Error('Local certificate is outside its validity period');
  if (!transport.publicKey.equals(createPublicKey(createPrivateKey(key)))) throw new Error('Transport key does not match certificate');
  const ca = env.RAIDIAM_TLS_CA ? await fs.readFile(env.RAIDIAM_TLS_CA) : undefined;
  const agent = new https.Agent({ cert, key, ca, rejectUnauthorized: true, ...(ca ? { allowPartialTrustChain: true } : {}) });
  async function send(method, url, body, headers = {}) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') throw new Error('HTTPS registry endpoints required');
    const data = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = https.request(parsed, { method, agent, headers: { ...(data ? { 'content-type': typeof body === 'string' ? 'application/x-www-form-urlencoded' : 'application/json', 'content-length': Buffer.byteLength(data) } : {}), ...headers } }, res => {
        let text = '';
        res.on('data', chunk => { text += chunk; if (text.length > 4 * 1024 * 1024) req.destroy(new Error('Oversized registry response')); });
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            const error = new Error(`Registry ${method} failed HTTP ${res.statusCode}`);
            error.safeMessage = error.message;
            reject(error); return;
          }
          try { resolve(JSON.parse(text)); } catch { resolve(text); }
        });
      });
      req.setTimeout(30000, () => req.destroy(new Error('Registry request timed out')));
      req.on('error', reject); req.end(data);
    });
  }
  const api = env.RAIDIAM_API_URL || 'https://matls-api.sandbox.eudi.raidiam.io';
  const auth = env.RAIDIAM_AUTH_URL || 'https://matls-auth.sandbox.eudi.raidiam.io';
  try {
    const oauth = await send('POST', `${auth}/token`, new URLSearchParams({ grant_type: 'client_credentials', client_id: env.RAIDIAM_CLIENT_ID || serviceId, scope: 'directory:software' }).toString());
    if (!oauth?.access_token) throw new Error('OAuth response omitted access token');
    const request = (method, resource, body) => send(method, `${api}${resource}`, body, { authorization: `Bearer ${oauth.access_token}` });
    const result = await provisionWrprcs({ bodies, manifestPath: env.TRUST_WRPRC_MANIFEST_PATH || path.join(root, 'certs/raidiam/registration/manifest.json'), request, verify, entityId, serviceId, registryUrl });
    for (const item of result.results) console.log(`${item.scenario}: ${item.status}${item.error ? ` (${item.error})` : ''}`);
    return result.ok;
  } finally { agent.destroy(); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(ok => { if (!ok) process.exitCode = 1; }).catch(error => {
    // Deliberately omit response bodies, key material and OAuth tokens.
    console.error(`WRPRC provisioning: ${error.safeMessage || (error.code ? `connection/configuration error ${error.code}` : error.message)}`);
    process.exitCode = 1;
  });
}
