import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export const RAIDiam_ENTITY = 'VATEL-090264862';
export const RAIDiam_SERVICE = '4c3ecfb0-76ff-4eea-8e51-c8fac931e186';
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export function declarationHash(body) { return createHash('sha256').update(canonical(body)).digest('hex'); }
function declaration(value) { return { purpose: value.purpose, privacyPolicy: value.privacyPolicy, credentials: value.credentials }; }
function identifier(value) { return value?.intendedUseIdentifier ?? value?.intendedUseId ?? value?.id; }
export function listItems(value) {
  if (Array.isArray(value)) return value;
  for (const key of ['data', 'items', 'intendedUses', 'registrationCertificates']) if (Array.isArray(value?.[key])) return value[key];
  throw new Error('Unrecognized registry list response; refusing to create duplicates');
}
export function certificateToken(value) {
  if (typeof value === 'string' && value.trim().split('.').length === 3) return value.trim();
  for (const key of ['certificate', 'registrationCertificate', 'token', 'jwt']) if (typeof value?.[key] === 'string') return certificateToken(value[key]);
  return null;
}
async function atomic(file, value) {
  const temporary = `${file}.${randomUUID()}.tmp`;
  await fs.writeFile(temporary, value, { mode: 0o600 });
  await fs.rename(temporary, file);
}
async function readManifest(file, entityId, serviceId) {
  try {
    const manifest = JSON.parse(await fs.readFile(file, 'utf8'));
    if (manifest.version !== 1 || manifest.entityId !== entityId || manifest.serviceId !== serviceId || !manifest.scenarios) throw new Error('Manifest identity or version mismatch');
    return manifest;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return { version: 1, entityId, serviceId, scenarios: {} };
  }
}

// request(method, relativePath, body) returns parsed JSON or a compact JWT.
// verify(token, bindings) must cryptographically verify signature, registrar trust,
// scope and WRPAC identity, returning {payload, intendedUse}.
export async function provisionWrprcs({ bodies, manifestPath, request, verify, entityId = RAIDiam_ENTITY, serviceId = RAIDiam_SERVICE, registryUrl, now = () => new Date() }) {
  const directory = path.dirname(manifestPath);
  await fs.mkdir(directory, { recursive: true });
  // Refuse concurrent issuers: two runs must never race registration creation.
  const lock = await fs.open(`${manifestPath}.lock`, 'wx', 0o600);
  try {
    const manifest = await readManifest(manifestPath, entityId, serviceId);
    const prefix = `/eudi/wrp/${encodeURIComponent(entityId)}/services/${encodeURIComponent(serviceId)}`;
    const save = async () => {
      try { await fs.copyFile(manifestPath, `${manifestPath}.${Date.now()}.${randomUUID()}.bak`); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      await atomic(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    };
    const results = [];
    for (const { scenario, body } of bodies) {
      try {
        if (!/^[a-z0-9-]+$/.test(scenario)) throw new Error('Invalid scenario identifier');
        const hash = declarationHash(body);
        let entry = manifest.scenarios[scenario];
        if (entry?.declarationHash === hash && entry.certificateFile) {
          try {
            const token = await fs.readFile(path.join(directory, entry.certificateFile), 'utf8');
            await verify(token.trim(), { entityId, serviceId, intendedUseId: entry.intendedUseId, declaration: body });
            results.push({ scenario, status: 'reused' });
            continue;
          } catch { /* Renew using the saved registration, retaining old token. */ }
        }
        let intendedUseId = entry?.declarationHash === hash ? entry.intendedUseId : null;
        if (!intendedUseId) {
          const remote = listItems(await request('GET', `${prefix}/intended-uses`));
          const matches = remote.filter(item => !item.revokedAt && declarationHash(declaration(item)) === hash);
          if (matches.length > 1) throw new Error('Ambiguous matching intended uses in registry');
          const registered = matches[0] ?? await request('POST', `${prefix}/intended-uses`, body);
          intendedUseId = identifier(registered);
          if (!intendedUseId || typeof intendedUseId !== 'string') throw new Error('Registry omitted intended-use identifier');
          entry = { declarationHash: hash, intendedUseId };
          manifest.scenarios[scenario] = entry;
          await save(); // Persist the registration before attempting issuance.
        }
        // Reconcile previously issued certificates before issuing a replacement.
        const certificates = listItems(await request('GET', `${prefix}/registration-certificates`));
        let verified, token;
        const bindings = { entityId, serviceId, intendedUseId, declaration: body };
        for (const cert of certificates.filter(cert => (cert.intendedUseId ?? cert.intendedUseIdentifier ?? cert.coversIntendedUseId) === intendedUseId && !cert.revokedAt)) {
          if (['revoked', 'suspended', 'deleted'].includes(String(cert.status).toLowerCase())) throw new Error('Registry existing certificate is not active');
          const detail = certificateToken(cert) ? cert : await request('GET', `${prefix}/registration-certificates/${encodeURIComponent(cert.registrationCertificateIdentifier ?? cert.certId ?? cert.id)}`);
          const candidate = certificateToken(detail);
          if (candidate) {
            const quarantineFile = `${scenario}.unverified.${createHash('sha256').update(candidate).digest('hex')}.jwt`;
            await atomic(path.join(directory, quarantineFile), `${candidate}\n`);
            entry = { ...entry, quarantineFile, certificateId: cert.registrationCertificateIdentifier ?? cert.certId ?? cert.id, registryStatus: cert.status };
            manifest.scenarios[scenario] = entry;
            await save();
            try { verified = await verify(candidate, bindings); token = candidate; break; }
            catch (error) {
              // Expired tokens can be replaced. An untrusted or malformed live
              // certificate requires investigation, not another issuance.
              if (error.code !== 'ERR_JWT_EXPIRED') throw error;
            }
          }
        }
        if (!token) {
          const issued = await request('POST', `${prefix}/registration-certificates`, { intendedUseId });
          const certificateId = issued?.registrationCertificateIdentifier ?? issued?.certId ?? issued?.id;
          const detail = certificateToken(issued) ? issued : certificateId ? await request('GET', `${prefix}/registration-certificates/${encodeURIComponent(certificateId)}`) : null;
          token = certificateToken(detail);
          if (!token) throw new Error('Registry omitted signed registration token or certificate identifier');
          const quarantineFile = `${scenario}.unverified.${createHash('sha256').update(token).digest('hex')}.jwt`;
          await atomic(path.join(directory, quarantineFile), `${token}\n`);
          entry = { ...entry, quarantineFile, certificateId, registryStatus: issued?.status };
          manifest.scenarios[scenario] = entry;
          await save();
          verified = await verify(token, bindings);
        }
        const dataset = {
          identifier: entityId, serviceId, srvDescription: verified.payload.srv_description ?? verified.payload.srvDescription ?? [body.purpose], registryURI: verified.payload.registry_uri ?? verified.payload.registryURI ?? registryUrl,
          intendedUseIdentifier: intendedUseId, purpose: body.purpose, policyURI: body.privacyPolicy[0].url,
        };
        if (!Number.isFinite(verified?.payload?.exp)) throw new Error('Verified certificate omitted expiry');
        const certificateFile = `${scenario}.${now().getTime()}.${randomUUID()}.jwt`;
        await atomic(path.join(directory, certificateFile), `${token}\n`);
        manifest.scenarios[scenario] = { ...entry, registrarDataset: dataset, certificateFile, expiresAt: new Date(verified.payload.exp * 1000).toISOString(), activatedAt: now().toISOString() };
        await save();
        results.push({ scenario, status: 'provisioned' });
      } catch (error) {
        // No remote response body or token is retained in diagnostics.
        results.push({ scenario, status: 'failed', error: error.safeMessage ?? (/^(WRPRC:|Registry|Unrecognized|Ambiguous|Invalid|Verified|Manifest)/.test(error.message) ? error.message : 'Provisioning failed; inspect configuration and registry support') });
      }
    }
    return { manifest, results, ok: results.every(result => result.status !== 'failed') };
  } finally { await lock.close(); await fs.unlink(`${manifestPath}.lock`); }
}
