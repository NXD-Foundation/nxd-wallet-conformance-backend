import fs from 'node:fs/promises';
import path from 'node:path';
import { X509Certificate } from 'node:crypto';
import { verifyWrprc, assertQueryScope, assertRegistrarDataset, encodeRegistrationCertificate } from './wrprc.js';
import { checkAccessCertificateTrust } from './trustFrameworkPolicy.js';
import { declarationHash, registrarDatasetForRegistration } from './raidiamProvisioning.js';

export const DEFAULT_WRPRC_MANIFEST = 'certs/raidiam/registration/manifest.json';
const DEFAULT_DECLARATIONS = 'data/trust/intended_uses';

export function wrpacEntityId(certificatePem) {
  const subject = new X509Certificate(certificatePem).subject;
  const match = subject.match(/(?:^|\n)(?:organizationIdentifier|2\.5\.4\.97|serialNumber)\s*=\s*([^\n]+)/i);
  if (!match) throw new Error('WRPRC: WRPAC has no registered entity identifier');
  return match[1].trim();
}

function normalizedCredentials(query) {
  return JSON.stringify((query?.credentials || []).map(c => ({
    format: c.format, meta: c.meta,
    claims: (c.claims || []).map(a => ({ path: a.path })),
  })));
}

/** Exact built-in query recognition is only a default, never subset/purpose inference. */
export async function resolveWrprcScenario({ scenario, cs07ProfileId, cs03Signing, query, declarationsDir = DEFAULT_DECLARATIONS }) {
  const selected = scenario || cs07ProfileId || (cs03Signing ? 'qualified-signing' : null);
  if (selected) {
    if (!/^[a-z0-9-]+$/.test(selected)) throw new Error('WRPRC: invalid scenario');
    return selected === 'ts12-payment' ? 'ts12-dpc' : selected;
  }
  const names = (await fs.readdir(declarationsDir)).filter(name => name.endsWith('.json'));
  const matches = [];
  for (const name of names) {
    const declaration = JSON.parse(await fs.readFile(path.join(declarationsDir, name), 'utf8'));
    if (normalizedCredentials(query) === normalizedCredentials(declaration)) matches.push(name.slice(0, -5));
  }
  if (matches.length !== 1) throw new Error('WRPRC: custom or ambiguous query requires wrprc_scenario');
  return matches[0];
}

// Registration metadata is independent of registration-certificate trust. The
// saved intended-use ID came from registration; descriptions and scope come from
// the submitted declaration. Never read quarantineFile to construct this data.
export async function selectRegistrarDataset({ scenario, cs07ProfileId, cs03Signing, query, certificatePem,
  manifestPath = process.env.TRUST_WRPRC_MANIFEST_PATH || DEFAULT_WRPRC_MANIFEST,
  declarationsDir = DEFAULT_DECLARATIONS }) {
  const scenarioId = await resolveWrprcScenario({ scenario, cs07ProfileId, cs03Signing, query, declarationsDir });
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  const entry = manifest.scenarios?.[scenarioId];
  if (manifest.version !== 1 || !entry?.intendedUseId) throw new Error(`WRPRC: no registered intended use for ${scenarioId}`);
  const declaration = JSON.parse(await fs.readFile(path.join(declarationsDir, `${scenarioId}.json`), 'utf8'));
  if (entry.declarationHash !== declarationHash(declaration)) throw new Error('WRPRC: declaration changed; reprovision scenario');
  const registrarDataset = entry.registrarDataset || registrarDatasetForRegistration({
    entityId: manifest.entityId, serviceId: manifest.serviceId, intendedUseId: entry.intendedUseId, body: declaration,
    registryUrl: process.env.RAIDIAM_REGISTRY_URI || `https://data.sandbox.eudi.raidiam.io/wrp/${encodeURIComponent(manifest.entityId)}/services/${encodeURIComponent(manifest.serviceId)}`,
  });
  const selection = { scenario: scenarioId, entityId: manifest.entityId, serviceId: manifest.serviceId,
    intendedUseId: entry.intendedUseId, declaration, registrarDataset };
  return { selection, ...validatePinnedRegistrarDataset({ selection, query, certificatePem }) };
}

export function validatePinnedRegistrarDataset({ selection, query, certificatePem }) {
  if (!selection?.intendedUseId || !selection?.serviceId || !selection?.declaration) throw new Error('WRPRC: pinned registrar dataset is missing');
  const entityId = wrpacEntityId(certificatePem);
  const serviceId = new X509Certificate(certificatePem).subject.match(/(?:^|\n)OU\s*=\s*([^\n]+)/)?.[1]?.trim();
  if (serviceId !== selection.serviceId) throw new Error('WRPRC: service does not match WRPAC');
  if (selection.entityId !== entityId) throw new Error('WRPRC: manifest entity does not match WRPAC');
  assertQueryScope(query, selection.declaration);
  assertRegistrarDataset(selection.registrarDataset, {
    registration: { sub: entityId }, intendedUse: selection.declaration, entityId,
    intendedUseId: selection.intendedUseId, serviceId,
  });
  return { verifierInfo: [{ format: 'registrar_dataset', data: selection.registrarDataset }] };
}

export async function validatePinnedWrprc({ selection, query, certificatePem, session, checkTrust, currentDate }) {
  if (!selection?.token || !selection?.intendedUseId || !selection?.serviceId) throw new Error('WRPRC: pinned registration is missing');
  const entityId = wrpacEntityId(certificatePem);
  const serviceId = new X509Certificate(certificatePem).subject.match(/(?:^|\n)OU\s*=\s*([^\n]+)/)?.[1]?.trim();
  if (serviceId !== selection.serviceId) throw new Error('WRPRC: service does not match WRPAC');
  if (selection.entityId !== entityId) throw new Error('WRPRC: manifest entity does not match WRPAC');
  const verified = await verifyWrprc(selection.token, {
    entityId, intendedUseId: selection.intendedUseId, serviceId: selection.serviceId, currentDate,
    checkTrust: checkTrust || (evidence => checkAccessCertificateTrust({ ...evidence, session })),
  });
  assertQueryScope(query, verified.intendedUse);
  assertRegistrarDataset(selection.registrarDataset, {
    registration: verified.payload, intendedUse: verified.intendedUse, entityId,
    intendedUseId: selection.intendedUseId, serviceId: selection.serviceId,
  });
  return {
    verifierInfo: [
      { format: 'registrar_dataset', data: selection.registrarDataset },
      { format: 'registration_cert', data: encodeRegistrationCertificate(selection.token) },
    ],
    trustDecision: verified.trustDecision,
  };
}

export async function selectWrprc({ scenario, cs07ProfileId, cs03Signing, query, certificatePem, session,
  manifestPath = process.env.TRUST_WRPRC_MANIFEST_PATH || DEFAULT_WRPRC_MANIFEST,
  declarationsDir, checkTrust, currentDate }) {
  const scenarioId = await resolveWrprcScenario({ scenario, cs07ProfileId, cs03Signing, query, declarationsDir });
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  const entry = manifest.scenarios?.[scenarioId];
  if (manifest.version !== 1 || !entry?.certificateFile) throw new Error(`WRPRC: no provisioned certificate for ${scenarioId}`);
  const declaration = JSON.parse(await fs.readFile(path.join(declarationsDir || DEFAULT_DECLARATIONS, `${scenarioId}.json`), 'utf8'));
  if (entry.declarationHash !== declarationHash(declaration)) throw new Error('WRPRC: declaration changed; reprovision scenario');
  const file = path.resolve(path.dirname(manifestPath), entry.certificateFile);
  const root = path.resolve(path.dirname(manifestPath));
  if (!file.startsWith(root + path.sep)) throw new Error('WRPRC: certificate must be inside manifest directory');
  const selection = {
    scenario: scenarioId, entityId: manifest.entityId, serviceId: manifest.serviceId,
    intendedUseId: entry.intendedUseId, registrarDataset: entry.registrarDataset,
    token: (await fs.readFile(file, 'utf8')).trim(),
  };
  const result = await validatePinnedWrprc({ selection, query, certificatePem, session, checkTrust, currentDate });
  return { selection, ...result };
}
