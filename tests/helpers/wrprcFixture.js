import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import forge from 'node-forge';
import { SignJWT, importPKCS8 } from 'jose';
import { declarationHash } from '../../utils/raidiamProvisioning.js';

export const WRPRC_ENTITY = 'VATEL-090264862';
export const WRPRC_SERVICE = '4c3ecfb0-76ff-4eea-8e51-c8fac931e186';

/** Isolated local registrar; never uses the deployment private keys. */
export async function createWrprcFixture() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'wrprc-requests-'));
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date(Date.now() - 60000);
  certificate.validity.notAfter = new Date(Date.now() + 86400000);
  const subject = [{ name: 'commonName', value: 'Test WRPRC Registrar' }];
  certificate.setSubject(subject); certificate.setIssuer(subject);
  certificate.setExtensions([{ name: 'basicConstraints', cA: true }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  const x5c = [forge.pki.certificateToPem(certificate).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')];
  const key = await importPKCS8(forge.pki.privateKeyInfoToPem(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey))), 'RS256');
  const declarations = {};
  const manifest = { version: 1, entityId: WRPRC_ENTITY, serviceId: WRPRC_SERVICE, scenarios: {} };
  async function token(scenario, overrides = {}) {
    const declaration = declarations[scenario];
    return new SignJWT({ sub: WRPRC_ENTITY, serviceId: WRPRC_SERVICE, intendedUseIdentifier: `use-${scenario}`,
      entitlements: ['https://uri.etsi.org/19475/Entitlement/Service_Provider'], ...declaration, ...overrides })
      .setProtectedHeader({ alg: 'RS256', typ: 'rc-wrp+jwt', x5c }).setIssuedAt().setExpirationTime(overrides.exp ?? '10m').sign(key);
  }
  for (const filename of (await fs.readdir('data/trust/intended_uses')).filter(f => f.endsWith('.json'))) {
    const scenario = filename.slice(0, -5);
    const declaration = JSON.parse(await fs.readFile(path.join('data/trust/intended_uses', filename), 'utf8'));
    declarations[scenario] = declaration;
    const certificateFile = `${scenario}.jwt`;
    await fs.writeFile(path.join(directory, certificateFile), await token(scenario));
    manifest.scenarios[scenario] = { declarationHash: declarationHash(declaration), intendedUseId: `use-${scenario}`, certificateFile,
      registrarDataset: { identifier: WRPRC_ENTITY, serviceId: WRPRC_SERVICE, intendedUseIdentifier: `use-${scenario}`,
        registryURI: 'https://registrar.example.test/api', srvDescription: [{ lang: 'en', value: scenario }],
        purpose: declaration.purpose, policyURI: declaration.privacyPolicy[0].url } };
  }
  const manifestPath = path.join(directory, 'manifest.json');
  async function save() { await fs.writeFile(manifestPath, JSON.stringify(manifest)); }
  await save();
  return { directory, manifestPath, manifest, declarations, token, save,
    cleanup: () => fs.rm(directory, { recursive: true, force: true }) };
}
