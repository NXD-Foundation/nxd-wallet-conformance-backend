import { expect } from 'chai';
import { resolveProvisioningWrpacPath } from '../scripts/provisionRaidiamWrprc.js';
import { KEY_MATERIAL_PATHS } from '../utils/keyMaterialPaths.js';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { activateQuarantinedWrprcs, provisionWrprcs, declarationHash, listItems, certificateToken } from '../utils/raidiamProvisioning.js';

const body = { purpose: [{ lang: 'en', content: 'Testing' }], privacyPolicy: [{ type: 'Privacy Statement', url: 'https://www.aegean.gr/' }], credentials: [{ format: 'dc+sd-jwt', meta: { vct_values: ['pid'] }, claims: [{ path: ['family_name'] }] }] };
describe('Raidiam registration provisioning regressions', () => {
  let directory, options, calls, remoteUses, remoteCerts, nextId;
  beforeEach(async () => {
    directory = await fs.mkdtemp(path.join(os.tmpdir(), 'wrprc-provision-'));
    calls = []; remoteUses = []; remoteCerts = []; nextId = 0;
    options = {
      bodies: [{ scenario: 'pid-basic', body }], manifestPath: path.join(directory, 'manifest.json'), registryUrl: 'https://registry.example/service',
      verify: async (token, bindings) => {
        if (token === 'bad.jwt.signature') throw new Error('WRPRC: signature invalid');
        expect(bindings.intendedUseId).to.equal('iu-1');
        return { payload: { exp: 2000000000 }, intendedUse: body };
      },
      request: async (method, resource, data) => {
        calls.push({ method, resource, data });
        if (resource.endsWith('/intended-uses')) {
          if (method === 'GET') return remoteUses;
          const registered = { ...data, intendedUseIdentifier: `iu-${++nextId}` };
          remoteUses.push(registered); return registered;
        }
        if (resource.endsWith('/registration-certificates')) {
          if (method === 'GET') return remoteCerts;
          const certificate = { id: `certificate-${nextId}`, intendedUseId: data.intendedUseId, certificate: 'signed.jwt.signature' };
          remoteCerts.push(certificate); return { id: certificate.id };
        }
        return remoteCerts.find(cert => resource.endsWith(`/${cert.id}`));
      },
    };
  });
  afterEach(async () => { await fs.rm(directory, { recursive: true, force: true }); });
  it('persists verified tokens and matching scenario bindings, then reuses without remote writes', async () => {
    const initial = await provisionWrprcs(options);
    expect(initial.ok).to.equal(true);
    const entry = initial.manifest.scenarios['pid-basic'];
    expect(entry.intendedUseId).to.equal('iu-1');
    expect(entry.declarationHash).to.equal(declarationHash(body));
    expect(entry.registrarDataset.policyURI).to.equal('https://www.aegean.gr/');
    expect(entry.registrarDataset.srvDescription).to.deep.equal([{ lang: 'en', value: 'Testing' }]);
    expect(entry.registrarDataset.purpose).to.deep.equal([{ lang: 'en', value: 'Testing' }]);
    expect(await fs.readFile(path.join(directory, entry.certificateFile), 'utf8')).to.equal('signed.jwt.signature\n');
    calls.length = 0;
    const repeated = await provisionWrprcs(options);
    expect(repeated.results[0].status).to.equal('reused');
    expect(calls).to.have.length(0);
  });
  it('reconciles live registrations and certificates after local-state loss without duplicates', async () => {
    remoteUses.push({ ...body, intendedUseIdentifier: 'iu-1' });
    remoteCerts.push({ certId: 'existing', coversIntendedUseId: 'iu-1', registrationCertificate: 'signed.jwt.signature', status: 'Active' });
    const result = await provisionWrprcs(options);
    expect(result.ok).to.equal(true);
    expect(calls.every(call => call.method === 'GET')).to.equal(true);
  });
  it('keeps a saved intended-use identifier after certificate issuance fails', async () => {
    const request = options.request;
    options.request = async (...args) => {
      if (args[0] === 'POST' && args[1].endsWith('/registration-certificates')) { const error = new Error('secret bearer-token response'); error.safeMessage = 'Registry POST failed HTTP 400'; throw error; }
      return request(...args);
    };
    const failed = await provisionWrprcs(options);
    expect(failed.ok).to.equal(false);
    expect(JSON.stringify(failed.results)).not.to.include('secret');
    expect(failed.manifest.scenarios['pid-basic'].intendedUseId).to.equal('iu-1');
    options.request = request; calls.length = 0;
    expect((await provisionWrprcs(options)).ok).to.equal(true);
    expect(calls.some(call => call.method === 'POST' && call.resource.endsWith('/intended-uses'))).to.equal(false);
  });
  it('rejects malformed certificates before activation and continues independent scenarios', async () => {
    const signing = { ...body, purpose: [{ lang: 'en', content: 'Signing' }] };
    options.bodies.unshift({ scenario: 'qualified-signing', body: signing });
    options.verify = async (token, bindings) => {
      if (bindings.declaration.purpose[0].content === 'Signing') throw new Error('WRPRC: malformed certificate');
      return { payload: { exp: 2000000000 }, intendedUse: body };
    };
    const result = await provisionWrprcs(options);
    expect(result.ok).to.equal(false);
    expect(result.results.map(item => item.status)).to.deep.equal(['failed', 'provisioned']);
    expect(result.manifest.scenarios['qualified-signing'].certificateFile).to.equal(undefined);
    expect(result.manifest.scenarios['pid-basic'].certificateFile).to.be.a('string');
  });
  it('refuses unrecognized or ambiguous remote lists rather than creating duplicates', async () => {
    remoteUses.push({ ...body, intendedUseIdentifier: 'iu-1' }, { ...body, intendedUseIdentifier: 'iu-2' });
    const result = await provisionWrprcs(options);
    expect(result.results[0].error).to.include('Ambiguous');
    expect(calls.some(call => call.method === 'POST')).to.equal(false);
    expect(() => listItems({ unknown: [] })).to.throw('Unrecognized');
  });
  it('retains historical token artifacts when replacing an invalid local token', async () => {
    const first = await provisionWrprcs(options);
    const original = first.manifest.scenarios['pid-basic'].certificateFile;
    await fs.writeFile(path.join(directory, original), 'bad.jwt.signature');
    const replacement = await provisionWrprcs(options);
    expect(replacement.ok).to.equal(true);
    expect(replacement.manifest.scenarios['pid-basic'].certificateFile).not.to.equal(original);
    expect(await fs.readFile(path.join(directory, original), 'utf8')).to.equal('bad.jwt.signature');
    expect((await fs.readdir(directory)).some(file => file.endsWith('.bak'))).to.equal(true);
  });
  it('does not issue duplicates when an existing remote certificate fails trust validation', async () => {
    remoteUses.push({ ...body, intendedUseIdentifier: 'iu-1' });
    remoteCerts.push({ certId: 'existing', coversIntendedUseId: 'iu-1', registrationCertificate: 'signed.jwt.signature', status: 'Active' });
    options.verify = async () => { throw new Error('WRPRC: registrar trust rejected (ANCHOR_MISMATCH)'); };
    const result = await provisionWrprcs(options);
    expect(result.ok).to.equal(false);
    expect(result.results[0].error).to.include('ANCHOR_MISMATCH');
    expect(result.manifest.scenarios['pid-basic'].certificateFile).to.equal(undefined);
    expect(result.manifest.scenarios['pid-basic'].certificateId).to.equal('existing');
    expect(await fs.readFile(path.join(directory, result.manifest.scenarios['pid-basic'].quarantineFile), 'utf8')).to.equal('signed.jwt.signature\n');
    expect(calls.some(call => call.method === 'POST')).to.equal(false);
  });
  it('refuses registry-revoked certificates without issuing a duplicate', async () => {
    remoteUses.push({ ...body, intendedUseIdentifier: 'iu-1' });
    remoteCerts.push({ certId: 'existing', coversIntendedUseId: 'iu-1', registrationCertificate: 'signed.jwt.signature', status: 'Revoked' });
    const result = await provisionWrprcs(options);
    expect(result.results[0].error).to.include('not active');
    expect(calls.some(call => call.method === 'POST')).to.equal(false);
  });
  it('blocks concurrent provisioners rather than racing remote registration', async () => {
    await fs.writeFile(`${options.manifestPath}.lock`, '');
    let error;
    try { await provisionWrprcs(options); } catch (caught) { error = caught; }
    expect(error.code).to.equal('EEXIST');
    expect(calls).to.have.length(0);
  });
  async function retainUntrustedToken() {
    const originalVerify = options.verify;
    options.verify = async () => { throw new Error('WRPRC: registrar not yet trusted'); };
    const retained = await provisionWrprcs(options);
    expect(retained.ok).to.equal(false);
    options.verify = originalVerify; calls.length = 0;
    return retained;
  }
  it('activates a retained token only after verification, without registration or issuance calls', async () => {
    const retained = await retainUntrustedToken();
    const quarantine = retained.manifest.scenarios['pid-basic'].quarantineFile;
    const activated = await activateQuarantinedWrprcs(options);
    expect(activated.ok).to.equal(true);
    const entry = activated.manifest.scenarios['pid-basic'];
    expect(await fs.readFile(path.join(directory, entry.certificateFile), 'utf8')).to.equal('signed.jwt.signature\n');
    expect(await fs.readFile(path.join(directory, quarantine), 'utf8')).to.equal('signed.jwt.signature\n');
    expect(calls).to.have.length(0);
  });
  it('keeps rejected or expired tokens quarantined and never issues replacements during activation', async () => {
    await retainUntrustedToken();
    for (const code of [undefined, 'ERR_JWT_EXPIRED']) {
      options.verify = async () => { const error = new Error('WRPRC: rejected token'); error.code = code; throw error; };
      const result = await activateQuarantinedWrprcs(options);
      expect(result.ok).to.equal(false);
      expect(result.manifest.scenarios['pid-basic']).not.to.have.property('certificateFile');
      expect(result.manifest.scenarios['pid-basic'].quarantineFile).to.be.a('string');
    }
    expect(calls).to.have.length(0);
  });
  it('does not register a changed declaration while activating quarantine', async () => {
    await retainUntrustedToken();
    options.bodies[0].body = { ...body, purpose: [{ lang: 'en', content: 'Changed purpose' }] };
    const result = await activateQuarantinedWrprcs(options);
    expect(result.ok).to.equal(false);
    expect(result.manifest.scenarios['pid-basic']).not.to.have.property('certificateFile');
    expect(calls).to.have.length(0);
  });
  it('uses canonical declaration hashes independent of object key order', () => {
    expect(declarationHash({ a: 1, b: { x: 2, y: 3 } })).to.equal(declarationHash({ b: { y: 3, x: 2 }, a: 1 }));
    expect(certificateToken({ certificate: 'signed.jwt.signature' })).to.equal('signed.jwt.signature');
    expect(certificateToken({ certificate: 'not-a-jwt' })).to.equal(null);
  });
});


describe('Raidiam provisioning WRPAC configuration', () => {
  it('uses the same ES256 certificate as verifier signing by default', () => {
    const root = '/deployment';
    expect(resolveProvisioningWrpacPath({}, root)).to.equal(path.resolve(root, KEY_MATERIAL_PATHS.verifierTrustWrpacCertificate));
    expect(resolveProvisioningWrpacPath({}, root)).to.include('uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem');
  });
  it('honors the verifier certificate override and an explicit provisioning override', () => {
    expect(resolveProvisioningWrpacPath({ TRUST_WRPAC_CERT_PATH: 'custom.pem' }, '/deployment')).to.equal('/deployment/custom.pem');
    expect(resolveProvisioningWrpacPath({ TRUST_WRPAC_CERT_PATH: 'custom.pem', RAIDIAM_WRPAC: '/explicit.pem' }, '/deployment')).to.equal('/explicit.pem');
  });
});
