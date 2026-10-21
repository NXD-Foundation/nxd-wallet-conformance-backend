import { loadVerifierP12 } from "../utils/cryptoUtils.js";
import { assertX509HashLeafMatchesClientId } from "../utils/cs02ClientIdBinding.js";
import { expect } from 'chai';
import { evaluateTrust } from '../trust/evaluate.js';
import { loadTrustProfile } from '../trust/profile.js';
import { certificateFingerprint } from '../trust/crypto.js';
import express from 'express';
import request from 'supertest';
import fs from 'node:fs/promises';
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from 'jose';
import x509Router from '../routes/verify/x509Routes.js';
import vpStandardRouter from '../routes/verify/vpStandardRoutes.js';
import { CONFIG } from '../utils/routeUtils.js';
import { getVPSession, storeVPSession } from '../services/cacheServiceRedis.js';
import { setTrustResolverForTests, clearTrustResolverForTests } from '../utils/trustFrameworkPolicy.js';
import { resolveWrprcScenario, selectWrprc, selectRegistrarDataset, validatePinnedRegistrarDataset } from '../utils/wrprcRegistry.js';
import { decodeRegistrationCertificate } from '../utils/wrprc.js';
import { createWrprcFixture, WRPRC_ENTITY } from './helpers/wrprcFixture.js';

const trusted = async () => ({ trusted: true, state: 'trusted', reasonCode: 'TRUSTED', evidence: {} });

describe('WRPRC signed presentation request integration', function () {
  this.timeout(20000);
  let fixture, previousEnv, previousServer, app;
  before(async () => {
    previousEnv = { ...process.env }; previousServer = CONFIG.SERVER_URL;
    Object.assign(process.env, { NODE_ENV: 'test', DC_API_RP_ORIGINS: 'https://dev-i4mlab.aegean.gr', DC_API_RP_PROFILES: 'pid-basic,ts12-dpc', VERIFIER_CS02_COMPATIBILITY: 'false' });
    CONFIG.SERVER_URL = 'https://dev-i4mlab.aegean.gr';
    app = express(); app.use(express.json()); app.use(express.urlencoded({ extended: false })); app.use(x509Router); app.use(vpStandardRouter);
    const { default: dcApiRouter } = await import('../routes/verify/dcApiRoutes.js?wrprc-integration'); app.use(dcApiRouter);
  });
  beforeEach(async () => {
    fixture = await createWrprcFixture(); process.env.TRUST_WRPRC_MANIFEST_PATH = fixture.manifestPath;
    setTrustResolverForTests({ resolve: trusted });
  });
  afterEach(async () => { clearTrustResolverForTests(); await fixture.cleanup(); });
  after(() => {
    CONFIG.SERVER_URL = previousServer;
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
  });
  async function create(sessionId, trust = true) {
    const res = await request(app).get('/generateVPRequestDCQL').query({ sessionId, ...(trust ? { trustFramework: 'true' } : {}) });
    expect(res.status, JSON.stringify(res.body)).to.equal(200); return res;
  }
  async function retrieve(sessionId) {
    return request(app).post(`/x509VPrequest/${sessionId}`).type('form').send({ wallet_nonce: 'wrprc-wallet-nonce' });
  }
  async function verifyJar(token, eudiP12 = false) {
    const header = decodeProtectedHeader(token);
    expect(header.alg).to.equal('ES256');
    const expectedLeaf = eudiP12 ? loadVerifierP12().certChain[0] : (await fs.readFile('certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem', 'utf8'))
      .match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/)[1].replace(/\s+/g, '');
    expect(header.x5c[0]).to.equal(expectedLeaf);
    assertX509HashLeafMatchesClientId(decodeJwt(token).client_id, header.x5c[0]);
    return (await jwtVerify(token, await importX509(`-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`, header.alg))).payload;
  }
  it('signs the matching base64url WRPRC and registrar dataset into redirect requests', async () => {
    await create('wrprc-redirect'); const res = await retrieve('wrprc-redirect');
    expect((await getVPSession('wrprc-redirect')).verifier_signing_profile).to.equal('raidiam');
    expect(res.status, res.text).to.equal(200);
    const payload = await verifyJar(res.text);
    expect(payload.wallet_nonce).to.equal('wrprc-wallet-nonce');
    expect(payload.verifier_info.map(v => v.format)).to.deep.equal(['registrar_dataset', 'registration_cert']);
    expect(payload.verifier_info[0].data.intendedUseIdentifier).to.equal('use-pid-basic');
    const registration = decodeJwt(decodeRegistrationCertificate(payload.verifier_info[1].data));
    expect(registration.sub).to.equal(WRPRC_ENTITY);
    expect(registration.credentials).to.deep.equal(fixture.declarations['pid-basic'].credentials);
  });
  it('pins selection across manifest replacement instead of silently switching registrations', async () => {
    await create('wrprc-pinned');
    const first = await retrieve('wrprc-pinned');
    fixture.manifest.scenarios = {}; await fixture.save();
    const again = await retrieve('wrprc-pinned'); expect(again.status, again.text).to.equal(200);
    expect(decodeJwt(again.text).verifier_info).to.deep.equal(decodeJwt(first.text).verifier_info);
  });
  it('rechecks expiry when an existing request URI is retrieved', async () => {
    await create('wrprc-expiry');
    const session = await getVPSession('wrprc-expiry');
    session.wrprcSelection.token = await fixture.token('pid-basic', { exp: 1 });
    await storeVPSession('wrprc-expiry', session);
    const res = await retrieve('wrprc-expiry'); expect(res.status).to.equal(500);
    expect(res.body).not.to.have.property('request');
    expect(res.text).not.to.match(/^eyJ/);
  });
  it('fails trust-enabled request creation when the certificate store is missing', async () => {
    process.env.TRUST_WRPRC_MANIFEST_PATH = `${fixture.directory}/missing.json`;
    const res = await request(app).get('/generateVPRequestDCQL').query({ sessionId: 'wrprc-missing', trustFramework: 'true' });
    expect(res.status).to.equal(500); expect(JSON.stringify(res.body)).to.include('ENOENT');
  });
  async function quarantineScenario(scenario = 'pid-basic') {
    const entry = fixture.manifest.scenarios[scenario];
    await fs.unlink(`${fixture.directory}/${entry.certificateFile}`);
    entry.quarantineFile = 'quarantined-token-must-not-be-read.jwt';
    delete entry.certificateFile;
    delete entry.registrarDataset;
    await fixture.save();
  }
  it('ordinary CS-02 uses EUDI P12 without Raidiam metadata or registration dependencies', async () => {
    await quarantineScenario();
    fixture.manifest.scenarios = {}; await fixture.save();
    await create('eudi-p12-no-registration', false);
    const first = await retrieve('eudi-p12-no-registration');
    expect(first.status, first.text).to.equal(200);
    const payload = await verifyJar(first.text, true);
    expect(payload).not.to.have.property('verifier_info');
    expect(decodeProtectedHeader(first.text).x5c).to.deep.equal([loadVerifierP12().certChain[0]]);
    const session = await getVPSession('eudi-p12-no-registration');
    expect(session.verifier_signing_profile).to.equal('eudi-p12');
    expect(session).not.to.have.property('wrprcSelection');
    expect(session).not.to.have.property('registrarDatasetSelection');
    const again = await retrieve('eudi-p12-no-registration');
    expect(again.status).to.equal(200);
    expect(decodeProtectedHeader(again.text).x5c).to.deep.equal(decodeProtectedHeader(first.text).x5c);
  });
  it('includes the registrar dataset in a trust-disabled CS-07 signed descriptor without opening quarantine', async () => {
    await quarantineScenario();
    const res = await request(app).post('/vp/dc-api/request').set('Origin', 'https://dev-i4mlab.aegean.gr')
      .send({ sessionId: 'registrar-dc-api', profile: 'pid-basic' });
    expect(res.status, JSON.stringify(res.body)).to.equal(200);
    const payload = await verifyJar(res.body.request.data.request);
    expect(payload.verifier_info.map(entry => entry.format)).to.deep.equal(['registrar_dataset']);
    expect(payload.verifier_info[0].data.intendedUseIdentifier).to.equal('use-pid-basic');
  });
  it('still rejects trust-enabled requests with quarantined WRPRCs', async () => {
    await quarantineScenario();
    const res = await request(app).get('/generateVPRequestDCQL').query({ sessionId: 'wrprc-quarantined', trustFramework: 'true' });
    expect(res.status).to.equal(500); expect(res.text).to.include('no provisioned certificate');
  });
  it('includes the same selected registration in the CS-07 signed descriptor', async () => {
    const res = await request(app).post('/vp/dc-api/request?trustFramework=true').set('Origin', 'https://dev-i4mlab.aegean.gr').send({ sessionId: 'wrprc-dc-api', profile: 'pid-basic' });
    expect(res.status, JSON.stringify(res.body)).to.equal(200);
    const payload = await verifyJar(res.body.request.data.request);
    expect(payload.verifier_info[0].data.intendedUseIdentifier).to.equal('use-pid-basic');
    expect(decodeJwt(decodeRegistrationCertificate(payload.verifier_info[1].data)).sub).to.equal(WRPRC_ENTITY);
  });
  it('does not fall back to dataset-only success when the registration signer is untrusted', async () => {
    setTrustResolverForTests({ resolve: async ({ role }) => role === 'wrpac-provider'
      ? trusted() : { trusted: false, state: 'not_trusted', reasonCode: 'ENTITY_NOT_LISTED' } });
    const res = await request(app).get('/generateVPRequestDCQL').query({ sessionId: 'registrar-untrusted', trustFramework: 'true' });
    expect(res.status).to.equal(500); expect(res.text).to.include('registration signing chain is not trusted');
  });
  async function useListedSigner(keyUsage) {
    await fixture.cleanup(); fixture = await createWrprcFixture({ ca: false, keyUsage });
    process.env.TRUST_WRPRC_MANIFEST_PATH = fixture.manifestPath;
    const profile = await loadTrustProfile('data/trust/webuild-wp4-pilot.json');
    const accessPem = await fs.readFile('certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem', 'utf8');
    const snapshot = { profile, profileId: profile.id,
      lotl: { source: { url: 'https://example.test/lotl' }, format: 'json', scheme: { sequence: 1 }, signer: { fingerprint: 'test-pinned' } },
      lists: Object.fromEntries([['wrpac-provider', accessPem], ['wrprc-provider', fixture.signerCertificatePem]].map(([role, pem]) => [role, [{
        source: { url: `https://example.test/${role}` }, format: 'xml', scheme: { sequence: 1 }, entities: [{ id: role, services: [{
          type: role, status: 'valid', certificates: [certificateFingerprint(pem)], certificatePems: [pem],
        }] }],
      }]])) };
    setTrustResolverForTests({ resolve: async ({ role, operation, presentedIdentity, credentialContext }) =>
      evaluateTrust({ snapshot, role, operation, presentedIdentity, credentialContext }) });
    return snapshot;
  }
  it('does not apply the absent-Key-Usage exception to WRPAC validation', async () => {
    const snapshot = await useListedSigner();
    const certificatePem = fixture.signerCertificatePem;
    const service = snapshot.lists['wrpac-provider'][0].entities[0].services[0];
    service.certificates = [certificateFingerprint(certificatePem)]; service.certificatePems = [certificatePem];
    const result = evaluateTrust({ snapshot, role: 'wrpac-provider', presentedIdentity: {
      certificateFingerprint: certificateFingerprint(certificatePem), certificateChain: [certificatePem],
    } });
    expect(result).to.include({ trusted: false, reasonCode: 'CERTIFICATE_PATH_INVALID' });
  });
  it('accepts and retrieves a WRPRC whose directly listed signer omits Key Usage', async () => {
    await useListedSigner();
    await create('wrprc-listed-no-ku');
    const response = await retrieve('wrprc-listed-no-ku');
    expect(response.status, response.text).to.equal(200);
    expect((await verifyJar(response.text)).verifier_info.map(entry => entry.format)).to.deep.equal(['registrar_dataset', 'registration_cert']);
    const session = await getVPSession('wrprc-listed-no-ku');
    expect(session.registrationCertificateTrust.trusted).to.equal(true);
    expect(session.registrationCertificateTrust.evidence.certificatePath.keyUsage).to.equal('absent-directly-listed-signer');
  });
  it('rejects a WRPRC whose directly listed signer explicitly forbids digital signatures', async () => {
    await useListedSigner({ keyEncipherment: true });
    const response = await request(app).get('/generateVPRequestDCQL').query({ sessionId: 'wrprc-listed-denied-ku', trustFramework: 'true' });
    expect(response.status).to.equal(500); expect(response.text).to.include('registration signing chain is not trusted');
  });
  it('keeps payment overrides within the configured final DPC query and certificate', async () => {
    const res = await request(app).post('/vp/dc-api/request?trustFramework=true').set('Origin', 'https://dev-i4mlab.aegean.gr').send({
      sessionId: 'wrprc-payment-override', profile: 'ts12-dpc', attestation_type: 'sca-user', transaction_id: 'payment-regression',
      merchant: 'Test Shop', payee_id: 'shop-1', amount: '12.34', currency: 'EUR',
    });
    expect(res.status, JSON.stringify(res.body)).to.equal(200);
    const payload = await verifyJar(res.body.request.data.request);
    expect(payload.dcql_query.credentials[0].meta.vct_values).to.deep.equal(['https://webuildconsortium.eu/sca/sca-card-dpc/1.0']);
    expect(payload.verifier_info[0].data.intendedUseIdentifier).to.equal('use-ts12-dpc');
    const certificatePem = await fs.readFile('certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem', 'utf8');
    let failure;
    try { await selectWrprc({ cs07ProfileId: 'ts12-dpc', query: { credentials: fixture.declarations['ts12-user'].credentials }, certificatePem, manifestPath: fixture.manifestPath, checkTrust: trusted }); }
    catch (error) { failure = error; }
    expect(failure?.message).to.include('exceeds intended-use');
  });
  it('rejects an explicit narrow scenario for a broader custom query', async () => {
    const certificatePem = await fs.readFile('certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem', 'utf8');
    const query = { credentials: [{ ...fixture.declarations['pid-basic'].credentials[0], claims: [{ path: ['family_name'] }, { path: ['picture'] }] }] };
    let failure;
    try { await selectWrprc({ scenario: 'pid-basic', query, certificatePem, manifestPath: fixture.manifestPath, checkTrust: trusted }); }
    catch (error) { failure = error; }
    expect(failure?.message).to.include('exceeds intended-use');
    const res = await request(app).get('/vp/request').query({ session_id: 'wrprc-narrow-override', credential_profile: 'arf-pid', wrprc_scenario: 'pid-basic', trustFramework: 'true' });
    expect(res.status).to.equal(500); expect(JSON.stringify(res.body)).to.include('exceeds intended-use');
  });
  it('rejects a manifest with a different service identity from the WRPAC', async () => {
    fixture.manifest.serviceId = 'unrelated-service'; await fixture.save();
    const res = await request(app).get('/generateVPRequestDCQL').query({ sessionId: 'wrprc-wrong-service', trustFramework: 'true' });
    expect(res.status).to.equal(500); expect(JSON.stringify(res.body)).to.include('service does not match WRPAC');
  });
  it('validates metadata scope and identity without requiring or reading a certificate', async () => {
    await quarantineScenario();
    const certificatePem = await fs.readFile('certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem', 'utf8');
    const query = { credentials: fixture.declarations['pid-basic'].credentials };
    const options = { scenario: 'pid-basic', query, certificatePem, manifestPath: fixture.manifestPath };
    const result = await selectRegistrarDataset(options);
    expect(result.verifierInfo.map(entry => entry.format)).to.deep.equal(['registrar_dataset']);
    const broaderQuery = structuredClone(query);
    broaderQuery.credentials[0].claims.push({ path: ['picture'] });
    expect(() => validatePinnedRegistrarDataset({ selection: result.selection, query: broaderQuery, certificatePem }))
      .to.throw('exceeds intended-use');
    const mismatched = structuredClone(result.selection); mismatched.entityId = 'another-entity';
    expect(() => validatePinnedRegistrarDataset({ selection: mismatched, query, certificatePem })).to.throw('entity does not match');
    const modified = structuredClone(result.selection); modified.registrarDataset.policyURI = 'https://other.example/privacy';
    expect(() => validatePinnedRegistrarDataset({ selection: modified, query, certificatePem })).to.throw('privacy policy mismatch');
  });
  it('does not invent registrar identifiers for trust-enabled requests when registration is missing', async () => {
    delete fixture.manifest.scenarios['pid-basic'].intendedUseId; await fixture.save();
    const res = await request(app).get('/generateVPRequestDCQL').query({ sessionId: 'registrar-missing-id', trustFramework: 'true' });
    expect(res.status).to.equal(500); expect(res.text).to.include('WRPRC:');
  });
  it('selects and validates all 13 explicit scenarios and every unambiguous exact query default', async () => {
    const certificatePem = await fs.readFile('certs/raidiam/uAaqzBHXMTOW0maXduvtPyAgFWY2RppjzxH5ucvky7U.pem', 'utf8');
    expect(Object.keys(fixture.declarations)).to.have.length(13);
    for (const [scenario, declaration] of Object.entries(fixture.declarations)) {
      const query = { credentials: declaration.credentials };
      const selected = await selectWrprc({ scenario, query, certificatePem, manifestPath: fixture.manifestPath, checkTrust: trusted });
      expect(selected.selection.scenario).to.equal(scenario);
      try { expect(await resolveWrprcScenario({ query })).to.equal(scenario); }
      catch (error) {
        // Equal query shapes with different stated purposes need an explicit scenario.
        expect(error.message).to.include('ambiguous query');
      }
    }
    expect(await resolveWrprcScenario({ cs07ProfileId: 'ts12-payment' })).to.equal('ts12-dpc');
    expect(await resolveWrprcScenario({ cs03Signing: true })).to.equal('qualified-signing');
  });
});
