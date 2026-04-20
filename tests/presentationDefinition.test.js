import { strict as assert } from 'assert';
import fs from 'fs';
import { execSync } from 'child_process';
import { createHash } from 'crypto';
import base64url from 'base64url';
import jwt from 'jsonwebtoken';
import { getSDsFromPresentationDef } from '../utils/vpHeplers.js';

function readPemBody(path) {
  return fs.readFileSync(path, 'utf8')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

function readP12LeafCertBody() {
  const envWithPass = { ...process.env, WEBUILD_P12_PASS: process.env.WEBUILD_P12_PASSWORD || 'webuild' };
  const certPem = execSync(
    'openssl pkcs12 -in "certs/WE-BUILD-Verifier.p12" -nokeys -passin env:WEBUILD_P12_PASS',
    { encoding: 'utf8', maxBuffer: 64 * 1024, env: envWithPass }
  );
  const matches = certPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches[0]
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

describe('Presentation Definition Utilities', () => {
  it('should extract Selective Disclosure fields from presentation_definition_mdl.json', () => {
    // Load the presentation definition from the JSON file
    const presentationDefinitionRaw = fs.readFileSync('./data/presentation_definition_mdl.json', 'utf-8');
    const presentation_definition_mdl = JSON.parse(presentationDefinitionRaw);

    // Call the function to get the selective disclosure fields
    const sdsRequested = getSDsFromPresentationDef(presentation_definition_mdl);

    // Print the results to the console
    console.log('Selective Disclosure Fields:', JSON.stringify(sdsRequested, null, 2));

    // Add assertions to ensure the function works as expected
    assert.ok(Array.isArray(sdsRequested), 'The result should be an array.');
    assert.strictEqual(sdsRequested.length, 2, 'There should be 3 fields requested.');

    console.log('sdsRequested', sdsRequested);
    // assert.deepStrictEqual(sdsRequested, [
    //   'surname',
    //   'given_name',
    //   'phone'
    // ], 'The extracted fields should match the expected values.');
  });
}); 

describe('Presentation Definition (PE) structure - OID4VP v1.0', () => {
  it('PID PD must use dc+sd-jwt and granular JSONPath fields', () => {
    const pdRaw = fs.readFileSync('./data/presentation_definition_pid.json', 'utf-8');
    const pd = JSON.parse(pdRaw);

    // Top-level format must advertise dc+sd-jwt
    assert.ok(pd.format && pd.format['dc+sd-jwt'], 'Top-level format.dc+sd-jwt is required');

    // Must have input_descriptors with constraints.fields
    assert.ok(Array.isArray(pd.input_descriptors) && pd.input_descriptors.length > 0, 'input_descriptors required');
    const id0 = pd.input_descriptors[0];
    assert.ok(id0.constraints && Array.isArray(id0.constraints.fields) && id0.constraints.fields.length > 0, 'constraints.fields required');

    // Fields should use JSONPath pointers starting with $
    const allPaths = id0.constraints.fields.flatMap(f => f.path || []);
    assert.ok(allPaths.every(p => typeof p === 'string' && p.startsWith('$.')), 'All field paths must be JSONPath starting with $.');

    // Granular selectors: ensure specific claims are requested (data minimization)
    const requiredClaims = ['given_name', 'family_name', 'birth_date', 'age_over_18'];
    for (const claim of requiredClaims) {
      const hasClaim = allPaths.some(p => p.endsWith(`.${claim}`) || p === `$.${claim}`);
      assert.ok(hasClaim, `PD must request granular claim: ${claim}`);
    }

    // Must not request entire credential objects
    assert.ok(!allPaths.includes('$') && !allPaths.includes('$.vc') && !allPaths.includes('$.credentialSubject'), 'PD must not target whole objects');

    // Ensure vct filter is specific to EU PID
    const vctField = id0.constraints.fields.find(f => Array.isArray(f.path) && f.path.some(p => p === '$.vct' || p === '$.vc.vct'));
    assert.ok(vctField && vctField.filter && vctField.filter.const === 'urn:eu.europa.ec.eudi:pid:1', 'vct filter must target EU PID');
  });

  it('Legacy SD-JWT PD should not be used for v1.0 (vc+sd-jwt present)', () => {
    const pdRaw = fs.readFileSync('./data/presentation_definition_sdjwt.json', 'utf-8');
    const pd = JSON.parse(pdRaw);

    // This file uses vc+sd-jwt; test documents that it is legacy (migration target is dc+sd-jwt)
    assert.ok(pd.format && pd.format['vc+sd-jwt'], 'Legacy PD advertises vc+sd-jwt');
  });

  it('Verifier metadata must advertise dc+sd-jwt (not vc+sd-jwt)', () => {
    const verifierConfigRaw = fs.readFileSync('./data/verifier-config.json', 'utf-8');
    const cfg = JSON.parse(verifierConfigRaw);

    // vp_formats_supported must contain dc+sd-jwt
    assert.ok(cfg.vp_formats_supported && cfg.vp_formats_supported['dc+sd-jwt'], 'verifier-config.vp_formats_supported.dc+sd-jwt required');
    // must not contain vc+sd-jwt
    assert.ok(!cfg.vp_formats_supported['vc+sd-jwt'], 'verifier-config must not advertise legacy vc+sd-jwt');

  });

  it('Verifier metadata must advertise CSC X.509 (CS-03)', () => {
    const verifierConfigRaw = fs.readFileSync('./data/verifier-config.json', 'utf-8');
    const cfg = JSON.parse(verifierConfigRaw);
    assert.ok(
      cfg.vp_formats_supported &&
        Object.prototype.hasOwnProperty.call(
          cfg.vp_formats_supported,
          'https://cloudsignatureconsortium.org/2025/x509'
        ),
      'verifier-config.vp_formats_supported must include CSC X.509 format URI'
    );
  });

  it('In-code CLIENT_METADATA must advertise dc+sd-jwt', async () => {
    // Dynamically import to read the object
    const rt = await import('../utils/routeUtils.js');
    const meta = rt.CLIENT_METADATA;
    assert.ok(meta && meta.vp_formats_supported && meta.vp_formats_supported['dc+sd-jwt'], 'CLIENT_METADATA.vp_formats_supported.dc+sd-jwt required');
    assert.ok(!meta.vp_formats_supported['vc+sd-jwt'], 'CLIENT_METADATA must not use legacy vc+sd-jwt');
    assert.ok(
      meta.vp_formats_supported &&
        Object.prototype.hasOwnProperty.call(
          meta.vp_formats_supported,
          'https://cloudsignatureconsortium.org/2025/x509'
        ),
      'CLIENT_METADATA.vp_formats_supported must include CSC X.509 format URI'
    );
  });

  it('Verifier metadata must specify sd-jwt_alg_values and kb-jwt_alg_values for dc+sd-jwt', () => {
    const verifierConfigRaw = fs.readFileSync('./data/verifier-config.json', 'utf-8');
    const cfg = JSON.parse(verifierConfigRaw);
    const vps = cfg.vp_formats_supported?.['dc+sd-jwt'];

    // vp_formats_supported
    assert.ok(vps && Array.isArray(vps['sd-jwt_alg_values']) && vps['sd-jwt_alg_values'].length > 0, 'vp_formats_supported.dc+sd-jwt.sd-jwt_alg_values required');
    assert.ok(vps && Array.isArray(vps['kb-jwt_alg_values']) && vps['kb-jwt_alg_values'].length > 0, 'vp_formats_supported.dc+sd-jwt.kb-jwt_alg_values required');
  });

  it('In-code CLIENT_METADATA must include both algorithm sets for dc+sd-jwt', async () => {
    const rt = await import('../utils/routeUtils.js');
    const fm = rt.CLIENT_METADATA?.vp_formats_supported?.['dc+sd-jwt'];
    assert.ok(fm && Array.isArray(fm['sd-jwt_alg_values']) && fm['sd-jwt_alg_values'].length > 0, 'CLIENT_METADATA.vp_formats_supported.dc+sd-jwt.sd-jwt_alg_values required');
    assert.ok(fm && Array.isArray(fm['kb-jwt_alg_values']) && fm['kb-jwt_alg_values'].length > 0, 'CLIENT_METADATA.vp_formats_supported.dc+sd-jwt.kb-jwt_alg_values required');
  });
});

describe('Verifier X509 client_id defaults', () => {
  function computeExpectedX509HashClientId() {
    const der = Buffer.from(readP12LeafCertBody(), 'base64');
    return `x509_hash:${base64url.encode(createHash('sha256').update(der).digest())}`;
  }

  it('CONFIG.ETSI_CLIENT_ID must be the leaf-cert SHA-256 x509_hash value', async () => {
    const rt = await import('../utils/routeUtils.js');
    assert.strictEqual(rt.CONFIG.ETSI_CLIENT_ID, computeExpectedX509HashClientId());
  });

  it('resolveVerifierX509ClientId must default to x509_hash for x509-ish inputs', async () => {
    const rt = await import('../utils/routeUtils.js');
    const expected = computeExpectedX509HashClientId();
    assert.strictEqual(rt.resolveVerifierX509ClientId(), expected);
    assert.strictEqual(rt.resolveVerifierX509ClientId('x509_hash'), expected);
    assert.strictEqual(rt.resolveVerifierX509ClientId('x509'), expected);
  });

  it('resolveVerifierX509ClientId must keep x509_san_dns as an explicit legacy override', async () => {
    const rt = await import('../utils/routeUtils.js');
    assert.strictEqual(rt.resolveVerifierX509ClientId('x509_san_dns'), rt.CONFIG.CLIENT_ID);
  });

  it('verifier-config must publish x509_hash as default client_id and advertise both supported schemes', () => {
    const cfg = JSON.parse(fs.readFileSync('./data/verifier-config.json', 'utf-8'));
    assert.strictEqual(cfg.client_id, computeExpectedX509HashClientId());
    assert.deepStrictEqual(cfg.client_id_schemes_supported, ['x509_hash', 'x509_san_dns']);
  });

  it('verifier-info config must publish the RFC002 verifier_info fields', () => {
    const verifierInfo = JSON.parse(fs.readFileSync('./data/verifier-info.json', 'utf-8'));

    assert.equal(typeof verifierInfo.verifier_id, 'string');
    assert.equal(typeof verifierInfo.service_description, 'string');
    assert.equal(typeof verifierInfo.rp_registrar_uri, 'string');
    assert.equal(typeof verifierInfo.intended_use, 'string');
    assert.equal(typeof verifierInfo.purpose, 'string');
    assert.equal(typeof verifierInfo.privacy_policy_uri, 'string');
    assert.ok(!('registration_certificate' in verifierInfo), 'registration_certificate should be derived at runtime from the active signing certificate');
  });

  it('resolveVerifierInfoFromRequest must merge request overrides onto configured defaults', async () => {
    const rt = await import('../utils/routeUtils.js');
    const resolved = rt.resolveVerifierInfoFromRequest(
      {
        query: {
          verifier_info: JSON.stringify({
            purpose: 'Custom policy purpose',
            intended_use: 'custom_use'
          })
        },
        body: {
          privacy_policy_uri: 'https://override.example/privacy'
        }
      },
      rt.loadVerifierInfo()
    );

    assert.equal(resolved.purpose, 'Custom policy purpose');
    assert.equal(resolved.intended_use, 'custom_use');
    assert.equal(resolved.privacy_policy_uri, 'https://override.example/privacy');
    assert.equal(resolved.verifier_id, 'dss.aegean.gr');
    assert.ok(!('registration_certificate' in resolved));
  });

  it('buildVpRequestJWT must emit verifier_info with the active RS256 signing certificate', async () => {
    const rt = await import('../utils/routeUtils.js');
    const cryptoUtils = await import('../utils/cryptoUtils.js');
    const verifierInfo = rt.loadVerifierInfo();
    const rs256ClientId = rt.computeX509HashClientId('./x509/client_certificate.crt');
    const dcqlQuery = {
      credentials: [
        {
          id: 'pid',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] }
        }
      ]
    };

    const token = await cryptoUtils.buildVpRequestJWT(
      rs256ClientId,
      'http://localhost:3000/direct_post/test-session',
      null,
      null,
      rt.CLIENT_METADATA,
      null,
      'http://localhost:3000',
      'vp_token',
      'test-nonce',
      dcqlQuery,
      null,
      'direct_post',
      undefined,
      null,
      null,
      null,
      'test-state',
      'RS256',
      verifierInfo
    );

    const payload = jwt.decode(token);
    assert.deepStrictEqual(payload.verifier_info, {
      ...verifierInfo,
      registration_certificate: [readPemBody('./x509/client_certificate.crt')]
    });
    assert.equal(payload.client_id, rs256ClientId);
  });

  it('buildVpRequestJWT must emit verifier_info with the active ES256 signing certificate chain', async () => {
    const rt = await import('../utils/routeUtils.js');
    const cryptoUtils = await import('../utils/cryptoUtils.js');
    const verifierInfo = rt.loadVerifierInfo();
    const dcqlQuery = {
      credentials: [
        {
          id: 'pid',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['urn:eu.europa.ec.eudi:pid:1'] }
        }
      ]
    };

    const token = await cryptoUtils.buildVpRequestJWT(
      rt.CONFIG.ETSI_CLIENT_ID,
      'http://localhost:3000/direct_post/test-session',
      null,
      null,
      rt.CLIENT_METADATA,
      null,
      'http://localhost:3000',
      'vp_token',
      'test-nonce',
      dcqlQuery,
      null,
      'direct_post',
      undefined,
      null,
      null,
      null,
      'test-state',
      'ES256',
      verifierInfo
    );

    const payload = jwt.decode(token);
    const header = jwt.decode(token, { complete: true }).header;
    assert.equal(header.alg, 'ES256');
    assert.deepStrictEqual(payload.verifier_info, {
      ...verifierInfo,
      registration_certificate: header.x5c
    });
  });
});
