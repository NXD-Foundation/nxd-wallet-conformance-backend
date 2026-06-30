import { expect } from 'chai';
import {
  createCredentialOfferConfig,
  DEFAULT_MDL_DCQL_QUERY,
  BOOKING_REFERENCE_PID_DCQL_QUERY,
  URL_SCHEMES,
  resolveCredentialOfferUrlScheme,
  getCredentialOfferSchemeFromRequest,
  getPublicIssuerBaseUrl,
  createOpenID4VPRequestUrl,
  resolvePidVpInvocationScheme,
  resolveCodeFlowOfferIssuanceOptions,
  isEtsiIssuanceProfileEnforced,
  parseBooleanEnvFlag,
  extractWIAFromTokenRequest,
} from '../utils/routeUtils.js';

describe('Route Utils', () => {
  describe('createCredentialOfferConfig', () => {
    it('should set issuer_state for authorization code flow', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'authorization_code'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('authorization_code');
      expect(config.grants.authorization_code).to.have.property('issuer_state');
      expect(config.grants.authorization_code.issuer_state).to.equal('test-session-123');
      expect(config.grants.authorization_code).to.not.have.property('pre-authorized_code');
      expect(config.grants.authorization_code.scope).to.equal('urn:eu.europa.ec.eudi:pid:1');
    });

    it('should set pre-authorized_code for pre-authorized code flow', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']).to.equal('test-session-123');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('issuer_state');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('scope');
    });

    it('should include transaction code when specified', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        true,
        'authorization_code'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('authorization_code');
      expect(config.grants.authorization_code).to.have.property('issuer_state');
      expect(config.grants.authorization_code).to.have.property('tx_code');
      expect(config.grants.authorization_code.tx_code).to.have.property('input_mode');
      expect(config.grants.authorization_code.tx_code).to.have.property('length');
      expect(config.grants.authorization_code.tx_code).to.have.property('description');
      expect(config.grants.authorization_code.scope).to.equal('urn:eu.europa.ec.eudi:pid:1');
    });

    it('should use default grant type when not specified', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('scope');
    });

    it('should set space-separated scope for authorization_code when multiple configuration ids', () => {
      const ids = ['urn:eu.europa.ec.eudi:pid:1', 'PhotoID'];
      const config = createCredentialOfferConfig(
        ids,
        'sess-1',
        false,
        'authorization_code'
      );

      expect(config.credential_configuration_ids).to.deep.equal(ids);
      expect(config.grants.authorization_code.scope).to.equal(
        'urn:eu.europa.ec.eudi:pid:1 PhotoID'
      );
    });

    it('should set space-separated scope for pre-authorized grant when multiple configuration ids', () => {
      const ids = ['urn:eu.europa.ec.eudi:pid:1', 'PhotoID'];
      const config = createCredentialOfferConfig(
        ids,
        'pre-1',
        false,
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'
      );

      expect(config.credential_configuration_ids).to.deep.equal(ids);
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].scope).to.equal(
        'urn:eu.europa.ec.eudi:pid:1 PhotoID'
      );
    });

    it('should include credential configuration IDs', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'authorization_code'
      );

      expect(config).to.have.property('credential_configuration_ids');
      expect(config.credential_configuration_ids).to.be.an('array');
      expect(config.credential_configuration_ids).to.include('urn:eu.europa.ec.eudi:pid:1');
    });

    it('should include credential issuer URL', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'authorization_code'
      );

      expect(config).to.have.property('credential_issuer');
      expect(config.credential_issuer).to.be.a('string');
      expect(config.credential_issuer).to.match(/^https?:\/\//);
    });
  });

  describe('DEFAULT_MDL_DCQL_QUERY', () => {
    it('uses the PID namespace for mso_mdoc claim paths', () => {
      const claimPaths = DEFAULT_MDL_DCQL_QUERY.credentials[0].claims.map(
        ({ path }) => path
      );

      claimPaths.forEach((path) => {
        expect(path[0]).to.equal('urn:eu.europa.ec.eudi:pid:1');
        expect(path[0]).to.not.equal('urn:eu.europa.ec.eudi:pid:1:mso_mdoc');
      });
    });
  });

  describe('BOOKING_REFERENCE_PID_DCQL_QUERY', () => {
    it('requests both booking reference and PID credentials', () => {
      const [bookingQuery, pidQuery] = BOOKING_REFERENCE_PID_DCQL_QUERY.credentials;

      expect(bookingQuery.meta.vct_values).to.deep.equal(['booking_reference_credential']);
      expect(bookingQuery.claims.map(({ path }) => path)).to.deep.equal([['booking_reference']]);

      expect(pidQuery.meta.vct_values).to.deep.equal(['urn:eu.europa.ec.eudi:pid:1']);
      expect(pidQuery.claims.map(({ path }) => path)).to.deep.equal([['family_name']]);
    });
  });

  describe('getPublicIssuerBaseUrl (RFC001 P3-5 / reverse proxy)', () => {
    const prevForwarded = process.env.TRUST_FORWARDED_ISSUER_URL;
    const prevServer = process.env.SERVER_URL;

    afterEach(() => {
      if (prevForwarded === undefined) {
        delete process.env.TRUST_FORWARDED_ISSUER_URL;
      } else {
        process.env.TRUST_FORWARDED_ISSUER_URL = prevForwarded;
      }
      if (prevServer === undefined) {
        delete process.env.SERVER_URL;
      } else {
        process.env.SERVER_URL = prevServer;
      }
    });

    it('uses SERVER_URL when forwarded trust is off', () => {
      delete process.env.TRUST_FORWARDED_ISSUER_URL;
      process.env.SERVER_URL = 'https://issuer.example.com';
      expect(
        getPublicIssuerBaseUrl({
          headers: {
            'x-forwarded-proto': 'https',
            'x-forwarded-host': 'public.example.org',
          },
        }),
      ).to.equal('https://issuer.example.com');
    });

    it('uses X-Forwarded-Proto and X-Forwarded-Host when TRUST_FORWARDED_ISSUER_URL=true', () => {
      process.env.TRUST_FORWARDED_ISSUER_URL = 'true';
      process.env.SERVER_URL = 'http://internal:3000';
      expect(
        getPublicIssuerBaseUrl({
          headers: {
            'x-forwarded-proto': 'https',
            'x-forwarded-host': 'wallet-facing.example.com',
          },
        }),
      ).to.equal('https://wallet-facing.example.com');
    });

    it('falls back to SERVER_URL when forwarded headers are incomplete', () => {
      process.env.TRUST_FORWARDED_ISSUER_URL = 'true';
      process.env.SERVER_URL = 'https://fallback.example.com';
      expect(getPublicIssuerBaseUrl({ headers: {} })).to.equal(
        'https://fallback.example.com',
      );
    });
  });

  describe('ETSI issuance enforcement env flag', () => {
    const previous = process.env.ENFORCE_ETSI_ISSUANCE_PROFILE;

    afterEach(() => {
      if (previous === undefined) {
        delete process.env.ENFORCE_ETSI_ISSUANCE_PROFILE;
      } else {
        process.env.ENFORCE_ETSI_ISSUANCE_PROFILE = previous;
      }
    });

    it('defaults to relaxed when env var is unset', () => {
      delete process.env.ENFORCE_ETSI_ISSUANCE_PROFILE;
      expect(isEtsiIssuanceProfileEnforced()).to.equal(false);
    });

    it('enables enforcement when env var is true-like', () => {
      process.env.ENFORCE_ETSI_ISSUANCE_PROFILE = 'true';
      expect(isEtsiIssuanceProfileEnforced()).to.equal(true);
    });

    it('treats explicit false-like values as relaxed mode', () => {
      process.env.ENFORCE_ETSI_ISSUANCE_PROFILE = 'false';
      expect(isEtsiIssuanceProfileEnforced()).to.equal(false);
      process.env.ENFORCE_ETSI_ISSUANCE_PROFILE = '0';
      expect(isEtsiIssuanceProfileEnforced()).to.equal(false);
      process.env.ENFORCE_ETSI_ISSUANCE_PROFILE = 'no';
      expect(isEtsiIssuanceProfileEnforced()).to.equal(false);
    });

    it('parses common boolean spellings', () => {
      expect(parseBooleanEnvFlag('true')).to.equal(true);
      expect(parseBooleanEnvFlag('1')).to.equal(true);
      expect(parseBooleanEnvFlag('yes')).to.equal(true);
      expect(parseBooleanEnvFlag('false', true)).to.equal(false);
      expect(parseBooleanEnvFlag('0', true)).to.equal(false);
      expect(parseBooleanEnvFlag('off', true)).to.equal(false);
      expect(parseBooleanEnvFlag('unexpected', true)).to.equal(true);
    });
  });

  describe('resolveCredentialOfferUrlScheme / getCredentialOfferSchemeFromRequest (RFC001 eu-eaa-offer)', () => {
    it('resolves eu_eaa / eu-eaa / eaa and full eu-eaa-offer:// prefix', () => {
      expect(resolveCredentialOfferUrlScheme('eu_eaa')).to.equal(URL_SCHEMES.EU_EAA);
      expect(resolveCredentialOfferUrlScheme('eu-eaa')).to.equal(URL_SCHEMES.EU_EAA);
      expect(resolveCredentialOfferUrlScheme('eaa')).to.equal(URL_SCHEMES.EU_EAA);
      expect(resolveCredentialOfferUrlScheme('eu-eaa-offer://')).to.equal(URL_SCHEMES.EU_EAA);
    });

    it('resolves haip and standard', () => {
      expect(resolveCredentialOfferUrlScheme('haip')).to.equal(URL_SCHEMES.HAIP);
      expect(resolveCredentialOfferUrlScheme(undefined)).to.equal(URL_SCHEMES.STANDARD);
      expect(resolveCredentialOfferUrlScheme('standard')).to.equal(URL_SCHEMES.STANDARD);
    });

    it('offer_scheme takes precedence over url_scheme on request', () => {
      const req = {
        query: { offer_scheme: 'eu_eaa', url_scheme: 'haip' },
        body: {},
      };
      expect(getCredentialOfferSchemeFromRequest(req)).to.equal(URL_SCHEMES.EU_EAA);
    });

    it('reads offer_scheme from JSON body when query is empty', () => {
      const req = {
        query: {},
        body: { offer_scheme: 'eu-eaa' },
      };
      expect(getCredentialOfferSchemeFromRequest(req)).to.equal(URL_SCHEMES.EU_EAA);
    });
  });

  describe('resolveCodeFlowOfferIssuanceOptions', () => {
    it('defaults to standard (non-dynamic, non-deferred)', () => {
      expect(resolveCodeFlowOfferIssuanceOptions({ query: {} })).to.deep.equal({
        isDynamic: false,
        isDeferred: false,
        includeCredentialType: true,
      });
    });

    it('maps issuance_mode=dynamic', () => {
      expect(
        resolveCodeFlowOfferIssuanceOptions({ query: { issuance_mode: 'dynamic' } }),
      ).to.deep.equal({
        isDynamic: true,
        isDeferred: false,
        includeCredentialType: false,
      });
    });

    it('maps dynamic_credential_request when mode omitted', () => {
      expect(
        resolveCodeFlowOfferIssuanceOptions({ query: { dynamic_credential_request: 'true' } }),
      ).to.deep.equal({
        isDynamic: true,
        isDeferred: false,
        includeCredentialType: false,
      });
    });

    it('issuance_mode takes precedence over dynamic_credential_request flag', () => {
      expect(
        resolveCodeFlowOfferIssuanceOptions({
          query: { issuance_mode: 'standard', dynamic_credential_request: 'true' },
        }),
      ).to.deep.equal({
        isDynamic: false,
        isDeferred: false,
        includeCredentialType: true,
      });
    });

    it('maps deferred and common typos', () => {
      expect(
        resolveCodeFlowOfferIssuanceOptions({ query: { issuance_mode: 'deferred' } }),
      ).to.deep.equal({
        isDynamic: false,
        isDeferred: true,
        includeCredentialType: false,
      });
      expect(
        resolveCodeFlowOfferIssuanceOptions({ query: { issuance_mode: 'deffered' } }),
      ).to.deep.equal({
        isDynamic: false,
        isDeferred: true,
        includeCredentialType: false,
      });
    });

    it('throws on unknown mode', () => {
      expect(() =>
        resolveCodeFlowOfferIssuanceOptions({ query: { issuance_mode: 'nope' } }),
      ).to.throw(/Invalid issuance_mode/);
    });
  });

  describe('createOpenID4VPRequestUrl (VP-CHECK-17 eu-eaap)', () => {
    const uri = 'https://rp.example/vp/x509VPrequest/s1';
    const clientId = 'x509_hash:abc';

    it('builds eu-eaap:// with the same query shape as openid4vp', () => {
      const eu = createOpenID4VPRequestUrl(uri, clientId, false, { scheme: 'eu-eaap' });
      const oi = createOpenID4VPRequestUrl(uri, clientId, false, { scheme: 'openid4vp' });
      expect(eu.startsWith('eu-eaap://?')).to.be.true;
      expect(eu.replace(/^eu-eaap:/, 'openid4vp:')).to.equal(oi);
    });

    it('accepts eu_eaap and request_uri_method=post', () => {
      const u = createOpenID4VPRequestUrl(uri, clientId, true, { scheme: 'eu_eaap' });
      expect(u).to.include('request_uri_method=post');
      expect(u.startsWith('eu-eaap://?')).to.be.true;
    });

    it('rejects unknown schemes', () => {
      expect(() =>
        createOpenID4VPRequestUrl(uri, clientId, false, { scheme: 'unknown' }),
      ).to.throw(/eu-eaap/);
    });
  });

  describe('resolvePidVpInvocationScheme (ETSI PID default)', () => {
    it('defaults to openid4vp when not ETSI profile', () => {
      expect(resolvePidVpInvocationScheme(undefined, false)).to.equal('openid4vp');
      expect(resolvePidVpInvocationScheme('', false)).to.equal('openid4vp');
    });

    it('defaults to eu-eaap when ETSI profile', () => {
      expect(resolvePidVpInvocationScheme(undefined, true)).to.equal('eu-eaap');
    });

    it('allows explicit openid4vp on ETSI profile', () => {
      expect(resolvePidVpInvocationScheme('openid4vp', true)).to.equal('openid4vp');
    });

    it('allows explicit eu-eaap off ETSI profile', () => {
      expect(resolvePidVpInvocationScheme('eu-eaap', false)).to.equal('eu-eaap');
    });

    it('rejects invalid values', () => {
      expect(() => resolvePidVpInvocationScheme('mdoc-openid4vp', false)).to.throw();
    });
  });

  describe('extractWIAFromTokenRequest', () => {
    it('prefers OAuth-Client-Attestation header over body client_assertion', () => {
      const headerWia = 'header.wia.jwt';
      const bodyWia = 'body.wia.jwt';
      expect(
        extractWIAFromTokenRequest(
          {
            client_assertion: bodyWia,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          },
          {
            'OAuth-Client-Attestation': headerWia,
            'OAuth-Client-Attestation-PoP': 'pop.jwt',
          },
        ),
      ).to.equal(headerWia);
    });

    it('falls back to body client_assertion when attestation header is absent', () => {
      const bodyWia = 'body.wia.jwt';
      expect(
        extractWIAFromTokenRequest(
          {
            client_assertion: bodyWia,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          },
          {},
        ),
      ).to.equal(bodyWia);
    });

    it('returns null when neither header nor body WIA is present', () => {
      expect(extractWIAFromTokenRequest({}, {})).to.equal(null);
    });
  });
}); 
