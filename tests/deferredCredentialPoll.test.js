import { expect } from 'chai';
import {
  DEFERRED_CREDENTIAL_POLL_INTERVAL_SECONDS,
  advanceDeferredCredentialPollState,
  getDeferredSessionAccessToken,
  isDeferredCredentialDenied,
} from '../utils/deferredCredentialPoll.js';

describe('deferredCredentialPoll (Phase 5)', () => {
  it('reads access tokens from code-flow and pre-auth sessions', () => {
    expect(getDeferredSessionAccessToken({ requests: { accessToken: 'code-token' } }, 'code')).to.equal('code-token');
    expect(getDeferredSessionAccessToken({ accessToken: 'preauth-token' }, 'pre-auth')).to.equal('preauth-token');
  });

  it('detects denied deferred sessions', () => {
    expect(isDeferredCredentialDenied({ status: 'failed' })).to.equal(true);
    expect(isDeferredCredentialDenied({ error: 'credential_request_denied' })).to.equal(true);
    expect(isDeferredCredentialDenied({ status: 'pending' })).to.equal(false);
  });

  it('returns pending 202 state until ready-after polls are reached', () => {
    const session = {
      transaction_id: 'tx-1',
      isCredentialReady: false,
      attempt: 0,
    };
    const env = { DEFERRED_CREDENTIAL_READY_AFTER_POLLS: '2' };

    const first = advanceDeferredCredentialPollState(session, env);
    expect(first).to.deep.include({
      action: 'pending',
      transaction_id: 'tx-1',
      interval: DEFERRED_CREDENTIAL_POLL_INTERVAL_SECONDS,
      attempt: 1,
    });
    expect(session.attempt).to.equal(1);
    expect(session.isCredentialReady).to.equal(false);

    const second = advanceDeferredCredentialPollState(session, env);
    expect(second.action).to.equal('ready');
    expect(second.attempt).to.equal(2);
    expect(session.isCredentialReady).to.equal(true);
  });

  it('returns credential_request_denied without advancing ready state', () => {
    const session = {
      transaction_id: 'tx-denied',
      status: 'failed',
      error_description: 'Issuer denied issuance',
      isCredentialReady: false,
      attempt: 0,
    };

    const result = advanceDeferredCredentialPollState(session);
    expect(result).to.deep.equal({
      action: 'denied',
      error: 'credential_request_denied',
      error_description: 'Issuer denied issuance',
    });
    expect(session.attempt).to.equal(0);
  });
});
