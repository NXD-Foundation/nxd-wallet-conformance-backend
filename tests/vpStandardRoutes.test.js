import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import vpStandardRouter from '../routes/verify/vpStandardRoutes.js';

const app = express();
app.use(express.json());

function resolveResponseMode(query) {
  const profile = query.profile || 'dcql';
  const isRfc002Profile = profile === 'etsi' || profile === 'rfc002';
  return query.response_mode || (isRfc002Profile ? 'direct_post.jwt' : 'direct_post');
}

const router = express.Router();

router.get('/vp/request', async (req, res) => {
  res.json({
    profile: req.query.profile || 'dcql',
    response_mode: resolveResponseMode(req.query),
  });
});

app.use('/', router);

describe('VP Standard Routes', () => {
  it('should default ETSI profile requests to direct_post.jwt', async () => {
    const response = await request(app)
      .get('/vp/request')
      .query({ profile: 'etsi' })
      .expect(200);

    expect(response.body).to.have.property('response_mode', 'direct_post.jwt');
  });

  it('should default RFC002 profile requests to direct_post.jwt', async () => {
    const response = await request(app)
      .get('/vp/request')
      .query({ profile: 'rfc002' })
      .expect(200);

    expect(response.body).to.have.property('response_mode', 'direct_post.jwt');
  });

  it('should keep direct_post available as an explicit ETSI override', async () => {
    const response = await request(app)
      .get('/vp/request')
      .query({ profile: 'etsi', response_mode: 'direct_post' })
      .expect(200);

    expect(response.body).to.have.property('response_mode', 'direct_post');
  });

  it('should keep non-ETSI profiles on direct_post by default', async () => {
    const response = await request(app)
      .get('/vp/request')
      .query({ profile: 'dcql' })
      .expect(200);

    expect(response.body).to.have.property('response_mode', 'direct_post');
  });
});

describe('VP Standard Routes — ETSI same-device entry', () => {
  const routerApp = express();
  routerApp.use('/', vpStandardRouter);

  it('GET /vp/etsi/same-device redirects to /vp/request with profile=etsi', async () => {
    const res = await request(routerApp)
      .get('/vp/etsi/same-device')
      .query({ credential_profile: 'pid', client_id_scheme: 'x509' });

    expect(res.status).to.equal(302);
    const loc = res.headers.location;
    expect(loc).to.match(/^\/vp\/request\?/);
    const qs = new URLSearchParams(loc.replace(/^\/vp\/request\?/, ''));
    expect(qs.get('profile')).to.equal('etsi');
    expect(qs.get('credential_profile')).to.equal('pid');
  });

  it('forces profile=etsi even if query tries to override', async () => {
    const res = await request(routerApp)
      .get('/vp/etsi/same-device')
      .query({ profile: 'dcql' });

    expect(res.status).to.equal(302);
    const loc = res.headers.location;
    const qs = new URLSearchParams(loc.replace(/^\/vp\/request\?/, ''));
    expect(qs.get('profile')).to.equal('etsi');
  });
});
