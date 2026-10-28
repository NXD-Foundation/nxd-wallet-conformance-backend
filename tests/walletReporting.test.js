import { strict as assert } from 'node:assert';
import { randomUUID } from 'node:crypto';
import { WalletReporting } from '../routes/walletReporting.js';

class Redis {
  data = new Map();
  async get(k) { return this.data.get(k) ?? null; }
  async set(k,v,options) { if (options?.NX && this.data.has(k)) return null; this.data.set(k,v); return 'OK'; }
  async eval(script,{keys,arguments:a}) { if(this.data.get(keys[0])!==a[0]) return 0; this.data.set(keys[0],a[1]); return 1; }
}
const event = (sequence = 1) => ({eventId:randomUUID(),sequence,timestamp:new Date().toISOString(), metadata:{event:'request_received',transport:'dc_api',token:'must disappear'}, message:'secret credential'});
describe('Native wallet reporting contract', () => {
  let service, now, sid, attempt, token;
  beforeEach(async () => { now=100000; service=new WalletReporting(new Redis(),{secret:'x'.repeat(32),now:()=>now}); sid=randomUUID();attempt=randomUUID();await service.create(sid);token=(await service.pair(sid,{installationId:randomUUID(),pairingRequestId:randomUUID()})).uploadToken; });
  it('binds pairing once, recovers a lost response and refuses a second installation', async () => {
    const s=await service.read(sid), body={installationId:s.installationId,pairingRequestId:s.pairingRequestId};
    assert.equal((await service.pair(sid,body)).uploadToken,token);
    await assert.rejects(service.pair(sid,{...body,installationId:randomUUID()}),e=>e.status===409);
    await assert.rejects(service.create(sid),e=>e.status===409);
  });
  it('authenticates uploads and excludes raw text and non-allowlisted metadata', async () => {
    const e=event(); await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[e]},'bad'),x=>x.status===401);
    await service.events(sid,attempt,{schemaVersion:1,events:[e]},token);
    assert.ok(!JSON.stringify(await service.logs(sid)).includes('secret credential'));
    assert.ok(!JSON.stringify(await service.logs(sid)).includes('must disappear'));
    const another=randomUUID();await service.create(another);
    await assert.rejects(service.events(another,attempt,{schemaVersion:1,events:[e]},token),x=>x.status===401);
  });
  it('deduplicates retries and rejects conflicting IDs or sequences', async () => {
    const e=event(); const body={schemaVersion:1,events:[e]};
    await Promise.all([service.events(sid,attempt,body,token),service.events(sid,attempt,body,token)]);
    assert.equal((await service.logs(sid)).count,1);
    await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[{...e,sequence:2}]},token),x=>x.status===409);
    await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[event()]},token),x=>x.status===409);
  });
  it('requires all sequences, consumes execution and permits identical completion retry', async () => {
    const finish={schemaVersion:1,completionId:randomUUID(),reportedOutcome:'response_produced',attempts:[{attemptId:attempt,finalSequence:2}]};
    await service.events(sid,attempt,{schemaVersion:1,events:[event(2)]},token);
    await assert.rejects(service.complete(sid,finish,token),e=>e.status===409);
    await service.events(sid,attempt,{schemaVersion:1,events:[event(1)]},token);
    assert.equal((await service.complete(sid,finish,token)).status,'completed');
    assert.equal((await service.complete(sid,finish,token)).evidenceComplete,true);
    await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[event(3)]},token),e=>e.status===409);
  });
  it('allows delayed evidence within grace but rejects expired capabilities', async () => {
    now+=service.executionMs+1;await service.events(sid,attempt,{schemaVersion:1,events:[event()]},token);
    const s=await service.read(sid);await assert.rejects(service.pair(sid,{installationId:s.installationId,pairingRequestId:s.pairingRequestId}),e=>e.status===410);
    now+=86400001;await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[event(2)]},token),e=>e.status===410);
  });
  it('keeps manual pairing available for three minutes and expires it after four minutes', async () => {
    assert.equal(service.executionMs, 240000);
    const fresh = randomUUID(); await service.create(fresh);
    const pairing = { installationId: randomUUID(), pairingRequestId: randomUUID() };
    const created = service.now(); now += 3 * 60 * 1000;
    const paired = await service.pair(fresh, pairing);
    assert.equal(paired.expiresAt, created + 240000);
    assert.ok(paired.uploadToken);
    now = created + 240001;
    await assert.rejects(service.pair(fresh, pairing), e => e.status === 410);
  });
  it('accepts Android debug batches and completes without losing diagnostic fields', async () => {
    const diagnostic = {...event(), level: 'debug', metadata: {
      event: 'diagnostic', transport: 'dc_api', stage: 'response_generation_started',
      elapsedMs: 456, selectionCount: 2, authenticationRequired: true, token: 'must disappear'
    }};
    await service.events(sid, attempt, {schemaVersion: 1, events: [diagnostic]}, token);
    const completion = {schemaVersion: 1, completionId: randomUUID(), reportedOutcome: 'response_produced',
      attempts: [{attemptId: attempt, finalSequence: 1}]};
    assert.equal((await service.complete(sid, completion, token)).status, 'completed');
    const logs = await service.logs(sid);
    assert.equal(logs.logs[0].level, 'debug');
    assert.equal(logs.logs[0].metadata.stage, 'response_generation_started');
    assert.equal(logs.logs[0].metadata.elapsedMs, 456);
    assert.equal(logs.logs[0].metadata.selectionCount, 2);
    assert.equal(logs.logs[0].metadata.authenticationRequired, true);
    assert.ok(!JSON.stringify(logs).includes('must disappear'));
  });
  it('bounds diagnostics and drops raw or malformed metadata', async () => {
    const e = {...event(), metadata: {event:'diagnostic', transport:'dc_api', stage:'response_generated',
      elapsedMs:-1, selectedClaimCount:'secret credential', authenticationRequired:'yes',
      exceptionClass:'java.lang.IllegalStateException', causeClasses:'java.lang.IllegalStateException -> java.lang.Exception',
      stackTrace:'java.lang.Exception\nat eu.europa.Controller.send(Controller.kt:42)',
      token:'must disappear'}};
    await service.events(sid,attempt,{schemaVersion:1,events:[e]},token);
    const metadata = (await service.logs(sid)).logs[0].metadata;
    assert.equal(metadata.exceptionClass,'java.lang.IllegalStateException');
    assert.equal(metadata.stackTrace,e.metadata.stackTrace);
    assert.equal(metadata.causeClasses,e.metadata.causeClasses);
    assert.ok(!('elapsedMs' in metadata));
    assert.ok(!('selectedClaimCount' in metadata));
    assert.ok(!('authenticationRequired' in metadata));
    const bad = {...event(2), metadata:{event:'diagnostic',stage:'token=secret',stackTrace:'secret credential'}};
    await service.events(sid,attempt,{schemaVersion:1,events:[bad]},token);
    assert.deepEqual((await service.logs(sid)).logs[1].metadata,{event:'diagnostic'});
    await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[{...event(3),metadata:{event:'unknown'}}]},token),x=>x.status===400);
  });
  it('never acknowledges unavailable storage', async () => {
    service.redis.eval=async()=>{throw Error('offline');};
    await assert.rejects(service.events(sid,attempt,{schemaVersion:1,events:[event()]},token),/offline/);
  });
});

describe('Native wallet reporting HTTP API', () => {
  let server, base, sid, token, service;
  beforeEach(async () => {
    const { default: express } = await import('express');
    const { walletReportingRouter } = await import('../routes/walletReporting.js');
    const redis=new Redis();redis.incr=async()=>1;redis.expire=async()=>1;
    service=new WalletReporting(redis,{secret:'x'.repeat(32)});
    const app=express();app.use('/itb-wallet/v1',walletReportingRouter(service,{apiKey:'test-service-key'}));
    server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
    base=`http://127.0.0.1:${server.address().port}/itb-wallet/v1`;sid=randomUUID();
  });
  afterEach(async()=> {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  const post=(url,body,headers={})=>fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body)});
  it('requires trusted service reads and creation, but permits UUID pairing and scoped writes',async()=>{
    assert.equal((await post(base+'/sessions',{sessionId:sid})).status,401);
    assert.equal((await post(base+'/sessions',{sessionId:sid},{'X-ITB-Service-Key':'test-service-key'})).status,200);
    const paired=await post(base+`/sessions/${sid}/pair`,{installationId:randomUUID(),pairingRequestId:randomUUID()});
    assert.equal(paired.status,200);token=(await paired.json()).uploadToken;
    assert.equal((await fetch(base+`/sessions/${sid}`,{headers:{Authorization:`Bearer ${token}`}})).status,401);
    assert.equal((await fetch(base+`/sessions/${sid}`,{headers:{'X-ITB-Service-Key':'test-service-key'}})).status,200);
    const attempt = randomUUID();
    const diagnostic = {...event(), metadata: {event: 'diagnostic', transport: 'dc_api', stage: 'response_generated', elapsedMs: 20}};
    const auth = {Authorization: `Bearer ${token}`};
    assert.equal((await post(base+`/sessions/${sid}/attempts/${attempt}/events`, {schemaVersion:1, events:[diagnostic]}, auth)).status, 200);
    const completed = await post(base+`/sessions/${sid}/complete`, {schemaVersion:1, completionId:randomUUID(), reportedOutcome:'response_produced', attempts:[{attemptId:attempt, finalSequence:1}]}, auth);
    assert.equal(completed.status, 200);
    assert.equal((await completed.json()).evidenceComplete, true);
  });
  it('returns controlled JSON errors for oversized, malformed and unknown requests',async()=>{
    const bad=await fetch(base+'/sessions',{method:'POST',headers:{'Content-Type':'application/json'},body:'{broken'});
    assert.equal(bad.status,400);assert.equal((await bad.json()).error,'Invalid reporting request body');
    const huge=await post(base+'/sessions',{data:'a'.repeat(140000)});assert.equal(huge.status,413);
    assert.equal((await fetch(base+'/unknown')).status,404);
  });
});
