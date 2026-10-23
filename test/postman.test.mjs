/**
 * The postman (0.8), end to end over HTTP, on POSTGRES over the real wire protocol (PGlite behind pglite-socket,
 * through pgmini — the ERP's lesson: a Postgres store is only proven over the wire).
 *   node test/postman.test.mjs
 */
import http from 'node:http';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { createPostman } from '../src/postman.mjs';
import { postmanStore } from '../src/postman-store.mjs';
import * as P from '../src/proto.mjs';

const { PGlite } = await import('@electric-sql/pglite');
const { PGLiteSocketServer } = await import('@electric-sql/pglite-socket');
const db = new PGlite();
await db.waitReady;
const sock = new PGLiteSocketServer({ db, port: 0, host: '127.0.0.1' });
await sock.start();
const pgPort = sock.server ? sock.server.address().port : sock.port;
const store = postmanStore('postgres://postgres:postgres@127.0.0.1:' + pgPort + '/postgres?sslmode=disable');
await store.init();

let clock = Date.now();
const handler = createPostman({ store, now: () => clock, companyMaxBytes: 3 * 1024 * 1024 });
const server = http.createServer(handler);
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = 'http://127.0.0.1:' + server.address().port;
let n = 0;
const ok = async (name, fn) => { await fn(); n++; console.log('  ok ' + name); };

const dev = (name) => { const k = P.newDeviceKeys(); return Object.assign(k, { id: P.deviceId(k.signPub), name }); };
async function call(d, method, p, data, o) {
  o = o || {};
  const body = data === undefined ? Buffer.alloc(0) : Buffer.isBuffer(data) ? data : Buffer.from(JSON.stringify(data));
  const time = String(o.time || ++clock);
  const text = P.canonical(method, p, time, d ? d.id : '', o.signedBody || body);
  const h = { 'x-dv-time': time, 'x-dv-device': d ? d.id : '', 'x-dv-sig': d ? P.sign(d.signPriv, text) : '' };
  if (o.headers) Object.assign(h, o.headers);
  const res = await fetch(base + p, { method, headers: h, body: method === 'GET' ? undefined : body });
  const buf = Buffer.from(await res.arrayBuffer());
  const type = res.headers.get('content-type') || '';
  return { status: res.status, data: /json/.test(type) ? JSON.parse(buf.toString('utf8')) : buf, headers: h };
}
const keys = (d) => ({ signPub: d.signPub, boxPub: d.boxPub });
const sealed = (s) => Buffer.from('SEALED:' + s).toString('base64');

const asha = dev('Asha PC'), ravi = dev('Ravi phone'), sita = dev('Sita PC'), bose = dev('Bose PC'), priya = dev('Priya phone');
let codeA = '', companyA = '', codeB = '';

await ok('hello: the postman, no password asked', async () => {
  const r = await fetch(base + '/v2/hello').then((x) => x.json());
  assert.equal(r.product, 'nexora-docvault-postman'); assert.equal(r.postman, true);
});
await ok('a new administrator\'s PC starts its company: an id and a short code to type (ABCD-EFGH)', async () => {
  const r = await call(asha, 'POST', '/v2/company', Object.assign(keys(asha), { userId: 'U1', userName: 'Asha', label: 'Asha office PC' }));
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.match(r.data.code, /^[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4}$/);
  codeA = r.data.code; companyA = r.data.companyId;
  assert.equal((await call(asha, 'POST', '/v2/company', keys(asha))).data.error, 'ALREADY_IN');
  const rows = await db.query('SELECT * FROM dvpm_companies');
  assert.ok(!JSON.stringify(rows.rows).includes(codeA.replace('-', '')) && !JSON.stringify(rows.rows).includes(codeA), 'the server keeps only the code\'s hash');
});
await ok('a second company (Bose) on the same server', async () => {
  const r = await call(bose, 'POST', '/v2/company', Object.assign(keys(bose), { userId: 'U1', userName: 'Bose' }));
  assert.equal(r.status, 200); codeB = r.data.code; assert.notEqual(r.data.companyId, companyA);
});
await ok('join: a wrong code is refused; the right one in any case, without the dash → waiting', async () => {
  assert.equal((await call(ravi, 'POST', '/v2/join', Object.assign(keys(ravi), { code: 'AAAA-BBBB', userName: 'Ravi' }))).data.error, 'WRONG_CODE');
  const r = await call(ravi, 'POST', '/v2/join', Object.assign(keys(ravi), { code: codeA.toLowerCase().replace('-', ''), userName: 'Ravi', label: 'Ravi phone', kind: 'phone' }));
  assert.equal(r.data.state, 'waiting'); assert.equal(r.data.companyId, companyA);
  assert.equal((await call(ravi, 'GET', '/v2/me')).data.state, 'waiting');
  assert.equal((await call(ravi, 'POST', '/v2/mail', { items: [{ to: 'admin', kind: 'doc', sealed: sealed('x') }] })).data.error, 'WAITING');
  await call(sita, 'POST', '/v2/join', Object.assign(keys(sita), { code: codeA, userName: 'Sita', kind: 'pc' }));
  await call(priya, 'POST', '/v2/join', Object.assign(keys(priya), { code: codeB, userName: 'Priya', kind: 'phone' }));
});
await ok('the administrator approves: the data key wrapped for that device, the administrator\'s box key and when it was here', async () => {
  const list = (await call(asha, 'GET', '/v2/devices')).data.devices;
  assert.deepEqual(list.map((d) => d.userName).sort(), ['Asha', 'Ravi', 'Sita']);
  for (const [d, u, name] of [[ravi, 'U2', 'Ravi'], [sita, 'U3', 'Sita']]) assert.equal((await call(asha, 'POST', '/v2/devices/approve', { deviceId: d.id, userId: u, userName: name, wrappedKey: P.wrapFor(d.boxPub, Buffer.alloc(32, 7)) })).status, 200);
  const me = (await call(ravi, 'GET', '/v2/me')).data;
  assert.equal(me.state, 'approved'); assert.equal(me.adminBox, asha.boxPub); assert.ok(me.adminSeen);
  assert.deepEqual(P.unwrap(ravi.boxPriv, me.wrappedKey), Buffer.alloc(32, 7));
});
await ok('companies are apart: one administrator neither sees nor approves another\'s devices', async () => {
  assert.ok(!(await call(bose, 'GET', '/v2/devices')).data.devices.some((d) => d.id === ravi.id));
  assert.equal((await call(asha, 'POST', '/v2/devices/approve', { deviceId: priya.id, userId: 'U9', wrappedKey: 'x' })).data.error, 'NO_DEVICE');
  assert.equal((await call(ravi, 'GET', '/v2/devices')).data.error, 'NOT_ADMIN');
});
await ok('a device writes only to the administrator\'s PC — not to another device', async () => {
  const r = await call(ravi, 'POST', '/v2/mail', { items: [{ to: 'admin', kind: 'doc', ref: 'D1', sealed: sealed('Ravi D1 v2') }, { to: sita.id, kind: 'doc', ref: 'D1', sealed: sealed('x') }] });
  assert.equal(r.data.results[0].ok, true); assert.equal(r.data.results[1].error, 'ONLY_TO_ADMIN');
  assert.equal((await call(sita, 'GET', '/v2/mail')).data.items.length, 0, 'Sita gets nothing of Ravi\'s directly');
});
await ok('status, the administrator\'s PC off: when it was last here, and which documents wait (no contents)', async () => {
  clock += 3 * 60 * 1000;
  const s = (await call(sita, 'GET', '/v2/status')).data;
  assert.equal(s.adminOn, false); assert.ok(s.adminSeen);
  assert.deepEqual(s.waiting.map((w) => [w.ref, w.from, w.mine]), [['D1', 'Ravi', false]]);
  assert.ok(!JSON.stringify(s).includes('SEALED'));
  assert.equal((await call(ravi, 'GET', '/v2/status')).data.waiting[0].mine, true);
});
await ok('the administrator\'s PC comes: takes its letters, says it has them — they are gone from the server', async () => {
  const got = (await call(asha, 'GET', '/v2/mail')).data;
  assert.equal(got.items.length, 1); assert.equal(Buffer.from(got.items[0].sealed, 'base64').toString(), 'SEALED:Ravi D1 v2');
  assert.equal((await call(asha, 'POST', '/v2/mail/ack', { seqs: got.items.map((i) => i.seq) })).data.gone, 1);
  assert.equal((await call(asha, 'GET', '/v2/mail')).data.items.length, 0);
  const s = (await call(sita, 'GET', '/v2/status')).data;
  assert.equal(s.adminOn, true); assert.equal(s.waiting.length, 0);
  assert.equal(Number((await db.query('SELECT count(*)::int AS n FROM dvpm_mail')).rows[0].n), 0, 'nothing kept once delivered');
});
await ok('the administrator\'s PC writes to each device; each gets only its own', async () => {
  const r = await call(asha, 'POST', '/v2/mail', { items: [{ to: sita.id, kind: 'doc', ref: 'D1', sealed: sealed('for Sita') }, { to: ravi.id, kind: 'ring', sealed: sealed('Ravi ring') }, { to: priya.id, kind: 'doc', sealed: sealed('x') }] });
  assert.deepEqual(r.data.results.map((x) => !!x.ok), [true, true, false], 'not to another company\'s device');
  const s = (await call(sita, 'GET', '/v2/mail')).data.items;
  assert.deepEqual(s.map((i) => i.ref), ['D1']);
  const rv = (await call(ravi, 'GET', '/v2/mail')).data.items;
  assert.deepEqual(rv.map((i) => i.kind), ['ring']);
  assert.equal((await call(ravi, 'POST', '/v2/mail/ack', { seqs: s.map((i) => i.seq) })).data.gone, 0, 'one acks only its own letters');
  await call(sita, 'POST', '/v2/mail/ack', { seqs: s.map((i) => i.seq) });
  await call(ravi, 'POST', '/v2/mail/ack', { seqs: rv.map((i) => i.seq) });
});
await ok('a file up from Ravi to the administrator\'s PC, on to Sita (not sent up twice), gone after the last has it', async () => {
  const bytes = crypto.randomBytes(5 * 1024 * 1024 + 123).subarray(0, 1500000);
  const parts = [bytes.subarray(0, 1000000), bytes.subarray(1000000)];
  for (let i = 0; i < 2; i++) assert.equal((await call(ravi, 'PUT', '/v2/blobs/F1/' + i, parts[i])).status, 200);
  assert.equal((await call(ravi, 'POST', '/v2/blobs/F1/done', { parts: 2, sha: P.sha256hex(bytes), to: [sita.id] })).data.error, 'ONLY_TO_ADMIN');
  assert.equal((await call(ravi, 'POST', '/v2/blobs/F1/done', { parts: 2, sha: P.sha256hex(bytes) })).status, 200);
  assert.equal((await call(sita, 'GET', '/v2/blobs/F1')).data.error, 'NO_FILE', 'Sita may not fetch it yet');
  const meta = (await call(asha, 'GET', '/v2/blobs/F1')).data;
  const back = Buffer.concat([(await call(asha, 'GET', '/v2/blobs/F1/0')).data, (await call(asha, 'GET', '/v2/blobs/F1/1')).data]);
  assert.equal(P.sha256hex(back), meta.sha);
  assert.equal((await call(asha, 'POST', '/v2/blobs/F1/forward', { to: [sita.id, priya.id] })).data.to, 1);
  assert.equal((await call(asha, 'POST', '/v2/blobs/F1/ack')).data.gone, false);
  assert.equal(P.sha256hex(Buffer.concat([(await call(sita, 'GET', '/v2/blobs/F1/0')).data, (await call(sita, 'GET', '/v2/blobs/F1/1')).data])), meta.sha);
  assert.equal((await call(sita, 'POST', '/v2/blobs/F1/ack')).data.gone, true);
  assert.deepEqual((await call(asha, 'POST', '/v2/blobs/have', { ids: ['F1'] })).data.have, []);
  assert.equal(Number((await db.query('SELECT count(*)::int AS n FROM dvpm_blob_parts')).rows[0].n), 0);
});
await ok('a company\'s room: letters past its limit are refused (the administrator\'s PC takes them when on)', async () => {
  const big = 'A'.repeat(2 * 1024 * 1024);
  assert.equal((await call(ravi, 'POST', '/v2/mail', { items: [{ to: 'admin', kind: 'doc', sealed: big }] })).status, 200);
  assert.equal((await call(ravi, 'POST', '/v2/mail', { items: [{ to: 'admin', kind: 'doc', sealed: big }] })).data.error, 'MAILBOX_FULL');
  const got = (await call(asha, 'GET', '/v2/mail')).data.items;
  await call(asha, 'POST', '/v2/mail/ack', { seqs: got.map((i) => i.seq) });
});
await ok('a request changed, replayed, or from a clock five minutes off is refused', async () => {
  const r1 = await call(ravi, 'GET', '/v2/status');
  assert.equal(r1.status, 200);
  const again = await fetch(base + '/v2/status', { headers: r1.headers });
  assert.equal((await again.json()).error, 'REPLAY');
  assert.equal((await call(ravi, 'POST', '/v2/mail', { items: [{ to: 'admin', kind: 'doc', sealed: sealed('a') }] }, { signedBody: Buffer.from('{}') })).data.error, 'BAD_SIGNATURE');
  assert.equal((await call(ravi, 'GET', '/v2/me', undefined, { time: clock - 6 * 60 * 1000 })).data.error, 'CLOCK');
});
await ok('a new join code: the old one stops working', async () => {
  const nc = (await call(asha, 'POST', '/v2/company/code', {})).data.code;
  assert.notEqual(nc, codeA);
  const d = dev('new');
  assert.equal((await call(d, 'POST', '/v2/join', Object.assign(keys(d), { code: codeA }))).data.error, 'WRONG_CODE');
  assert.equal((await call(d, 'POST', '/v2/join', Object.assign(keys(d), { code: nc }))).data.state, 'waiting');
});
await ok('one user = one PC + one phone: Ravi\'s new phone replaces the old; a removed device gets nothing more', async () => {
  const ravi2 = dev('Ravi new phone');
  await call(asha, 'POST', '/v2/mail', { items: [{ to: ravi.id, kind: 'doc', sealed: sealed('old phone') }] });
  const nc = (await call(asha, 'POST', '/v2/company/code', {})).data.code;
  await call(ravi2, 'POST', '/v2/join', Object.assign(keys(ravi2), { code: nc, kind: 'phone', userName: 'Ravi' }));
  const r = await call(asha, 'POST', '/v2/devices/approve', { deviceId: ravi2.id, userId: 'U2', wrappedKey: P.wrapFor(ravi2.boxPub, Buffer.alloc(32, 7)) });
  assert.deepEqual(r.data.replaced, [ravi.id]);
  assert.equal((await call(ravi, 'GET', '/v2/me')).data.state, 'replaced');
  assert.equal((await call(ravi, 'GET', '/v2/mail')).data.error, 'NOT_APPROVED');
  assert.equal(Number((await db.query('SELECT count(*)::int AS n FROM dvpm_mail WHERE to_dev = $1', [ravi.id])).rows[0].n), 0, 'its letters dropped');
  await call(asha, 'POST', '/v2/devices/remove', { deviceId: sita.id });
  assert.equal((await call(sita, 'GET', '/v2/status')).data.error, 'NOT_APPROVED');
  assert.equal((await call(asha, 'POST', '/v2/devices/remove', { deviceId: asha.id })).data.error, 'ADMIN_PC');
});
await ok('letters nobody fetched for 90 days are dropped', async () => {
  const ravi2 = (await call(asha, 'GET', '/v2/devices')).data.devices.find((d) => d.state === 'approved' && d.kind === 'phone');
  await call(asha, 'POST', '/v2/mail', { items: [{ to: ravi2.id, kind: 'doc', sealed: sealed('old') }] });
  clock += 91 * 24 * 3600 * 1000;
  const r = await handler.purge();
  assert.ok(r.mail >= 1);
  assert.equal(Number((await db.query('SELECT count(*)::int AS n FROM dvpm_mail')).rows[0].n), 0);
});
await ok('five new companies a day from one address — the sixth waits', async () => {
  const codes = [];
  /* (the clock went on 91 days above: a new day for this address) */
  for (let i = 0; i < 6; i++) { const d = dev('c' + i); codes.push((await call(d, 'POST', '/v2/company', keys(d))).status); }
  assert.deepEqual(codes, [200, 200, 200, 200, 200, 429], 'five today — the sixth waits');
});

server.close();
await sock.stop();
await db.close();
console.log('postman: ' + n + ' passed');
process.exit(0);
