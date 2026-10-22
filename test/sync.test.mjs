/**
 * The Sync Server, end to end over HTTP — once with the FOLDER store, once with POSTGRES over the real wire protocol
 * (PGlite behind pglite-socket, through pgmini — the ERP's lesson: a Postgres store is only proven over the wire).
 *   node test/sync.test.mjs
 */
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';
import { folderStore } from '../src/store-folder.mjs';
import { pgStore } from '../src/store-pg.mjs';
import * as P from '../src/proto.mjs';

const PASSWORD = 'asha-sync-2026!';
let total = 0;

async function suite(label, store) {
  await store.init();
  let clock = Date.now();
  const server = http.createServer(createApp({ store, password: PASSWORD, now: () => clock }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  let n = 0;
  const ok = async (name, fn) => { await fn(); n++; console.log('  ok [' + label + '] ' + name); };

  const dev = (name) => { const k = P.newDeviceKeys(); return Object.assign(k, { id: P.deviceId(k.signPub), name }); };
  /* one request as a device would make it; t: the time it says (a clock off, a replay) */
  async function call(d, method, p, data, o) {
    o = o || {};
    const body = data === undefined ? Buffer.alloc(0) : Buffer.isBuffer(data) ? data : Buffer.from(JSON.stringify(data));
    /* every request its own millisecond (a client never sends two the same: the server takes the second for a replay) */
    const h = P.headers({ method, path: p, time: o.time || ++clock, device: d ? d.id : '', body, password: o.password || PASSWORD, signPriv: d ? d.signPriv : '' });
    const res = await fetch(base + p, { method, headers: h, body: method === 'GET' ? undefined : body });
    const buf = Buffer.from(await res.arrayBuffer());
    const type = res.headers.get('content-type') || '';
    return { status: res.status, data: /json/.test(type) ? JSON.parse(buf.toString('utf8')) : buf };
  }

  const adminPc = dev('Asha PC'), ravi = dev('Ravi PC'), raviPhone = dev('Ravi phone'), raviNewPc = dev('Ravi new PC'), stranger = dev('Stranger');
  const dataKey = crypto.randomBytes(32);
  const company = { companyId: 'V1a2b3c4d5e6f7a8b', name: 'Asha Packaging', code: 'ASHA-7K2Q' };

  await ok('hello, and the status page says nothing secret', async () => {
    const r = await (await fetch(base + '/v1/hello')).json();
    assert.equal(r.setUp, false);
    assert.equal(r.oneCompany, true);
    const page = await (await fetch(base + '/')).text();
    assert.match(page, /Nexora DocVault Sync Server/);
    assert.doesNotMatch(page, /ASHA-7K2Q/);
  });
  await ok('the administrator\'s PC sets the company up; a wrong server password is refused', async () => {
    const reg = Object.assign({}, company, { signPub: adminPc.signPub, boxPub: adminPc.boxPub, userId: 'U1', userName: 'Asha' });
    assert.equal((await call(adminPc, 'POST', '/v1/register', reg, { password: 'wrong-password-1' })).status, 401);
    const r = await call(adminPc, 'POST', '/v1/register', reg);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal((await call(adminPc, 'GET', '/v1/me')).data.admin, true);
  });
  await ok('one company per server: another is refused', async () => {
    const other = dev('Other');
    const r = await call(other, 'POST', '/v1/register', { companyId: 'Vother', name: 'Other Co', code: 'X', signPub: other.signPub, boxPub: other.boxPub });
    assert.equal(r.status, 409);
    assert.equal(r.data.error, 'ALREADY_SET_UP');
  });
  await ok('join with the company ID and code → waiting; a wrong code is refused', async () => {
    const bad = await call(stranger, 'POST', '/v1/join', { companyId: company.companyId, code: 'WRONG', signPub: stranger.signPub, boxPub: stranger.boxPub });
    assert.equal(bad.status, 403);
    for (const [d, kind] of [[ravi, 'pc'], [raviPhone, 'phone'], [raviNewPc, 'pc']]) {
      const r = await call(d, 'POST', '/v1/join', { companyId: company.companyId, code: 'asha-7k2q', kind, userName: 'Ravi', signPub: d.signPub, boxPub: d.boxPub });
      assert.equal(r.data.state, 'waiting');
    }
    const me = await call(ravi, 'GET', '/v1/me');
    assert.equal(me.data.state, 'waiting');
    assert.equal(me.data.wrappedKey, null);
    assert.equal((await call(ravi, 'GET', '/v1/changes?since=0')).data.error, 'WAITING');
  });
  await ok('only the administrator approves; the data key reaches the device wrapped for it alone', async () => {
    assert.equal((await call(ravi, 'GET', '/v1/devices')).status, 403);
    const list = (await call(adminPc, 'GET', '/v1/devices')).data.devices;
    const r = list.find((x) => x.id === ravi.id);
    const ap = await call(adminPc, 'POST', '/v1/devices/approve', { deviceId: ravi.id, userId: 'U2', userName: 'Ravi', wrappedKey: P.wrapFor(r.boxPub, dataKey) });
    assert.equal(ap.status, 200);
    const me = await call(ravi, 'GET', '/v1/me');
    assert.equal(me.data.state, 'approved');
    assert.ok(P.unwrap(ravi.boxPriv, me.data.wrappedKey).equals(dataKey));
    assert.throws(() => P.unwrap(stranger.boxPriv, me.data.wrappedKey));
  });
  await ok('one user = one PC + one phone: a new PC replaces the old one; the phone stays', async () => {
    await call(adminPc, 'POST', '/v1/devices/approve', { deviceId: raviPhone.id, userId: 'U2', userName: 'Ravi', wrappedKey: P.wrapFor(raviPhone.boxPub, dataKey) });
    const r = await call(adminPc, 'POST', '/v1/devices/approve', { deviceId: raviNewPc.id, userId: 'U2', userName: 'Ravi', wrappedKey: P.wrapFor(raviNewPc.boxPub, dataKey) });
    assert.deepEqual(r.data.replaced, [ravi.id]);
    assert.equal((await call(ravi, 'GET', '/v1/me')).data.state, 'replaced');
    assert.equal((await call(ravi, 'GET', '/v1/changes?since=0')).status, 403);
    assert.equal((await call(raviPhone, 'GET', '/v1/me')).data.state, 'approved');
  });
  await ok('records: a change against its rev; a clash is sent back with the newer one', async () => {
    const a = await call(adminPc, 'POST', '/v1/changes', { items: [{ id: 'Dd1', kind: 'doc', baseRev: 0, sealed: 'sealed-v1' }] });
    assert.equal(a.data.results[0].ok, true);
    const rev1 = a.data.results[0].rev;
    const b = await call(raviNewPc, 'POST', '/v1/changes', { items: [{ id: 'Dd1', kind: 'doc', baseRev: rev1, sealed: 'sealed-v2-ravi' }] });
    assert.equal(b.data.results[0].ok, true);
    const c = await call(raviPhone, 'POST', '/v1/changes', { items: [{ id: 'Dd1', kind: 'doc', baseRev: rev1, sealed: 'sealed-v2-phone' }] });
    assert.equal(c.data.results[0].conflict, true);
    assert.equal(c.data.results[0].sealed, 'sealed-v2-ravi');
    const pull = await call(raviPhone, 'GET', '/v1/changes?since=0');
    assert.equal(pull.data.items.length, 1);
    assert.equal(pull.data.items[0].sealed, 'sealed-v2-ravi');
    assert.equal((await call(raviPhone, 'GET', '/v1/changes?since=' + pull.data.rev)).data.items.length, 0);
  });
  await ok('files in parts, checked whole by their sha256; never changed once whole', async () => {
    const bytes = crypto.randomBytes(3 * 1024 * 1024 + 123);
    const parts = [bytes.subarray(0, 2 * 1024 * 1024), bytes.subarray(2 * 1024 * 1024)];
    for (let i = 0; i < parts.length; i++) assert.equal((await call(raviNewPc, 'PUT', '/v1/blobs/Fabc/' + i, parts[i])).status, 200);
    const bad = await call(raviNewPc, 'POST', '/v1/blobs/Fabc/done', { parts: 2, sha: '00' });
    assert.equal(bad.data.error, 'BAD_SHA');
    const sha = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal((await call(raviNewPc, 'POST', '/v1/blobs/Fabc/done', { parts: 2, sha })).data.size, bytes.length);
    assert.deepEqual((await call(adminPc, 'POST', '/v1/blobs/have', { ids: ['Fabc', 'Fnone'] })).data.have, ['Fabc']);
    const meta = (await call(adminPc, 'GET', '/v1/blobs/Fabc')).data;
    const back = [];
    for (let i = 0; i < meta.parts; i++) back.push((await call(adminPc, 'GET', '/v1/blobs/Fabc/' + i)).data);
    assert.ok(Buffer.concat(back).equals(bytes));
    assert.equal((await call(raviNewPc, 'PUT', '/v1/blobs/Fabc/0', Buffer.from('changed'))).data.already, true);
  });
  await ok('a replayed, late or unsigned request is refused', async () => {
    const t = clock;
    assert.equal((await call(adminPc, 'GET', '/v1/me', undefined, { time: t })).status, 200);
    assert.equal((await call(adminPc, 'GET', '/v1/me', undefined, { time: t })).data.error, 'REPLAY');
    assert.equal((await call(adminPc, 'GET', '/v1/me', undefined, { time: t - 6 * 60 * 1000 })).data.error, 'CLOCK');
    const forged = Object.assign({}, adminPc, { signPriv: stranger.signPriv });
    assert.equal((await call(forged, 'GET', '/v1/me', undefined, { time: t + 1 })).data.error, 'BAD_SIGNATURE');
    assert.equal((await call(stranger, 'GET', '/v1/me', undefined, { time: t + 2 })).data.error, 'UNKNOWN_DEVICE');
  });
  await ok('the administrator removes a device; hands over to another PC', async () => {
    await call(adminPc, 'POST', '/v1/devices/remove', { deviceId: raviPhone.id });
    assert.equal((await call(raviPhone, 'GET', '/v1/me')).data.state, 'removed');
    assert.equal((await call(adminPc, 'POST', '/v1/devices/remove', { deviceId: adminPc.id })).data.error, 'ADMIN_PC');
    assert.equal((await call(adminPc, 'POST', '/v1/admin/handover', { deviceId: raviNewPc.id })).status, 200);
    assert.equal((await call(raviNewPc, 'GET', '/v1/me')).data.admin, true);
    assert.equal((await call(adminPc, 'GET', '/v1/devices')).data.error, 'NOT_ADMIN');
  });
  await ok('twenty wrong passwords from one place: ten minutes out', async () => {
    for (let i = 0; i < 20; i++) await call(stranger, 'GET', '/v1/me', undefined, { password: 'nope-nope-nope', time: clock + 10 + i });
    assert.equal((await call(adminPc, 'GET', '/v1/me', undefined, { time: clock + 100 })).status, 429);
    clock += 11 * 60 * 1000;
    assert.equal((await call(raviNewPc, 'GET', '/v1/me')).status, 200);
  });
  const page = await (await fetch(base + '/')).text();
  server.close();
  total += n;
  return page;
}

/* the folder store */
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-sync-'));
const page = await suite('folder', folderStore(dir));
fs.writeFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'out-status.html'), page);
const again = folderStore(dir); await again.init();
assert.equal((await again.changes(0)).items.length, 1, 'the folder store reads its log back after a restart');
assert.ok(!fs.readFileSync(path.join(dir, 'records.log'), 'utf8').includes('ASHA-7K2Q'));
fs.rmSync(dir, { recursive: true, force: true });

/* Postgres, over the wire */
const { PGlite } = await import('@electric-sql/pglite');
const { PGLiteSocketServer } = await import('@electric-sql/pglite-socket');
const db = new PGlite();
await db.waitReady;
const sock = new PGLiteSocketServer({ db, port: 0, host: '127.0.0.1' });
await sock.start();
const pgPort = sock.server ? sock.server.address().port : sock.port;
await suite('postgres', pgStore('postgres://postgres:postgres@127.0.0.1:' + pgPort + '/postgres?sslmode=disable'));
await sock.stop();
await db.close();
console.log('sync server: ' + total + ' passed');
process.exit(0);
