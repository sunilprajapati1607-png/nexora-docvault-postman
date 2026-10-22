/**
 * Nexora DocVault Sync Server — the requests (0.6a)
 * ======================================================================
 * The user, 2026-10-22: "ujar potanu server jodi sake aevo option aapo … in house server pn hoi sake ane ujar online
 * render jeva server pn" and "aa software … ek company mate j". ONE company per server. The server keeps the sealed
 * copy (records and files it cannot read) so every approved PC and phone can sync, the administrator's PC on or off.
 *
 *   GET  /                          a status page (nothing secret)
 *   GET  /v1/hello                  what this is, whether a company is set up
 *   POST /v1/register               the administrator's PC sets the company up (once)
 *   POST /v1/join                   a PC or phone asks to join with the company ID and join code → waiting
 *   GET  /v1/me                     this device: waiting / approved (+ the data key wrapped for it, and the
 *                                   administrator's PC's public box key, for a key made here) / removed
 *   GET  /v1/devices                (administrator) every device
 *   POST /v1/devices/approve        (administrator) one user = one PC + one phone: an older one of that kind is replaced
 *   POST /v1/devices/remove         (administrator)
 *   POST /v1/admin/handover         (administrator) another approved PC becomes the administrator's
 *   GET  /v1/changes?since=N        sealed records after N
 *   POST /v1/changes                sealed records, each against the rev it was based on — a clash is sent back;
 *                                   a device's key ring (kind 'ring', 0.6e) only from the administrator's PC
 *   PUT  /v1/blobs/:id/:n           a part of a sealed file; POST /v1/blobs/:id/done checks the whole by its sha256
 *   GET  /v1/blobs/:id[/:n]         a file's parts back; POST /v1/blobs/have — which are already here
 * Every /v1 request but hello carries the server password's HMAC and the device's signature (proto.mjs).
 */
import crypto from 'node:crypto';
import * as P from './proto.mjs';

export const VERSION = '0.6.5';
const ID = /^[A-Za-z0-9_.-]{1,80}$/;
const JSON_MAX = 20 * 1024 * 1024, PART_MAX = 9 * 1024 * 1024;

function body(req, max) {
  return new Promise((resolve, reject) => {
    const parts = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > max) { reject(Object.assign(new Error('Too large.'), { status: 413 })); req.destroy(); return; } parts.push(c); });
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}
function send(res, status, obj, type) {
  const b = Buffer.isBuffer(obj) ? obj : Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj));
  res.writeHead(status, { 'content-type': type || 'application/json; charset=utf-8', 'content-length': b.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(b);
}
const fail = (status, code, message) => Object.assign(new Error(message), { status: status, code: code });
const same = (a, b) => { const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || '')); return x.length === y.length && crypto.timingSafeEqual(x, y); };
/** the join code as the server keeps it: a hash bound to the company, any case, no spaces */
const codeHash = (companyId, code) => crypto.createHash('sha256').update('nxdv-code:' + companyId + ':' + String(code || '').toUpperCase().replace(/\s+/g, '')).digest('hex');

export function createApp(o) {
  const store = o.store;
  const key = P.passwordKey(o.password);
  const now = o.now || (() => Date.now());
  const seen = new Map();                  /* replays inside the window */
  const misses = new Map();                /* wrong passwords by address: 20 in 10 minutes → 10 minutes out */

  function tooMany(ip) { const m = misses.get(ip); return m && m.n >= 20 && now() - m.at < 10 * 60 * 1000; }
  function missed(ip) { const m = misses.get(ip); if (!m || now() - m.at > 10 * 60 * 1000) misses.set(ip, { n: 1, at: now() }); else m.n++; }

  /** the password's HMAC, the time, no replay; then the device's signature with the key it is known by (or brings) */
  async function authorise(req, raw, ownPub) {
    const ip = req.socket.remoteAddress || '';
    if (tooMany(ip)) throw fail(429, 'TOO_MANY', 'Too many wrong tries — wait ten minutes.');
    const time = String(req.headers['x-dv-time'] || ''), device = String(req.headers['x-dv-device'] || '');
    if (!/^\d{12,14}$/.test(time) || Math.abs(now() - Number(time)) > P.WINDOW_MS) throw fail(401, 'CLOCK', 'This PC\'s clock and the server\'s differ by more than five minutes.');
    const text = P.canonical(req.method, req.url, time, device, raw);
    if (!same(req.headers['x-dv-auth'], P.hmac(key, text))) { missed(ip); throw fail(401, 'SERVER_PASSWORD', 'The server password is not right.'); }
    const sig = String(req.headers['x-dv-sig'] || '');
    const k = device + '|' + time + '|' + sig;
    if (seen.has(k)) throw fail(401, 'REPLAY', 'This request was already made.');
    seen.set(k, now());
    if (seen.size > 5000) for (const [kk, t] of seen) if (now() - t > P.WINDOW_MS) seen.delete(kk);
    let dev = null, pub = ownPub;
    if (!pub) { dev = await store.getDevice(device); if (!dev) throw fail(403, 'UNKNOWN_DEVICE', 'This PC or phone has not joined.'); pub = dev.signPub; }
    if (P.deviceId(pub) !== device || !P.verify(pub, text, sig)) throw fail(401, 'BAD_SIGNATURE', 'The device\'s signature does not match.');
    return dev;
  }
  async function approved(req, raw) {
    const dev = await authorise(req, raw);
    if (dev.state !== 'approved') throw fail(403, dev.state === 'waiting' ? 'WAITING' : 'NOT_APPROVED', dev.state === 'waiting' ? 'Waiting for the administrator\'s approval.' : 'This PC or phone is not approved.');
    return dev;
  }
  async function admin(req, raw) {
    const dev = await approved(req, raw);
    const c = await store.getCompany();
    if (!c || c.adminDevice !== dev.id) throw fail(403, 'NOT_ADMIN', 'Only the administrator\'s PC does this.');
    return { dev: dev, company: c };
  }
  const json = (raw) => { try { return JSON.parse(raw.toString('utf8') || '{}'); } catch (e) { throw fail(400, 'BAD_JSON', 'Not JSON.'); } };
  const pub = (d) => ({ id: d.id, kind: d.kind, userId: d.userId || '', userName: d.userName || '', state: d.state, boxPub: d.boxPub, requested: d.requested, approvedAt: d.approvedAt || null, label: d.label || '' });

  async function statusPage() {
    const c = await store.getCompany(), s = await store.stats();
    return '<!doctype html><html><head><meta charset="utf-8"><title>Nexora DocVault Sync Server</title><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<style>body{font-family:"Segoe UI",Arial,sans-serif;background:#f4f6fb;color:#1a2233;margin:0;padding:40px}.c{max-width:620px;margin:auto;background:#fff;border:1px solid #e1e5ee;border-radius:16px;padding:28px 32px;box-shadow:0 10px 30px rgba(15,23,42,.08)}' +
      'h1{font-size:22px;margin:0 0 4px}.m{color:#667085}.k{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:20px}.k div{background:#eceff5;border-radius:12px;padding:12px 14px}.k b{display:block;font-size:22px}' +
      '.ok{display:inline-block;margin-top:14px;padding:4px 12px;border-radius:999px;background:#d1fae5;color:#047857;font-weight:700}</style></head><body><div class="c">' +
      '<h1>Nexora DocVault Sync Server</h1><div class="m">Version ' + VERSION + ' · keeps one company\'s documents sealed — it cannot read them</div>' +
      '<span class="ok">● Running · ' + (c ? 'company set up' : 'waiting for the administrator\'s PC') + '</span>' +
      '<div class="k"><div><b>' + s.approved + '</b>devices approved</div><div><b>' + s.waiting + '</b>waiting</div><div><b>' + s.records + '</b>records · ' + s.blobs + ' files</div></div>' +
      '<p class="m" style="margin-top:18px">Storage: ' + (store.kind === 'folder' ? 'a folder on this server' : 'a Postgres database') + '</p></div></body></html>';
  }

  async function route(req, res) {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname, m = req.method;
    if (m === 'GET' && p === '/') return send(res, 200, await statusPage(), 'text/html; charset=utf-8');
    if (m === 'GET' && p === '/v1/hello') { const c = await store.getCompany(); return send(res, 200, { product: 'nexora-docvault-sync', version: VERSION, setUp: !!c, oneCompany: true }); }

    /* blob parts are raw bytes; everything else is JSON */
    const partM = /^\/v1\/blobs\/([^/]+)\/(\d{1,6})$/.exec(p);
    const raw = await body(req, m === 'PUT' && partM ? PART_MAX : JSON_MAX);

    if (m === 'POST' && p === '/v1/register') {
      const b = json(raw);
      if (!b.signPub || !b.boxPub || !ID.test(String(b.companyId || '')) || !b.code) throw fail(400, 'BAD_REQUEST', 'The company ID, join code and device keys are needed.');
      await authorise(req, raw, b.signPub);
      const dId = P.deviceId(b.signPub);
      const c = await store.getCompany();
      if (c && !(c.id === b.companyId && c.adminDevice === dId)) throw fail(409, 'ALREADY_SET_UP', 'This server already keeps a company (' + (c.id === b.companyId ? 'set up by another PC' : 'another company') + ') — one company per server.');
      /* the join code is kept only as a hash, and the company's name not at all — the server needs neither to read */
      await store.setCompany({ id: b.companyId, codeHash: codeHash(b.companyId, b.code), adminDevice: dId, created: c ? c.created : new Date(now()).toISOString() });
      await store.putDevice({ id: dId, kind: 'pc', signPub: b.signPub, boxPub: b.boxPub, userId: String(b.userId || ''), userName: String(b.userName || ''), label: String(b.label || '').slice(0, 80), state: 'approved', requested: new Date(now()).toISOString(), approvedAt: new Date(now()).toISOString() });
      return send(res, 200, { ok: true, deviceId: dId });
    }
    if (m === 'POST' && p === '/v1/join') {
      const b = json(raw);
      if (!b.signPub || !b.boxPub) throw fail(400, 'BAD_REQUEST', 'The device keys are needed.');
      await authorise(req, raw, b.signPub);
      const c = await store.getCompany();
      if (!c) throw fail(409, 'NOT_SET_UP', 'No company on this server yet — the administrator\'s PC sets it up first.');
      if (b.companyId !== c.id || !same(codeHash(c.id, b.code), c.codeHash)) throw fail(403, 'WRONG_CODE', 'The company ID or join code is not right.');
      const dId = P.deviceId(b.signPub);
      const had = await store.getDevice(dId);
      if (had && had.state !== 'removed' && had.state !== 'replaced') return send(res, 200, { ok: true, deviceId: dId, state: had.state });
      await store.putDevice({ id: dId, kind: b.kind === 'phone' ? 'phone' : 'pc', signPub: b.signPub, boxPub: b.boxPub, userName: String(b.userName || '').slice(0, 60), label: String(b.label || '').slice(0, 80), state: 'waiting', requested: new Date(now()).toISOString() });
      return send(res, 200, { ok: true, deviceId: dId, state: 'waiting' });
    }
    if (m === 'GET' && p === '/v1/me') {
      const dev = await authorise(req, raw);
      const c = await store.getCompany();
      const adm = c && dev.state === 'approved' ? await store.getDevice(c.adminDevice) : null;
      return send(res, 200, { id: dev.id, state: dev.state, kind: dev.kind, userId: dev.userId || '', userName: dev.userName || '', admin: !!(c && c.adminDevice === dev.id), wrappedKey: dev.state === 'approved' ? dev.wrappedKey || null : null, adminBox: adm ? adm.boxPub : null, company: c ? { id: c.id } : null });
    }
    if (m === 'GET' && p === '/v1/devices') { await admin(req, raw); return send(res, 200, { devices: (await store.listDevices()).map(pub) }); }
    if (m === 'POST' && p === '/v1/devices/approve') {
      await admin(req, raw);
      const b = json(raw);
      const d = await store.getDevice(String(b.deviceId || ''));
      if (!d) throw fail(404, 'NO_DEVICE', 'No such device.');
      if (!b.wrappedKey || !b.userId) throw fail(400, 'BAD_REQUEST', 'The user and the wrapped key are needed.');
      /* the user, 2026-10-22: "ek j ujar ek pc ane ek mobile allowed che" */
      const replaced = [];
      for (const o2 of await store.listDevices()) {
        if (o2.id !== d.id && o2.state === 'approved' && o2.userId === String(b.userId) && o2.kind === d.kind) {
          const c = await store.getCompany();
          if (c.adminDevice === o2.id) throw fail(409, 'ADMIN_PC', 'That is the administrator\'s PC — hand the administrator over first.');
          o2.state = 'replaced'; o2.wrappedKey = null; await store.putDevice(o2); replaced.push(o2.id);
        }
      }
      Object.assign(d, { state: 'approved', userId: String(b.userId), userName: String(b.userName || d.userName || ''), wrappedKey: String(b.wrappedKey), approvedAt: new Date(now()).toISOString() });
      await store.putDevice(d);
      return send(res, 200, { ok: true, replaced: replaced });
    }
    if (m === 'POST' && p === '/v1/devices/remove') {
      const a = await admin(req, raw);
      const b = json(raw);
      if (b.deviceId === a.company.adminDevice) throw fail(409, 'ADMIN_PC', 'The administrator\'s own PC is not removed.');
      const d = await store.getDevice(String(b.deviceId || ''));
      if (!d) throw fail(404, 'NO_DEVICE', 'No such device.');
      d.state = 'removed'; d.wrappedKey = null; await store.putDevice(d);
      return send(res, 200, { ok: true });
    }
    if (m === 'POST' && p === '/v1/admin/handover') {
      const a = await admin(req, raw);
      const b = json(raw);
      const d = await store.getDevice(String(b.deviceId || ''));
      if (!d || d.state !== 'approved' || d.kind !== 'pc') throw fail(400, 'BAD_DEVICE', 'Hand over to an approved PC.');
      a.company.adminDevice = d.id; await store.setCompany(a.company);
      return send(res, 200, { ok: true });
    }
    if (m === 'GET' && p === '/v1/changes') {
      await approved(req, raw);
      return send(res, 200, await store.changes(Number(url.searchParams.get('since')) || 0, Math.min(1000, Number(url.searchParams.get('limit')) || 500)));
    }
    if (m === 'POST' && p === '/v1/changes') {
      const dev = await approved(req, raw);
      const c = await store.getCompany();
      const isAdmin = !!(c && c.adminDevice === dev.id);
      const b = json(raw);
      const items = Array.isArray(b.items) ? b.items.slice(0, 500) : [];
      const results = [];
      for (const it of items) {
        if (!ID.test(String(it.id || '')) || !/^[a-z]{1,20}$/.test(String(it.kind || '')) || typeof it.sealed !== 'string' || it.sealed.length > 8 * 1024 * 1024) { results.push({ id: it.id, error: 'BAD_ITEM' }); continue; }
        /* 0.6e — which keys a PC or phone holds is the administrator's to say */
        if ((it.kind === 'ring' || /^ring-/.test(String(it.id))) && !isAdmin) { results.push({ id: it.id, error: 'NOT_ADMIN' }); continue; }
        results.push(Object.assign({ id: it.id }, await store.putRecord(it.id, it.kind, Number(it.baseRev) || 0, it.sealed)));
      }
      return send(res, 200, { results: results });
    }
    if (m === 'PUT' && partM) {
      await approved(req, raw);
      if (!ID.test(partM[1])) throw fail(400, 'BAD_ID', 'Bad file id.');
      const meta = await store.blobMeta(partM[1]);
      if (meta) return send(res, 200, { ok: true, already: true });      /* a file's bytes never change once whole */
      await store.putBlobPart(partM[1], Number(partM[2]), raw);
      return send(res, 200, { ok: true });
    }
    const doneM = /^\/v1\/blobs\/([^/]+)\/done$/.exec(p);
    if (m === 'POST' && doneM) {
      await approved(req, raw);
      const b = json(raw);
      if (await store.blobMeta(doneM[1])) return send(res, 200, { ok: true, already: true });
      const r = await store.finishBlob(doneM[1], Math.max(1, Number(b.parts) || 1), String(b.sha || ''));
      if (!r.ok) throw fail(409, r.badSha ? 'BAD_SHA' : 'PART_MISSING', r.badSha ? 'The file\'s parts do not add up — send it again.' : 'Part ' + r.missing + ' is missing.');
      return send(res, 200, { ok: true, size: r.size });
    }
    if (m === 'POST' && p === '/v1/blobs/have') {
      await approved(req, raw);
      const b = json(raw);
      const have = [];
      for (const id of (Array.isArray(b.ids) ? b.ids.slice(0, 2000) : [])) if (ID.test(String(id)) && await store.blobMeta(id)) have.push(id);
      return send(res, 200, { have: have });
    }
    const getM = /^\/v1\/blobs\/([^/]+)(?:\/(\d{1,6}))?$/.exec(p);
    if (m === 'GET' && getM) {
      await approved(req, raw);
      const meta = await store.blobMeta(getM[1]);
      if (!meta) throw fail(404, 'NO_FILE', 'Not on the server.');
      if (getM[2] === undefined) return send(res, 200, meta);
      const part = await store.getBlobPart(getM[1], Number(getM[2]));
      if (!part) throw fail(404, 'NO_PART', 'No such part.');
      return send(res, 200, part, 'application/octet-stream');
    }
    throw fail(404, 'NOT_FOUND', 'Nothing here.');
  }

  return async function handler(req, res) {
    try { await route(req, res); }
    catch (e) { send(res, e.status || 500, { error: e.code || 'ERROR', message: e.status ? e.message : 'The server could not do it.' }); if (!e.status) console.error(e); }
  };
}
