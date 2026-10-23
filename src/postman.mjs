/**
 * Nexora DocVault Postman — the requests (0.8)
 * ======================================================================
 * The user, 2026-10-23: "ok use only our server as tapali, data base admin pc rahese, same mobile app pn connect thavi
 * joiye to have copy link krvani jarur nahi rahe ne". Nexora's own server for many companies, carrying sealed letters
 * between a company's devices and its ADMINISTRATOR'S PC — which alone keeps the documents (its vault is the
 * database). A letter waits here only until its reader has it. While the administrator's PC is off nothing passes
 * between the others; every device keeps working on its own copy, and each can ask what waits and since when (the
 * user: "pc 2 ne a doc kholta mesej dekhavo joiye ke latest copy sync thayel nthi admin pc band hovathi").
 *
 *   GET  /v2/hello                 what this is
 *   POST /v2/company               a new administrator's PC starts its company → { companyId, code } (the short join
 *                                  code "ABCD-EFGH" the people type on their PC or phone)
 *   POST /v2/company/code          (administrator) a new join code; the old one stops working
 *   POST /v2/join                  a PC or phone asks to join with the code → waiting
 *   GET  /v2/me                    this device: waiting / approved (+ the data key wrapped for it, the administrator's
 *                                  PC's box key and when it was last here) / removed / replaced
 *   GET  /v2/devices               (administrator) the company's devices; POST /v2/devices/approve | remove
 *   POST /v2/admin/handover        (administrator) another approved PC becomes the administrator's
 *   POST /v2/mail                  sealed letters: from a device only to 'admin'; from the administrator's PC to any
 *                                  of the company's devices. kind + ref (a document's id) travel plain — no words
 *   GET  /v2/mail?after=N          the letters to this device, oldest first; POST /v2/mail/ack — had them, gone
 *   GET  /v2/status                the administrator's PC last seen, and what waits for it (which documents, from
 *                                  whom, since when)
 *   PUT  /v2/blobs/:id/:n          a sealed file in parts; POST …/done names who may fetch it ('admin' or devices)
 *   GET  /v2/blobs/:id[/:n]        its parts, for one it is meant for; POST …/ack — had it (gone after the last)
 *   POST /v2/blobs/:id/forward     (administrator) a file it was sent, on to devices — not sent up twice
 *   POST /v2/blobs/have            which of these files wait here
 * Every request but hello carries the device's own signature over METHOD \n PATH \n TIME \n DEVICE \n sha256(body)
 * (proto.mjs), five minutes at most, never twice. There is no server password: one server serves every company, and
 * what keeps a stranger out is the administrator's approval of each device — and the seal on everything.
 */
import crypto from 'node:crypto';
import * as P from './proto.mjs';

export const VERSION = '0.8.0';
const ID = /^[A-Za-z0-9_.-]{1,80}$/;
const JSON_MAX = 20 * 1024 * 1024, PART_MAX = 9 * 1024 * 1024, LETTER_MAX = 8 * 1024 * 1024;
const KINDS = /^[a-z]{1,20}$/;
/* the code people type: no 0/O, 1/I/L — read over the phone without a mistake */
const ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

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
export const normCode = (code) => String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
export const codeHash = (code) => crypto.createHash('sha256').update('nxdv-pm-code:' + normCode(code)).digest('hex');
function newCode() {
  const b = crypto.randomBytes(8);
  let s = '';
  for (let i = 0; i < 8; i++) s += ALPHA[b[i] % ALPHA.length];
  return s.slice(0, 4) + '-' + s.slice(4);
}

/**
 * o.store: postman-store.mjs; o.now (tests); o.companyMaxBytes — what one company's waiting letters and files may
 * take (500 MB); o.newCompaniesPerDay — from one address (5); o.keepDays — a letter nobody fetched (90).
 */
export function createPostman(o) {
  const store = o.store;
  const now = o.now || (() => Date.now());
  const MAX = o.companyMaxBytes || 500 * 1024 * 1024;
  const ADMIN_ON = o.adminOnMs || 2 * 60 * 1000;      /* "on": the administrator's PC asked within this (the tests: seconds) */
  const seen = new Map();                  /* replays inside the window */
  const tries = new Map();                 /* by address: wrong codes, new companies */

  function limited(ip, what, n, ms) {
    const k = what + '|' + ip, t = tries.get(k);
    if (!t || now() - t.at > ms) { tries.set(k, { n: 1, at: now() }); return false; }
    t.n++;
    return t.n > n;
  }
  function overLimit(ip, what, n, ms) { const t = tries.get(what + '|' + ip); return !!(t && t.n >= n && now() - t.at <= ms); }

  /** the time, no replay, then the device's signature with the key it is known by (or brings, to join) */
  async function authorise(req, raw, ownPub) {
    const time = String(req.headers['x-dv-time'] || ''), device = String(req.headers['x-dv-device'] || '');
    if (!/^\d{12,14}$/.test(time) || Math.abs(now() - Number(time)) > P.WINDOW_MS) throw fail(401, 'CLOCK', 'This device\'s clock and the server\'s differ by more than five minutes.');
    const text = P.canonical(req.method, req.url, time, device, raw);
    const sig = String(req.headers['x-dv-sig'] || '');
    const k = device + '|' + time + '|' + sig;
    if (seen.has(k)) throw fail(401, 'REPLAY', 'This request was already made.');
    let dev = null, pub = ownPub;
    if (!pub) { dev = await store.getDevice(device); if (!dev) throw fail(403, 'UNKNOWN_DEVICE', 'This PC or phone has not joined.'); pub = dev.signPub; }
    if (P.deviceId(pub) !== device || !P.verify(pub, text, sig)) throw fail(401, 'BAD_SIGNATURE', 'The device\'s signature does not match.');
    seen.set(k, now());
    if (seen.size > 20000) for (const [kk, t] of seen) if (now() - t > P.WINDOW_MS) seen.delete(kk);
    /* when it was last here — kept at most every half minute (the administrator's PC's is what the others are told) */
    if (dev && (!dev.seen || now() - dev.seen > Math.min(30000, ADMIN_ON / 4))) { dev.seen = now(); await store.putDevice(dev); }
    return dev;
  }
  async function approved(req, raw) {
    const dev = await authorise(req, raw);
    if (dev.state !== 'approved') throw fail(403, dev.state === 'waiting' ? 'WAITING' : 'NOT_APPROVED', dev.state === 'waiting' ? 'Waiting for the administrator\'s approval.' : 'This PC or phone is not approved.');
    const company = await store.getCompany(dev.company);
    if (!company) throw fail(403, 'NO_COMPANY', 'This company is no longer on the server.');
    return { dev: dev, company: company, isAdmin: company.adminDevice === dev.id };
  }
  async function admin(req, raw) {
    const a = await approved(req, raw);
    if (!a.isAdmin) throw fail(403, 'NOT_ADMIN', 'Only the administrator\'s PC does this.');
    return a;
  }
  const json = (raw) => { try { return JSON.parse(raw.toString('utf8') || '{}'); } catch (e) { throw fail(400, 'BAD_JSON', 'Not JSON.'); } };
  const pub = (d) => ({ id: d.id, kind: d.kind, userId: d.userId || '', userName: d.userName || '', state: d.state, boxPub: d.boxPub, requested: d.requested, approvedAt: d.approvedAt || null, label: d.label || '', seen: d.seen || null });
  const iso = (t) => t ? new Date(t).toISOString() : null;
  /** a reader's own boxes: its id, and 'admin' for the administrator's PC */
  const boxes = (a) => a.isAdmin ? [a.dev.id, 'admin'] : [a.dev.id];
  async function room(cid, more) { if (await store.bytesOf(cid) + more > MAX) throw fail(507, 'MAILBOX_FULL', 'The company\'s letters waiting on the server are too many — the administrator\'s PC takes them when it is on.'); }
  async function freshCode() {
    for (let i = 0; i < 20; i++) { const c = newCode(); if (!await store.codeTaken(codeHash(c))) return c; }
    throw fail(503, 'BUSY', 'Try again.');
  }

  async function route(req, res) {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname, m = req.method;
    const ip = req.socket.remoteAddress || '';
    if (m === 'GET' && (p === '/' || p === '/v2/hello')) {
      if (p === '/') return send(res, 200, '<!doctype html><meta charset="utf-8"><title>Nexora DocVault Postman</title><body style="font-family:Segoe UI,Arial;padding:40px;color:#1a2233"><h1>Nexora DocVault Postman</h1><p>Version ' + VERSION + ' — carries sealed letters between a company\'s devices and its administrator\'s PC. It cannot read them, and keeps none once delivered.</p></body>', 'text/html; charset=utf-8');
      return send(res, 200, { product: 'nexora-docvault-postman', version: VERSION, postman: true });
    }
    const partM = /^\/v2\/blobs\/([^/]+)\/(\d{1,6})$/.exec(p);
    const raw = await body(req, m === 'PUT' && partM ? PART_MAX : JSON_MAX);

    /* ---------------- a company, and who is in it ---------------- */
    if (m === 'POST' && p === '/v2/company') {
      const b = json(raw);
      if (!b.signPub || !b.boxPub) throw fail(400, 'BAD_REQUEST', 'The device keys are needed.');
      if (overLimit(ip, 'company', 5, 24 * 3600 * 1000)) throw fail(429, 'TOO_MANY', 'Too many new companies from here today.');
      await authorise(req, raw, b.signPub);
      const dId = P.deviceId(b.signPub);
      const had = await store.getDevice(dId);
      if (had) throw fail(409, 'ALREADY_IN', 'This PC already belongs to a company on this server.');
      limited(ip, 'company', 5, 24 * 3600 * 1000);
      const id = 'C' + crypto.randomBytes(8).toString('hex');
      const code = await freshCode();
      await store.createCompany({ id: id, codeHash: codeHash(code), adminDevice: dId, created: new Date(now()).toISOString() });
      await store.putDevice({ id: dId, company: id, kind: 'pc', signPub: b.signPub, boxPub: b.boxPub, userId: String(b.userId || ''), userName: String(b.userName || '').slice(0, 60), label: String(b.label || '').slice(0, 80), state: 'approved', requested: new Date(now()).toISOString(), approvedAt: new Date(now()).toISOString(), seen: now() });
      /* the code is shown once to the administrator's PC, which keeps it; the server keeps only its hash */
      return send(res, 200, { ok: true, companyId: id, code: code, deviceId: dId });
    }
    if (m === 'POST' && p === '/v2/company/code') {
      const a = await admin(req, raw);
      const code = await freshCode();
      await store.setCode(a.company.id, codeHash(code));
      return send(res, 200, { ok: true, code: code });
    }
    if (m === 'POST' && p === '/v2/join') {
      const b = json(raw);
      if (!b.signPub || !b.boxPub) throw fail(400, 'BAD_REQUEST', 'The device keys are needed.');
      if (overLimit(ip, 'code', 20, 10 * 60 * 1000)) throw fail(429, 'TOO_MANY', 'Too many wrong codes — wait ten minutes.');
      await authorise(req, raw, b.signPub);
      const c = normCode(b.code).length === 8 ? await store.companyByCode(codeHash(b.code)) : null;
      if (!c) { limited(ip, 'code', 20, 10 * 60 * 1000); throw fail(403, 'WRONG_CODE', 'That company code is not right — ask the administrator for it.'); }
      const dId = P.deviceId(b.signPub);
      const had = await store.getDevice(dId);
      if (had && had.company !== c.id && had.state !== 'removed' && had.state !== 'replaced') throw fail(409, 'ALREADY_IN', 'This device already belongs to another company.');
      if (had && had.company === c.id && had.state !== 'removed' && had.state !== 'replaced') return send(res, 200, { ok: true, deviceId: dId, state: had.state, companyId: c.id });
      await store.putDevice({ id: dId, company: c.id, kind: b.kind === 'phone' ? 'phone' : 'pc', signPub: b.signPub, boxPub: b.boxPub, userName: String(b.userName || '').slice(0, 60), label: String(b.label || '').slice(0, 80), state: 'waiting', requested: new Date(now()).toISOString() });
      return send(res, 200, { ok: true, deviceId: dId, state: 'waiting', companyId: c.id });
    }
    if (m === 'GET' && p === '/v2/me') {
      const dev = await authorise(req, raw);
      const c = await store.getCompany(dev.company);
      const adm = c && dev.state === 'approved' ? await store.getDevice(c.adminDevice) : null;
      return send(res, 200, { id: dev.id, state: dev.state, kind: dev.kind, userId: dev.userId || '', userName: dev.userName || '', admin: !!(c && c.adminDevice === dev.id),
        wrappedKey: dev.state === 'approved' ? dev.wrappedKey || null : null, adminBox: adm ? adm.boxPub : null, adminSeen: adm ? iso(adm.seen) : null, company: c ? { id: c.id } : null });
    }
    if (m === 'GET' && p === '/v2/devices') { const a = await admin(req, raw); return send(res, 200, { devices: (await store.listDevices(a.company.id)).map(pub) }); }
    if (m === 'POST' && p === '/v2/devices/approve') {
      const a = await admin(req, raw);
      const b = json(raw);
      const d = await store.getDevice(String(b.deviceId || ''));
      if (!d || d.company !== a.company.id) throw fail(404, 'NO_DEVICE', 'No such device.');
      if (!b.wrappedKey || !b.userId) throw fail(400, 'BAD_REQUEST', 'The user and the wrapped key are needed.');
      /* one user = one PC + one phone: an older one of that kind is replaced */
      const replaced = [];
      for (const o2 of await store.listDevices(a.company.id)) {
        if (o2.id !== d.id && o2.state === 'approved' && o2.userId === String(b.userId) && o2.kind === d.kind) {
          if (a.company.adminDevice === o2.id) throw fail(409, 'ADMIN_PC', 'That is the administrator\'s PC — hand the administrator over first.');
          o2.state = 'replaced'; o2.wrappedKey = null; await store.putDevice(o2); await store.dropMailTo(a.company.id, o2.id); replaced.push(o2.id);
        }
      }
      Object.assign(d, { state: 'approved', userId: String(b.userId), userName: String(b.userName || d.userName || ''), wrappedKey: String(b.wrappedKey), approvedAt: new Date(now()).toISOString() });
      await store.putDevice(d);
      return send(res, 200, { ok: true, replaced: replaced });
    }
    if (m === 'POST' && p === '/v2/devices/remove') {
      const a = await admin(req, raw);
      const b = json(raw);
      if (b.deviceId === a.company.adminDevice) throw fail(409, 'ADMIN_PC', 'The administrator\'s own PC is not removed.');
      const d = await store.getDevice(String(b.deviceId || ''));
      if (!d || d.company !== a.company.id) throw fail(404, 'NO_DEVICE', 'No such device.');
      d.state = 'removed'; d.wrappedKey = null; await store.putDevice(d);
      await store.dropMailTo(a.company.id, d.id);
      return send(res, 200, { ok: true });
    }
    if (m === 'POST' && p === '/v2/admin/handover') {
      const a = await admin(req, raw);
      const b = json(raw);
      const d = await store.getDevice(String(b.deviceId || ''));
      if (!d || d.company !== a.company.id || d.state !== 'approved' || d.kind !== 'pc') throw fail(400, 'BAD_DEVICE', 'Hand over to an approved PC of this company.');
      await store.setAdmin(a.company.id, d.id);
      return send(res, 200, { ok: true });
    }

    /* ---------------- letters ---------------- */
    if (m === 'POST' && p === '/v2/mail') {
      const a = await approved(req, raw);
      const b = json(raw);
      const items = Array.isArray(b.items) ? b.items.slice(0, 500) : [];
      const devs = a.isAdmin ? new Map((await store.listDevices(a.company.id)).filter((d) => d.state === 'approved').map((d) => [d.id, d])) : null;
      await room(a.company.id, items.reduce((s, it) => s + String(it.sealed || '').length, 0));
      const results = [];
      for (const it of items) {
        const to = String(it.to || '');
        if (!KINDS.test(String(it.kind || '')) || typeof it.sealed !== 'string' || !it.sealed || it.sealed.length > LETTER_MAX || (it.ref && !ID.test(String(it.ref)))) { results.push({ error: 'BAD_ITEM' }); continue; }
        /* a device writes only to the administrator's PC; the administrator's PC to the company's approved devices */
        if (to !== 'admin' && !(a.isAdmin && devs.has(to))) { results.push({ error: a.isAdmin ? 'NO_DEVICE' : 'ONLY_TO_ADMIN' }); continue; }
        const seq = await store.putMail({ company: a.company.id, to: to, from: a.dev.id, kind: it.kind, ref: String(it.ref || ''), sealed: it.sealed, at: now() });
        results.push({ ok: true, seq: seq });
      }
      return send(res, 200, { results: results });
    }
    if (m === 'GET' && p === '/v2/mail') {
      const a = await approved(req, raw);
      return send(res, 200, await store.mailFor(a.company.id, boxes(a), Number(url.searchParams.get('after')) || 0, Math.min(500, Number(url.searchParams.get('limit')) || 200)));
    }
    if (m === 'POST' && p === '/v2/mail/ack') {
      const a = await approved(req, raw);
      const b = json(raw);
      const seqs = (Array.isArray(b.seqs) ? b.seqs : []).map(Number).filter((n) => Number.isInteger(n) && n > 0).slice(0, 2000);
      return send(res, 200, { ok: true, gone: await store.ackMail(a.company.id, boxes(a), seqs) });
    }
    if (m === 'GET' && p === '/v2/status') {
      const a = await approved(req, raw);
      const adm = await store.getDevice(a.company.adminDevice);
      const waiting = await store.waitingFor(a.company.id, 'admin');
      const names = new Map((await store.listDevices(a.company.id)).map((d) => [d.id, d.userName || d.label || '']));
      return send(res, 200, { adminSeen: adm ? iso(adm.seen) : null, adminOn: !!(adm && adm.seen && now() - adm.seen < ADMIN_ON),
        waiting: waiting.map((w) => ({ ref: w.ref, kind: w.kind, from: names.get(w.from) || '', mine: w.from === a.dev.id, at: iso(w.at) })) });
    }

    /* ---------------- files ---------------- */
    const may = (a, meta) => meta && (meta.recips.indexOf(a.dev.id) > -1 || (a.isAdmin && meta.recips.indexOf('admin') > -1));
    if (m === 'PUT' && partM) {
      const a = await approved(req, raw);
      if (!ID.test(partM[1])) throw fail(400, 'BAD_ID', 'Bad file id.');
      if (await store.blobMeta(a.company.id, partM[1])) return send(res, 200, { ok: true, already: true });
      await room(a.company.id, raw.length);
      await store.putBlobPart(a.company.id, partM[1], Number(partM[2]), raw, now());
      return send(res, 200, { ok: true });
    }
    const doneM = /^\/v2\/blobs\/([^/]+)\/(done|ack|forward)$/.exec(p);
    if (m === 'POST' && doneM && doneM[2] === 'done') {
      const a = await approved(req, raw);
      const b = json(raw);
      const devs = new Set((await store.listDevices(a.company.id)).filter((d) => d.state === 'approved').map((d) => d.id));
      const recips = Array.from(new Set((Array.isArray(b.to) ? b.to : ['admin']).map(String))).filter((t) => t === 'admin' || (a.isAdmin && devs.has(t)));
      if (!recips.length) throw fail(400, a.isAdmin ? 'NO_DEVICE' : 'ONLY_TO_ADMIN', 'A file goes to the administrator\'s PC, or from it to the company\'s devices.');
      if (!a.isAdmin && recips.some((t) => t !== 'admin')) throw fail(400, 'ONLY_TO_ADMIN', 'A device sends files to the administrator\'s PC only.');
      if (await store.blobMeta(a.company.id, doneM[1])) return send(res, 200, { ok: true, already: true });
      const r = await store.finishBlob(a.company.id, doneM[1], Math.max(1, Number(b.parts) || 1), String(b.sha || ''), recips, now());
      if (!r.ok) throw fail(409, r.badSha ? 'BAD_SHA' : 'PART_MISSING', r.badSha ? 'The file\'s parts do not add up — send it again.' : 'Part ' + r.missing + ' is missing.');
      return send(res, 200, { ok: true, size: r.size });
    }
    if (m === 'POST' && doneM && doneM[2] === 'forward') {
      const a = await admin(req, raw);
      const b = json(raw);
      /* the hub may send on any file of its own company that is still here (one it was sent, or one it sent) */
      const meta = await store.blobMeta(a.company.id, doneM[1]);
      if (!meta) throw fail(404, 'NO_FILE', 'Not here any more.');
      const devs = new Set((await store.listDevices(a.company.id)).filter((d) => d.state === 'approved').map((d) => d.id));
      const add = (Array.isArray(b.to) ? b.to : []).map(String).filter((t) => devs.has(t));
      await store.setRecips(a.company.id, doneM[1], Array.from(new Set(meta.recips.concat(add))));
      return send(res, 200, { ok: true, to: add.length });
    }
    if (m === 'POST' && doneM && doneM[2] === 'ack') {
      const a = await approved(req, raw);
      const meta = await store.blobMeta(a.company.id, doneM[1]);
      if (!meta) return send(res, 200, { ok: true, gone: true });
      const left = meta.recips.filter((t) => t !== a.dev.id && !(a.isAdmin && t === 'admin'));
      await store.setRecips(a.company.id, doneM[1], left);
      return send(res, 200, { ok: true, gone: !left.length });
    }
    if (m === 'POST' && p === '/v2/blobs/have') {
      const a = await approved(req, raw);
      const b = json(raw);
      const have = [];
      for (const id of (Array.isArray(b.ids) ? b.ids.slice(0, 2000) : [])) if (ID.test(String(id)) && await store.blobMeta(a.company.id, id)) have.push(id);
      return send(res, 200, { have: have });
    }
    const getM = /^\/v2\/blobs\/([^/]+)(?:\/(\d{1,6}))?$/.exec(p);
    if (m === 'GET' && getM) {
      const a = await approved(req, raw);
      const meta = await store.blobMeta(a.company.id, getM[1]);
      if (!may(a, meta)) throw fail(404, 'NO_FILE', 'Not waiting here for this device.');
      if (getM[2] === undefined) return send(res, 200, { id: meta.id, parts: meta.parts, size: meta.size, sha: meta.sha });
      const part = await store.getBlobPart(a.company.id, getM[1], Number(getM[2]));
      if (!part) throw fail(404, 'NO_PART', 'No such part.');
      return send(res, 200, part, 'application/octet-stream');
    }
    throw fail(404, 'NOT_FOUND', 'Nothing here.');
  }

  const handler = async function (req, res) {
    try { await route(req, res); }
    catch (e) { send(res, e.status || 500, { error: e.code || 'ERROR', message: e.status ? e.message : 'The server could not do it.' }); if (!e.status) console.error(e); }
  };
  /** letters and files nobody fetched in keepDays (90) are dropped — run every hour by postman-server.mjs */
  handler.purge = () => store.purge(now() - (o.keepDays || 90) * 24 * 3600 * 1000);
  return handler;
}
