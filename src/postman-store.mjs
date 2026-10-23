/**
 * Nexora DocVault Postman — what the postman keeps, in POSTGRES (0.8)
 * ======================================================================
 * The user, 2026-10-23: "ok use only our server as tapali, data base admin pc rahese". Many companies on one server;
 * each company's mail waits here only until its reader takes it, then it is gone. Nothing here can be read: every
 * letter and file is sealed by the company's own devices. Tables (pm_ — beside the one-company server's dv_ tables):
 *   pm_companies   id, the join code's hash (never the code), the administrator's PC, created
 *   pm_devices     each PC and phone: its company, keys, state (waiting / approved / removed / replaced), last seen
 *   pm_mail        a sealed letter: company, to (a device, or 'admin'), from, kind, ref (a document's id — no words),
 *                  size, when — deleted when its reader says it has it
 *   pm_blobs / pm_blob_parts   a sealed file in parts, with who may still fetch it; gone when the last of them has it
 * Talks through pgmini.js (the wire protocol, no driver); every value a parameter; sealed bytes as base64.
 */
import crypto from 'node:crypto';
import { createClient } from './pgmini.js';

const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS pm_companies (id text PRIMARY KEY, code_hash text UNIQUE NOT NULL, v text NOT NULL)',
  'CREATE TABLE IF NOT EXISTS pm_devices (id text PRIMARY KEY, company text NOT NULL, v text NOT NULL)',
  'CREATE INDEX IF NOT EXISTS pm_devices_company ON pm_devices (company)',
  'CREATE TABLE IF NOT EXISTS pm_mail (seq bigserial PRIMARY KEY, company text NOT NULL, to_dev text NOT NULL, from_dev text NOT NULL, kind text NOT NULL, ref text NOT NULL, sealed text NOT NULL, size int NOT NULL, at bigint NOT NULL)',
  'CREATE INDEX IF NOT EXISTS pm_mail_to ON pm_mail (company, to_dev, seq)',
  'CREATE TABLE IF NOT EXISTS pm_blobs (company text NOT NULL, id text NOT NULL, parts int NOT NULL, size bigint NOT NULL, sha text NOT NULL, recips text NOT NULL, at bigint NOT NULL, PRIMARY KEY (company, id))',
  'CREATE TABLE IF NOT EXISTS pm_blob_parts (company text NOT NULL, id text NOT NULL, n int NOT NULL, data text NOT NULL, at bigint NOT NULL, PRIMARY KEY (company, id, n))'
];

/** db: { query(text, params) → rows, tx(fn(q)) } — pgmini's pool, or the tests' own */
export function postmanStore(url, db) {
  const pool = db || createClient(url, 3);
  const q = (t, p) => pool.query(t, p || []);
  const company = (r) => r ? Object.assign(JSON.parse(r.v), { id: r.id }) : null;
  const store = {
    kind: 'postgres',
    where: String(url || '').replace(/\/\/([^:@/]+)(:[^@/]*)?@/, '//$1:•••@'),
    async init() { for (const s of SCHEMA) await q(s); },

    /* ---------------- companies and devices ---------------- */
    async createCompany(c) { await q('INSERT INTO pm_companies (id, code_hash, v) VALUES ($1, $2, $3)', [c.id, c.codeHash, JSON.stringify({ adminDevice: c.adminDevice, created: c.created })]); },
    async getCompany(id) { const r = await q('SELECT id, v FROM pm_companies WHERE id = $1', [String(id)]); return company(r[0]); },
    async companyByCode(hash) { const r = await q('SELECT id, v FROM pm_companies WHERE code_hash = $1', [String(hash)]); return company(r[0]); },
    async setAdmin(id, adminDevice) { const c = await store.getCompany(id); c.adminDevice = adminDevice; await q('UPDATE pm_companies SET v = $2 WHERE id = $1', [id, JSON.stringify({ adminDevice: c.adminDevice, created: c.created })]); },
    async setCode(id, hash) { await q('UPDATE pm_companies SET code_hash = $2 WHERE id = $1', [id, hash]); },
    async codeTaken(hash) { return (await q('SELECT 1 FROM pm_companies WHERE code_hash = $1', [hash])).length > 0; },
    async getDevice(id) { const r = await q('SELECT v FROM pm_devices WHERE id = $1', [String(id)]); return r.length ? JSON.parse(r[0].v) : null; },
    async putDevice(d) { await q('INSERT INTO pm_devices (id, company, v) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET company = EXCLUDED.company, v = EXCLUDED.v', [d.id, d.company, JSON.stringify(d)]); },
    async listDevices(cid) { return (await q('SELECT v FROM pm_devices WHERE company = $1', [String(cid)])).map((r) => JSON.parse(r.v)); },

    /* ---------------- letters ---------------- */
    async putMail(m) {
      const r = await q('INSERT INTO pm_mail (company, to_dev, from_dev, kind, ref, sealed, size, at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING seq',
        [m.company, m.to, m.from, m.kind, m.ref || '', m.sealed, m.sealed.length, m.at]);
      return Number(r[0].seq);
    },
    /** the letters to one reader (its own id, and 'admin' when it is the administrator's PC), oldest first */
    async mailFor(cid, tos, after, limit) {
      const rows = await q('SELECT seq, to_dev, from_dev, kind, ref, sealed, at FROM pm_mail WHERE company = $1 AND to_dev = ANY($2::text[]) AND seq > $3 ORDER BY seq LIMIT $4',
        [cid, '{' + tos.join(',') + '}', Number(after) || 0, limit + 1]);
      return { items: rows.slice(0, limit).map((r) => ({ seq: Number(r.seq), to: r.to_dev, from: r.from_dev, kind: r.kind, ref: r.ref, sealed: r.sealed, at: Number(r.at) })), more: rows.length > limit };
    },
    async ackMail(cid, tos, seqs) {
      if (!seqs.length) return 0;
      const r = await q('DELETE FROM pm_mail WHERE company = $1 AND to_dev = ANY($2::text[]) AND seq = ANY($3::bigint[]) RETURNING seq', [cid, '{' + tos.join(',') + '}', '{' + seqs.join(',') + '}']);
      return r.length;
    },
    /** what waits for the administrator's PC: which documents, from whom, since when — no contents */
    async waitingFor(cid, to) {
      return (await q('SELECT from_dev, kind, ref, at FROM pm_mail WHERE company = $1 AND to_dev = $2 ORDER BY seq LIMIT 500', [cid, to])).map((r) => ({ from: r.from_dev, kind: r.kind, ref: r.ref, at: Number(r.at) }));
    },
    async dropMailTo(cid, dev) { await q('DELETE FROM pm_mail WHERE company = $1 AND to_dev = $2', [cid, dev]); },

    /* ---------------- files ---------------- */
    async blobMeta(cid, id) {
      const r = await q('SELECT parts, size, sha, recips FROM pm_blobs WHERE company = $1 AND id = $2', [cid, String(id)]);
      return r.length ? { id: id, parts: Number(r[0].parts), size: Number(r[0].size), sha: r[0].sha, recips: JSON.parse(r[0].recips) } : null;
    },
    async putBlobPart(cid, id, n, bytes, at) { await q('INSERT INTO pm_blob_parts (company, id, n, data, at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (company, id, n) DO UPDATE SET data = EXCLUDED.data, at = EXCLUDED.at', [cid, id, n, Buffer.from(bytes).toString('base64'), at]); },
    async finishBlob(cid, id, parts, sha, recips, at) {
      const h = crypto.createHash('sha256');
      let size = 0;
      for (let i = 0; i < parts; i++) {
        const r = await q('SELECT data FROM pm_blob_parts WHERE company = $1 AND id = $2 AND n = $3', [cid, id, i]);
        if (!r.length) return { missing: i };
        const b = Buffer.from(r[0].data, 'base64'); h.update(b); size += b.length;
      }
      if (h.digest('hex') !== sha) return { badSha: true };
      await q('INSERT INTO pm_blobs (company, id, parts, size, sha, recips, at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (company, id) DO NOTHING', [cid, id, parts, size, sha, JSON.stringify(recips), at]);
      return { ok: true, size: size };
    },
    async setRecips(cid, id, recips) {
      if (recips.length) { await q('UPDATE pm_blobs SET recips = $3 WHERE company = $1 AND id = $2', [cid, id, JSON.stringify(recips)]); return; }
      await q('DELETE FROM pm_blob_parts WHERE company = $1 AND id = $2', [cid, id]);
      await q('DELETE FROM pm_blobs WHERE company = $1 AND id = $2', [cid, id]);
    },
    async getBlobPart(cid, id, n) { const r = await q('SELECT data FROM pm_blob_parts WHERE company = $1 AND id = $2 AND n = $3', [cid, String(id), Number(n)]); return r.length ? Buffer.from(r[0].data, 'base64') : null; },
    async blobsFor(cid) { return (await q('SELECT id, recips FROM pm_blobs WHERE company = $1', [cid])).map((r) => ({ id: r.id, recips: JSON.parse(r.recips) })); },

    /* ---------------- room and age ---------------- */
    async bytesOf(cid) {
      const m = await q('SELECT coalesce(sum(size), 0)::bigint AS n FROM pm_mail WHERE company = $1', [cid]);
      const b = await q('SELECT coalesce(sum(size), 0)::bigint AS n FROM pm_blobs WHERE company = $1', [cid]);
      const p = await q('SELECT coalesce(sum(length(data)), 0)::bigint AS n FROM pm_blob_parts p WHERE company = $1 AND NOT EXISTS (SELECT 1 FROM pm_blobs b WHERE b.company = p.company AND b.id = p.id)', [cid]);
      return Number(m[0].n) + Number(b[0].n) + Math.round(Number(p[0].n) * 3 / 4);
    },
    /** letters and files older than the limit, and file parts never finished, are dropped */
    async purge(before) {
      const m = await q('DELETE FROM pm_mail WHERE at < $1 RETURNING seq', [before]);
      const old = await q('SELECT company, id FROM pm_blobs WHERE at < $1', [before]);
      for (const b of old) await store.setRecips(b.company, b.id, []);
      await q('DELETE FROM pm_blob_parts p WHERE p.at < $1 AND NOT EXISTS (SELECT 1 FROM pm_blobs b WHERE b.company = p.company AND b.id = p.id)', [before]);
      return { mail: m.length, files: old.length };
    },
    async stats() {
      const c = await q('SELECT count(*)::int AS n FROM pm_companies'), d = await q("SELECT count(*)::int AS n FROM pm_devices WHERE v LIKE '%\"state\":\"approved\"%'");
      const m = await q('SELECT count(*)::int AS n FROM pm_mail'), b = await q('SELECT count(*)::int AS n FROM pm_blobs');
      return { companies: Number(c[0].n), approved: Number(d[0].n), letters: Number(m[0].n), files: Number(b[0].n) };
    }
  };
  return store;
}
