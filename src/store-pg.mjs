/**
 * Nexora DocVault Sync — the sealed copy in POSTGRES (an online server with no lasting disk: Render, or a database
 * from Supabase / Neon; DATABASE_URL). The same as the folder store, in six tables:
 *   dv_company (one row) · dv_devices · dv_records (id, kind, rev, sealed) · dv_seq (one row) · dv_blobs · dv_blob_parts
 * Talks through pgmini.js (the wire protocol, no driver); every value is a parameter. Sealed bytes travel as base64.
 */
import crypto from 'node:crypto';
import { createClient } from './pgmini.js';

const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS dv_company (k int PRIMARY KEY, v text NOT NULL)',
  'CREATE TABLE IF NOT EXISTS dv_devices (id text PRIMARY KEY, v text NOT NULL)',
  'CREATE TABLE IF NOT EXISTS dv_records (id text PRIMARY KEY, kind text NOT NULL, rev bigint NOT NULL, sealed text NOT NULL)',
  'CREATE INDEX IF NOT EXISTS dv_records_rev ON dv_records (rev)',
  'CREATE TABLE IF NOT EXISTS dv_seq (k int PRIMARY KEY, v bigint NOT NULL)',
  'INSERT INTO dv_seq (k, v) VALUES (1, 0) ON CONFLICT (k) DO NOTHING',
  'CREATE TABLE IF NOT EXISTS dv_blobs (id text PRIMARY KEY, parts int NOT NULL, size bigint NOT NULL, sha text NOT NULL)',
  'CREATE TABLE IF NOT EXISTS dv_blob_parts (id text NOT NULL, n int NOT NULL, data text NOT NULL, PRIMARY KEY (id, n))'
];

/** db: { query(text, params) → rows, tx(fn(q)) } — pgmini's pool, or the tests' PGlite */
export function pgStore(url, db) {
  const pool = db || createClient(url, 3);
  const q = (t, p) => pool.query(t, p || []);
  return {
    kind: 'postgres',
    where: String(url || '').replace(/\/\/([^:@/]+)(:[^@/]*)?@/, '//$1:•••@'),
    async init() { for (const s of SCHEMA) await q(s); },
    async getCompany() { const r = await q('SELECT v FROM dv_company WHERE k = 1'); return r.length ? JSON.parse(r[0].v) : null; },
    async setCompany(c) { await q('INSERT INTO dv_company (k, v) VALUES (1, $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v', [JSON.stringify(c)]); },
    async listDevices() { return (await q('SELECT v FROM dv_devices')).map((r) => JSON.parse(r.v)); },
    async getDevice(id) { const r = await q('SELECT v FROM dv_devices WHERE id = $1', [String(id)]); return r.length ? JSON.parse(r[0].v) : null; },
    async putDevice(d) { await q('INSERT INTO dv_devices (id, v) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET v = EXCLUDED.v', [d.id, JSON.stringify(d)]); },
    async changes(since, limit) {
      const lim = limit || 500;
      const rows = await q('SELECT id, kind, rev, sealed FROM dv_records WHERE rev > $1 ORDER BY rev LIMIT $2', [Number(since) || 0, lim + 1]);
      const seq = await q('SELECT v FROM dv_seq WHERE k = 1');
      return { rev: Number(seq[0].v), items: rows.slice(0, lim).map((r) => ({ id: r.id, kind: r.kind, rev: Number(r.rev), sealed: r.sealed })), more: rows.length > lim };
    },
    putRecord(id, kind, baseRev, sealed) {
      return pool.tx(async (t) => {
        /* the sequence row is the lock: one change at a time, as the folder store */
        const s = await t('UPDATE dv_seq SET v = v WHERE k = 1 RETURNING v');
        const cur = await t('SELECT kind, rev, sealed FROM dv_records WHERE id = $1', [id]);
        const curRev = cur.length ? Number(cur[0].rev) : 0;
        if (curRev !== (Number(baseRev) || 0)) return { conflict: true, rev: curRev, sealed: cur[0].sealed, kind: cur[0].kind };
        const rev = Number(s[0].v) + 1;
        await t('UPDATE dv_seq SET v = $1 WHERE k = 1', [rev]);
        await t('INSERT INTO dv_records (id, kind, rev, sealed) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, rev = EXCLUDED.rev, sealed = EXCLUDED.sealed', [id, kind, rev, sealed]);
        return { ok: true, rev: rev };
      });
    },
    async blobMeta(id) { const r = await q('SELECT parts, size, sha FROM dv_blobs WHERE id = $1', [String(id)]); return r.length ? { id: id, parts: Number(r[0].parts), size: Number(r[0].size), sha: r[0].sha, done: true } : null; },
    async putBlobPart(id, n, bytes) { await q('INSERT INTO dv_blob_parts (id, n, data) VALUES ($1, $2, $3) ON CONFLICT (id, n) DO UPDATE SET data = EXCLUDED.data', [id, n, Buffer.from(bytes).toString('base64')]); },
    async finishBlob(id, parts, sha) {
      const h = crypto.createHash('sha256');
      let size = 0;
      for (let i = 0; i < parts; i++) {
        const r = await q('SELECT data FROM dv_blob_parts WHERE id = $1 AND n = $2', [id, i]);
        if (!r.length) return { missing: i };
        const b = Buffer.from(r[0].data, 'base64'); h.update(b); size += b.length;
      }
      if (h.digest('hex') !== sha) return { badSha: true };
      await q('INSERT INTO dv_blobs (id, parts, size, sha) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING', [id, parts, size, sha]);
      return { ok: true, size: size };
    },
    async getBlobPart(id, n) { const r = await q('SELECT data FROM dv_blob_parts WHERE id = $1 AND n = $2', [String(id), Number(n)]); return r.length ? Buffer.from(r[0].data, 'base64') : null; },
    async stats() {
      const devs = await this.listDevices();
      const n = await q('SELECT count(*)::int AS n FROM dv_records'), b = await q('SELECT count(*)::int AS n FROM dv_blobs'), s = await q('SELECT v FROM dv_seq WHERE k = 1');
      return { records: Number(n[0].n), rev: Number(s[0].v), blobs: Number(b[0].n), approved: devs.filter((x) => x.state === 'approved').length, waiting: devs.filter((x) => x.state === 'waiting').length };
    }
  };
}
