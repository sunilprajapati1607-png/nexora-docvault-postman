/**
 * Nexora DocVault Sync — the sealed copy in a FOLDER (an in-house server, a VPS, a server's lasting disk)
 * ======================================================================
 *   company.json        the one company this server keeps (id, name, join code, the administrator's device)
 *   devices\<id>.json   each PC and phone: its keys, its user, waiting / approved / removed, its wrapped data key
 *   records.log         one line per change: { id, kind, rev, sealed } — the last line of an id is its record;
 *                       compacted when it grows to three times what it holds
 *   blobs\<id>\         a file's sealed bytes in parts (p0, p1, …) and meta.json once all parts are in
 * Nothing here is readable without the vault's data key, which this server never has.
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

function writeAtomic(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}
const safe = (id) => /^[A-Za-z0-9_.-]{1,80}$/.test(String(id || ''));

export function folderStore(dir) {
  const recs = new Map();
  let seq = 0, logLines = 0, chain = Promise.resolve();
  const logFile = path.join(dir, 'records.log');
  /* one write at a time: a compare-and-set must not race another */
  const serial = (fn) => { const p = chain.then(fn, fn); chain = p.then(() => null, () => null); return p; };
  function compact() {
    const lines = Array.from(recs.values()).sort((a, b) => a.rev - b.rev).map((r) => JSON.stringify(r)).join('\n');
    writeAtomic(logFile, lines ? lines + '\n' : '');
    logLines = recs.size;
  }
  return {
    kind: 'folder',
    where: dir,
    async init() {
      fs.mkdirSync(path.join(dir, 'devices'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'blobs'), { recursive: true });
      if (fs.existsSync(logFile)) {
        for (const l of fs.readFileSync(logFile, 'utf8').split('\n')) {
          if (!l.trim()) continue;
          try { const r = JSON.parse(l); recs.set(r.id, r); seq = Math.max(seq, r.rev); logLines++; } catch (e) { /* a line cut by a power failure */ }
        }
      }
    },
    async getCompany() { try { return JSON.parse(fs.readFileSync(path.join(dir, 'company.json'), 'utf8')); } catch (e) { return null; } },
    async setCompany(c) { writeAtomic(path.join(dir, 'company.json'), JSON.stringify(c, null, 2)); },
    async listDevices() {
      return fs.readdirSync(path.join(dir, 'devices')).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(fs.readFileSync(path.join(dir, 'devices', f), 'utf8')));
    },
    async getDevice(id) { if (!safe(id)) return null; try { return JSON.parse(fs.readFileSync(path.join(dir, 'devices', id + '.json'), 'utf8')); } catch (e) { return null; } },
    async putDevice(d) { if (!safe(d.id)) throw new Error('bad device id'); writeAtomic(path.join(dir, 'devices', d.id + '.json'), JSON.stringify(d, null, 2)); },
    async changes(since, limit) {
      const out = [];
      for (const r of recs.values()) if (r.rev > since) out.push(r);
      out.sort((a, b) => a.rev - b.rev);
      return { rev: seq, items: out.slice(0, limit || 500), more: out.length > (limit || 500) };
    },
    putRecord(id, kind, baseRev, sealed) {
      return serial(async () => {
        const cur = recs.get(id);
        if ((cur ? cur.rev : 0) !== (Number(baseRev) || 0)) return { conflict: true, rev: cur.rev, sealed: cur.sealed, kind: cur.kind };
        const r = { id: id, kind: kind, rev: ++seq, sealed: sealed };
        recs.set(id, r);
        await fsp.appendFile(logFile, JSON.stringify(r) + '\n');
        if (++logLines > 3 * recs.size + 100) compact();
        return { ok: true, rev: r.rev };
      });
    },
    async blobMeta(id) { if (!safe(id)) return null; try { return JSON.parse(fs.readFileSync(path.join(dir, 'blobs', id, 'meta.json'), 'utf8')); } catch (e) { return null; } },
    async putBlobPart(id, n, bytes) {
      if (!safe(id)) throw new Error('bad blob id');
      const d = path.join(dir, 'blobs', id);
      fs.mkdirSync(d, { recursive: true });
      writeAtomic(path.join(d, 'p' + n), bytes);
    },
    async finishBlob(id, parts, sha) {
      const d = path.join(dir, 'blobs', id);
      const h = crypto.createHash('sha256');
      let size = 0;
      for (let i = 0; i < parts; i++) {
        const p = path.join(d, 'p' + i);
        if (!fs.existsSync(p)) return { missing: i };
        const b = fs.readFileSync(p); h.update(b); size += b.length;
      }
      if (h.digest('hex') !== sha) return { badSha: true };
      writeAtomic(path.join(d, 'meta.json'), JSON.stringify({ id: id, parts: parts, size: size, sha: sha, done: true }));
      return { ok: true, size: size };
    },
    async getBlobPart(id, n) { if (!safe(id)) return null; try { return fs.readFileSync(path.join(dir, 'blobs', id, 'p' + n)); } catch (e) { return null; } },
    async stats() {
      const devs = await this.listDevices();
      return { records: recs.size, rev: seq, blobs: fs.readdirSync(path.join(dir, 'blobs')).length, approved: devs.filter((x) => x.state === 'approved').length, waiting: devs.filter((x) => x.state === 'waiting').length };
    }
  };
}
