/**
 * Nexora DocVault Sync Server — start it
 * ======================================================================
 * The company's own server (the user, 2026-10-22: "in house server pn hoi sake ane ujar online render jeva server pn"):
 *
 *   DV_SYNC_PASSWORD   the server password (at least 12 characters) — typed once in each DocVault that connects
 *   DV_SYNC_DATA       a folder for the sealed copy (in-house server, VPS, a lasting disk)       — or —
 *   DATABASE_URL       postgres://… (Render, Supabase, Neon: a server with no lasting disk)
 *   PORT               default 8790
 *
 * In-house:  set DV_SYNC_PASSWORD=…  then  node server.mjs   (or START-SYNC-SERVER.bat)
 * Render:    a Web Service from this folder, start command  node server.mjs, the two variables above.
 */
import http from 'node:http';
import path from 'node:path';
import { createApp, VERSION } from './src/app.mjs';
import { folderStore } from './src/store-folder.mjs';
import { pgStore } from './src/store-pg.mjs';

const password = String(process.env.DV_SYNC_PASSWORD || '');
if (password.length < 12) { console.error('DV_SYNC_PASSWORD is not set (at least 12 characters) — the server does not start without it.'); process.exit(2); }
const url = String(process.env.DATABASE_URL || '').trim();
if (!url && process.env.RENDER && !process.env.DV_SYNC_DATA) { console.error('On Render: set DATABASE_URL (a Postgres) — Render\'s own disk is wiped at each deploy.'); process.exit(2); }
const store = url ? pgStore(url) : folderStore(path.resolve(process.env.DV_SYNC_DATA || 'data'));
await store.init();
const port = Number(process.env.PORT) || 8790;
http.createServer(createApp({ store: store, password: password })).listen(port, () => {
  console.log('Nexora DocVault Sync Server ' + VERSION + ' — port ' + port + ' — storage: ' + store.kind + ' (' + store.where + ')');
});
