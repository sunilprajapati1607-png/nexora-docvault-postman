/**
 * Nexora DocVault Postman — Nexora's own server for many companies (0.8). The administrator's PC of each company keeps
 * its documents; this only carries sealed letters between that PC and the company's other PCs and phones.
 *   DATABASE_URL   postgres://… (Render with Supabase / Neon: a server with no lasting disk) — required
 *   PORT           (Render sets it)
 *   node postman-server.mjs
 * A company's own server stays the one-company Sync Server (server.mjs), under Settings → Advanced.
 */
import http from 'node:http';
import { createPostman, VERSION } from './src/postman.mjs';
import { postmanStore } from './src/postman-store.mjs';

const url = String(process.env.DATABASE_URL || '').trim();
if (!url) { console.error('DATABASE_URL is not set (a Postgres) — the postman keeps waiting letters there.'); process.exit(2); }
const store = postmanStore(url);
await store.init();
const handler = createPostman({ store: store });
const port = Number(process.env.PORT) || 8790;
http.createServer(handler).listen(port, () => console.log('Nexora DocVault Postman ' + VERSION + ' — port ' + port + ' — ' + store.where));
setInterval(() => handler.purge().then((r) => { if (r.mail || r.files) console.log('purged ' + r.mail + ' letters, ' + r.files + ' files nobody fetched'); }).catch((e) => console.error('purge: ' + e.message)), 3600 * 1000);
