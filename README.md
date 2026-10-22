# Nexora DocVault Sync Server

One company's documents, kept **sealed** on the company's own server — in-house or online. The server cannot read
anything: every record and file is locked with the vault's key before it leaves a PC or phone, and that key reaches a
new device only wrapped by the administrator for that device.

## In-house (an office server or any always-on PC)

1. Install Node.js 20 or newer.
2. Copy this folder to the server and run `START-SYNC-SERVER.bat`; type the server password (12+ characters) once.
3. Let the PCs reach port 8790 (from other networks: the router's port forward, or a VPN).

## Online (Render, or any host that runs Node)

1. A Web Service from this folder (`render.yaml`), start command `node server.mjs`.
2. `DV_SYNC_PASSWORD` — the server password; `DATABASE_URL` — a Postgres (Render's, Supabase or Neon).

## In Nexora DocVault

Settings → Sync: the server's address, the server password, and (on other PCs and phones) the company ID and join
code from the administrator's PC. The administrator approves each device; one user = one PC + one phone.

## Check it

`npm test` — the whole protocol, on a folder and on Postgres over the wire.
