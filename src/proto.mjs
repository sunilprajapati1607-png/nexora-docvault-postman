/**
 * Nexora DocVault Sync — how a request proves who sent it (the server and every client sign the same way)
 * ======================================================================
 * The user, 2026-10-22: "server ne lagta parameter ane passward nakhase etle server jode auto connect thase".
 *
 *   SERVER PASSWORD  set where the server is installed (DV_SYNC_PASSWORD). It never travels: each request carries an
 *                    HMAC of what it says, keyed by sha256('nxdv-sync:' + password).
 *   DEVICE KEY       every PC and phone has its own Ed25519 key; each request is signed with it. A device the
 *                    administrator has not approved is refused everything but asking to join.
 *   THE WORDS SIGNED METHOD \n PATH \n TIME \n DEVICE \n sha256(BODY) — a request changed, replayed after five
 *                    minutes or sent again within them is refused.
 */
import crypto from 'node:crypto';

export const WINDOW_MS = 5 * 60 * 1000;

export function passwordKey(password) { return crypto.createHash('sha256').update('nxdv-sync:' + String(password)).digest(); }
export function sha256hex(buf) { return crypto.createHash('sha256').update(buf || Buffer.alloc(0)).digest('hex'); }
export function canonical(method, path, time, device, body) {
  return [String(method).toUpperCase(), path, time, device || '', sha256hex(body)].join('\n');
}
export function hmac(key, text) { return crypto.createHmac('sha256', key).update(text).digest('base64'); }

/** a device's two keys: Ed25519 to sign, X25519 for the data key wrapped to it — the public halves as base64 SPKI */
export function newDeviceKeys() {
  const s = crypto.generateKeyPairSync('ed25519'), x = crypto.generateKeyPairSync('x25519');
  return {
    signPub: s.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    signPriv: s.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    boxPub: x.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    boxPriv: x.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  };
}
export function sign(signPrivB64, text) {
  const k = crypto.createPrivateKey({ key: Buffer.from(signPrivB64, 'base64'), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(text), k).toString('base64');
}
export function verify(signPubB64, text, sigB64) {
  try {
    const k = crypto.createPublicKey({ key: Buffer.from(signPubB64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(text), k, Buffer.from(String(sigB64 || ''), 'base64'));
  } catch (e) { return false; }
}
export function deviceId(signPubB64) { return 'D' + sha256hex(Buffer.from(signPubB64, 'base64')).slice(0, 24); }

/** the headers of one request (the clients' side) */
export function headers(o) {
  const time = String(o.time || Date.now());
  const text = canonical(o.method, o.path, time, o.device, o.body);
  return { 'x-dv-time': time, 'x-dv-device': o.device || '', 'x-dv-auth': hmac(passwordKey(o.password), text), 'x-dv-sig': o.signPriv ? sign(o.signPriv, text) : '' };
}

/**
 * The data key, wrapped for one device: an ephemeral X25519 key, its shared secret with the device's box key, HKDF,
 * AES-256-GCM. Only that device can open it; the server keeps it without being able to.
 */
export function wrapFor(boxPubB64, dataKey) {
  const eph = crypto.generateKeyPairSync('x25519');
  const peer = crypto.createPublicKey({ key: Buffer.from(boxPubB64, 'base64'), format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: peer });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), 'nxdv-wrap', 32));
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(dataKey), c.final()]);
  return JSON.stringify({ e: eph.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), iv: iv.toString('base64'), t: c.getAuthTag().toString('base64'), c: ct.toString('base64') });
}
export function unwrap(boxPrivB64, wrapped) {
  const w = JSON.parse(wrapped);
  const priv = crypto.createPrivateKey({ key: Buffer.from(boxPrivB64, 'base64'), format: 'der', type: 'pkcs8' });
  const peer = crypto.createPublicKey({ key: Buffer.from(w.e, 'base64'), format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: peer });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), 'nxdv-wrap', 32));
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(w.iv, 'base64'));
  d.setAuthTag(Buffer.from(w.t, 'base64'));
  return Buffer.concat([d.update(Buffer.from(w.c, 'base64')), d.final()]);
}
