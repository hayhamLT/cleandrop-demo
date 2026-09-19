/* Decrypts the protected demo in the visitor's browser (see build.mjs).
 * Requests under <site>/game/ are answered from the matching encrypted file
 * in c/, decrypted with the key the sign-in page hands over. The key is kept
 * in IndexedDB as a non-extractable CryptoKey, so a returning visitor on the
 * same browser is not asked again; "Sign out" on the gate page forgets it. */
const TYPES = { html: 'text/html; charset=utf-8', js: 'text/javascript', mjs: 'text/javascript', json: 'application/json',
  css: 'text/css', svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp', ttf: 'font/ttf',
  woff2: 'font/woff2', mp3: 'audio/mpeg', webm: 'video/webm', mp4: 'video/mp4', mov: 'video/quicktime', md: 'text/markdown' };
const SCOPE = new URL(self.registration.scope);
const GAME = new URL('game/', SCOPE).pathname;
let KEY = null, META = null;
// what has been decrypted this visit, so the splash's pre-load makes the game open at once
const PLAIN = new Map();

const db = () => new Promise((res, rej) => { const r = indexedDB.open('cleandrop-demo', 1);
  r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains('k')) r.result.createObjectStore('k'); }; r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const idb = async (mode, fn) => { const d = await db(); return new Promise((res, rej) => {
  const t = d.transaction('k', mode), q = fn(t.objectStore('k')); t.oncomplete = () => res(q && q.result); t.onerror = () => rej(t.error); }); };
async function key(){
  if (!KEY) KEY = await idb('readonly', s => s.get('key')).catch(() => null);
  return KEY;
}
async function meta(){ return META || (META = await (await fetch(new URL('meta.json', SCOPE), { cache: 'no-cache' })).json()); }
async function nameOf(path){
  const m = await meta();
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(m.salt + '|' + path));
  return [...new Uint8Array(h)].slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => {
  const m = e.data || {};
  if (m.type === 'key') e.waitUntil((async () => {
    KEY = await crypto.subtle.importKey('raw', m.raw, 'AES-GCM', false, ['decrypt']);
    await idb('readwrite', s => s.put(KEY, 'key'));
    e.source?.postMessage({ type: 'key-ok' });
  })().catch(err => e.source?.postMessage({ type: 'error', message: String(err && err.message || err) })));
  if (m.type === 'lock') e.waitUntil((async () => { KEY = null; PLAIN.clear(); await idb('readwrite', s => s.delete('key')); e.source?.postMessage({ type: 'locked' }); })());
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== SCOPE.origin || !url.pathname.startsWith(GAME)) return;     // the gate itself, meta, c/: straight through
  e.respondWith((async () => {
    const k = await key();
    if (!k) return Response.redirect(new URL('./', SCOPE).href, 302);          // not signed in: back to the gate
    let rel = decodeURIComponent(url.pathname.slice(GAME.length)) || 'splash.html';
    if (rel.endsWith('/')) rel += 'index.html';
    const ext = (rel.split('.').pop() || '').toLowerCase();
    const hdr = { 'content-type': TYPES[ext] || 'application/octet-stream', 'cache-control': 'no-store', 'accept-ranges': 'bytes' };
    /* Safari only plays audio and video it can fetch in byte ranges (206);
       handed the whole file it plays nothing - no music, no engine (18 Sept).
       So a Range request gets the slice it asked for. */
    const reply = plain => {
      const range = /^bytes=(\d*)-(\d*)$/.exec(e.request.headers.get('range') || '');
      const n = plain.byteLength;
      if (!range) return new Response(plain, { status: 200, headers: { ...hdr, 'content-length': String(n) } });
      let a = range[1] === '' ? Math.max(0, n - +range[2]) : +range[1];
      let b = range[1] === '' ? n - 1 : (range[2] === '' ? n - 1 : Math.min(+range[2], n - 1));
      if (a >= n || a > b) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${n}` } });
      return new Response(plain.slice(a, b + 1), { status: 206, headers: { ...hdr, 'content-range': `bytes ${a}-${b}/${n}`, 'content-length': String(b - a + 1) } });
    };
    if (PLAIN.has(rel)) return reply(PLAIN.get(rel));
    const r = await fetch(new URL('c/' + (await nameOf(rel)) + '.bin', SCOPE));
    if (!r.ok) return new Response('not found', { status: 404 });
    const buf = new Uint8Array(await r.arrayBuffer());
    let plain;
    try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, k, buf.slice(12)); }
    catch { return new Response('locked', { status: 403 }); }
    PLAIN.set(rel, plain);
    return reply(plain);
  })());
});
