// Accounts for Blast Arena: register, login, load and save progress.
// Passwords are stored only as scrypt hashes. The CREATOR password lives in the
// CREATOR_PASSWORD environment setting, never in the game files.
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const sign = (s) => crypto.createHmac('sha256', process.env.PASS_SECRET || '').update('sess|' + s).digest('hex');
const mkTok = (u, cr) => { const b = u + '.' + (cr ? 1 : 0) + '.' + (Date.now() + 30 * 864e5); return b + '.' + sign(b); };
const readTok = (t) => {
  const p = String(t || '').split('.');
  if (p.length !== 4) return null;
  const a = Buffer.from(p[3]), c = Buffer.from(sign(p.slice(0, 3).join('.')));
  if (a.length !== c.length || !crypto.timingSafeEqual(a, c) || +p[2] < Date.now()) return null;
  return { u: p[0], cr: p[1] === '1' };
};
const hash = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 32, (e, k) => (e ? no(e) : ok(k.toString('hex')))));
const eq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const okData = (d) => typeof d === 'string' && d.length <= 40000 && /^BA1-[A-Za-z0-9+/]*-[a-z0-9]+$/.test(d);

export default async (req) => {
  if (req.method !== 'POST') return J({ error: 'POST only' }, 405);
  if (!process.env.PASS_SECRET) return J({ error: 'Server is not set up yet' }, 500);
  let b; try { b = await req.json(); } catch { return J({ error: 'Bad request' }, 400); }
  const acc = getStore('accounts'), lock = getStore('locks'), act = b.action;

  if (act === 'register' || act === 'login') {
    const u = String(b.u || '').trim(), p = String(b.p || ''), k = u.toLowerCase();
    if (!/^[A-Za-z0-9_]{3,12}$/.test(u)) return J({ error: 'Username must be 3 to 12 letters, numbers or underscores' }, 400);
    if (p.length < 6 || p.length > 64) return J({ error: 'Password must be 6 to 64 characters' }, 400);
    const L = await lock.get(k, { type: 'json' }).catch(() => null);
    if (L && L.n >= 8 && Date.now() - L.t < 9e5) return J({ error: 'Too many tries. Please wait 15 minutes.' }, 429);

    if (act === 'register') {
      if (k === 'creator') return J({ error: 'That username is taken' }, 409);
      const salt = crypto.randomBytes(16).toString('hex');
      const rec = { u, salt, h: await hash(p, salt), data: okData(b.data) ? b.data : '', made: Date.now() };
      const r = await acc.setJSON(k, rec, { onlyIfNew: true });
      if (!r.modified) return J({ error: 'That username is taken' }, 409);
      return J({ ok: true, u, token: mkTok(u, false), data: rec.data });
    }

    const fail = async () => {
      await lock.setJSON(k, { n: (L && Date.now() - L.t < 9e5 ? L.n : 0) + 1, t: Date.now() });
      return J({ error: 'Wrong username or password' }, 401);
    };
    if (k === 'creator') {
      const cp = process.env.CREATOR_PASSWORD || '';
      if (!cp || !eq(p, cp)) return fail();
      await lock.delete(k);
      return J({ ok: true, u: 'CREATOR', creator: true, token: mkTok('CREATOR', true) });
    }
    const rec = await acc.get(k, { type: 'json' }).catch(() => null);
    if (!rec || !eq(await hash(p, rec.salt), rec.h)) return fail();
    await lock.delete(k);
    return J({ ok: true, u: rec.u, token: mkTok(rec.u, false), data: rec.data || '' });
  }

  const s = readTok(b.token);
  if (!s) return J({ error: 'Please log in again' }, 401);
  if (s.cr) return J({ ok: true, creator: true });
  const k = s.u.toLowerCase(), rec = await acc.get(k, { type: 'json' }).catch(() => null);
  if (!rec) return J({ error: 'Please log in again' }, 401);
  if (act === 'load') return J({ ok: true, data: rec.data || '' });
  if (act === 'save') {
    if (!okData(b.data)) return J({ error: 'Bad data' }, 400);
    rec.data = b.data;
    await acc.setJSON(k, rec);
    return J({ ok: true });
  }
  return J({ error: 'Bad request' }, 400);
};
