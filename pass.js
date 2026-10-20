// ?sid=...   after paying: confirms the payment with Stripe and returns an unlock code.
// ?token=... checks that an unlock code is real and the payment was not refunded.
const crypto = require('crypto');
const sign = (s) => crypto.createHmac('sha256', process.env.PASS_SECRET).update(s).digest('hex').slice(0, 32);
const send = (c, o) => ({ statusCode: c, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify(o) });
const ID = /^cs_[A-Za-z0-9_]+$/;

async function paid(sid) {
  const r = await fetch('https://api.stripe.com/v1/checkout/sessions/' + encodeURIComponent(sid) + '?expand[]=payment_intent.latest_charge&expand[]=line_items',
    { headers: { Authorization: 'Bearer ' + process.env.STRIPE_SECRET_KEY } });
  if (!r.ok) return false;
  const s = await r.json();
  if (s.mode !== 'payment' || s.payment_status !== 'paid') return false;
  const items = (s.line_items && s.line_items.data) || [];
  if (!items.some((i) => i.price && i.price.id === process.env.STRIPE_PRICE_ID)) return false;
  const c = s.payment_intent && s.payment_intent.latest_charge;
  return !(c && c.refunded);
}

exports.handler = async (e) => {
  const q = e.queryStringParameters || {};
  if (q.sid) {
    if (!ID.test(q.sid) || !(await paid(q.sid))) return send(402, { ok: false });
    return send(200, { ok: true, token: q.sid + '.' + sign(q.sid) });
  }
  if (q.token) {
    const [sid, sig] = String(q.token).split('.');
    if (!sid || !sig || !ID.test(sid)) return send(200, { ok: false });
    const a = Buffer.from(sig), b = Buffer.from(sign(sid));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b) || !(await paid(sid))) return send(200, { ok: false });
    return send(200, { ok: true });
  }
  return send(400, { ok: false });
};
