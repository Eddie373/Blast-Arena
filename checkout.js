// Creates a Stripe Checkout page for the one-time Special Modes Pass.
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'POST only' };
  const origin = process.env.URL || ('https://' + event.headers.host);
  const body = new URLSearchParams({
    mode: 'payment',
    'line_items[0][price]': process.env.STRIPE_PRICE_ID,
    'line_items[0][quantity]': '1',
    success_url: origin + '/?paid={CHECKOUT_SESSION_ID}',
    cancel_url: origin + '/'
  });
  const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.STRIPE_SECRET_KEY, 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  const j = await r.json();
  if (!r.ok || !j.url) return { statusCode: 500, body: JSON.stringify({ error: 'checkout_failed' }) };
  return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: j.url }) };
};
