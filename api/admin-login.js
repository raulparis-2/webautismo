const crypto = require('node:crypto');

const COOKIE = 'af_admin_session';
const MAX_AGE = 30 * 24 * 60 * 60;

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}
function validSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return false;
  const raw = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='));
  if (!raw) return false;
  const token = decodeURIComponent(raw.slice(COOKIE.length + 1));
  const parts = token.split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const issued = Number(parts[0]);
  const now = Math.floor(Date.now() / 1000);
  if (issued > now + 60 || now - issued > MAX_AGE) return false;
  const expected = sign(parts[0], secret);
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') {
    if (validSession(req)) return res.status(200).json({ ok: true });
    return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  }
  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie', COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
    return res.status(200).json({ ok: true });
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST, DELETE');
    return res.status(405).json({ error: 'Método no permitido.' });
  }
  const password = process.env.ADMIN_PASSWORD;
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!password || !secret) return res.status(500).json({ error: 'Falta configurar la autenticación en el servidor.' });
  const supplied = typeof req.body?.password === 'string' ? req.body.password : '';
  const a = Buffer.from(supplied);
  const b = Buffer.from(password);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Contraseña incorrecta.' });
  }
  const issued = String(Math.floor(Date.now() / 1000));
  const token = issued + '.' + sign(issued, secret);
  res.setHeader('Set-Cookie', COOKIE + '=' + encodeURIComponent(token) + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + MAX_AGE);
  return res.status(200).json({ ok: true });
};
