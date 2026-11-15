const crypto = require('node:crypto');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }
  const cloud = process.env.CLOUDINARY_CLOUD_NAME;
  const key = process.env.CLOUDINARY_API_KEY;
  const secret = process.env.CLOUDINARY_API_SECRET;
  const firebaseKey = process.env.FIREBASE_WEB_API_KEY;
  if (!cloud || !key || !secret || !firebaseKey) {
    return res.status(503).json({ error: 'Falta configurar Cloudinary o Firebase en Vercel.' });
  }
  const match = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'Inicia sesión para subir el vídeo.' });
  try {
    const verify = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(firebaseKey), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: match[1] }),
      signal: AbortSignal.timeout(10000)
    });
    const identity = await verify.json().catch(() => ({}));
    const user = identity.users && identity.users[0];
    if (!verify.ok || !user || !user.localId) return res.status(401).json({ error: 'La sesión ha caducado. Inicia sesión de nuevo.' });
    const timestamp = Math.floor(Date.now() / 1000);
    const folder = 'autismo-familiar/profile-videos';
    const params = { folder, timestamp };
    const toSign = Object.keys(params).sort().map(k => k + '=' + params[k]).join('&') + secret;
    const signature = crypto.createHash('sha1').update(toSign).digest('hex');
    return res.status(200).json({ cloudName: cloud, apiKey: key, timestamp, folder, signature });
  } catch (error) {
    return res.status(500).json({ error: 'No se pudo preparar la subida segura del vídeo.' });
  }
};
