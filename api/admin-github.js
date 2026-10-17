const REPO = 'raulparis-2/webautismo';
const API = 'https://api.github.com';
const crypto = require('node:crypto');

function validSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return false;
  const raw = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('af_admin_session='));
  if (!raw) return false;
  const token = decodeURIComponent(raw.slice('af_admin_session='.length));
  const parts = token.split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const issued = Number(parts[0]), now = Math.floor(Date.now() / 1000);
  if (issued > now + 60 || now - issued > 30 * 24 * 60 * 60) return false;
  const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]), b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function githubFetch(path, options = {}) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) throw new Error('Falta configurar GITHUB_TOKEN en las variables de entorno de Vercel.');
  const response = await fetch(API + path, {
    ...options,
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(options.headers || {})
    }
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(result.message || 'GitHub ha rechazado la operación.');
    err.status = response.status;
    throw err;
  }
  return result;
}
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }
  if (!validSession(req)) return res.status(401).json({ error: 'La sesión ha caducado. Vuelve a iniciar sesión.' });
  try {
    const body = req.body || {};
    if (body.action === 'getContent') {
      const file = await githubFetch('/repos/' + REPO + '/contents/content.json?ref=main');
      const decoded = Buffer.from(file.content.replace(/\n/g, ''), 'base64').toString('utf8');
      return res.status(200).json({ data: JSON.parse(decoded), sha: file.sha });
    }
    if (body.action === 'publish') {
      if (!body.data || typeof body.data !== 'object' || !body.sha) return res.status(400).json({ error: 'Faltan los datos o la versión del archivo.' });
      const content = Buffer.from(JSON.stringify(body.data, null, 2), 'utf8').toString('base64');
      const out = await githubFetch('/repos/' + REPO + '/contents/content.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Actualizar contenido desde el panel Autismo Familiar', content, sha: body.sha, branch: 'main' })
      });
      return res.status(200).json({ sha: out.content.sha });
    }
    if (body.action === 'upload') {
      if (typeof body.filePath !== 'string' || !/^uploads\/(image|video)-\d+-[a-z0-9_-]+\.[a-z0-9]{1,8}$/.test(body.filePath)) {
        return res.status(400).json({ error: 'Nombre de archivo no válido.' });
      }
      if (typeof body.content !== 'string' || !body.content.length || body.content.length > 4 * 1024 * 1024) {
        return res.status(413).json({ error: 'El archivo debe pesar como máximo 3 MB.' });
      }
      const out = await githubFetch('/repos/' + REPO + '/contents/' + body.filePath.split('/').map(encodeURIComponent).join('/'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Añadir ' + (body.kind === 'video' ? 'vídeo' : 'imagen') + ' desde el panel Autismo Familiar', content: body.content, branch: 'main' })
      });
      return res.status(200).json({ path: out.content.path, sha: out.content.sha });
    }
    return res.status(400).json({ error: 'Acción no reconocida.' });
  } catch (error) {
    const status = error.status && error.status >= 400 && error.status < 600 ? error.status : 500;
    return res.status(status).json({ error: error.message || 'Error interno del servidor.' });
  }
};
