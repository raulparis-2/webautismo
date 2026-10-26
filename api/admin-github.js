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
    if (body.action === 'importDriveText') {
      if (typeof body.url !== 'string' || body.url.length > 2000) return res.status(400).json({ error: 'Pega un enlace público de Google Docs.' });
      let url;
      try { url = new URL(body.url); } catch { return res.status(400).json({ error: 'El enlace no es válido.' }); }
      if (url.hostname !== 'docs.google.com' || !/^\/document\/d\/[A-Za-z0-9_-]+\/(?:edit|view|export)?/.test(url.pathname)) {
        return res.status(400).json({ error: 'Para importar texto, utiliza un documento de Google Docs con permiso «Cualquier persona con el enlace: lector».' });
      }
      const match = url.pathname.match(/^\/document\/d\/([A-Za-z0-9_-]+)/);
      if (!match) return res.status(400).json({ error: 'No se reconoce el documento de Google Docs.' });
      const response = await fetch('https://docs.google.com/document/d/' + match[1] + '/export?format=txt', { redirect: 'follow', signal: AbortSignal.timeout(12000) });
      if (!response.ok) return res.status(400).json({ error: 'No se pudo leer el documento. Comprueba que el enlace esté compartido públicamente como lector.' });
      const text = await response.text();
      if (!text || text.length > 25000 || /<html[\s>]/i.test(text.slice(0, 500))) return res.status(400).json({ error: 'Google Docs no devolvió texto legible. Revisa los permisos y el tamaño del documento (máximo 25.000 caracteres).' });
      const lines = text.replace(/\r\n?/g, '\n').split('\n');
      const titleIndex = lines.findIndex(line => line.trim());
      const title = titleIndex >= 0 ? lines[titleIndex].trim().slice(0, 150) : '';
      if (titleIndex >= 0) lines.splice(titleIndex, 1);
      const articleBody = lines.join('\n').trim();
      const firstParagraph = articleBody.split(/\n\s*\n/).map(part => part.trim()).find(Boolean) || articleBody;
      const summary = firstParagraph.replace(/\s+/g, ' ').slice(0, 4000);
      return res.status(200).json({ title, summary, body: articleBody, text });
    }
    if (body.action === 'importDriveImage') {
      if (typeof body.url !== 'string' || body.url.length > 2000) return res.status(400).json({ error: 'Pega un enlace público de una imagen de Google Drive.' });
      let url;
      try { url = new URL(body.url); } catch { return res.status(400).json({ error: 'El enlace no es válido.' }); }
      if (!['drive.google.com', 'docs.google.com'].includes(url.hostname)) return res.status(400).json({ error: 'Solo se aceptan enlaces de Google Drive.' });
      const idMatch = url.pathname.match(/\/(?:file\/d|document\/d|uc)\/([A-Za-z0-9_-]+)/) || url.searchParams.get('id')?.match(/^([A-Za-z0-9_-]+)$/);
      const fileId = typeof idMatch === 'string' ? idMatch : idMatch?.[1];
      if (!fileId) return res.status(400).json({ error: 'No se encuentra el ID del archivo. Usa un enlace de Drive con formato drive.google.com/file/d/…' });
      const response = await fetch('https://drive.google.com/uc?export=download&id=' + encodeURIComponent(fileId), { redirect: 'follow', signal: AbortSignal.timeout(12000) });
      if (!response.ok) return res.status(400).json({ error: 'No se pudo descargar la imagen. Comprueba que el archivo esté compartido públicamente como lector.' });
      const mime = (response.headers.get('content-type') || '').split(';')[0].toLowerCase();
      if (!/^image\/(?:jpeg|png|webp|gif)$/.test(mime)) return res.status(400).json({ error: 'Drive no ha devuelto una imagen válida. Comprueba el enlace y que el archivo sea una imagen.' });
      const declared = Number(response.headers.get('content-length') || 0);
      if (declared > 3 * 1024 * 1024) return res.status(413).json({ error: 'La imagen debe pesar como máximo 3 MB.' });
      const bytes = Buffer.from(await response.arrayBuffer());
      if (!bytes.length || bytes.length > 3 * 1024 * 1024) return res.status(413).json({ error: 'La imagen debe pesar como máximo 3 MB.' });
      const ext = ({'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'})[mime];
      const filePath = 'uploads/image-' + Date.now() + '-drive-import.' + ext;
      const out = await githubFetch('/repos/' + REPO + '/contents/' + filePath.split('/').map(encodeURIComponent).join('/'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Importar imagen pública de Google Drive', content: bytes.toString('base64'), branch: 'main' })
      });
      return res.status(200).json({ path: out.content.path, sha: out.content.sha });
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
