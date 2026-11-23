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
    if (body.action === 'signVideoUpload' || body.action === 'signImageUpload') {
      const cloud = process.env.CLOUDINARY_CLOUD_NAME;
      const key = process.env.CLOUDINARY_API_KEY;
      const secret = process.env.CLOUDINARY_API_SECRET;
      if (!cloud || !key || !secret) return res.status(503).json({ error: 'Falta configurar Cloudinary en Vercel.' });
      const timestamp = Math.floor(Date.now() / 1000);
      const folder = body.action === 'signImageUpload' ? 'autismo-familiar/site-documents' : 'autismo-familiar/site-videos';
      const signature = crypto.createHash('sha1').update('folder=' + folder + '&timestamp=' + timestamp + secret).digest('hex');
      return res.status(200).json({ cloudName: cloud, apiKey: key, timestamp, folder, signature });
    }
    const cloud = process.env.CLOUDINARY_CLOUD_NAME;
    const key = process.env.CLOUDINARY_API_KEY;
    const secret = process.env.CLOUDINARY_API_SECRET;
    if (body.action === 'signConsentUpload') {
      if (!cloud || !key || !secret) return res.status(503).json({ error: 'Falta configurar Cloudinary en Vercel.' });
      const timestamp = Math.floor(Date.now() / 1000);
      const folder = 'autismo-familiar/authorizations';
      const signature = crypto.createHash('sha1').update('folder=' + folder + '&timestamp=' + timestamp + secret).digest('hex');
      return res.status(200).json({ cloudName: cloud, apiKey: key, timestamp, folder, signature });
    }
    if (body.action === 'listConsents') {
      if (!cloud || !key || !secret) return res.status(503).json({ error: 'Falta configurar Cloudinary en Vercel.' });
      const auth = 'Basic ' + Buffer.from(key + ':' + secret).toString('base64');
      const all = [];
      for (const resourceType of ['raw', 'image']) {
        const url = 'https://api.cloudinary.com/v1_1/' + cloud + '/resources/' + resourceType + '/authenticated?prefix=autismo-familiar/authorizations/&max_results=100';
        const response = await fetch(url, { headers: { Authorization: auth } });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error?.message || 'No se pudieron consultar las autorizaciones.');
        all.push(...(data.resources || []).map(x => ({ publicId:x.public_id, assetId:x.asset_id, resourceType, format:x.format, bytes:x.bytes, createdAt:x.created_at, filename:x.public_id.split('/').pop() })));
      }
      all.sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt)));
      return res.status(200).json({ items: all });
    }
    if (body.action === 'downloadConsent') {
      if (!cloud || !key || !secret) return res.status(503).json({ error: 'Falta configurar Cloudinary en Vercel.' });
      if (typeof body.publicId !== 'string' || !/^autismo-familiar\/authorizations\/[a-zA-Z0-9_./-]+$/.test(body.publicId) || !['raw','image'].includes(body.resourceType)) return res.status(400).json({ error: 'Documento no válido.' });
      const timestamp = Math.floor(Date.now()/1000), expiresAt = timestamp + 600, format = String(body.format || '').replace(/[^a-z0-9]/gi,'').toLowerCase();
      const params = { expires_at: expiresAt, format, public_id: body.publicId, timestamp };
      const serialized = Object.keys(params).sort().map(k=>k+'='+params[k]).join('&');
      const signature = crypto.createHash('sha1').update(serialized+secret).digest('hex');
      const url = 'https://api.cloudinary.com/v1_1/'+cloud+'/'+body.resourceType+'/download?'+serialized+'&signature='+signature+'&api_key='+key;
      return res.status(200).json({ url, expiresAt });
    }
    if (body.action === 'deleteConsent') {
      if (!cloud || !key || !secret) return res.status(503).json({ error: 'Falta configurar Cloudinary en Vercel.' });
      if (typeof body.publicId !== 'string' || !/^autismo-familiar\/authorizations\/[a-zA-Z0-9_./-]+$/.test(body.publicId) || !['raw','image'].includes(body.resourceType)) return res.status(400).json({ error: 'Documento no válido.' });
      const timestamp=Math.floor(Date.now()/1000), params={public_id:body.publicId,timestamp};
      const serialized=Object.keys(params).sort().map(k=>k+'='+params[k]).join('&');
      const signature=crypto.createHash('sha1').update(serialized+secret).digest('hex');
      const response=await fetch('https://api.cloudinary.com/v1_1/'+cloud+'/'+body.resourceType+'/destroy',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({...params,api_key:key,signature})});
      const data=await response.json().catch(()=>({}));
      if(!response.ok||data.result!=='ok')throw new Error(data.error?.message||'No se pudo eliminar el documento.');
      return res.status(200).json({ok:true});
    }
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
      if (typeof body.filePath !== 'string' || !/^uploads\/(image|video|pdf)-\d+-[a-z0-9_-]+\.[a-z0-9]{1,8}$/.test(body.filePath)) {
        return res.status(400).json({ error: 'Nombre de archivo no válido.' });
      }
      if (typeof body.content !== 'string' || !body.content.length) {
        return res.status(413).json({ error: 'El contenido del archivo no es válido.' });
      }
      const out = await githubFetch('/repos/' + REPO + '/contents/' + body.filePath.split('/').map(encodeURIComponent).join('/'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Añadir ' + (body.kind === 'video' ? 'vídeo' : body.kind === 'pdf' ? 'PDF' : 'imagen') + ' desde el panel Autismo Familiar', content: body.content, branch: 'main' })
      });
      return res.status(200).json({ path: out.content.path, sha: out.content.sha });
    }
    return res.status(400).json({ error: 'Acción no reconocida.' });
  } catch (error) {
    const status = error.status && error.status >= 400 && error.status < 600 ? error.status : 500;
    return res.status(status).json({ error: error.message || 'Error interno del servidor.' });
  }
};
