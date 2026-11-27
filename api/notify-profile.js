module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }

  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  const resendKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM;
  if (!apiKey || !resendKey || !from) {
    return res.status(503).json({ error: 'Notificaciones pendientes de configuración.' });
  }

  const auth = String(req.headers.authorization || '');
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'Sesión no válida.' });

  try {
    const verify = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(apiKey), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: match[1] }),
      signal: AbortSignal.timeout(10000)
    });
    const identity = await verify.json().catch(() => ({}));
    const user = identity.users && identity.users[0];
    if (!verify.ok || !user || !user.localId) return res.status(401).json({ error: 'Sesión caducada. Inicia sesión de nuevo.' });

    const body = req.body || {};
    const clean = value => String(value || '').replace(/[<>]/g, '').trim().slice(0, 1600);
    const name = clean(body.name);
    const location = clean(body.location);
    const description = clean(body.description);
    const email = clean(body.contactEmail);
    const type = body.profileType === 'professional' ? 'Profesional / cuidador' : 'Familia que busca apoyo';
    if (!name || !location || !description || !email || name.length > 120 || email.length > 180) {
      return res.status(400).json({ error: 'Datos de solicitud incompletos.' });
    }

    const sent = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + resendKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: ['autismofamiliar@autismofamiliar.com'],
        subject: 'Nueva solicitud de anuncio pendiente de revisión',
        text: [
          'Se ha recibido una nueva solicitud en Autismo Familiar.',
          '',
          'Tipo: ' + type,
          'Título: ' + name,
          'Zona: ' + location,
          'Correo de contacto: ' + email,
          'UID de la cuenta: ' + user.localId,
          '',
          'Descripción:',
          description,
          '',
          'El anuncio NO se ha publicado. Debe revisarse y aprobarse manualmente en Firebase.'
        ].join('\\n')
      }),
      signal: AbortSignal.timeout(12000)
    });
    const result = await sent.json().catch(() => ({}));
    if (!sent.ok) return res.status(502).json({ error: 'Resend no ha podido enviar el aviso.', detail: result.message || result.name || 'Error de envío.' });
    return res.status(200).json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: 'No se pudo enviar la notificación.' });
  }
};
