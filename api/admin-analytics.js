const crypto = require('node:crypto');

const PROPERTY_ID = process.env.GA4_PROPERTY_ID || '559375875';

function validSession(req) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return false;
  const raw = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('af_admin_session='));
  if (!raw) return false;
  let token;
  try { token = decodeURIComponent(raw.slice('af_admin_session='.length)); } catch { return false; }
  const parts = token.split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const issued = Number(parts[0]), now = Math.floor(Date.now() / 1000);
  if (issued > now + 60 || now - issued > 30 * 24 * 60 * 60) return false;
  const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]), b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const b64url = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

async function getAccessToken() {
  const email = process.env.GA4_CLIENT_EMAIL;
  const privateKey = (process.env.GA4_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (!email || !privateKey) {
    throw new Error('Falta configurar GA4_CLIENT_EMAIL y GA4_PRIVATE_KEY en Vercel. Crea una cuenta de servicio de Google y dale acceso de lector a la propiedad GA4.');
  }
  const now = Math.floor(Date.now() / 1000);
  const header = b64url({ alg: 'RS256', typ: 'JWT' });
  const claim = b64url({
    iss: email,
    scope: 'https://www.googleapis.com/auth/analytics.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  });
  const unsigned = header + '.' + claim;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const assertion = unsigned + '.' + signer.sign(privateKey, 'base64url');
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    })
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) {
    throw new Error('Google no ha aceptado las credenciales de Analytics. Revisa la cuenta de servicio y GA4_CLIENT_EMAIL / GA4_PRIVATE_KEY.');
  }
  return result.access_token;
}

async function report(token, body) {
  const response = await fetch('https://analyticsdata.googleapis.com/v1beta/properties/' + encodeURIComponent(PROPERTY_ID) + ':runReport', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(result.error?.message || 'Google Analytics no ha podido generar el informe.');
    error.status = response.status;
    throw error;
  }
  return result;
}
function val(row, index) { return Number(row?.metricValues?.[index]?.value || 0); }
function dateLabel(raw) {
  const s = String(raw || '');
  if (!/^\d{8}$/.test(s)) return s;
  return s.slice(6, 8) + '/' + s.slice(4, 6);
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }
  if (!validSession(req)) return res.status(401).json({ error: 'Inicia sesión para ver las estadísticas.' });
  const days = Math.max(1, Math.min(90, Number(req.body?.days) || 30));
  try {
    const token = await getAccessToken();
    const dateRanges = [{ startDate: (days - 1) + 'daysAgo', endDate: 'today' }];
    const [trendReport, pagesReport, channelsReport] = await Promise.all([
      report(token, {
        dateRanges,
        dimensions: [{ name: 'date' }],
        metricAggregations: ['TOTAL'],
        metrics: [
          { name: 'sessions' },
          { name: 'totalUsers' },
          { name: 'averageSessionDuration' },
          { name: 'screenPageViewsPerSession' }
        ],
        orderBys: [{ dimension: { dimensionName: 'date' } }],
        limit: 100
      }),
      report(token, {
        dateRanges,
        dimensions: [{ name: 'pagePath' }],
        metrics: [{ name: 'screenPageViews' }],
        orderBys: [{ metric: { metricName: 'screenPageViews' }, desc: true }],
        limit: 8
      }),
      report(token, {
        dateRanges,
        dimensions: [{ name: 'sessionDefaultChannelGroup' }],
        metrics: [{ name: 'sessions' }],
        orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
        limit: 8
      })
    ]);
    const trendRows = trendReport.rows || [];
    const total = trendReport.totals?.[0]?.metricValues || [];
    const overview = {
      sessions: Number(total[0]?.value || trendRows.reduce((sum, row) => sum + val(row, 0), 0)),
      users: Number(total[1]?.value || trendRows.reduce((sum, row) => sum + val(row, 1), 0)),
      avgDuration: Number(total[2]?.value || 0),
      pagesPerSession: Number(total[3]?.value || 0)
    };
    return res.status(200).json({
      propertyId: PROPERTY_ID,
      days,
      overview,
      trend: trendRows.map(row => ({
        label: dateLabel(row.dimensionValues?.[0]?.value),
        sessions: val(row, 0),
        users: val(row, 1),
        avgDuration: val(row, 2)
      })),
      pages: (pagesReport.rows || []).map(row => ({
        label: row.dimensionValues?.[0]?.value || '(sin página)',
        value: val(row, 0)
      })),
      channels: (channelsReport.rows || []).map(row => ({
        label: row.dimensionValues?.[0]?.value || '(sin canal)',
        value: val(row, 0)
      }))
    });
  } catch (error) {
    const status = error.status && error.status >= 400 && error.status < 600 ? error.status : 500;
    return res.status(status).json({ error: error.message || 'No se pudieron cargar las estadísticas.' });
  }
};
