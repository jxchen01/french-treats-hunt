const crypto = require('crypto');

function getPassword() {
  return (process.env.FR_TREATS_PASSWORD || '').trim();
}

function getSessionSecret() {
  return (process.env.FR_TREATS_SESSION_SECRET || process.env.FR_TREATS_PASSWORD || 'fr-treats-hunt').trim();
}

function signedSessionValue() {
  return crypto
    .createHmac('sha256', getSessionSecret())
    .update('fr-treats-hunt-authenticated')
    .digest('hex');
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    if (!req.body && req.method !== 'POST') {
      resolve({});
      return;
    }

    if (req.body) {
      resolve(req.body);
      return;
    }

    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        resolve({ password: raw });
      }
    });
    req.on('error', reject);
  });
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;

  cookieHeader.split(';').forEach((entry) => {
    const [name, ...rest] = entry.trim().split('=');
    if (!name) return;
    cookies[name] = rest.join('=');
  });
  return cookies;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const configuredPassword = getPassword();
  if (!configuredPassword) {
    res.status(500).json({
      authenticated: false,
      error: 'Set FR_TREATS_PASSWORD in your Vercel project environment variables before deploying.'
    });
    return;
  }

  if (req.method === 'GET') {
    const cookie = parseCookies(req.headers.cookie || '').fr_treats_session;
    const isAuthenticated = cookie === signedSessionValue();
    res.status(isAuthenticated ? 200 : 401).json({ authenticated: isAuthenticated });
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ authenticated: false, error: 'Method not allowed.' });
    return;
  }

  const body = await readJsonBody(req);
  const submittedPassword = String(body.password || '').trim();

  if (submittedPassword !== configuredPassword) {
    res.status(401).json({ authenticated: false, error: 'Incorrect password.' });
    return;
  }

  const signedValue = signedSessionValue();
  res.setHeader('Set-Cookie', `fr_treats_session=${signedValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800;`);
  res.status(200).json({ authenticated: true });
};
