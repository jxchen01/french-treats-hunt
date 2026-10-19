const crypto = require('crypto');
const { kv } = require('@vercel/kv');

const STORAGE_KEY = 'fr-treats-progress';
const memoryState = globalThis.__frTreatsProgress || (globalThis.__frTreatsProgress = {});

function getPassword() {
  return (process.env.FR_TREATS_PASSWORD || '').trim();
}

function getSessionSecret() {
  return (process.env.FR_TREATS_SESSION_SECRET || process.env.FR_TREATS_PASSWORD || 'fr-treats-hunt').trim();
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

function signedSessionValue() {
  return crypto
    .createHmac('sha256', getSessionSecret())
    .update('fr-treats-hunt-authenticated')
    .digest('hex');
}

async function loadProgress() {
  try {
    const value = await kv.get(STORAGE_KEY);
    if (value && typeof value === 'object') {
      return value;
    }
  } catch (error) {
    // fall back to the in-memory store for local or non-Vercel runs
  }

  return memoryState[STORAGE_KEY] || {};
}

async function saveProgress(progress) {
  const nextValue = progress && typeof progress === 'object' ? progress : {};

  try {
    await kv.set(STORAGE_KEY, nextValue);
  } catch (error) {
    memoryState[STORAGE_KEY] = nextValue;
  }

  memoryState[STORAGE_KEY] = nextValue;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,OPTIONS');
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

  const cookie = parseCookies(req.headers.cookie || '').fr_treats_session;
  const isAuthenticated = cookie === signedSessionValue();
  if (!isAuthenticated) {
    res.status(401).json({ authenticated: false, error: 'Unauthorized.' });
    return;
  }

  if (req.method === 'GET') {
    const progress = await loadProgress();
    res.status(200).json({ authenticated: true, done: progress });
    return;
  }

  if (req.method !== 'PUT') {
    res.status(405).json({ authenticated: false, error: 'Method not allowed.' });
    return;
  }

  let body = {};
  if (req.body && typeof req.body === 'object') {
    body = req.body;
  } else {
    try {
      const raw = await new Promise((resolve, reject) => {
        let data = '';
        req.on('data', (chunk) => {
          data += chunk;
        });
        req.on('end', () => resolve(data));
        req.on('error', reject);
      });
      body = raw ? JSON.parse(raw) : {};
    } catch (error) {
      res.status(400).json({ authenticated: true, error: 'Bad request.' });
      return;
    }
  }

  const nextProgress = body.done && typeof body.done === 'object' ? body.done : {};
  await saveProgress(nextProgress);
  res.status(200).json({ authenticated: true, done: nextProgress });
};
