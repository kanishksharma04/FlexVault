// login.js
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// reuse Prisma across invocations (prevents socket exhaustion on serverless)
const prisma = global.prisma || new PrismaClient();
if (!global.prisma) global.prisma = prisma;

const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL || '*';
const LOG_PREFIX = '[auth:login]';

function parseAllowedOrigins(value) {
  if (!value) return [];
  return value.split(',').map(s => s.trim()).filter(Boolean);
}

function setCorsHeaders(req, res) {
  const allowed = parseAllowedOrigins(CLIENT_URL);
  const originHeader = req.headers.origin || '*';

  // If CLIENT_URL is '*' we allow any origin (but echo back actual origin for credentials)
  if (CLIENT_URL === '*' || allowed.length === 0) {
    res.setHeader('Access-Control-Allow-Origin', originHeader);
  } else {
    // If list provided, allow only if origin matches one of them
    if (allowed.includes(originHeader)) {
      res.setHeader('Access-Control-Allow-Origin', originHeader);
    } else {
      // not allowed -> no Access-Control-Allow-Origin is set
      // still proceed for server-side requests (curl) but browsers will block frontend
    }
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  // vary by origin so caches behave correctly
  res.setHeader('Vary', 'Origin');
}

function safeParseBody(req) {
  // If req.body is already object, return it.
  if (req.body && typeof req.body === 'object') return req.body;
  // If it's a string, try parse it.
  if (typeof req.body === 'string' && req.body.length) {
    try {
      return JSON.parse(req.body);
    } catch (e) {
      // fallthrough
    }
  }
  // Some platforms provide raw body as req.rawBody or req.buffer; attempt those too
  if (req.rawBody && typeof req.rawBody === 'string') {
    try { return JSON.parse(req.rawBody); } catch (e) {}
  }
  return {};
}

module.exports = async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!JWT_SECRET) {
    console.error(`${LOG_PREFIX} JWT_SECRET missing`);
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  const body = safeParseBody(req);
  const { email, password } = body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.status(200).json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error(`${LOG_PREFIX} Login error:`, err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Server error' });
  }
};
