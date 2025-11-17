// signup.js
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// reuse Prisma across invocations (prevents socket exhaustion on serverless)
const prisma = global.prisma || new PrismaClient();
if (!global.prisma) global.prisma = prisma;

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL || '*';
const LOG_PREFIX = '[auth:signup]';

function parseAllowedOrigins(value) {
  if (!value) return [];
  return value.split(',').map(s => s.trim()).filter(Boolean);
}

function setCorsHeaders(req, res) {
  const allowed = parseAllowedOrigins(CLIENT_URL);
  const originHeader = req.headers.origin || '*';

  if (CLIENT_URL === '*' || allowed.length === 0) {
    res.setHeader('Access-Control-Allow-Origin', originHeader);
  } else {
    if (allowed.includes(originHeader)) {
      res.setHeader('Access-Control-Allow-Origin', originHeader);
    }
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
}

function safeParseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body.length) {
    try { return JSON.parse(req.body); } catch (e) {}
  }
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
  const { name, email, password, role = 'user' } = body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword, role },
    });

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error(`${LOG_PREFIX} Signup error:`, err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Server error' });
  }
};
