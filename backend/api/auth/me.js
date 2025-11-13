const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');

const prisma = global.prisma || new PrismaClient();
if (!global.prisma) global.prisma = prisma;

const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL || '*';

function setCors(req, res) {
  const origin = CLIENT_URL === '*' ? (req.headers.origin || '*') : CLIENT_URL;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function authenticateToken(req, res) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return null;

  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (_) {
    return null;
  }
}

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!JWT_SECRET) {
    return res.status(500).json({ error: 'Server misconfiguration: JWT_SECRET is missing' });
  }

  const payload = authenticateToken(req, res);
  if (!payload) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: { id: true, name: true, email: true, role: true }
    });
    return res.status(200).json(user);
  } catch (err) {
    console.error('Me error:', err?.message || err);
    return res.status(500).json({ error: 'Server error' });
  }
};