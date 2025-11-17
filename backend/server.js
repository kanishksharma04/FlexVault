require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

// Secrets & config
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const PORT = process.env.PORT || 3001;

// Prisma client with verbose logging for debugging on Render
const prisma = new PrismaClient({ log: ['query', 'info', 'warn', 'error'] });

// Try to connect to DB at startup and print useful info
(async () => {
  try {
    console.log('NODE_ENV:', process.env.NODE_ENV || 'not set');
    console.log('PORT:', process.env.PORT || 'not set');
    const dbPresent = !!(process.env.DATABASE_URL || process.env.DATABASE_URL?.length);
    // Mask DB URL when printing
    const maskedDb = process.env.DATABASE_URL ? `${process.env.DATABASE_URL.slice(0, 40)}...` : '(not set)';
    console.log('DATABASE_URL present:', dbPresent);
    console.log('DATABASE_URL (masked):', maskedDb);

    await prisma.$connect();
    console.log('Prisma connected successfully');
  } catch (err) {
    console.error('Prisma connection failed:', err);
    // don't exit automatically — let Render logs show the error; you may uncomment exit(1) during aggressive debugging
    // process.exit(1);
  }
})();

const app = express();

// CORS setup
const parseOrigins = (value) =>
  value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

const clientUrlEnv = process.env.CLIENT_URL;
const defaultDevOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5174',
];
const isDev = process.env.NODE_ENV !== 'production';

const corsOrigin =
  // In dev, be permissive to unblock local testing
  isDev || !clientUrlEnv || clientUrlEnv === '*'
    ? (origin, callback) => callback(null, true)
    : [...parseOrigins(clientUrlEnv), ...defaultDevOrigins];

app.use(cors({
  origin: corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));
app.options(/.*/, cors({
  origin: corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));

// Basic request logger for debugging on Render
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.originalUrl} - origin: ${req.headers.origin || 'no-origin'} - bodyKeys: ${req.body ? Object.keys(req.body).join(',') : 'none'}`);
  next();
});

app.use(express.json());

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
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

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    console.error('Error in /api/auth/signup:', error);
    // Return a bit more info in dev to help debugging, but keep generic in production
    if (isDev) {
      return res.status(500).json({ error: 'Server error', details: error.message });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// Backwards-compatible signup route for frontends calling POST /signup
app.post('/signup', async (req, res) => {
  try {
    console.log('Signup route working - payload keys:', Object.keys(req.body || {}));
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await prisma.user.create({ data: { name, email, password: hashedPassword, role } });

    // Return the simple JSON shape requested by the frontend
    return res.status(201).json({ success: true, message: 'User created' });
  } catch (error) {
    console.error('Error in /signup:', error);
    if (isDev) {
      return res.status(500).json({ success: false, message: 'Server error', details: error.message });
    }
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    console.error('Error in /api/auth/login:', error);
    if (isDev) {
      return res.status(500).json({ error: 'Server error', details: error.message });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: { id: true, name: true, email: true, role: true },
    });
    res.json(user);
  } catch (error) {
    console.error('Error in /api/auth/me:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'CareerLink API', env: process.env.NODE_ENV || 'development' });
});
app.get('/api', (req, res) => {
  res.json({ status: 'ok' });
});

// Global error handler (fallback)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (isDev) return res.status(500).json({ error: 'Unhandled server error', details: err.message });
  return res.status(500).json({ error: 'Unhandled server error' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('SIGINT received: disconnecting Prisma');
  await prisma.$disconnect();
  process.exit(0);
});
process.on('SIGTERM', async () => {
  console.log('SIGTERM received: disconnecting Prisma');
  await prisma.$disconnect();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
