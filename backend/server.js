require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

/* ---------------------- Crash handlers (helps debugging startup failures) ---------------------- */
/* Use gracefulShutdown so Prisma disconnects before exiting */
async function gracefulShutdown(code = 0, reason = '') {
  try {
    console.log('Graceful shutdown start', reason ? `reason=${reason}` : '');
    if (prisma) {
      await prisma.$disconnect();
      console.log('Prisma disconnected');
    }
  } catch (e) {
    console.error('Error during gracefulShutdown:', e && e.stack ? e.stack : e);
  } finally {
    console.log('Exiting with code', code);
    process.exit(code);
  }
}

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
  // attempt a graceful shutdown then exit
  gracefulShutdown(1, 'uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION at', promise, 'reason:', reason && reason.stack ? reason.stack : reason);
  // attempt a graceful shutdown then exit
  gracefulShutdown(1, 'unhandledRejection');
});

/* ----------------------------- Config & Secrets -------------------------------- */
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const REQUESTED_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;

/* ----------------------------- Prisma client ---------------------------------- */
const prisma = new PrismaClient({ log: ['query', 'info', 'warn', 'error'] });

/* DB connection check on startup (non-blocking) */
(async () => {
  try {
    console.log('NODE_ENV:', process.env.NODE_ENV || 'not set');
    const maskedDb = process.env.DATABASE_URL
      ? `${process.env.DATABASE_URL.slice(0, 40)}...`
      : '(not set)';
    console.log('DATABASE_URL:', maskedDb);

    // Attempt to connect, but don't exit if it fails here — we log the error
    await prisma.$connect();
    console.log('Prisma connected successfully');
  } catch (err) {
    console.error('Prisma connection failed (startup):', err && err.stack ? err.stack : err);
    // Do NOT exit; keep server up so we can debug endpoints or accept connections while DB recovers.
  }
})();

const app = express();

/* --------------------------- BODY PARSERS --------------------------- */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

/* ------------------------------ CORS -------------------------------- */
const isDev = process.env.NODE_ENV !== 'production';
const parseOrigins = (value) =>
  value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

const clientUrlEnv = process.env.CLIENT_URL || '';
const defaultDevOrigins = ['http://localhost:5173', 'http://127.0.0.1:5173'];

const corsOrigin =
  isDev || !clientUrlEnv || clientUrlEnv === '*'
    ? (origin, callback) => callback(null, true)
    : [...parseOrigins(clientUrlEnv), ...defaultDevOrigins];

app.use(
  cors({
    origin: corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    maxAge: 86400,
  })
);

app.options(
  /.*/,
  cors({
    origin: corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    maxAge: 86400,
  })
);

/* --------------------------- DEBUG LOGGER --------------------------- */
app.use((req, res, next) => {
  const bodyKeys = req.body && Object.keys(req.body).length ? Object.keys(req.body).join(',') : 'none';
  console.log(`[REQ] ${req.method} ${req.originalUrl} - origin: ${req.headers.origin || 'no-origin'} - bodyKeys: ${bodyKeys}`);
  next();
});

/* --------------------------- DEBUG TEST ROUTE --------------------------- */
app.post('/__debug_echo', (req, res) => {
  res.json({
    received: req.body,
    bodyKeys: Object.keys(req.body || {}),
    headers: {
      'content-type': req.headers['content-type'],
      origin: req.headers.origin || null,
    },
  });
});

/* --------------------------- AUTH MIDDLEWARE --------------------------- */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

/* ---------------------------------- ROUTES ---------------------------------- */

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'User already exists' });

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);

    const user = await prisma.user.create({
      data: { name, email, password: hashed, role },
    });

    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({ message: 'User created successfully', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Signup error:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'Server error' });
  }
});

// BACKWARD COMPAT SIGNUP
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ success: false, message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    await prisma.user.create({ data: { name, email, password: hashedPassword, role } });

    res.status(201).json({ success: true, message: 'User created' });
  } catch (err) {
    console.error('Error in /signup:', err && err.stack ? err.stack : err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET LOGGED-IN USER
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.userId }, select: { id: true, name: true, email: true, role: true } });
    res.json(user);
  } catch (err) {
    console.error('Error in /api/auth/me:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'Server error' });
  }
});

// HEALTH CHECK
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'FlexVault API', env: process.env.NODE_ENV || 'dev' });
});

/* --------------------------- GLOBAL ERROR --------------------------- */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'Unhandled server error' });
});

/* ------------------------------ START ------------------------------- */
/**
 * Attempts to start the server on a port; if EADDRINUSE occurs it will
 * try the next port up to `maxAttempts`. If using Render, Render will
 * provide the correct PORT in process.env.PORT and that will be used.
 */
function startServer(initialPort = REQUESTED_PORT, maxAttempts = 5) {
  let attempt = 0;
  let portToTry = initialPort;
  let listening = false;

  const tryListen = () => {
    attempt += 1;
    console.log(`Attempt ${attempt} to listen on port ${portToTry}...`);
    const server = app.listen(portToTry, '0.0.0.0', () => {
      listening = true;
      console.log(`Server running on port ${portToTry}`);
    });

    server.on('error', (err) => {
      // If server already listening, skip
      if (listening) return;

      if (err && err.code === 'EADDRINUSE') {
        console.warn(`Port ${portToTry} is in use (EADDRINUSE). Attempt ${attempt}/${maxAttempts}.`);
        server.close?.();
        if (attempt < maxAttempts) {
          portToTry += 1; // try next port
          console.log(`Trying next port: ${portToTry}`);
          setTimeout(tryListen, 250);
        } else {
          console.error(`Unable to bind to a free port after ${maxAttempts} attempts. Please free port ${initialPort} or set PORT env to another port and try again.`);
          gracefulShutdown(1, 'port_bind_failed');
        }
      } else {
        console.error('Server listen error:', err && err.stack ? err.stack : err);
        gracefulShutdown(1, 'listen_error');
      }
    });

    // safety: if process exits, close server
    process.on('SIGINT', () => {
      server.close(() => console.log('Server closed due to SIGINT'));
    });
  };

  tryListen();
}

// Start server
startServer();
