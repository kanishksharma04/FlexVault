const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'unset';
const CLIENT_URL = process.env.CLIENT_URL || '*';

function setCors(req, res) {
  const origin = CLIENT_URL === '*' ? (req.headers.origin || '*') : CLIENT_URL;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  return res.status(200).json({
    status: 'ok',
    message: 'Backend serverless is alive',
    hasJwtSecret: JWT_SECRET !== 'unset',
    env: {
      clientUrl: CLIENT_URL,
    },
  });
};