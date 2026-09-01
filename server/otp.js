const crypto = require('crypto');

function hashCode(email, code) {
  const secret = process.env.SESSION_SECRET || 'dev-secret';
  return crypto.createHash('sha256').update(`${email}:${code}:${secret}`).digest('hex');
}

function generateCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

module.exports = { hashCode, generateCode };