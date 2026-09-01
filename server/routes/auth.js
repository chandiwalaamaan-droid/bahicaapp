const express = require('express');
const crypto = require('crypto');

const { hashCode, generateCode } = require('../otp');
const { sendOtp } = require('../mailer');
const db = require('../db');

const router = express.Router();

const OTP_TTL_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

router.post('/request-otp', express.json(), async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'invalid_email' });
  }
  const code = generateCode();
  const codeHash = hashCode(email, code);
  const expiresAt = Date.now() + OTP_TTL_MS;

  db.prepare('DELETE FROM otps WHERE email = ?').run(email);
  db.prepare('INSERT INTO otps (email, code_hash, expires_at, attempts) VALUES (?, ?, ?, 0)')
    .run(email, codeHash, expiresAt);

  try {
    await sendOtp(email, code);
    res.json({ ok: true });
  } catch (err) {
    console.error('sendOtp failed:', err);
    res.status(500).json({ error: 'send_failed' });
  }
});

router.post('/verify-otp', express.json(), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'invalid_code' });

  const row = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY expires_at DESC LIMIT 1').get(email);
  if (!row) return res.status(400).json({ error: 'no_code' });
  if (Date.now() > row.expires_at) {
    db.prepare('DELETE FROM otps WHERE email = ?').run(email);
    return res.status(400).json({ error: 'expired' });
  }
  if (row.attempts >= MAX_ATTEMPTS) return res.status(429).json({ error: 'too_many_attempts' });

  const ok = crypto.timingSafeEqual(Buffer.from(row.code_hash), Buffer.from(hashCode(email, code)));
  if (!ok) {
    db.prepare('UPDATE otps SET attempts = attempts + 1 WHERE email = ?').run(email);
    return res.status(400).json({ error: 'wrong_code' });
  }

  db.prepare('DELETE FROM otps WHERE email = ?').run(email);
  db.prepare('INSERT OR IGNORE INTO users (email, created_at) VALUES (?, ?)')
    .run(email, Date.now());

  req.session.user = { email };
  res.json({ ok: true });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

router.get('/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

module.exports = router;