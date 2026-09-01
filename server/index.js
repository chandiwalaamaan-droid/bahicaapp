require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');

// Single shared DB connection (schema is created here on first require).
require('./db');

const app = express();

// The frontend now lives on a different origin (e.g. Netlify), so the
// backend needs explicit CORS + credentialed cookies. Set FRONTEND_URL
// in .env to your deployed frontend's origin (no trailing slash).
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // Cross-site cookies require sameSite=none + secure=true, which only
    // works over HTTPS. In local dev (http://localhost) this falls back
    // to 'lax' so cookies still work on plain http.
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use('/auth', require('./routes/auth'));
app.use('/api', require('./routes/api'));

app.get('/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Tally backend listening on http://localhost:${PORT}`));
