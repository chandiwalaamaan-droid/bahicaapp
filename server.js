import "dotenv/config";
import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";

const app = express();

// ---------- CORS ----------
// Lock this to your real frontend origin(s) in production via FRONTEND_URL.
// Comma-separate multiple origins, e.g. "https://bahi.app,https://www.bahi.app"
const allowedOrigins = (process.env.FRONTEND_URL || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, cb) {
      // allow same-origin / server-to-server / curl (no Origin header)
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error(
    "Missing JWT_SECRET env var. Set a long random string (e.g. `openssl rand -hex 32`) before starting the server."
  );
  process.exit(1);
}

// ---------- Google Sign-In ----------
// Same OAuth 2.0 Client ID (Web application type) must be set on the frontend
// as VITE_GOOGLE_CLIENT_ID. Without it, "Continue with Google" is simply not
// offered — email/password auth keeps working either way.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
if (!GOOGLE_CLIENT_ID) {
  console.warn("GOOGLE_CLIENT_ID not set — Google sign-in is disabled, email/password auth still works.");
}
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// ---------- TiDB connection ----------
if (!process.env.TIDB_HOST || !process.env.TIDB_USER || !process.env.TIDB_DATABASE) {
  console.error(
    "Missing TiDB config. Set TIDB_HOST, TIDB_USER, TIDB_PASSWORD, TIDB_DATABASE (and optionally TIDB_PORT) as environment variables."
  );
}

const pool = mysql.createPool({
  host: process.env.TIDB_HOST,
  port: process.env.TIDB_PORT ? Number(process.env.TIDB_PORT) : 4000,
  user: process.env.TIDB_USER,
  password: process.env.TIDB_PASSWORD,
  database: process.env.TIDB_DATABASE || "test",
  ssl: { minVersion: "TLSv1.2", rejectUnauthorized: true },
  waitForConnections: true,
  connectionLimit: 5,
  maxIdle: 5,
  idleTimeout: 60000,
  enableKeepAlive: true,
  decimalNumbers: true, // return DECIMAL columns as JS numbers, not strings
});

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(36) PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255),
      name VARCHAR(255),
      google_id VARCHAR(255) UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id VARCHAR(64) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      date VARCHAR(10) NOT NULL,
      type VARCHAR(16) NOT NULL,
      category VARCHAR(64) NOT NULL,
      amount DECIMAL(15,2) NOT NULL,
      note TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_txn_user (user_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS business_profile (
      user_id VARCHAR(36) PRIMARY KEY,
      business_name VARCHAR(255),
      gstin VARCHAR(15),
      pan VARCHAR(10),
      address TEXT,
      phone VARCHAR(20),
      email VARCHAR(255)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS invoices (
      id VARCHAR(64) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      number VARCHAR(32) NOT NULL,
      client VARCHAR(255) NOT NULL,
      client_gstin VARCHAR(15),
      client_address TEXT,
      date VARCHAR(10) NOT NULL,
      due_date VARCHAR(10),
      status VARCHAR(16) NOT NULL DEFAULT 'unpaid',
      items TEXT NOT NULL,
      subtotal DECIMAL(15,2) NOT NULL,
      gstTotal DECIMAL(15,2) NOT NULL,
      grand DECIMAL(15,2) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_inv_user (user_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      role VARCHAR(16) NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_chat_user (user_id, id)
    )
  `);
  // Per-user counter so invoice numbers don't collide under concurrent requests.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS invoice_counters (
      user_id VARCHAR(36) PRIMARY KEY,
      next_number INT NOT NULL DEFAULT 1
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS invoice_notes (
      id VARCHAR(64) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      invoice_id VARCHAR(64) NOT NULL,
      type VARCHAR(16) NOT NULL,
      number VARCHAR(32),
      date VARCHAR(10) NOT NULL,
      amount DECIMAL(15,2) NOT NULL,
      reason TEXT,
      status VARCHAR(16) NOT NULL DEFAULT 'unpaid',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_notes_inv (invoice_id),
      INDEX idx_notes_user (user_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS note_counters (
      user_id VARCHAR(36) PRIMARY KEY,
      next_number INT NOT NULL DEFAULT 1
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id VARCHAR(64) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      token_hash VARCHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      used_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_reset_user (user_id),
      INDEX idx_reset_token (token_hash)
    )
  `);

  // Recurring invoice templates: generate a real invoice on a schedule.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS recurring_invoices (
      id VARCHAR(64) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      client VARCHAR(255) NOT NULL,
      client_gstin VARCHAR(15),
      client_address TEXT,
      items TEXT NOT NULL,
      subtotal DECIMAL(15,2) NOT NULL,
      gst_total DECIMAL(15,2) NOT NULL,
      grand DECIMAL(15,2) NOT NULL,
      frequency VARCHAR(16) NOT NULL DEFAULT 'monthly',
      start_date VARCHAR(10) NOT NULL,
      end_date VARCHAR(10),
      next_date VARCHAR(10) NOT NULL,
      payment_terms INT NOT NULL DEFAULT 14,
      status VARCHAR(16) NOT NULL DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_ri_user (user_id),
      INDEX idx_ri_next (next_date)
    )
  `);

  // In-app notifications (due-date reminders, recurring generation alerts, etc.)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id VARCHAR(64) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      type VARCHAR(32) NOT NULL,
      message TEXT NOT NULL,
      link TEXT,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_notif_user (user_id, is_read, created_at),
      INDEX idx_notif_created (created_at)
    )
  `);

  // Safe no-op if columns already exist (idempotent for pre-existing deployments).
  const migrations = [
    "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS client_gstin VARCHAR(15)",
    "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS client_address TEXT",
    "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS due_date VARCHAR(10)",
    "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'unpaid'",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS gst_amount DECIMAL(15,2) NOT NULL DEFAULT 0",
    // Google sign-in: existing accounts keep their password; new Google-only
    // accounts have no password, so the column can no longer be NOT NULL.
    // NOTE: TiDB rejects "ADD COLUMN ... UNIQUE" in one statement, so the
    // column and its unique index are added separately below.
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255)",
    "ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL",
  ];
  for (const sql of migrations) {
    try {
      await pool.query(sql);
    } catch (err) {
      console.error("Migration skipped:", sql, err.message);
    }
  }

  // Add a unique index on google_id if it doesn't already exist.
  // TiDB doesn't support "ADD INDEX IF NOT EXISTS", so check information_schema first.
  try {
    const [rows] = await pool.query(
      `SELECT COUNT(*) AS cnt FROM information_schema.statistics
       WHERE table_schema = DATABASE() AND table_name = 'users' AND index_name = 'idx_users_google_id'`
    );
    if (rows[0].cnt === 0) {
      await pool.query(
        "ALTER TABLE users ADD UNIQUE INDEX idx_users_google_id (google_id)"
      );
    }
  } catch (err) {
    console.error("Migration skipped: add unique index idx_users_google_id", err.message);
  }
}

// ---------- Auth helpers ----------
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------- Date helpers ----------
const todayISO = () => new Date().toISOString().slice(0, 10);
function addDays(dateStr, days) {
  const d = new Date(dateStr);
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}
function advanceDate(dateStr, frequency) {
  const d = new Date(dateStr);
  if (frequency === "monthly") d.setMonth(d.getMonth() + 1);
  else if (frequency === "quarterly") d.setMonth(d.getMonth() + 3);
  else if (frequency === "yearly") d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().slice(0, 10);
}
function monthKey(iso) {
  return iso.slice(0, 7);
}

// ---------- Validation schemas ----------
const emailSchema = z.string().trim().toLowerCase().email().max(255);
const passwordSchema = z.string().min(8).max(200);

const authSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().trim().max(255).optional(),
});

const txnSchema = z.object({
  id: z.string().min(1).max(64),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD"),
  type: z.enum(["income", "expense"]),
  category: z.string().trim().min(1).max(64),
  amount: z.coerce.number().finite().positive().max(999999999999),
  note: z.string().trim().max(2000).optional().default(""),
  gst_amount: z.preprocess(
    (v) => (v === undefined || v === "" || v === null ? 0 : v),
    z.coerce.number().finite().nonnegative().max(999999999999)
  ).optional().default(0),
});

const businessProfileSchema = z.object({
  business_name: z.string().trim().max(255).optional().default(""),
  gstin: z
    .string()
    .trim()
    .toUpperCase()
    .regex(/^[0-9A-Z]{15}$/, "GSTIN must be 15 characters")
    .optional()
    .or(z.literal(""))
    .default(""),
  pan: z
    .string()
    .trim()
    .toUpperCase()
    .regex(/^[A-Z]{5}[0-9]{4}[A-Z]$/, "PAN must be in the format ABCDE1234F")
    .optional()
    .or(z.literal(""))
    .default(""),
  address: z.string().trim().max(1000).optional().default(""),
  phone: z.string().trim().max(20).optional().default(""),
  email: z.string().trim().email().optional().or(z.literal("")).default(""),
});

const invoiceItemSchema = z.object({
  id: z.string().min(1).max(64),
  desc: z.string().trim().max(500),
  qty: z.coerce.number().finite().nonnegative().max(1000000),
  rate: z.coerce.number().finite().nonnegative().max(999999999),
  gst: z.coerce.number().finite().min(0).max(100),
});

const invoiceSchema = z.object({
  id: z.string().min(1).max(64),
  client: z.string().trim().min(1).max(255),
  clientGstin: z
    .string()
    .trim()
    .toUpperCase()
    .regex(/^[0-9A-Z]{15}$/, "GSTIN must be 15 characters")
    .optional()
    .or(z.literal(""))
    .default(""),
  clientAddress: z.string().trim().max(1000).optional().default(""),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD"),
  dueDate: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "due date must be YYYY-MM-DD")
    .optional()
    .or(z.literal(""))
    .default(""),
  status: z.enum(["paid", "unpaid"]).optional().default("unpaid"),
  items: z.array(invoiceItemSchema).min(1).max(200),
  subtotal: z.coerce.number().finite().nonnegative(),
  gstTotal: z.coerce.number().finite().nonnegative(),
  grand: z.coerce.number().finite().nonnegative(),
});

const chatSchema = z.object({
  message: z.string().trim().min(1).max(4000),
});

const googleAuthSchema = z.object({ credential: z.string().trim().min(20) });

const forgotPasswordSchema = z.object({ email: emailSchema });
const resetPasswordSchema = z.object({
  token: z.string().trim().min(20).max(200),
  password: passwordSchema,
});

function validate(schema, data, res) {
  const result = schema.safeParse(data);
  if (!result.success) {
    res.status(400).json({ error: "Invalid input", details: result.error.flatten() });
    return null;
  }
  return result.data;
}

// ---------- Password reset email ----------
// Uses Resend (resend.com) — free tier, one API key, same pattern as the AI
// provider keys. Without RESEND_API_KEY set, reset links are just logged to
// the server console so local/dev testing still works without an email account.
async function sendResetEmail(toEmail, resetLink) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log(`[dev] Password reset link for ${toEmail}: ${resetLink}`);
    return;
  }
  const from = process.env.RESEND_FROM_EMAIL || "Bahi <onboarding@resend.dev>";
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [toEmail],
      subject: "Reset your Bahi password",
      html: `<p>We received a request to reset your Bahi password.</p><p><a href="${resetLink}">Click here to choose a new password</a></p><p>This link expires in 30 minutes. If you didn't request this, you can safely ignore this email.</p>`,
    }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Resend API error ${resp.status}: ${text}`);
  }
}

// ---------- Auth routes ----------
app.post("/api/auth/register", async (req, res) => {
  const body = validate(authSchema, req.body, res);
  if (!body) return;
  try {
    const [existing] = await pool.execute("SELECT id FROM users WHERE email = ?", [body.email]);
    if (existing.length) return res.status(409).json({ error: "An account with this email already exists" });

    const id = crypto.randomUUID();
    const password_hash = await bcrypt.hash(body.password, 10);
    await pool.execute(
      "INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)",
      [id, body.email, password_hash, body.name || null]
    );
    const user = { id, email: body.email, name: body.name || null };
    res.json({ token: signToken(user), user });
  } catch (err) {
    console.error("POST /api/auth/register failed:", err.message);
    res.status(500).json({ error: "Could not create account" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const body = validate(authSchema.pick({ email: true, password: true }), req.body, res);
  if (!body) return;
  try {
    const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [body.email]);
    const row = rows[0];
    // Constant-ish response either way to avoid trivially confirming which emails exist.
    if (!row) return res.status(401).json({ error: "Invalid email or password" });
    if (!row.password_hash) {
      return res.status(401).json({ error: "This account uses Google sign-in. Continue with Google instead." });
    }
    const ok = await bcrypt.compare(body.password, row.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });
    const user = { id: row.id, email: row.email, name: row.name };
    res.json({ token: signToken(user), user });
  } catch (err) {
    console.error("POST /api/auth/login failed:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/auth/google", async (req, res) => {
  if (!googleClient) return res.status(503).json({ error: "Google sign-in is not configured on this server" });
  const body = validate(googleAuthSchema, req.body, res);
  if (!body) return;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: body.credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.email) return res.status(401).json({ error: "Google did not return an email address" });
    if (!payload.email_verified) {
      return res.status(401).json({ error: "Your Google email isn't verified" });
    }
    const email = payload.email.toLowerCase();
    const googleId = payload.sub;
    const name = payload.name || null;

    const [byGoogleId] = await pool.execute("SELECT * FROM users WHERE google_id = ?", [googleId]);
    let row = byGoogleId[0];

    if (!row) {
      const [byEmail] = await pool.execute("SELECT * FROM users WHERE email = ?", [email]);
      row = byEmail[0];
      if (row) {
        // Existing password-based account signing in with Google for the first time — link it.
        await pool.execute("UPDATE users SET google_id = ? WHERE id = ?", [googleId, row.id]);
      } else {
        const id = crypto.randomUUID();
        await pool.execute(
          "INSERT INTO users (id, email, password_hash, name, google_id) VALUES (?, ?, NULL, ?, ?)",
          [id, email, name, googleId]
        );
        row = { id, email, name };
      }
    }

    const user = { id: row.id, email: row.email, name: row.name };
    res.json({ token: signToken(user), user });
  } catch (err) {
    console.error("POST /api/auth/google failed:", err.message);
    res.status(401).json({ error: "Google sign-in failed. Please try again." });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const body = validate(forgotPasswordSchema, req.body, res);
  if (!body) return;
  try {
    const [rows] = await pool.execute("SELECT id, email FROM users WHERE email = ?", [body.email]);
    const user = rows[0];
    // Only act if the account exists, but ALWAYS send back the same response below —
    // this stops the endpoint being used to check which emails have an account.
    if (user) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      await pool.execute(
        "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
        [crypto.randomUUID(), user.id, tokenHash, expiresAt]
      );
      const frontendOrigin = allowedOrigins[0] || "http://localhost:5173";
      const resetLink = `${frontendOrigin}/?resetToken=${rawToken}`;
      try {
        await sendResetEmail(user.email, resetLink);
      } catch (err) {
        console.error("Failed to send reset email:", err.message);
      }
    }
    res.json({ message: "If that email is registered, we've sent a password reset link." });
  } catch (err) {
    console.error("POST /api/auth/forgot-password failed:", err.message);
    res.status(500).json({ error: "Could not process request" });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  const body = validate(resetPasswordSchema, req.body, res);
  if (!body) return;
  try {
    const tokenHash = crypto.createHash("sha256").update(body.token).digest("hex");
    const [rows] = await pool.execute(
      "SELECT * FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()",
      [tokenHash]
    );
    const reset = rows[0];
    if (!reset) {
      return res.status(400).json({ error: "This reset link is invalid or has expired. Request a new one." });
    }

    const password_hash = await bcrypt.hash(body.password, 10);
    await pool.execute("UPDATE users SET password_hash = ? WHERE id = ?", [password_hash, reset.user_id]);
    // Invalidate this and any other outstanding reset tokens for this user.
    await pool.execute("UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL", [
      reset.user_id,
    ]);
    res.json({ message: "Password updated. You can now sign in." });
  } catch (err) {
    console.error("POST /api/auth/reset-password failed:", err.message);
    res.status(500).json({ error: "Could not reset password" });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT id, email, name FROM users WHERE id = ?", [req.userId]);
    if (!rows[0]) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /api/auth/me failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Everything below this line requires a valid token and is scoped to req.userId.
app.use("/api/transactions", requireAuth);
app.use("/api/invoices", requireAuth);
app.use("/api/invoice-notes", requireAuth);
app.use("/api/chat", requireAuth);
app.use("/api/business-profile", requireAuth);
app.use("/api/recurring", requireAuth);
app.use("/api/notifications", requireAuth);
app.use("/api/reports", requireAuth);

// ---------- Business profile ----------
app.get("/api/business-profile", async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT * FROM business_profile WHERE user_id = ?", [req.userId]);
    const row = rows[0];
    res.json(
      row
        ? {
            business_name: row.business_name || "",
            gstin: row.gstin || "",
            pan: row.pan || "",
            address: row.address || "",
            phone: row.phone || "",
            email: row.email || "",
          }
        : { business_name: "", gstin: "", pan: "", address: "", phone: "", email: "" }
    );
  } catch (err) {
    console.error("GET /api/business-profile failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.put("/api/business-profile", async (req, res) => {
  const body = validate(businessProfileSchema, req.body, res);
  if (!body) return;
  try {
    await pool.execute(
      `INSERT INTO business_profile (user_id, business_name, gstin, pan, address, phone, email)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE business_name=VALUES(business_name), gstin=VALUES(gstin), pan=VALUES(pan),
         address=VALUES(address), phone=VALUES(phone), email=VALUES(email)`,
      [req.userId, body.business_name, body.gstin, body.pan, body.address, body.phone, body.email]
    );
    res.json(body);
  } catch (err) {
    console.error("PUT /api/business-profile failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- AI providers ----------
const SYSTEM_PROMPT_BASE =
  "You are the AI Advisor inside 'Bahi', a personal accounting web app for Indian users (accessed at whatever URL the user visits it at — you don't know a fixed domain, so never invent one like 'bahi.in'). The app has exactly these sections, shown as tabs in the sidebar: Dashboard (income/expense/GST summary), Transactions (log income and expenses by category, with quick-add and auto-categorize from notes), Invoices (create GST invoices, mark paid/unpaid, issue credit/debit notes, and set up recurring templates that auto-generate on a schedule), Reports (profit and loss, cash flow, GST summary, and trend charts), Tax Calculator (income tax estimate) (income tax estimate), GST Calculator, AI Advisor (this chat), and Business Profile (name, GSTIN, PAN, address). The app also sends in-app notifications for due-date reminders and when recurring invoices auto-generate. There is no separate login domain, no 'magic link' sign-in, no Chart of Accounts. Do not describe features that aren't in this list, even if they sound plausible for an accounting app. If asked how to do something in the app, only describe these real tabs and actions. Help with bookkeeping, GST, income tax (India), invoicing, and general financial planning questions, using current Indian tax rules as you understand them (FY 2025-26: new regime default, slabs 0-4L nil/4-8L 5%/8-12L 10%/12-16L 15%/16-20L 20%/20-24L 25%/>24L 30%, 87A rebate up to 12L taxable income; old regime slabs 0-2.5L nil/2.5-5L 5%/5-10L 20%/>10L 30%). Be direct and confident, like a sharp advisor who knows the numbers — don't hedge on routine questions. Show your math in short form (e.g. \"₹8L × 10% = ₹80,000\") so the person can follow and trust the figure, not just take it on faith. You are an AI assistant, not a licensed Chartered Accountant; only say so explicitly when it actually matters — filings, large or unusual transactions, notices from the tax department, or anything the person could get penalized for — and even then keep it to one short line recommending they confirm with a qualified CA, not a disclaimer on every message. You may be given a snapshot of the user's own books below — use it to answer questions about their actual income, expenses, and invoices, but don't assume it's complete.";

const PROVIDER_TIMEOUT = 15000;

async function withTimeout(fn, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fn(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

// Defaults match what Bahi shipped with; override on Render (or any host) via
// env vars without touching code any time a provider ships a new model.
const DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite";
const DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b";
const DEFAULT_CLOUDFLARE_MODEL = "@cf/zai-org/glm-4.7-flash";

async function callGemini(systemPrompt, history, signal, apiKey, model) {
  if (!apiKey) throw new Error("missing GOOGLE_API_KEY");

  const contents = history.map((m) => ({
    role: m.role === "user" ? "user" : "model",
    parts: [{ text: m.content }],
  }));

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents,
        systemInstruction: { parts: [{ text: systemPrompt }] },
        generationConfig: {
          maxOutputTokens: 1000,
          // Gemini 3.x models default to MEDIUM "thinking" effort, which adds
          // meaningful latency. LOW is Google's own recommendation for
          // latency-sensitive chat use cases like this one.
          thinkingConfig: { thinkingLevel: "LOW" },
        },
      }),
      signal,
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Gemini (${model}) ${res.status}: ${text}`);
  }

  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error("Gemini returned empty response");
  return text;
}

async function callGroq(systemPrompt, history, signal, apiKey, model) {
  if (!apiKey) throw new Error("missing GROQ_API_KEY");

  const messages = [
    { role: "system", content: systemPrompt },
    ...history.map((m) => ({ role: m.role, content: m.content })),
  ];

  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      max_tokens: 1000,
      messages,
    }),
    signal,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Groq (${model}) ${res.status}: ${text}`);
  }

  const data = await res.json();
  const text = data?.choices?.[0]?.message?.content;
  if (!text) throw new Error("Groq returned empty response");
  return text;
}

async function callCloudflare(systemPrompt, history, signal, accountId, apiToken, model) {
  if (!accountId || !apiToken) throw new Error("missing CLOUDFLARE_ACCOUNT_ID or CLOUDFLARE_API_TOKEN");

  const promptLines = [`System: ${systemPrompt}`];
  for (const m of history) {
    promptLines.push(`${m.role === "user" ? "User" : "Assistant"}: ${m.content}`);
  }
  promptLines.push("Assistant:");

  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/${model}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiToken}`,
      },
      body: JSON.stringify({
        prompt: promptLines.join("\n\n"),
        max_tokens: 1000,
      }),
      signal,
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Cloudflare (${model}) ${res.status}: ${text}`);
  }

  const data = await res.json();
  const text = data?.result?.response ?? data?.result;
  if (!text) throw new Error("Cloudflare returned empty response");
  return String(text);
}

// Each provider can have a primary key and one fallback key (e.g. GOOGLE_API_KEY /
// GOOGLE_API_KEY_2). We try every key for a provider before moving to the next
// provider, so the order is: gemini key1 -> gemini key2 -> groq key1 -> groq key2 ->
// cloudflare key1 -> cloudflare key2.
//
// Models are read from env vars so you can switch a provider's model on Render
// (or any host) without touching code or redeploying from source:
//   GEMINI_MODEL              (both gemini keys, unless overridden per-key below)
//   GEMINI_MODEL_2            (overrides GEMINI_MODEL for the #2 key only)
//   GROQ_MODEL / GROQ_MODEL_2
//   CLOUDFLARE_MODEL / CLOUDFLARE_MODEL_2
// Any unset var falls back to the DEFAULT_*_MODEL constant above.
function buildProviderAttempts() {
  const attempts = [];

  const geminiKeys = [process.env.GOOGLE_API_KEY, process.env.GOOGLE_API_KEY_2].filter(Boolean);
  for (const [i, apiKey] of geminiKeys.entries()) {
    const model =
      (i === 1 && process.env.GEMINI_MODEL_2) || process.env.GEMINI_MODEL || DEFAULT_GEMINI_MODEL;
    attempts.push({
      label: `gemini${i > 0 ? `#${i + 1}` : ""} (${model})`,
      call: (systemPrompt, history, signal) => callGemini(systemPrompt, history, signal, apiKey, model),
    });
  }

  const groqKeys = [process.env.GROQ_API_KEY, process.env.GROQ_API_KEY_2].filter(Boolean);
  for (const [i, apiKey] of groqKeys.entries()) {
    const model = (i === 1 && process.env.GROQ_MODEL_2) || process.env.GROQ_MODEL || DEFAULT_GROQ_MODEL;
    attempts.push({
      label: `groq${i > 0 ? `#${i + 1}` : ""} (${model})`,
      call: (systemPrompt, history, signal) => callGroq(systemPrompt, history, signal, apiKey, model),
    });
  }

  // Cloudflare fallback token can optionally use a different account id
  // (CLOUDFLARE_ACCOUNT_ID_2); if not set, it falls back to the primary account id.
  const cloudflarePairs = [
    [process.env.CLOUDFLARE_ACCOUNT_ID, process.env.CLOUDFLARE_API_TOKEN],
    [process.env.CLOUDFLARE_ACCOUNT_ID_2 || process.env.CLOUDFLARE_ACCOUNT_ID, process.env.CLOUDFLARE_API_TOKEN_2],
  ].filter(([accountId, apiToken]) => accountId && apiToken);
  for (const [i, [accountId, apiToken]] of cloudflarePairs.entries()) {
    const model =
      (i === 1 && process.env.CLOUDFLARE_MODEL_2) || process.env.CLOUDFLARE_MODEL || DEFAULT_CLOUDFLARE_MODEL;
    attempts.push({
      label: `cloudflare${i > 0 ? `#${i + 1}` : ""} (${model})`,
      call: (systemPrompt, history, signal) => callCloudflare(systemPrompt, history, signal, accountId, apiToken, model),
    });
  }

  return attempts;
}

async function getAIReply(systemPrompt, history) {
  const attempts = buildProviderAttempts();
  if (attempts.length === 0) {
    throw new Error("All AI providers failed: no provider API keys are configured");
  }

  const errors = [];
  for (const { label, call } of attempts) {
    try {
      const reply = await withTimeout((signal) => call(systemPrompt, history, signal), PROVIDER_TIMEOUT);
      console.log(`AI provider (${label}) answered`);
      return reply;
    } catch (err) {
      console.error(`AI provider (${label}) failed:`, err.message);
      errors.push(`${label}: ${err.message}`);
    }
  }

  throw new Error(`All AI providers failed: ${errors.join(" | ")}`);
}

// Uses the same provider fallback chain to turn a free-text note into a
// structured transaction, e.g. "paid 2500 for canva" -> {type, category, amount, note}.
const QUICK_ADD_CATEGORIES = {
  income: ["Client payment", "Salary", "Freelance", "Interest", "Other income"],
  expense: ["Rent", "Software/tools", "Travel", "Supplies", "Utilities", "Salaries paid", "Marketing", "Taxes", "Other expense"],
};

async function parseTransactionFromText(text) {
  const prompt = `Extract a bookkeeping transaction from this note: "${text}"

Respond with ONLY a JSON object, no markdown, no explanation, in exactly this shape:
{"type": "income" or "expense", "category": one of ${JSON.stringify([...QUICK_ADD_CATEGORIES.income, ...QUICK_ADD_CATEGORIES.expense])}, "amount": number (INR, no symbol), "note": short cleaned-up description}

If the amount is genuinely unclear, set "amount" to 0. Today's date is ${new Date().toISOString().slice(0, 10)}.`;

  let raw;
  try {
    raw = await getAIReply(
      "You are a precise data-extraction tool. You only output valid JSON, nothing else.",
      [{ role: "user", content: prompt }]
    );
  } catch (err) {
    console.error("Quick-add AI error:", err);
    if (err.message && err.message.includes("no provider API keys are configured")) {
      throw new Error("Quick add isn't available — no AI provider is configured on this server. Use the form below instead.");
    }
    throw new Error("Quick add couldn't reach the AI provider just now — please try again shortly, or use the form below instead.");
  }

  const cleaned = raw.replace(/```json|```/g, "").trim();
  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw new Error("Could not understand that — try rephrasing, e.g. 'paid 2500 for Canva subscription'.");
  }

  const type = parsed.type === "income" ? "income" : "expense";
  const validCategories = QUICK_ADD_CATEGORIES[type];
  const category = validCategories.includes(parsed.category) ? parsed.category : validCategories[validCategories.length - 1];
  const amount = Number(parsed.amount);
  if (!amount || !Number.isFinite(amount) || amount <= 0) {
    throw new Error("Could not find a clear amount — try rephrasing with a number, e.g. 'received 5000 from Rahul'.");
  }
  const note = typeof parsed.note === "string" ? parsed.note.slice(0, 500) : text.slice(0, 500);

  return { type, category, amount, note };
}

// Build a compact financial snapshot for the AI so it can actually reason
// about the user's books instead of only their chat history.
async function buildFinancialContext(userId) {
  const [txns] = await pool.execute(
    "SELECT date, type, category, amount FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT 500",
    [userId]
  );
  const [invRows] = await pool.execute(
    "SELECT client, date, grand, gstTotal FROM invoices WHERE user_id = ? ORDER BY date DESC LIMIT 100",
    [userId]
  );

  if (txns.length === 0 && invRows.length === 0) {
    return "The user has no transactions or invoices recorded yet.";
  }

  const now = new Date().toISOString().slice(0, 7);
  const thisMonth = txns.filter((t) => t.date.slice(0, 7) === now);
  const sum = (rows) => rows.reduce((s, r) => s + Number(r.amount), 0);
  const income = sum(thisMonth.filter((t) => t.type === "income"));
  const expense = sum(thisMonth.filter((t) => t.type === "expense"));

  const byCategory = {};
  thisMonth
    .filter((t) => t.type === "expense")
    .forEach((t) => {
      byCategory[t.category] = (byCategory[t.category] || 0) + Number(t.amount);
    });
  const topExpenses =
    Object.entries(byCategory)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([cat, amt]) => `${cat}: ₹${Math.round(amt).toLocaleString("en-IN")}`)
      .join(", ") || "none";

  const gstCollected = sum(invRows.map((r) => ({ amount: r.grand })));
  const gstTotal = sum(invRows.map((r) => ({ amount: r.gstTotal })));
  const totalIncomeAllTime = sum(txns.filter((t) => t.type === "income"));
  const totalExpenseAllTime = sum(txns.filter((t) => t.type === "expense"));

  return [
    "USER FINANCIAL CONTEXT (from their Bahi books; may be incomplete)",
    `This month — income: ₹${Math.round(income).toLocaleString("en-IN")}, expenses: ₹${Math.round(
      expense
    ).toLocaleString("en-IN")}, net: ₹${Math.round(income - expense).toLocaleString("en-IN")}`,
    `Top expense categories this month: ${topExpenses}`,
    `All-time totals — income: ₹${Math.round(totalIncomeAllTime).toLocaleString(
      "en-IN"
    )}, expenses: ₹${Math.round(totalExpenseAllTime).toLocaleString("en-IN")}`,
    `Invoices on file: ${invRows.length}, total invoiced ₹${Math.round(gstCollected).toLocaleString(
      "en-IN"
    )}, GST on those invoices ₹${Math.round(gstTotal).toLocaleString("en-IN")}`,
  ].join("\n");
}

// ---------- Transactions ----------
app.get("/api/transactions", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, date, type, category, amount, note, gst_amount FROM transactions WHERE user_id = ? ORDER BY date DESC",
      [req.userId]
    );
    res.json(rows.map((r) => ({ ...r, amount: Number(r.amount), gst_amount: Number(r.gst_amount) })));
  } catch (err) {
    console.error("GET /api/transactions failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

const quickAddSchema = z.object({ text: z.string().trim().min(1).max(500) });

app.post("/api/transactions/parse", async (req, res) => {
  const body = validate(quickAddSchema, req.body, res);
  if (!body) return;
  try {
    const parsed = await parseTransactionFromText(body.text);
    res.json(parsed);
  } catch (err) {
    res.status(422).json({ error: err.message || "Could not parse that entry." });
  }
});

app.post("/api/transactions", async (req, res) => {
  const body = validate(txnSchema, req.body, res);
  if (!body) return;
  try {
    await pool.execute(
      "INSERT INTO transactions (id, user_id, date, type, category, amount, note, gst_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [body.id, req.userId, body.date, body.type, body.category, body.amount, body.note || "", body.gst_amount || 0]
    );
    const [rows] = await pool.execute(
      "SELECT id, date, type, category, amount, note, gst_amount FROM transactions WHERE id = ? AND user_id = ?",
      [body.id, req.userId]
    );
    const row = rows[0];
    res.json({ ...row, amount: Number(row.amount), gst_amount: Number(row.gst_amount) });
  } catch (err) {
    console.error("POST /api/transactions failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.put("/api/transactions/:id", async (req, res) => {
  const body = validate(txnSchema.partial({ id: true }), req.body, res);
  if (!body) return;
  try {
    const [existing] = await pool.execute("SELECT id FROM transactions WHERE id = ? AND user_id = ?", [
      req.params.id,
      req.userId,
    ]);
    if (!existing.length) return res.status(404).json({ error: "Transaction not found" });

    await pool.execute(
      "UPDATE transactions SET date=?, type=?, category=?, amount=?, note=?, gst_amount=? WHERE id=? AND user_id=?",
      [body.date, body.type, body.category, body.amount, body.note || "", body.gst_amount || 0, req.params.id, req.userId]
    );
    const [rows] = await pool.execute(
      "SELECT id, date, type, category, amount, note, gst_amount FROM transactions WHERE id = ? AND user_id = ?",
      [req.params.id, req.userId]
    );
    const row = rows[0];
    res.json({ ...row, amount: Number(row.amount), gst_amount: Number(row.gst_amount) });
  } catch (err) {
    console.error("PUT /api/transactions failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.delete("/api/transactions/:id", async (req, res) => {
  try {
    const [result] = await pool.execute("DELETE FROM transactions WHERE id = ? AND user_id = ?", [
      req.params.id,
      req.userId,
    ]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Transaction not found" });
    res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/transactions failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- Invoices ----------
app.get("/api/invoices", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, number, client, client_gstin, client_address, date, due_date, status, items, subtotal, gstTotal, grand FROM invoices WHERE user_id = ? ORDER BY date DESC",
      [req.userId]
    );
    res.json(
      rows.map((r) => ({
        id: r.id,
        number: r.number,
        client: r.client,
        clientGstin: r.client_gstin || "",
        clientAddress: r.client_address || "",
        date: r.date,
        dueDate: r.due_date || "",
        status: r.status || "unpaid",
        items: JSON.parse(r.items),
        subtotal: Number(r.subtotal),
        gstTotal: Number(r.gstTotal),
        grand: Number(r.grand),
      }))
    );
  } catch (err) {
    console.error("GET /api/invoices failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/invoices", async (req, res) => {
  const body = validate(invoiceSchema, req.body, res);
  if (!body) return;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Atomically claim the next invoice number for this user.
    await conn.execute(
      "INSERT INTO invoice_counters (user_id, next_number) VALUES (?, 2) ON DUPLICATE KEY UPDATE next_number = next_number + 1",
      [req.userId]
    );
    const [[counterRow]] = await conn.execute(
      "SELECT next_number FROM invoice_counters WHERE user_id = ?",
      [req.userId]
    );
    const seq = counterRow.next_number - 1;
    const number = `INV-${String(seq).padStart(4, "0")}`;

    await conn.execute(
      `INSERT INTO invoices
        (id, user_id, number, client, client_gstin, client_address, date, due_date, status, items, subtotal, gstTotal, grand)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        body.id,
        req.userId,
        number,
        body.client,
        body.clientGstin || null,
        body.clientAddress || null,
        body.date,
        body.dueDate || null,
        body.status,
        JSON.stringify(body.items),
        body.subtotal,
        body.gstTotal,
        body.grand,
      ]
    );
    await conn.commit();

    res.json({
      id: body.id,
      number,
      client: body.client,
      clientGstin: body.clientGstin || "",
      clientAddress: body.clientAddress || "",
      date: body.date,
      dueDate: body.dueDate || "",
      status: body.status,
      items: body.items,
      subtotal: body.subtotal,
      gstTotal: body.gstTotal,
      grand: body.grand,
    });
  } catch (err) {
    await conn.rollback();
    console.error("POST /api/invoices failed:", err.message);
    res.status(500).json({ error: "Database error" });
  } finally {
    conn.release();
  }
});

app.put("/api/invoices/:id", async (req, res) => {
  const body = validate(invoiceSchema.partial({ id: true }), req.body, res);
  if (!body) return;
  try {
    const [existing] = await pool.execute("SELECT id FROM invoices WHERE id = ? AND user_id = ?", [
      req.params.id,
      req.userId,
    ]);
    if (!existing.length) return res.status(404).json({ error: "Invoice not found" });

    await pool.execute(
      `UPDATE invoices SET client=?, client_gstin=?, client_address=?, date=?, due_date=?, status=?,
         items=?, subtotal=?, gstTotal=?, grand=? WHERE id=? AND user_id=?`,
      [
        body.client,
        body.clientGstin || null,
        body.clientAddress || null,
        body.date,
        body.dueDate || null,
        body.status,
        JSON.stringify(body.items),
        body.subtotal,
        body.gstTotal,
        body.grand,
        req.params.id,
        req.userId,
      ]
    );
    const [rows] = await pool.execute(
      "SELECT id, number, client, client_gstin, client_address, date, due_date, status, items, subtotal, gstTotal, grand FROM invoices WHERE id = ? AND user_id = ?",
      [req.params.id, req.userId]
    );
    const r = rows[0];
    res.json({
      id: r.id,
      number: r.number,
      client: r.client,
      clientGstin: r.client_gstin || "",
      clientAddress: r.client_address || "",
      date: r.date,
      dueDate: r.due_date || "",
      status: r.status || "unpaid",
      items: JSON.parse(r.items),
      subtotal: Number(r.subtotal),
      gstTotal: Number(r.gstTotal),
      grand: Number(r.grand),
    });
  } catch (err) {
    console.error("PUT /api/invoices/:id failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.patch("/api/invoices/:id/status", async (req, res) => {
  const body = validate(z.object({ status: z.enum(["paid", "unpaid"]) }), req.body, res);
  if (!body) return;
  try {
    const [result] = await pool.execute("UPDATE invoices SET status=? WHERE id=? AND user_id=?", [
      body.status,
      req.params.id,
      req.userId,
    ]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Invoice not found" });
    res.json({ ok: true, status: body.status });
  } catch (err) {
    console.error("PATCH /api/invoices/:id/status failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.delete("/api/invoices/:id", async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute("DELETE FROM invoice_notes WHERE invoice_id = ? AND user_id = ?", [req.params.id, req.userId]);
    const [result] = await conn.execute("DELETE FROM invoices WHERE id = ? AND user_id = ?", [
      req.params.id,
      req.userId,
    ]);
    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({ error: "Invoice not found" });
    }
    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    console.error("DELETE /api/invoices failed:", err.message);
    res.status(500).json({ error: "Database error" });
  } finally {
    conn.release();
  }
});

// ---------- Credit / Debit Notes ----------
const noteSchema = z.object({
  id: z.string().min(1).max(64),
  invoiceId: z.string().min(1).max(64),
  type: z.enum(["credit", "debit"]),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD"),
  amount: z.coerce.number().finite().positive().max(999999999999),
  reason: z.string().trim().max(1000).optional().default(""),
});

app.get("/api/invoice-notes", async (req, res) => {
  const invoiceId = req.query.invoice_id;
  if (!invoiceId) return res.status(400).json({ error: "invoice_id query param required" });
  try {
    const [invCheck] = await pool.execute("SELECT id FROM invoices WHERE id = ? AND user_id = ?", [invoiceId, req.userId]);
    if (!invCheck.length) return res.status(404).json({ error: "Invoice not found" });
    const [rows] = await pool.execute(
      "SELECT id, invoice_id, type, number, date, amount, reason, status FROM invoice_notes WHERE invoice_id = ? AND user_id = ? ORDER BY date DESC",
      [invoiceId, req.userId]
    );
    res.json(rows.map((r) => ({
      id: r.id,
      invoiceId: r.invoice_id,
      type: r.type,
      number: r.number,
      date: r.date,
      amount: Number(r.amount),
      reason: r.reason || "",
      status: r.status || "unpaid",
    })));
  } catch (err) {
    console.error("GET /api/invoice-notes failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/invoice-notes", async (req, res) => {
  const body = validate(noteSchema, req.body, res);
  if (!body) return;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [invCheck] = await conn.execute("SELECT id FROM invoices WHERE id = ? AND user_id = ?", [body.invoiceId, req.userId]);
    if (!invCheck.length) {
      await conn.rollback();
      return res.status(404).json({ error: "Invoice not found" });
    }
    const prefix = body.type === "credit" ? "CRN" : "DNR";
    await conn.execute(
      "INSERT INTO note_counters (user_id, next_number) VALUES (?, 2) ON DUPLICATE KEY UPDATE next_number = next_number + 1",
      [req.userId]
    );
    const [[counterRow]] = await conn.execute("SELECT next_number FROM note_counters WHERE user_id = ?", [req.userId]);
    const seq = counterRow.next_number - 1;
    const number = `${prefix}-${String(seq).padStart(4, "0")}`;

    await conn.execute(
      "INSERT INTO invoice_notes (id, user_id, invoice_id, type, number, date, amount, reason, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unpaid')",
      [body.id, req.userId, body.invoiceId, body.type, number, body.date, body.amount, body.reason || ""]
    );
    await conn.commit();
    res.json({ id: body.id, number, invoiceId: body.invoiceId, type: body.type, date: body.date, amount: body.amount, reason: body.reason || "", status: "unpaid" });
  } catch (err) {
    await conn.rollback();
    console.error("POST /api/invoice-notes failed:", err.message);
    res.status(500).json({ error: "Database error" });
  } finally {
    conn.release();
  }
});

app.delete("/api/invoice-notes/:id", async (req, res) => {
  try {
    const [result] = await pool.execute("DELETE FROM invoice_notes WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Note not found" });
    res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/invoice-notes failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- Chat (private per user, backed by their own books) ----------
app.get("/api/chat", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, role, content FROM chat WHERE user_id = ? ORDER BY id ASC",
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /api/chat failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

const MAX_CHAT_HISTORY = 20; // cap how much prior chat we resend to the model

// Fetches up to MAX_CHAT_HISTORY prior messages (oldest first) for this user,
// optionally bounded by an id (used when editing/regenerating mid-conversation),
// then calls the AI and returns its reply text. Never throws — falls back to a
// friendly message on any provider failure, matching the original behavior.
async function fetchChatHistory(userId, { beforeId = null, includeId = null } = {}) {
  let sql = `SELECT role, content FROM chat WHERE user_id = ?`;
  const params = [userId];
  if (beforeId !== null) {
    sql += ` AND id < ?`;
    params.push(beforeId);
  } else if (includeId !== null) {
    sql += ` AND id <= ?`;
    params.push(includeId);
  }
  // NOTE: LIMIT can't be a bound parameter over MySQL/TiDB's prepared-statement
  // protocol — MAX_CHAT_HISTORY is a fixed server constant, safe to inline.
  sql += ` ORDER BY id DESC LIMIT ${Number(MAX_CHAT_HISTORY)}`;
  const [rows] = await pool.execute(sql, params);
  return rows.reverse().map((r) => ({ role: r.role, content: r.content }));
}

async function generateAssistantReply(userId, history) {
  try {
    const financialContext = await buildFinancialContext(userId);
    const systemPrompt = `${SYSTEM_PROMPT_BASE}\n\n${financialContext}`;
    return await getAIReply(systemPrompt, history);
  } catch (err) {
    console.error("AI fallback error:", err);
    // Distinguish "nobody configured any AI provider keys" (a setup problem,
    // permanent until an admin fixes it) from "providers were reachable but
    // all failed this one time" (transient — retrying may well work). Telling
    // a user to "try again shortly" when it's actually the former just wastes
    // their time, since retrying can never succeed until keys are added.
    if (err.message && err.message.includes("no provider API keys are configured")) {
      return "The AI Advisor isn't set up yet on this server — no AI provider API keys have been configured. This is a one-time setup step for whoever runs this Bahi instance, not something you can fix from here. Everything else in the app (Transactions, Invoices, calculators) works normally without it.";
    }
    return "The AI Advisor couldn't get a response from any AI provider just now. This is usually temporary — please try again in a minute. If it keeps happening, the configured provider keys may have expired or hit a quota limit.";
  }
}

function parseChatIdParam(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: "Invalid message id" });
    return null;
  }
  return id;
}

app.post("/api/chat", async (req, res) => {
  const body = validate(chatSchema, req.body, res);
  if (!body) return;

  try {
    await pool.execute("INSERT INTO chat (user_id, role, content) VALUES (?, ?, ?)", [
      req.userId,
      "user",
      body.message,
    ]);

    const history = await fetchChatHistory(req.userId);
    const reply = await generateAssistantReply(req.userId, history);
    await pool.execute("INSERT INTO chat (user_id, role, content) VALUES (?, ?, ?)", [
      req.userId,
      "assistant",
      reply,
    ]);
    res.json({ reply });
  } catch (err) {
    console.error("POST /api/chat failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Edit one of your own past messages: updates its text, drops everything that
// came after it (the conversation branches from here), and gets a fresh reply.
app.post("/api/chat/:id/edit", async (req, res) => {
  const id = parseChatIdParam(req, res);
  if (id === null) return;
  const body = validate(chatSchema, req.body, res);
  if (!body) return;

  try {
    const [rows] = await pool.execute("SELECT id, role FROM chat WHERE id = ? AND user_id = ?", [id, req.userId]);
    const target = rows[0];
    if (!target) return res.status(404).json({ error: "Message not found" });
    if (target.role !== "user") return res.status(400).json({ error: "Only your own messages can be edited" });

    await pool.execute("UPDATE chat SET content = ? WHERE id = ?", [body.message, id]);
    await pool.execute("DELETE FROM chat WHERE user_id = ? AND id > ?", [req.userId, id]);

    const history = await fetchChatHistory(req.userId, { includeId: id });
    const reply = await generateAssistantReply(req.userId, history);
    await pool.execute("INSERT INTO chat (user_id, role, content) VALUES (?, ?, ?)", [
      req.userId,
      "assistant",
      reply,
    ]);
    res.json({ reply });
  } catch (err) {
    console.error("POST /api/chat/:id/edit failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Regenerate one of the AI's past replies: drops it (and anything after it),
// then asks the model again from the same point in the conversation.
app.post("/api/chat/:id/regenerate", async (req, res) => {
  const id = parseChatIdParam(req, res);
  if (id === null) return;

  try {
    const [rows] = await pool.execute("SELECT id, role FROM chat WHERE id = ? AND user_id = ?", [id, req.userId]);
    const target = rows[0];
    if (!target) return res.status(404).json({ error: "Message not found" });
    if (target.role !== "assistant") return res.status(400).json({ error: "Only an AI reply can be regenerated" });

    await pool.execute("DELETE FROM chat WHERE user_id = ? AND id >= ?", [req.userId, id]);

    const history = await fetchChatHistory(req.userId, { beforeId: id });
    const reply = await generateAssistantReply(req.userId, history);
    await pool.execute("INSERT INTO chat (user_id, role, content) VALUES (?, ?, ?)", [
      req.userId,
      "assistant",
      reply,
    ]);
    res.json({ reply });
  } catch (err) {
    console.error("POST /api/chat/:id/regenerate failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Delete a single message (no cascading — just that one row).
app.delete("/api/chat/:id", async (req, res) => {
  const id = parseChatIdParam(req, res);
  if (id === null) return;

  try {
    const [result] = await pool.execute("DELETE FROM chat WHERE id = ? AND user_id = ?", [id, req.userId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Message not found" });
    res.json({ deleted: true });
  } catch (err) {
    console.error("DELETE /api/chat/:id failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- Auto-categorize (rules-based, no AI required) ----------
// Keyword rules for guessing a transaction's type + category from its note text.
// Works without any AI provider keys; the AI quick-add (/parse) is still available
// as a richer alternative for free-text entry.
const CATEGORY_KEYWORDS = {
  "Client payment": ["client", "received from", "payment", "invoice", "paid by"],
  "Salary": ["salary", "salary"],
  "Freelance": ["freelance", "consulting", "contract"],
  "Interest": ["interest", "dividend"],
  "Rent": ["rent", "rental", "bhatakni"],
  "Software/tools": ["canva", "subscription", "software", "tool", "saas", "aws", "hosting", "netflix", "github", "figma", "notion", "adobe", "microsoft 365", "google workspace", "slack", "zoom", "spotify"],
  "Travel": ["travel", "flight", "air", "uber", "ola", "taxi", "train", "bus", "petrol", "fuel", "railway"],
  "Supplies": ["supplies", "stationery", "notebook", "pen", "paper", "printer", "ink"],
  "Utilities": ["electricity", "water bill", "internet", "wifi", "broadband", "phone", "mobile", "diesel", "gas"],
  "Salaries paid": ["salary to", "wages", "payroll", "employee"],
  "Marketing": ["marketing", "ads", "advertisement", "facebook", "instagram", "google ads", "promotion", "ppc", "campaign"],
  "Taxes": ["gst", "tax", "income tax", "fee", "penalty", "compliance", "filings"],
};

function categorizeNote(text) {
  const lower = (text || "").toLowerCase().trim();
  if (!lower) return { type: "expense", category: "Other expense" };

  let best = null;
  let bestScore = 0;
  for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
    let score = 0;
    for (const kw of keywords) if (lower.includes(kw)) score += 1;
    const isIncome = QUICK_ADD_CATEGORIES.income.includes(category);
    if (score > bestScore) {
      bestScore = score;
      best = { type: isIncome ? "income" : "expense", category };
    }
  }
  if (!best || bestScore === 0) return { type: "expense", category: "Other expense" };
  return best;
}

const categorizeSchema = z.object({ text: z.string().trim().min(1).max(500) });

app.post("/api/transactions/categorize", async (req, res) => {
  const body = validate(categorizeSchema, req.body, res);
  if (!body) return;
  const result = categorizeNote(body.text);
  res.json(result);
});

// ---------- Recurring invoices ----------
const recurringSchema = z.object({
  id: z.string().min(1).max(64),
  client: z.string().trim().min(1).max(255),
  clientGstin: z.string().trim().toUpperCase().regex(/^[0-9A-Z]{15}$/, "GSTIN must be 15 characters").optional().or(z.literal("")).default(""),
  clientAddress: z.string().trim().max(1000).optional().default(""),
  frequency: z.enum(["monthly", "quarterly", "yearly"]).default("monthly"),
  startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD").optional().or(z.literal("")).default(""),
  endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD").optional().or(z.literal("")).default(""),
  paymentTerms: z.coerce.number().int().nonnegative().max(365).optional().default(14),
  status: z.enum(["active", "paused"]).optional().default("active"),
  items: z.array(invoiceItemSchema).min(1).max(200),
});

app.get("/api/recurring", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, client, client_gstin, client_address, frequency, start_date, end_date, next_date, payment_terms, status, items, subtotal, gst_total, grand, created_at FROM recurring_invoices WHERE user_id = ? ORDER BY created_at DESC",
      [req.userId]
    );
    res.json(
      rows.map((r) => ({
        id: r.id,
        client: r.client,
        clientGstin: r.client_gstin || "",
        clientAddress: r.client_address || "",
        frequency: r.frequency,
        startDate: r.start_date || "",
        endDate: r.end_date || "",
        nextDate: r.next_date || "",
        paymentTerms: Number(r.payment_terms || 0),
        status: r.status,
        items: JSON.parse(r.items),
        subtotal: Number(r.subtotal),
        gstTotal: Number(r.gst_total),
        grand: Number(r.grand),
        createdAt: r.created_at,
      }))
    );
  } catch (err) {
    console.error("GET /api/recurring failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/recurring", async (req, res) => {
  const body = validate(recurringSchema, req.body, res);
  if (!body) return;
  try {
    const id = crypto.randomUUID();
    const startDate = body.startDate || todayISO();
    const nextDate = body.startDate || todayISO();
    await pool.execute(
      `INSERT INTO recurring_invoices
        (id, user_id, client, client_gstin, client_address, items, subtotal, gst_total, grand,
         frequency, start_date, end_date, next_date, payment_terms, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id, req.userId, body.client, body.clientGstin || null, body.clientAddress || null,
        JSON.stringify(body.items),
        body.items.reduce((s, it) => s + (parseFloat(it.rate) || 0) * (parseFloat(it.qty) || 0), 0),
        body.items.reduce((s, it) => s + ((parseFloat(it.rate) || 0) * (parseFloat(it.qty) || 0) * (parseFloat(it.gst) || 0)) / 100, 0),
        body.items.reduce((s, it) => s + (parseFloat(it.rate) || 0) * (parseFloat(it.qty) || 0) * (1 + (parseFloat(it.gst) || 0) / 100), 0),
        body.frequency, startDate, body.endDate || null, nextDate, body.paymentTerms, body.status,
      ]
    );
    const [rows] = await pool.execute(
      "SELECT id, client, client_gstin, client_address, frequency, start_date, end_date, next_date, payment_terms, status, items, subtotal, gst_total, grand FROM recurring_invoices WHERE id = ?",
      [id]
    );
    const r = rows[0];
    res.json({
      id: r.id, client: r.client, clientGstin: r.client_gstin || "", clientAddress: r.client_address || "",
      frequency: r.frequency, startDate: r.start_date || "", endDate: r.end_date || "", nextDate: r.next_date || "",
      paymentTerms: Number(r.payment_terms || 0), status: r.status, items: JSON.parse(r.items),
      subtotal: Number(r.subtotal), gstTotal: Number(r.gst_total), grand: Number(r.grand),
    });
  } catch (err) {
    console.error("POST /api/recurring failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.put("/api/recurring/:id", async (req, res) => {
  const body = validate(recurringSchema.partial({ id: true }), req.body, res);
  if (!body) return;
  try {
    const [existing] = await pool.execute("SELECT id FROM recurring_invoices WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
    if (!existing.length) return res.status(404).json({ error: "Recurring invoice not found" });

    const subtotal = body.items ? body.items.reduce((s, it) => s + (parseFloat(it.rate) || 0) * (parseFloat(it.qty) || 0), 0) : undefined;
    const gstTotal = body.items ? body.items.reduce((s, it) => s + ((parseFloat(it.rate) || 0) * (parseFloat(it.qty) || 0) * (parseFloat(it.gst) || 0)) / 100, 0) : undefined;
    const grand = body.items ? subtotal + gstTotal : undefined;

    const updates = [];
    const params = [];
    if (body.client !== undefined) { updates.push("client = ?"); params.push(body.client); }
    if (body.clientGstin !== undefined) { updates.push("client_gstin = ?"); params.push(body.clientGstin || null); }
    if (body.clientAddress !== undefined) { updates.push("client_address = ?"); params.push(body.clientAddress || null); }
    if (body.frequency !== undefined) { updates.push("frequency = ?"); params.push(body.frequency); }
    if (body.startDate !== undefined) { updates.push("start_date = ?"); params.push(body.startDate || null); }
    if (body.endDate !== undefined) { updates.push("end_date = ?"); params.push(body.endDate || null); }
    if (body.status !== undefined) { updates.push("status = ?"); params.push(body.status); }
    if (body.paymentTerms !== undefined) { updates.push("payment_terms = ?"); params.push(body.paymentTerms); }
    if (body.items !== undefined) {
      updates.push("items = ?"); params.push(JSON.stringify(body.items));
      updates.push("subtotal = ?"); params.push(subtotal);
      updates.push("gst_total = ?"); params.push(gstTotal);
      updates.push("grand = ?"); params.push(grand);
    }
    params.push(req.params.id, req.userId);
    await pool.execute(
      `UPDATE recurring_invoices SET ${updates.join(", ")} WHERE id = ? AND user_id = ?`,
      params
    );

    const [rows] = await pool.execute(
      "SELECT id, client, client_gstin, client_address, frequency, start_date, end_date, next_date, payment_terms, status, items, subtotal, gst_total, grand FROM recurring_invoices WHERE id = ?",
      [req.params.id]
    );
    const r = rows[0];
    res.json({
      id: r.id, client: r.client, clientGstin: r.client_gstin || "", clientAddress: r.client_address || "",
      frequency: r.frequency, startDate: r.start_date || "", endDate: r.end_date || "", nextDate: r.next_date || "",
      paymentTerms: Number(r.payment_terms || 0), status: r.status, items: JSON.parse(r.items),
      subtotal: Number(r.subtotal), gstTotal: Number(r.gst_total), grand: Number(r.grand),
    });
  } catch (err) {
    console.error("PUT /api/recurring/:id failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.delete("/api/recurring/:id", async (req, res) => {
  try {
    const [result] = await pool.execute("DELETE FROM recurring_invoices WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Recurring invoice not found" });
    res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/recurring/:id failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Manually generate an invoice from a recurring template now.
app.post("/api/recurring/:id/generate", async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT * FROM recurring_invoices WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
    const ri = rows[0];
    if (!ri) return res.status(404).json({ error: "Recurring invoice not found" });

    const invoiceId = crypto.randomUUID();
    const conn = await pool.getConnection();
    await conn.beginTransaction();
    try {
      await conn.execute(
        "INSERT INTO invoice_counters (user_id, next_number) VALUES (?, 2) ON DUPLICATE KEY UPDATE next_number = next_number + 1",
        [req.userId]
      );
      const [[counterRow]] = await conn.execute("SELECT next_number FROM invoice_counters WHERE user_id = ?", [req.userId]);
      const seq = counterRow.next_number - 1;
      const number = `INV-${String(seq).padStart(4, "0")}`;
      const dueDate = addDays(ri.next_date, Number(ri.payment_terms || 14));

      await conn.execute(
        `INSERT INTO invoices
          (id, user_id, number, client, client_gstin, client_address, date, due_date, status, items, subtotal, gstTotal, grand)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          invoiceId, req.userId, number, ri.client, ri.client_gstin || null, ri.client_address || null,
          ri.next_date, dueDate, "unpaid", ri.items, ri.subtotal, ri.gst_total, ri.grand,
        ]
      );

      // Advance next_date
      const newNext = advanceDate(ri.next_date, ri.frequency);
      if (ri.end_date && newNext > ri.end_date) {
        await conn.execute("UPDATE recurring_invoices SET next_date = ?, status = 'completed' WHERE id = ?", [ri.end_date, ri.id]);
      } else {
        await conn.execute("UPDATE recurring_invoices SET next_date = ? WHERE id = ?", [newNext, ri.id]);
      }

      await conn.execute(
        "INSERT INTO notifications (id, user_id, type, message, link, is_read) VALUES (?, ?, ?, ?, ?, FALSE)",
        [crypto.randomUUID(), req.userId, "recurring_generated", `Recurring invoice ${number} for ${ri.client} was generated.`, `/invoices:${invoiceId}`]
      );

      await conn.commit();
      res.json({ ok: true, invoiceId, number });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("POST /api/recurring/:id/generate failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- Notifications ----------
app.get("/api/notifications", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "50"), 100);
    const [rows] = await pool.execute(
      "SELECT id, type, message, link, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
      [req.userId, limit]
    );
    res.json(
      rows.map((r) => ({
        id: r.id,
        type: r.type,
        message: r.message,
        link: r.link || null,
        isRead: Boolean(r.is_read),
        createdAt: r.created_at,
      }))
    );
  } catch (err) {
    console.error("GET /api/notifications failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/notifications/read", async (req, res) => {
  try {
    await pool.execute("UPDATE notifications SET is_read = TRUE WHERE user_id = ? AND is_read = FALSE", [req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("POST /api/notifications/read failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/notifications/:id/read", async (req, res) => {
  try {
    const [result] = await pool.execute("UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Notification not found" });
    res.json({ ok: true });
  } catch (err) {
    console.error("POST /api/notifications/:id/read failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- Reports ----------
const reportPeriodSchema = z.object({
  start: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "start must be YYYY-MM-DD").optional(),
  end: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "end must be YYYY-MM-DD").optional(),
});

function defaultPeriod() {
  const end = todayISO();
  const d = new Date();
  d.setMonth(d.getMonth() - 11);
  d.setDate(1);
  const start = d.toISOString().slice(0, 10);
  return { start, end };
}

// Profit & Loss: income vs expenses by category for the period.
app.get("/api/reports/pnl", async (req, res) => {
  const parsed = validate(reportPeriodSchema, req.query, res);
  if (!parsed) return;
  const dp = defaultPeriod();
  const start = parsed.start || dp.start;
  const end = parsed.end || dp.end;
  try {
    const [txns] = await pool.execute(
      "SELECT date, type, category, amount FROM transactions WHERE user_id = ? AND date >= ? AND date <= ? ORDER BY date",
      [req.userId, start, end]
    );

    let income = 0, expense = 0;
    const incomeByCat = {}, expenseByCat = {};
    for (const t of txns) {
      const amt = Number(t.amount);
      if (t.type === "income") {
        income += amt;
        incomeByCat[t.category] = (incomeByCat[t.category] || 0) + amt;
      } else {
        expense += amt;
        expenseByCat[t.category] = (expenseByCat[t.category] || 0) + amt;
      }
    }

    res.json({
      period: { start, end },
      income: { total: income, byCategory: incomeByCat },
      expenses: { total: expense, byCategory: expenseByCat },
      netProfit: income - expense,
      transactionCount: txns.length,
    });
  } catch (err) {
    console.error("GET /api/reports/pnl failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Cash flow: daily and monthly aggregation of income vs expenses.
app.get("/api/reports/cashflow", async (req, res) => {
  const parsed = validate(reportPeriodSchema, req.query, res);
  if (!parsed) return;
  const dp = defaultPeriod();
  const start = parsed.start || dp.start;
  const end = parsed.end || dp.end;
  try {
    const [txns] = await pool.execute(
      "SELECT date, type, amount FROM transactions WHERE user_id = ? AND date >= ? AND date <= ? ORDER BY date",
      [req.userId, start, end]
    );

    const byDay = {};
    const byMonth = {};
    for (const t of txns) {
      const d = t.date;
      const m = monthKey(d);
      const amt = Number(t.amount);
      if (!byDay[d]) byDay[d] = { income: 0, expense: 0 };
      if (!byMonth[m]) byMonth[m] = { income: 0, expense: 0, count: 0 };
      if (t.type === "income") {
        byDay[d].income += amt;
        byMonth[m].income += amt;
      } else {
        byDay[d].expense += amt;
        byMonth[m].expense += amt;
      }
      byMonth[m].count += 1;
    }

    const days = Object.keys(byDay).sort().map((d) => ({
      date: d, income: byDay[d].income, expense: byDay[d].expense, net: byDay[d].income - byDay[d].expense,
    }));
    const months = Object.keys(byMonth).sort().map((m) => ({
      month: m, income: byMonth[m].income, expense: byMonth[m].expense, net: byMonth[m].income - byMonth[m].expense, txns: byMonth[m].count,
    }));

    const netCashFlow = txns.reduce((s, t) => s + (t.type === "income" ? 1 : -1) * Number(t.amount), 0);

    res.json({
      period: { start, end },
      netCashFlow,
      byDay: days,
      byMonth: months,
    });
  } catch (err) {
    console.error("GET /api/reports/cashflow failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// GST summary: output tax (from invoices) by rate, input tax (from expenses), net payable.
app.get("/api/reports/gst", async (req, res) => {
  const parsed = validate(reportPeriodSchema, req.query, res);
  if (!parsed) return;
  const dp = defaultPeriod();
  const start = parsed.start || dp.start;
  const end = parsed.end || dp.end;
  try {
    const [invRows] = await pool.execute(
      "SELECT date, items, grand, gst_total FROM invoices WHERE user_id = ? AND date >= ? AND date <= ? ORDER BY date",
      [req.userId, start, end]
    );

    const byRate = {};
    let totalTaxable = 0, totalGst = 0, totalBilled = 0, invoiceCount = 0;
    const taxableByRate = {};
    for (const inv of invRows) {
      invoiceCount += 1;
      const items = JSON.parse(inv.items);
      for (const item of items) {
        const base = (parseFloat(item.rate) || 0) * (parseFloat(item.qty) || 0);
        const gstPct = parseFloat(item.gst) || 0;
        const gstAmt = (base * gstPct) / 100;
        const rateStr = String(gstPct || 0);
        if (!byRate[rateStr]) byRate[rateStr] = { count: 0, taxable: 0, gst: 0, total: 0 };
        byRate[rateStr].count += 1;
        byRate[rateStr].taxable += base;
        byRate[rateStr].gst += gstAmt;
        byRate[rateStr].total += base + gstAmt;
        totalTaxable += base;
        totalGst += gstAmt;
        taxableByRate[rateStr] = (taxableByRate[rateStr] || 0) + base;
      }
      totalBilled += Number(inv.grand);
    }

    // Input tax: GST amounts recorded on expense transactions.
    const [txnRows] = await pool.execute(
      "SELECT gst_amount FROM transactions WHERE user_id = ? AND type = 'expense' AND gst_amount > 0 AND date >= ? AND date <= ?",
      [req.userId, start, end]
    );
    const inputGst = txnRows.reduce((s, r) => s + Number(r.gst_amount), 0);

    res.json({
      period: { start, end },
      outputTax: { totalGst, totalTaxable, totalBilled, byRate },
      inputTax: inputGst,
      netGstPayable: totalGst - inputGst,
      invoiceCount,
    });
  } catch (err) {
    console.error("GET /api/reports/gst failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Trends: monthly income/expense/invoice totals for the last N months.
app.get("/api/reports/trends", async (req, res) => {
  const months = Math.min(Math.max(parseInt(req.query.months || "12"), 1), 36);
  try {
    const d = new Date();
    d.setMonth(d.getMonth() - months + 1);
    d.setDate(1);
    const start = d.toISOString().slice(0, 10);

    const [txns] = await pool.execute(
      "SELECT date, type, amount FROM transactions WHERE user_id = ? AND date >= ? ORDER BY date",
      [req.userId, start]
    );
    const [invRows] = await pool.execute(
      "SELECT date, grand FROM invoices WHERE user_id = ? AND date >= ? ORDER BY date",
      [req.userId, start]
    );

    const byMonth = {};
    for (let i = 0; i < months; i++) {
      const m = new Date();
      m.setMonth(m.getMonth() - i);
      const key = `${m.getFullYear()}-${String(m.getMonth() + 1).padStart(2, "0")}`;
      byMonth[key] = { month: key, income: 0, expense: 0, invoiceTotal: 0, invoiceCount: 0 };
    }
    for (const t of txns) {
      const k = monthKey(t.date);
      if (!byMonth[k]) continue;
      const amt = Number(t.amount);
      if (t.type === "income") byMonth[k].income += amt;
      else byMonth[k].expense += amt;
    }
    for (const inv of invRows) {
      const k = monthKey(inv.date);
      if (!byMonth[k]) continue;
      byMonth[k].invoiceTotal += Number(inv.grand);
      byMonth[k].invoiceCount += 1;
    }
    const labels = Object.keys(byMonth).sort();
    const trendData = labels.map((k) => ({
      month: k, income: byMonth[k].income, expense: byMonth[k].expense,
      net: byMonth[k].income - byMonth[k].expense, invoiceTotal: byMonth[k].invoiceTotal, invoiceCount: byMonth[k].invoiceCount,
    }));

    // Category breakdown for the most recent non-empty month
    const latestMonth = labels.find((k) => byMonth[k].income > 0 || byMonth[k].expense > 0) || labels[labels.length - 1];
    let catBreakdown = { income: {}, expense: {} };
    if (latestMonth) {
      const [monthTxns] = await pool.execute(
        "SELECT type, category, amount FROM transactions WHERE user_id = ? AND date LIKE ? ORDER BY date DESC",
        [req.userId, `${latestMonth}%`]
      );
      for (const t of monthTxns) {
        const bk = t.type === "income" ? catBreakdown.income : catBreakdown.expense;
        bk[t.category] = (bk[t.category] || 0) + Number(t.amount);
      }
    }

    res.json({ months: trendData, latestMonth, categoryBreakdown: catBreakdown });
  } catch (err) {
    console.error("GET /api/reports/trends failed:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- Background jobs: recurring generation + due-date reminders ----------
// Runs periodically (every hour) while the server process is alive. On each tick it
// generates any overdue recurring invoices as real invoices and sends a
// notification for unpaid invoices whose due date has passed.
let jobRunning = false;

async function backgroundJobs() {
  if (jobRunning) return;
  jobRunning = true;
  try {
    await generateDueRecurringInvoices();
    await checkOverdueInvoices();
  } catch (err) {
    console.error("Background job error:", err.message);
  } finally {
    jobRunning = false;
  }
}

async function generateDueRecurringInvoices() {
  try {
    const today = todayISO();
    const [rows] = await pool.execute(
      "SELECT * FROM recurring_invoices WHERE status = 'active' AND next_date <= ? ORDER BY user_id",
      [today]
    );
    for (const ri of rows) {
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.execute(
          "INSERT INTO invoice_counters (user_id, next_number) VALUES (?, 2) ON DUPLICATE KEY UPDATE next_number = next_number + 1",
          [ri.user_id]
        );
        const [[counterRow]] = await conn.execute("SELECT next_number FROM invoice_counters WHERE user_id = ?", [ri.user_id]);
        const seq = counterRow.next_number - 1;
        const number = `INV-${String(seq).padStart(4, "0")}`;
        const invoiceId = crypto.randomUUID();
        const dueDate = addDays(ri.next_date, Number(ri.payment_terms || 14));

        await conn.execute(
          `INSERT INTO invoices
            (id, user_id, number, client, client_gstin, client_address, date, due_date, status, items, subtotal, gstTotal, grand)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            invoiceId, ri.user_id, number, ri.client, ri.client_gstin || null, ri.client_address || null,
            ri.next_date, dueDate, "unpaid", ri.items, ri.subtotal, ri.gst_total, ri.grand,
          ]
        );

        const newNext = advanceDate(ri.next_date, ri.frequency);
        if (ri.end_date && newNext > ri.end_date) {
          await conn.execute("UPDATE recurring_invoices SET next_date = ?, status = 'completed' WHERE id = ?", [ri.end_date, ri.id]);
        } else {
          await conn.execute("UPDATE recurring_invoices SET next_date = ? WHERE id = ?", [newNext, ri.id]);
        }

        await conn.execute(
          "INSERT INTO notifications (id, user_id, type, message, link, is_read) VALUES (?, ?, ?, ?, ?, FALSE)",
          [crypto.randomUUID(), ri.user_id, "recurring_generated", `Recurring invoice ${number} for ${ri.client} was generated.`, `/invoices:${invoiceId}`]
        );

        await conn.commit();
      } catch (err) {
        await conn.rollback();
        console.error("Recurring generate error for", ri.id, ":", err.message);
      } finally {
        conn.release();
      }
    }
  } catch (err) {
    console.error("generateDueRecurringInvoices failed:", err.message);
  }
}

async function checkOverdueInvoices() {
  try {
    const today = todayISO();
    // Only flag invoices overdue by up to 30 days (avoid re-notifying very old debt).
    const recentCutoff = addDays(today, -30);
    const [rows] = await pool.execute(
      `SELECT id, user_id, number, client, due_date FROM invoices
       WHERE status = 'unpaid' AND due_date IS NOT NULL AND due_date < ? AND due_date >= ?`,
      [today, recentCutoff]
    );
    for (const inv of rows) {
      // Don't spam: skip if we already notified about this invoice in the last 7 days.
      const [existing] = await pool.execute(
        "SELECT COUNT(*) AS cnt FROM notifications WHERE link = ? AND created_at > ?",
        [`/invoices:${inv.id}`, addDays(today, -7)]
      );
      if (existing[0].cnt > 0) continue;

      await pool.execute(
        "INSERT INTO notifications (id, user_id, type, message, link, is_read) VALUES (?, ?, ?, ?, ?, FALSE)",
        [
          crypto.randomUUID(),
          inv.user_id,
          "invoice_overdue",
          `Invoice ${inv.number} to ${inv.client} was due on ${inv.due_date} and is still unpaid.`,
          `/invoices:${inv.id}`,
        ]
      );
    }
  } catch (err) {
    console.error("checkOverdueInvoices failed:", err.message);
  }
}

initSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Bahi backend listening on :${PORT}`));
    // Run once right after schema init (so invoices generated while the server
    // was down catch up), then every hour while the process is alive. Started
    // only once initSchema() has resolved so the first run never races the
    // CREATE TABLE / migration statements above.
    backgroundJobs();
    setInterval(backgroundJobs, 60 * 60 * 1000);
  })
  .catch((err) => {
    console.error("Failed to initialize TiDB schema:", err.message);
    process.exit(1);
  });
