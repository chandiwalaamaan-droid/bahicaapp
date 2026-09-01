const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, '..', 'data.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS otps (
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email);

  CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    ig_user_id TEXT NOT NULL,
    ig_username TEXT NOT NULL,
    taken_at INTEGER NOT NULL,
    followers_json TEXT NOT NULL,
    following_json TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_snapshots_user ON snapshots(user_email, ig_user_id, taken_at);
`);

module.exports = db;
