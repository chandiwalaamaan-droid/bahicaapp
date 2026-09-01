const express = require('express');
const crypto = require('crypto');

const db = require('../db');

const router = express.Router();

// This router is mounted at /api in index.js, so the real callback path is
// /api/instagram/callback — the redirect URI must match that (and match
// whatever's registered in the Meta app), not /auth/instagram/callback.
function defaultRedirectUri() {
  return process.env.IG_REDIRECT_URI || `${process.env.APP_URL}/api/instagram/callback`;
}

// The frontend is now a separate app/origin, so post-OAuth redirects must
// point there instead of back to this server's own root.
function frontendUrl() {
  return process.env.FRONTEND_URL || 'http://localhost:5173';
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'unauthorized' });
  next();
}

const IG_SCOPES = ['instagram_basic', 'pages_show_list'];

router.get('/instagram/login', requireAuth, (req, res) => {
  const clientId = process.env.IG_CLIENT_ID;
  const redirect = defaultRedirectUri();
  if (!clientId) return res.status(500).json({ error: 'ig_not_configured' });

  const state = crypto.randomBytes(16).toString('hex');
  req.session.igState = state;

  const url = new URL('https://www.instagram.com/oauth/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirect);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', IG_SCOPES.join(','));
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

router.get('/instagram/callback', requireAuth, async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`${frontendUrl()}/?ig_error=${encodeURIComponent(String(error))}`);
  if (!code || state !== req.session.igState) return res.status(400).send('Invalid OAuth state.');
  delete req.session.igState;

  try {
    const redirect = defaultRedirectUri();
    const tokenRes = await fetch('https://api.instagram.com/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.IG_CLIENT_ID,
        client_secret: process.env.IG_CLIENT_SECRET,
        grant_type: 'authorization_code',
        redirect_uri: redirect,
        code: String(code)
      })
    });
    const shortToken = await tokenRes.json();
    if (!shortToken.access_token) throw new Error('no_access_token');

    const longRes = await fetch(`https://graph.instagram.com/access_token?grant_type=ig_exchange_token&client_secret=${process.env.IG_CLIENT_SECRET}&access_token=${shortToken.access_token}`);
    const longToken = await longRes.json();
    const token = longToken.access_token || shortToken.access_token;

    const meRes = await fetch(`https://graph.instagram.com/me?fields=id,username&access_token=${token}`);
    const me = await meRes.json();

    req.session.ig = { token, userId: me.id, username: me.username };
    res.redirect(`${frontendUrl()}/?ig_connected=1`);
  } catch (err) {
    console.error('OAuth callback failed:', err);
    res.redirect(`${frontendUrl()}/?ig_error=exchange_failed`);
  }
});

router.post('/instagram/disconnect', requireAuth, (req, res) => {
  delete req.session.ig;
  res.json({ ok: true });
});

router.get('/instagram/status', requireAuth, (req, res) => {
  res.json({ connected: !!req.session.ig, account: req.session.ig?.username || null });
});

async function fetchAll(url, token) {
  const out = [];
  let next = url;
  while (next) {
    const res = await fetch(next, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    if (data.error) throw new Error(data.error.message);
    out.push(...(data.data || []));
    next = data.paging?.next || null;
  }
  return out;
}

router.get('/instagram/analysis', requireAuth, async (req, res) => {
  if (!req.session.ig?.token) return res.status(400).json({ error: 'not_connected' });
  const { token, userId } = req.session.ig;
  const userEmail = req.session.user.email;

  try {
    const [following, followers] = await Promise.all([
      fetchAll(`https://graph.instagram.com/${userId}/follows?fields=id,username&limit=100&access_token=${token}`, token),
      fetchAll(`https://graph.instagram.com/${userId}/followed_by?fields=id,username&limit=100&access_token=${token}`, token)
    ]);

    const followerSet = new Map(followers.map(u => [u.username.toLowerCase(), u]));
    const followingSet = new Map(following.map(u => [u.username.toLowerCase(), u]));

    const notBack = [...followingSet.values()].filter(u => !followerSet.has(u.username.toLowerCase()));
    const fans = [...followerSet.values()].filter(u => !followingSet.has(u.username.toLowerCase()));
    const mutual = [...followingSet.values()].filter(u => followerSet.has(u.username.toLowerCase()));

    // Diff against the previous snapshot BEFORE inserting the new one, so we
    // don't need an OFFSET-based query (and don't open extra DB connections).
    const prev = db.prepare(
      'SELECT followers_json, following_json, taken_at FROM snapshots WHERE user_email = ? AND ig_user_id = ? ORDER BY taken_at DESC LIMIT 1'
    ).get(userEmail, userId);

    // Persist snapshot for historical diffing, using the single shared connection.
    db.prepare(
      'INSERT INTO snapshots (user_email, ig_user_id, ig_username, taken_at, followers_json, following_json) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(
      userEmail, userId, req.session.ig.username, Date.now(),
      JSON.stringify(followers.map(u => u.username)),
      JSON.stringify(following.map(u => u.username))
    );

    let recentUnfollowed = [];
    if (prev) {
      const prevFollowers = new Set(JSON.parse(prev.followers_json).map(u => u.toLowerCase()));
      const currentFollowers = new Set(followers.map(u => u.username.toLowerCase()));
      recentUnfollowed = [...prevFollowers].filter(u => !currentFollowers.has(u));
    }

    res.json({
      username: req.session.ig.username,
      counts: {
        following: followingSet.size,
        followers: followerSet.size,
        notBack: notBack.length,
        fans: fans.length,
        mutual: mutual.length,
        recentUnfollowed: recentUnfollowed.length
      },
      notBack: notBack.map(u => u.username),
      fans: fans.map(u => u.username),
      mutual: mutual.map(u => u.username),
      followersList: followers.map(u => u.username),
      followingList: following.map(u => u.username),
      recentUnfollowed,
      lastSnapshotAt: Date.now()
    });
  } catch (err) {
    console.error('analysis failed:', err);
    res.status(500).json({ error: 'analysis_failed', detail: err.message });
  }
});

module.exports = router;