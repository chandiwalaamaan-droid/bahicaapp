# Tally — split into frontend / backend

Two independent pieces now:

```
tally-stack/
├── backend/     ← Express API + SQLite + OTP + Instagram OAuth (Node server)
└── frontend/    ← Static index.html (no build step, plain JS)
```

## Why they're separate

The backend is a long-running Node process (SQLite file + sessions), so it
needs a host built for that — Render, Railway, Fly.io, a VPS. The frontend
is a single static HTML file, so it can go anywhere static, including
Netlify.

## 1. Deploy the backend (e.g. Render)

```
cd backend
npm install        # test locally first
cp .env.example .env
```

Fill in `.env` — same as before, plus one new variable:
- `FRONTEND_URL` — the URL your frontend will be hosted at (e.g.
  `https://tally.netlify.app`). No trailing slash. This is used for CORS
  and for redirecting back to your app after Instagram login.

Deploy `backend/` to Render as a Web Service:
- Build command: `npm install`
- Start command: `npm start`
- Add all the `.env` variables in Render's dashboard, with `APP_URL` and
  `IG_REDIRECT_URI` pointing at the **Render** URL, not localhost.
- Set `NODE_ENV=production` (this switches cookies to `sameSite=none;
  secure` so they work cross-site over HTTPS).

Update your Meta app's OAuth redirect URI to
`https://your-backend.onrender.com/api/instagram/callback`.

## 2. Deploy the frontend (e.g. Netlify)

Open `frontend/index.html` and edit the one line near the top:

```html
window.TALLY_API_BASE = 'https://your-backend.onrender.com';
```

Then drag-and-drop the `frontend/` folder onto Netlify (or connect it as a
site with publish directory `frontend`, no build command needed since
there's no build step).

## Local development

Terminal 1:
```
cd backend
npm install
npm start        # http://localhost:3000
```

Terminal 2 — just open `frontend/index.html` directly in a browser, or
serve it with any static server, e.g.:
```
cd frontend
npx serve -l 5173
```

`window.TALLY_API_BASE` defaults to `http://localhost:3000`, so no edits
needed for local dev as long as the backend runs on that port.
