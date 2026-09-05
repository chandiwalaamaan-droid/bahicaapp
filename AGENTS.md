# Bahi — agent instructions

## Project layout
- `bahi-backend` (this folder) — single-file Express API (`server.js`), MySQL/TiDB, CommonJS-less ESM (`"type": "module"`).
- `bahi-frontend` — Vite + React 18 SPA. Runs on port 5173 and proxies `/api` to `localhost:3001`.

## Key commands

### Backend (`bahi-backend`)
```bash
npm install      # install deps
npm run dev      # start with --watch (needs TiDB env vars)
npm start        # plain node server.js
```
Requires env: `JWT_SECRET`, `TIDB_HOST`, `TIDB_USER`, `TIDB_PASSWORD`, `TIDB_DATABASE`, `TIDB_PORT` (optional), `GOOGLE_CLIENT_ID` (optional), `GOOGLE_API_KEY`/`GROQ_API_KEY`/`CLOUDFLARE_API_TOKEN` (optional, for AI), `RESEND_API_KEY`/`RESEND_FROM_EMAIL` (optional, for password-reset email).

### Frontend (`bahi-frontend`)
```bash
npm install      # install deps
npm run dev      # vite dev server on :5173
npm run build    # production build -> dist/
npm run preview  # preview production build
```
Proxy: Vite proxies `/api` → `http://localhost:3001`.

## Conventions
- The backend is a single `server.js` (1400+ lines). Keep new routes in the same file, organized in clearly-commented sections that match the existing style. Use `zod` for validation, `validate()` helper, `requireAuth` middleware.
- Express app uses `app.use("/api/<resource>", requireAuth)` then standalone route handlers.
- Frontend uses plain React + Vite, no framework/router/state lib. Tabs in `src/constants.js`. API calls via `src/utils.js` (`apiGet`/`apiPost`/`apiPut`/`apiPatch`/`apiDelete`).
- Styling: all CSS is in `src/styles.js` as a template string injected via `<style>{CSS}</style>`. Uses CSS custom properties (`--ink`, `--paper`, `--card`, `--primary`, etc.).
- Icons: hand-rolled SVG components in `src/Icons.jsx` (no icon library). Add new icons here and register in `NAV_ICONS`.
- Components in `src/components/`. Lazy-load heavy tabs (`Dashboard`, `Advisor`, `Invoices`) via `React.lazy` + `Suspense`.
- No ESLint/Prettier/TS. No test runner. Verify with `npm run build` (frontend) and `node server.js` syntax check (backend).
- Dark mode: toggle a `dark` class on `document.documentElement`; CSS variables must support both light and dark. Persist to `localStorage`.

## Tagline
App is positioned as "your personal CA." Tagline in `index.html` and sidebar: "ur personal CA". Keep legal disclaimers (Advisor component, FAQ, Terms, Guide) since they are required for compliance.
