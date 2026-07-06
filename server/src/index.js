'use strict';
/*
 * BC-ASSISTANT API — SUMMIT Business Center leasing CRM backend.
 * - Single shared workspace (one JSONB row), last-write-wins.
 * - One shared login (AUTH_USER + bcrypt AUTH_PASSWORD_HASH) -> JWT (Bearer).
 * - File attachments stored on local disk (FILES_DIR), metadata in Postgres.
 * All /api/* except /api/health and /api/login require a valid token.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const PORT = parseInt(process.env.PORT || '8100', 10);
const HOST = process.env.HOST || '127.0.0.1';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const JWT_SECRET = process.env.JWT_SECRET;
const AUTH_USER = process.env.AUTH_USER || 'summit';
const AUTH_PASSWORD_HASH = process.env.AUTH_PASSWORD_HASH;
const FILES_DIR = process.env.FILES_DIR || path.join(__dirname, '..', 'files');
const TOKEN_TTL = process.env.TOKEN_TTL || '12h';
const MAX_FILE_MB = parseInt(process.env.MAX_FILE_MB || '25', 10);

if (!JWT_SECRET || !AUTH_PASSWORD_HASH) {
  console.error('FATAL: JWT_SECRET and AUTH_PASSWORD_HASH must be set in .env');
  process.exit(1);
}
fs.mkdirSync(FILES_DIR, { recursive: true });

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.set('trust proxy', 1); // behind Tailscale Funnel
app.use(cors({
  origin: CORS_ORIGINS.length ? CORS_ORIGINS : false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}));
app.use(express.json({ limit: '25mb' }));

// ---- health (no auth) ----
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'bc-assistant' }));

// ---- login (no auth, rate-limited) ----
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { user, password } = req.body || {};
    const okUser = typeof user === 'string' && user === AUTH_USER;
    const okPass = typeof password === 'string' && await bcrypt.compare(password, AUTH_PASSWORD_HASH);
    if (!okUser || !okPass) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const token = jwt.sign({ sub: AUTH_USER }, JWT_SECRET, { expiresIn: TOKEN_TTL });
    res.json({ token });
  } catch (e) { console.error('login', e); res.status(500).json({ error: 'server error' }); }
});

// ---- auth middleware ----
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'no token' });
  try { req.user = jwt.verify(m[1], JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'invalid token' }); }
}

// ---- shared workspace state ----
app.get('/api/state', auth, async (_req, res) => {
  try {
    const r = await pool.query('SELECT state, updated_at FROM workspace WHERE id = 1');
    const row = r.rows[0];
    const state = row && row.state && Object.keys(row.state).length ? row.state : null;
    res.json({ state, updated_at: row ? row.updated_at : null });
  } catch (e) { console.error('get state', e); res.status(500).json({ error: 'server error' }); }
});

app.put('/api/state', auth, async (req, res) => {
  try {
    const state = req.body && req.body.state;
    if (!state || typeof state !== 'object') return res.status(400).json({ error: 'state required' });
    const r = await pool.query(
      `INSERT INTO workspace (id, state, updated_at) VALUES (1, $1, now())
       ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()
       RETURNING updated_at`,
      [state]
    );
    res.json({ ok: true, updated_at: r.rows[0].updated_at });
  } catch (e) { console.error('put state', e); res.status(500).json({ error: 'server error' }); }
});

// ---- files (local disk) ----
const upload = multer({ dest: FILES_DIR, limits: { fileSize: MAX_FILE_MB * 1024 * 1024 } });

app.post('/api/files', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'file required' });
    const id = 'f_' + crypto.randomBytes(12).toString('hex');
    const name = Buffer.from(req.file.originalname, 'latin1').toString('utf8'); // multer gives latin1
    await pool.query(
      'INSERT INTO files (id, name, type, size, path) VALUES ($1,$2,$3,$4,$5)',
      [id, name, req.file.mimetype || '', req.file.size, req.file.filename]
    );
    res.json({ id, name, type: req.file.mimetype || '', size: req.file.size });
  } catch (e) { console.error('upload', e); res.status(500).json({ error: 'server error' }); }
});

app.get('/api/files/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT name, type, path FROM files WHERE id = $1', [req.params.id]);
    const f = r.rows[0];
    if (!f) return res.status(404).json({ error: 'not found' });
    const abs = path.join(FILES_DIR, path.basename(f.path));
    if (!fs.existsSync(abs)) return res.status(404).json({ error: 'file missing' });
    if (f.type) res.type(f.type);
    res.setHeader('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(f.name));
    fs.createReadStream(abs).pipe(res);
  } catch (e) { console.error('get file', e); res.status(500).json({ error: 'server error' }); }
});

app.delete('/api/files/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM files WHERE id = $1 RETURNING path', [req.params.id]);
    const f = r.rows[0];
    if (f) { try { fs.unlinkSync(path.join(FILES_DIR, path.basename(f.path))); } catch {} }
    res.json({ ok: true });
  } catch (e) { console.error('del file', e); res.status(500).json({ error: 'server error' }); }
});

app.listen(PORT, HOST, () => console.log(`bc-assistant API on http://${HOST}:${PORT}`));
