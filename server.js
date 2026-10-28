'use strict';
// Timetrack with accounts: Express + PostgreSQL (no native add-ons, no local files).
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const express = require('express');
const pg = require('pg');
const scrypt = promisify(crypto.scrypt);

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';                 // set HOST=0.0.0.0 on a host that needs it
const SECURE = process.env.INSECURE_COOKIES !== '1';          // INSECURE_COOKIES=1 only for plain-http testing
const OPEN_SIGNUP = process.env.REGISTRATION !== 'closed';
const MAX_USERS = Number(process.env.MAX_USERS || 10000);
const MAX_SESSIONS = 100000, MAX_BATCH = 500, DAY = 86400000, LOGIN_DAYS = 30, COOKIE = 'tt_sid', WIN = 15 * 60000;

/* ---------- database ---------- */
pg.types.setTypeParser(20, (v) => Number(v));                 // BIGINT comes back as a number, not a string
function dbConfig() {
  const e = process.env;
  if (e.DATABASE_URL) return { connectionString: e.DATABASE_URL, ssl: e.PGSSL === '1' ? { rejectUnauthorized: false } : undefined };
  const host = e.DB_HOST || e.PGHOST;
  if (!host) return {};                                       // fall back to the standard PG* variables
  return { host, port: Number(e.DB_PORT || e.PGPORT || 5432), database: e.DB_NAME || e.PGDATABASE,
    user: e.DB_USERNAME || e.PGUSER, password: e.DB_PASSWORD || e.PGPASSWORD, ssl: e.PGSSL === '1' ? { rejectUnauthorized: false } : undefined };
}
const pool = new pg.Pool({ ...dbConfig(), max: Number(process.env.DB_POOL || 5) });
const Q = (text, params) => pool.query(text, params);

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL, username_lc TEXT NOT NULL UNIQUE,
     pw TEXT NOT NULL, ver BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS logins (
     token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS logins_user ON logins (user_id)`,
  `CREATE TABLE IF NOT EXISTS recovery (
     user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, code_hash TEXT NOT NULL,
     used BOOLEAN NOT NULL DEFAULT FALSE, PRIMARY KEY (user_id, code_hash))`,
  `CREATE TABLE IF NOT EXISTS sessions (
     user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     id TEXT NOT NULL, semester TEXT NOT NULL, subject TEXT NOT NULL,
     start_ms BIGINT NOT NULL, end_ms BIGINT NOT NULL, duration_s BIGINT NOT NULL CHECK (duration_s >= 0),
     created_at BIGINT NOT NULL, deleted BOOLEAN NOT NULL DEFAULT FALSE, ver BIGINT NOT NULL,
     PRIMARY KEY (user_id, id))`,
  `CREATE INDEX IF NOT EXISTS sessions_ver ON sessions (user_id, ver)`,
  `CREATE TABLE IF NOT EXISTS meta (
     user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
     subjects JSONB NOT NULL, active JSONB, ver BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS limits (k TEXT PRIMARY KEY, n INTEGER NOT NULL, t0 BIGINT NOT NULL)`,
];
async function initDb() { for (const s of SCHEMA) await Q(s); }

const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');

/* ---------- passwords, codes, logins ---------- */
const SC = { N: 32768, r: 8, p: 1, len: 64 };
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw.normalize('NFKC'), salt, SC.len, { N: SC.N, r: SC.r, p: SC.p, maxmem: 64 * 1024 * 1024 });
  return ['s1', SC.N, SC.r, SC.p, salt.toString('base64'), h.toString('base64')].join('$');
}
async function checkPw(pw, stored) {
  const [v, n, r, p, s, h] = stored.split('$');
  if (v !== 's1') return false;
  const want = Buffer.from(h, 'base64');
  const got = await scrypt(pw.normalize('NFKC'), Buffer.from(s, 'base64'), want.length, { N: +n, r: +r, p: +p, maxmem: 64 * 1024 * 1024 });
  return crypto.timingSafeEqual(got, want);
}
let dummy = null;                                              // so unknown usernames cost the same time as real ones
const dummyHash = () => dummy || (dummy = hashPw('not-a-real-password'));

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const newCode = () => crypto.randomBytes(16).reduce((s, b) => s + ALPHABET[b % 32], '').match(/.{4}/g).join('-');
const codeHash = (c) => sha('rc:' + String(c || '').toUpperCase().replace(/[^A-Z2-9]/g, ''));
async function makeCodes(uid) {
  const codes = Array.from({ length: 8 }, newCode);
  await Q(`WITH d AS (DELETE FROM recovery WHERE user_id = $1::bigint)
           INSERT INTO recovery (user_id, code_hash) SELECT $1::bigint, jsonb_array_elements_text($2::jsonb)`,
    [uid, JSON.stringify(codes.map(codeHash))]);
  return codes;
}

const parseCookies = (h) => Object.fromEntries((h || '').split(';').map((c) => c.trim().split('=')).filter((a) => a[0]).map(([k, ...v]) => [k, v.join('=')]));
const setCookie = (res, val, maxAge) => res.set('Set-Cookie',
  `${COOKIE}=${val}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${SECURE ? '; Secure' : ''}`);
async function startLogin(res, uid) {
  const tok = crypto.randomBytes(32).toString('base64url'), now = Date.now();
  await Q('INSERT INTO logins (token_hash, user_id, expires_at, created_at) VALUES ($1::text, $2::bigint, $3::bigint, $4::bigint)',
    [sha(tok), uid, now + LOGIN_DAYS * DAY, now]);
  setCookie(res, tok, LOGIN_DAYS * 86400);
}

/* ---------- attempt limits, kept in the database so they hold across instances and restarts ---------- */
async function full(key, max, win) {
  const { rows } = await Q('SELECT n, t0 FROM limits WHERE k = $1::text', [key]);
  return rows.length > 0 && Date.now() - rows[0].t0 < win && rows[0].n >= max;
}
async function strike(key, win) {
  const now = Date.now();
  await Q(`INSERT INTO limits (k, n, t0) VALUES ($1::text, 1, $2::bigint)
           ON CONFLICT (k) DO UPDATE SET
             n = CASE WHEN $2::bigint - limits.t0 >= $3::bigint THEN 1 ELSE limits.n + 1 END,
             t0 = CASE WHEN $2::bigint - limits.t0 >= $3::bigint THEN $2::bigint ELSE limits.t0 END`, [key, now, win]);
}
const clearKey = (key) => Q('DELETE FROM limits WHERE k = $1::text', [key]);
async function cleanup() {
  const now = Date.now();
  await Q('DELETE FROM logins WHERE expires_at < $1::bigint', [now]);
  await Q('DELETE FROM limits WHERE t0 < $1::bigint', [now - 3600000]);
}

/* ---------- validation ---------- */
const COMMON = new Set(['password', 'password1', '1234567890', '12345678910', 'qwertyuiop', 'iloveyou12', '0123456789', 'letmein123', 'timetrack1']);
function pwProblem(pw, username) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Password must be at least 10 characters.';
  if (pw.length > 128) return 'Password must be at most 128 characters.';
  if (COMMON.has(pw.toLowerCase()) || /^(.)\1+$/.test(pw) || pw.toLowerCase() === String(username || '').toLowerCase()) return 'Choose a less guessable password.';
  return null;
}
const ID = /^[\w.~:@+-]{1,40}$/, RESERVED = new Set(['__proto__', 'constructor', 'prototype']);
const okSem = (v) => typeof v === 'string' && /^\w{1,12}$/.test(v) && !RESERVED.has(v);
const okName = (v) => typeof v === 'string' && v.trim().length > 0 && v.length <= 40;
const num = Number.isFinite;
function checkSession(s) {
  if (!s || typeof s !== 'object' || typeof s.id !== 'string' || !ID.test(s.id)) return 'bad session id';
  if (s.deleted === true) return null;
  if (!okSem(s.semester) || !okName(s.subject)) return 'bad semester or subject';
  if (!num(s.start) || !num(s.end) || s.end < s.start) return 'bad start or end';
  return null;
}
function checkMeta(m) {
  if (!m || typeof m !== 'object' || !m.subjects || typeof m.subjects !== 'object') return 'bad meta';
  const keys = Object.keys(m.subjects);
  if (keys.length > 100) return 'too many semesters';
  for (const k of keys) {
    const l = m.subjects[k];
    if (!okSem(k) || !Array.isArray(l) || l.length > 200 || !l.every(okName)) return 'bad subjects';
  }
  const a = m.active;
  if (a != null && !(okSem(a.semester) && okName(a.subject) && num(a.start))) return 'bad active session';
  return null;
}

/* ---------- http ---------- */
const app = express();
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
  "font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const PUBLIC = new Set(['/api/health', '/api/register', '/api/login', '/api/recover']);
const NO = (res, code, error) => res.status(code).json({ error });
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

app.use((req, res, next) => {
  res.set('Content-Security-Policy', CSP);
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  if (SECURE) res.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(async (req, res, next) => {
  const p = req.path;
  if (!p.startsWith('/api/')) return next();
  res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'HEAD') {          // CSRF: custom header + same-origin check
    if (req.headers['x-tt'] !== '1') return NO(res, 403, 'Forbidden');
    const o = req.headers.origin;
    if (o) { let h = null; try { h = new URL(o).host; } catch { /* bad origin */ } if (h !== req.headers.host) return NO(res, 403, 'Forbidden'); }
  }
  if (PUBLIC.has(p)) return next();
  const tok = parseCookies(req.headers.cookie)[COOKIE];
  const { rows } = tok ? await Q('SELECT l.user_id AS id, l.expires_at AS exp, u.username AS username FROM logins l JOIN users u ON u.id = l.user_id WHERE l.token_hash = $1::text', [sha(tok)]) : { rows: [] };
  const row = rows[0];
  if (!row || row.exp < Date.now()) return NO(res, 401, 'Not signed in');
  req.user = { id: row.id, username: row.username };
  req.tokHash = sha(tok);
  if (row.exp - Date.now() < (LOGIN_DAYS - 1) * DAY) {          // sliding expiry
    await Q('UPDATE logins SET expires_at = $1::bigint WHERE token_hash = $2::text', [Date.now() + LOGIN_DAYS * DAY, req.tokHash]);
    setCookie(res, tok, LOGIN_DAYS * 86400);
  }
  next();
});

const userByName = async (lc) => (await Q('SELECT id, username, pw FROM users WHERE username_lc = $1::text', [lc])).rows[0];

app.get('/api/health', wrap(async (req, res) => { await Q('SELECT 1'); res.json({ ok: true }); }));

app.post('/api/register', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!OPEN_SIGNUP) return NO(res, 403, 'Sign-up is closed.');
  if (await full('reg:' + req.ip, 5, 3600000)) return NO(res, 429, 'Too many attempts. Try again later.');
  await strike('reg:' + req.ip, 3600000);
  if (typeof username !== 'string' || !/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return NO(res, 400, 'Username must be 3 to 32 characters: letters, numbers, dot, dash or underscore.');
  const bad = pwProblem(password, username);
  if (bad) return NO(res, 400, bad);
  if ((await Q('SELECT COUNT(*)::int AS c FROM users')).rows[0].c >= MAX_USERS) return NO(res, 503, 'Sign-ups are full right now.');
  const pw = await hashPw(password);
  let uid;
  try {
    uid = (await Q('INSERT INTO users (username, username_lc, pw, created_at) VALUES ($1::text, $2::text, $3::text, $4::bigint) RETURNING id',
      [username, username.toLowerCase(), pw, Date.now()])).rows[0].id;
  } catch (e) { if (e && e.code === '23505') return NO(res, 409, 'That username is taken.'); throw e; }
  const recoveryCodes = await makeCodes(uid);
  await startLogin(res, uid);
  if (Math.random() < 0.02) cleanup().catch(() => {});
  res.json({ username, recoveryCodes });
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 128) return NO(res, 400, 'Enter your username and password.');
  const lc = username.toLowerCase(), kIp = 'ip:' + req.ip, kU = 'u:' + lc;
  if ((await full(kIp, 20, WIN)) || (await full(kU, 8, WIN))) return NO(res, 429, 'Too many attempts. Try again in 15 minutes.');
  const row = await userByName(lc);
  const ok = await checkPw(password, row ? row.pw : await dummyHash());
  if (!row || !ok) { await strike(kIp, WIN); await strike(kU, WIN); return NO(res, 401, 'Wrong username or password.'); }
  await clearKey(kU);
  await startLogin(res, row.id);
  if (Math.random() < 0.02) cleanup().catch(() => {});
  res.json({ username: row.username });
}));

app.post('/api/logout', wrap(async (req, res) => {
  await Q('DELETE FROM logins WHERE token_hash = $1::text', [req.tokHash]);
  setCookie(res, '', 0);
  res.json({ ok: true });
}));

app.get('/api/me', wrap(async (req, res) => { res.json({ username: req.user.username }); }));

app.post('/api/password', wrap(async (req, res) => {
  const { current, next } = req.body || {};
  const k = 'pw:' + req.user.id;
  if (await full(k, 8, WIN)) return NO(res, 429, 'Too many attempts. Try again later.');
  const row = await userByName(req.user.username.toLowerCase());
  if (typeof current !== 'string' || !(await checkPw(current, row.pw))) { await strike(k, WIN); return NO(res, 401, 'Your current password is wrong.'); }
  const bad = pwProblem(next, req.user.username);
  if (bad) return NO(res, 400, bad);
  await Q('UPDATE users SET pw = $1::text WHERE id = $2::bigint', [await hashPw(next), req.user.id]);
  await Q('DELETE FROM logins WHERE user_id = $1::bigint AND token_hash <> $2::text', [req.user.id, req.tokHash]);
  res.json({ ok: true });
}));

app.post('/api/recovery-codes', wrap(async (req, res) => {
  const { password } = req.body || {};
  const k = 'pw:' + req.user.id;
  if (await full(k, 8, WIN)) return NO(res, 429, 'Too many attempts. Try again later.');
  const row = await userByName(req.user.username.toLowerCase());
  if (typeof password !== 'string' || !(await checkPw(password, row.pw))) { await strike(k, WIN); return NO(res, 401, 'Your password is wrong.'); }
  res.json({ recoveryCodes: await makeCodes(req.user.id) });
}));

app.post('/api/recover', wrap(async (req, res) => {
  const { username, code, newPassword } = req.body || {};
  if (typeof username !== 'string' || typeof code !== 'string') return NO(res, 400, 'Enter your username, a recovery code and a new password.');
  const lc = username.toLowerCase(), kIp = 'ip:' + req.ip, kU = 'rec:' + lc;
  if ((await full(kIp, 20, WIN)) || (await full(kU, 8, WIN))) return NO(res, 429, 'Too many attempts. Try again in 15 minutes.');
  const bad = pwProblem(newPassword, username);
  if (bad) return NO(res, 400, bad);
  const row = await userByName(lc);
  const used = row ? await Q('UPDATE recovery SET used = TRUE WHERE user_id = $1::bigint AND code_hash = $2::text AND used = FALSE RETURNING 1 AS ok', [row.id, codeHash(code)]) : null;
  if (!row || used.rowCount !== 1) { await strike(kIp, WIN); await strike(kU, WIN); return NO(res, 401, 'That username and code do not match.'); }
  await Q('UPDATE users SET pw = $1::text WHERE id = $2::bigint', [await hashPw(newPassword), row.id]);
  await Q('DELETE FROM logins WHERE user_id = $1::bigint', [row.id]);
  await startLogin(res, row.id);
  const left = (await Q('SELECT COUNT(*)::int AS c FROM recovery WHERE user_id = $1::bigint AND used = FALSE', [row.id])).rows[0].c;
  res.json({ username: row.username, remaining: left });
}));

app.post('/api/account/delete', wrap(async (req, res) => {
  const { password } = req.body || {};
  const k = 'pw:' + req.user.id;
  if (await full(k, 8, WIN)) return NO(res, 429, 'Too many attempts. Try again later.');
  const row = await userByName(req.user.username.toLowerCase());
  if (typeof password !== 'string' || !(await checkPw(password, row.pw))) { await strike(k, WIN); return NO(res, 401, 'Your password is wrong.'); }
  await Q('DELETE FROM users WHERE id = $1::bigint', [req.user.id]);   // cascades to logins, codes, sessions, meta
  setCookie(res, '', 0);
  res.json({ ok: true });
}));

// Everything that changed after the client's cursor, including deletions.
app.get('/api/changes', wrap(async (req, res) => {
  const uid = req.user.id, since = Math.max(0, parseInt(req.query.since, 10) || 0);
  const [ver, ss, meta] = await Promise.all([
    Q('SELECT ver FROM users WHERE id = $1::bigint', [uid]),
    Q('SELECT id AS sid, deleted, semester, subject, start_ms, end_ms, duration_s, created_at FROM sessions WHERE user_id = $1::bigint AND ver > $2::bigint ORDER BY ver, id', [uid, since]),
    Q('SELECT subjects, active, ver FROM meta WHERE user_id = $1::bigint', [uid]),
  ]);
  const m = meta.rows[0];
  res.json({
    cursor: ver.rows[0].ver,
    sessions: ss.rows.map((r) => r.deleted
      ? { id: r.sid, deleted: true }
      : { id: r.sid, semester: r.semester, subject: r.subject, start: r.start_ms, end: r.end_ms, duration: r.duration_s, createdAt: r.created_at }),
    meta: m && m.ver > since ? { subjects: m.subjects, active: m.active } : null,
  });
}));

// One statement, so it is atomic: bump the user's counter, upsert sessions (or deletion markers), save the topic list.
async function writeAll(uid, sessions, meta) {
  const byId = new Map();                                       // a batch may repeat an id: the last one wins
  for (const s of sessions) {
    byId.set(s.id, s.deleted === true
      ? { id: s.id, sem: '_', sub: '_', st: 0, en: 0, du: 0, cr: 0, de: true }
      : { id: s.id, sem: s.semester, sub: s.subject.trim().replace(/\s+/g, ' '), st: Math.round(s.start), en: Math.round(s.end),
          du: Math.round((s.end - s.start) / 1000), cr: num(s.createdAt) ? Math.round(s.createdAt) : Math.round(s.end), de: false });
  }
  const params = [uid, JSON.stringify([...byId.values()])];
  let metaCte = '';
  if (meta) {
    const a = meta.active;
    params.push(JSON.stringify(meta.subjects), a ? JSON.stringify({ semester: a.semester, subject: a.subject, start: a.start }) : '');
    metaCte = `, m AS (INSERT INTO meta (user_id, subjects, active, ver)
        SELECT $1::bigint, $3::jsonb, NULLIF($4::text, '')::jsonb, v.ver FROM v
        ON CONFLICT (user_id) DO UPDATE SET subjects = EXCLUDED.subjects, active = EXCLUDED.active, ver = EXCLUDED.ver)`;
  }
  const r = await Q(`WITH v AS (UPDATE users SET ver = ver + 1 WHERE id = $1::bigint RETURNING ver),
    ins AS (INSERT INTO sessions AS s (user_id, id, semester, subject, start_ms, end_ms, duration_s, created_at, deleted, ver)
      SELECT $1::bigint, x.id, x.sem, x.sub, x.st, x.en, x.du, x.cr, x.de, v.ver
      FROM jsonb_to_recordset($2::jsonb) AS x(id text, sem text, sub text, st bigint, en bigint, du bigint, cr bigint, de boolean), v
      ON CONFLICT (user_id, id) DO UPDATE SET
        deleted = EXCLUDED.deleted, ver = EXCLUDED.ver,
        semester = CASE WHEN EXCLUDED.deleted THEN s.semester ELSE EXCLUDED.semester END,
        subject = CASE WHEN EXCLUDED.deleted THEN s.subject ELSE EXCLUDED.subject END,
        start_ms = CASE WHEN EXCLUDED.deleted THEN s.start_ms ELSE EXCLUDED.start_ms END,
        end_ms = CASE WHEN EXCLUDED.deleted THEN s.end_ms ELSE EXCLUDED.end_ms END,
        duration_s = CASE WHEN EXCLUDED.deleted THEN s.duration_s ELSE EXCLUDED.duration_s END,
        created_at = CASE WHEN EXCLUDED.deleted THEN s.created_at ELSE EXCLUDED.created_at END)${metaCte}
    SELECT ver FROM v`, params);
  return r.rows[0].ver;
}

app.put('/api/sync', wrap(async (req, res) => {
  const b = req.body || {}, sessions = Array.isArray(b.sessions) ? b.sessions : [];
  if (sessions.length > MAX_BATCH) return NO(res, 400, 'batch too large');
  for (const s of sessions) { const e = checkSession(s); if (e) return NO(res, 400, e); }
  if (b.meta) { const e = checkMeta(b.meta); if (e) return NO(res, 400, e); }
  const c = (await Q('SELECT COUNT(*)::int AS c FROM sessions WHERE user_id = $1::bigint', [req.user.id])).rows[0].c;
  if (c + sessions.length > MAX_SESSIONS) return NO(res, 413, 'storage limit reached');
  res.json({ cursor: await writeAll(req.user.id, sessions, b.meta || null) });
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {                              // JSON errors, never a stack trace
  const st = err && (err.status || err.statusCode);
  if (st && st < 500) return res.status(st).json({ error: 'Bad request' });
  console.error('handler error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

/* ---------- start, or run an admin command ---------- */
(async () => {
  try { await dummyHash(); } catch (e) {
    console.error('This host cannot run password hashing (crypto.scrypt): ' + e.message + '\nTimetrack cannot start safely here.');
    process.exit(1);
  }
  await initDb();
  if (process.argv[2] === 'set-password') {
    const u = await userByName(String(process.argv[3] || '').toLowerCase());
    if (!u) { console.error('No such user.'); process.exit(1); }
    const tmp = crypto.randomBytes(12).toString('base64url');
    await Q('UPDATE users SET pw = $1::text WHERE id = $2::bigint', [await hashPw(tmp), u.id]);
    await Q('DELETE FROM logins WHERE user_id = $1::bigint', [u.id]);
    console.log(`Temporary password for ${u.username}: ${tmp}\nTell them to change it after signing in.`);
    process.exit(0);
  }
  await cleanup();
  setInterval(() => cleanup().catch(() => {}), 600000).unref();
  const srv = app.listen(PORT, HOST, () => console.log(`Timetrack listening on ${HOST}:${PORT}`));
  const stop = () => { srv.close(() => pool.end().finally(() => process.exit(0))); setTimeout(() => process.exit(0), 3000).unref(); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
})().catch((e) => { console.error('startup failed:', e.message); process.exit(1); });
