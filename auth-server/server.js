// auth-server/server.js  (ESM)
import dotenv from 'dotenv';
dotenv.config();

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { logEntry } = require('../shared/logger.js');

import express   from 'express';
import cors      from 'cors';
import helmet    from 'helmet';
import morgan    from 'morgan';
import bcrypt    from 'bcryptjs';
import jwt       from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode    from 'qrcode';
import { v4 as uuid } from 'uuid';
import Database  from 'better-sqlite3';
import path      from 'path';
import { fileURLToPath } from 'url';

/* ---------- helper: map origin → app name --------------------------- */
function getAppName(origin) {
  switch (origin) {
    case 'http://localhost:3000': return 'App1';
    case 'http://localhost:3001': return 'App2';
    default:                      return origin;
  }
}

/* ---------- config --------------------------------------------------- */
const PORT       = process.env.PORT       || 4000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ISSUER     = process.env.ISSUER     || 'AI-SSO';
if (!JWT_SECRET) {
  console.error('❌  Missing JWT_SECRET in .env');
  process.exit(1);
}

/* ---------- __dirname for ESM ---------------------------------------- */
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/* ---------- sqlite DB + migration ----------------------------------- */
const db = new Database(path.join(__dirname, 'auth.db'), { timeout: 5000 });
db.pragma('journal_mode = WAL');

// Ensure base tables exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    username   TEXT UNIQUE,
    hash       TEXT,
    mfaSecret  TEXT
  );
  CREATE TABLE IF NOT EXISTS events (
    id  INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT,
    ts  INTEGER,
    ip  TEXT,
    ua  TEXT
  );
`);

// Auto‑migrate any new columns if missing
const cols = db.prepare("PRAGMA table_info(users)").all().map(r => r.name);
if (!cols.includes('email'))      db.exec("ALTER TABLE users ADD COLUMN email TEXT");
if (!cols.includes('department')) db.exec("ALTER TABLE users ADD COLUMN department TEXT");
if (!cols.includes('role'))       db.exec("ALTER TABLE users ADD COLUMN role TEXT");
if (!cols.includes('idNumber'))   db.exec("ALTER TABLE users ADD COLUMN idNumber TEXT");

/* ---------- prepared statements -------------------------------------- */
const findUser = db.prepare('SELECT * FROM users WHERE username = ?');
// insert all fields
const insertUserExtended = db.prepare(`
  INSERT INTO users
    (id, username, hash, email, department, role, idNumber)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const setMfa   = db.prepare('UPDATE users SET mfaSecret = ? WHERE id = ?');
const logEvent = db.prepare('INSERT INTO events (uid,ts,ip,ua) VALUES (?,?,?,?)');

/* ---------- helper: sign JWT + log ----------------------------------- */
function signAndLog(uid, req) {
  const token = jwt.sign({ sub: uid }, JWT_SECRET, {
    issuer: ISSUER,
    expiresIn: '15m'
  });

  // fetch username for logs
  const { username } = db
    .prepare('SELECT username FROM users WHERE id = ?')
    .get(uid);

  const { cnt: loginCount } = db
    .prepare('SELECT COUNT(*) AS cnt FROM events WHERE uid = ?')
    .get(uid);

  const origin = req.headers.origin;
  logEntry('SIGN', {
    uid,
    username,
    origin,
    app:         getAppName(origin),
    browser:     req.headers['user-agent'],
    loginCount,
    token
  });

  return token;
}

/* ---------- Express setup -------------------------------------------- */
const app = express();
app.use(cors({
  origin:        ['http://localhost:3000','http://localhost:3001'],
  credentials:   true,
  methods:       'GET,POST,PUT,DELETE,OPTIONS',
  allowedHeaders:'Content-Type,Authorization'
}));
app.use(express.json());
app.use(helmet());
app.use(morgan('dev'));

/* ---------- ROUTES --------------------------------------------------- */

// 1) Register: collects username, email, password, department, role, idNumber
app.post('/register', async (req, res) => {
  const origin = req.headers.origin;
  const { username, email, password, department, role, idNumber } = req.body;

  if (findUser.get(username.trim())) {
    logEntry('REGISTER_FAIL', {
      username,
      origin,
      app:      getAppName(origin),
      browser:  req.headers['user-agent']
    });
    return res.status(409).json({ msg: 'exists' });
  }

  const id = uuid();
  await insertUserExtended.run(
    id,
    username.trim(),
    await bcrypt.hash(password, 10),
    email.trim().toLowerCase(),
    department,
    role,
    idNumber
  );

  logEntry('REGISTER', {
    uid:        id,
    username,
    email:      email.trim().toLowerCase(),
    department,
    role,
    idNumber,
    origin,
    app:        getAppName(origin),
    browser:    req.headers['user-agent']
  });

  res.json({ msg: 'registered' });
});

// 2a) Login step 1: accept identifier (username OR email) + password
app.post('/login', async (req, res) => {
  const origin = req.headers.origin;
  const rawId   = req.body.identifier ?? req.body.username;
  const password= req.body.password;

  if (!rawId || !password) {
    logEntry('LOGIN_FAIL', {
      identifier: rawId,
      origin,
      app:        getAppName(origin),
      browser:    req.headers['user-agent']
    });
    return res.status(400).json({ msg: 'missing fields' });
  }

  const idClean = rawId.trim();

  // Lookup by username OR email, case‑INSENSITIVE
  const u = db.prepare(`
    SELECT * FROM users
     WHERE username = ? COLLATE NOCASE
        OR email    = ? COLLATE NOCASE
  `).get(idClean, idClean);

  if (!u || !(await bcrypt.compare(password, u.hash))) {
    logEntry('LOGIN_FAIL', {
      identifier: rawId,
      origin,
      app:        getAppName(origin),
      browser:    req.headers['user-agent']
    });
    return res.status(401).json({ msg: 'bad creds' });
  }

  // If no MFA yet, bootstrap
  if (!u.mfaSecret) {
    const secret = speakeasy.generateSecret({ issuer: ISSUER, name: u.username });
    setMfa.run(secret.base32, u.id);
    logEntry('MFA_SETUP', {
      uid:       u.id,
      username:  u.username,
      origin,
      app:       getAppName(origin),
      browser:   req.headers['user-agent']
    });
    const qrData = await qrcode.toDataURL(secret.otpauth_url);
    return res.json({ mfaRequired: true, qrData });
  }

  // Otherwise move to TOTP
  res.json({ mfaRequired: true });
});

// 2b) Login step 2: verify TOTP (unchanged identifier handling)
app.post('/verify-mfa', (req, res) => {
  const origin  = req.headers.origin;
  const rawId    = req.body.identifier ?? req.body.username;
  const rawToken = req.body.token;

  if (!rawId || !rawToken) {
    logEntry('TOTP_FAIL', {
      identifier: rawId,
      origin,
      app:    getAppName(origin),
      browser:req.headers['user-agent']
    });
    return res.status(400).json({ msg: 'missing fields' });
  }

  const identifier = rawId.trim();
  const token      = rawToken.trim();

  const u = db.prepare(`
    SELECT * FROM users
     WHERE username = ? COLLATE NOCASE
        OR email    = ? COLLATE NOCASE
  `).get(identifier, identifier);

  if (!u) {
    logEntry('TOTP_FAIL', {
      identifier,
      origin,
      app:    getAppName(origin),
      browser:req.headers['user-agent']
    });
    return res.status(401).json({ msg: 'bad credentials' });
  }

  const ok = speakeasy.totp.verify({
    secret:   u.mfaSecret,
    encoding: 'base32',
    token,
    window:   1
  });
  if (!ok) {
    logEntry('TOTP_FAIL', {
      uid:       u.id,
      username:  u.username,
      origin,
      app:       getAppName(origin),
      browser:   req.headers['user-agent']
    });
    return res.status(401).json({ msg: 'bad TOTP' });
  }

  logEvent.run(u.id, Date.now(), req.ip, req.headers['user-agent']);
  const jwtToken = signAndLog(u.id, req);
  res.json({ token: jwtToken });
});

// 3) Refresh
app.post('/refresh', (req, res) => {
  const origin = req.headers.origin;
  try {
    const { sub } = jwt.verify(req.body.token, JWT_SECRET, { ignoreExpiration:true });
    const newToken = jwt.sign({ sub }, JWT_SECRET, { issuer:ISSUER, expiresIn:'15m' });
    const loginCount = db.prepare('SELECT COUNT(*) AS cnt FROM events WHERE uid = ?').get(sub).cnt;

    logEntry('REFRESH', {
      uid:       sub,
      username:  db.prepare('SELECT username FROM users WHERE id = ?').get(sub).username,
      origin,
      app:       getAppName(origin),
      browser:   req.headers['user-agent'],
      loginCount,
      token:     newToken
    });

    res.json({ token: newToken });
  } catch {
    res.status(400).end();
  }
});

// 4) Protected
app.get('/me', (req, res) => {
  try {
    const tok = req.headers.authorization?.split(' ')[1];
    const { sub } = jwt.verify(tok, JWT_SECRET);
    const u = db.prepare('SELECT username,department,role,idNumber,email FROM users WHERE id = ?').get(sub);
    res.json(u);
  } catch {
    res.status(401).end();
  }
});

// 5) Logout
app.post('/logout', (req, res) => {
  const origin = req.headers.origin;
  const auth   = req.headers.authorization?.split(' ')[1];
  if (auth) {
    try {
      const { sub } = jwt.verify(auth, JWT_SECRET);
      const { username } = db.prepare('SELECT username FROM users WHERE id = ?').get(sub);
      logEntry('LOGOUT', {
        uid:      sub,
        username,
        origin,
        app:      getAppName(origin),
        browser:  req.headers['user-agent']
      });
    } catch {
      /* ignore invalid token */
    }
  }
  res.json({ msg: 'logged out' });
});

/* ---------- debug & ping --------------------------------------------- */
app.get('/debug/users', (_,res)=>res.json(
  db.prepare('SELECT * FROM users').all()
));
app.get('/debug/events',(_,res)=>res.json(
  db.prepare(`
    SELECT e.id,u.username,
           datetime(e.ts/1000,'unixepoch','localtime') AS time,
           e.ip
    FROM events e JOIN users u ON u.id=e.uid
    ORDER BY e.id DESC
  `).all()
));
app.get('/debug/totp/:user',(req,res)=>{
  const u = findUser.get(req.params.user.trim());
  if(!u) return res.status(404).send('no such user');
  res.send(speakeasy.totp({secret:u.mfaSecret,encoding:'base32'}));
});
app.get('/ping',(_,res)=>res.send('pong'));

/* ---------- start ----------------------------------------------------- */
app.listen(PORT,()=>console.log(`✅  Auth‑server listening on http://localhost:${PORT}`));
