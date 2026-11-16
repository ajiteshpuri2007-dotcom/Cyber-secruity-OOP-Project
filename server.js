// server.js - cleaned and consolidated
const express = require('express');
const path = require('path');
const { spawn } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // load .env if present

const app = express();
const PORT = process.env.PORT || 3000;

// Secret for JWT – use env variable, fallback to placeholder (replace before production)
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_strong_secret';
// Admin registration key – env variable fallback
const ADMIN_REG_KEY = process.env.ADMIN_REG_KEY || 'PRIVY_ADMIN_SECRET';

app.use(express.json());
app.use(express.static('public'));

// ----- SQLite DB setup -----
const db = new sqlite3.Database(path.join(__dirname, 'privy.db'));

db.serialize(() => {
  // Users table with email column
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user','admin'))
  )`);
  // Scans table
  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    result TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// ----- Helper middleware -----
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user; // { id, username, role }
    next();
  });
}

function authorizeRoles(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// ----- Auth routes -----
app.post('/api/register', (req, res) => {
  const { username, email, password, role, adminKey } = req.body;
  if (!username || !email || !password || !role) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  // Admin registration requires correct key
  if (role === 'admin' && adminKey !== ADMIN_REG_KEY) {
    return res.status(403).json({ error: 'Invalid admin registration key' });
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)');
  stmt.run(username, email, passwordHash, role, function (err) {
    if (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    const token = jwt.sign({ id: this.lastID, username, role }, JWT_SECRET, { expiresIn: '8h' });
    // Return token, role, and basic user data
    res.json({ token, role, user: { id: this.lastID, username, email, role } });
  });
  stmt.finalize();
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = bcrypt.compareSync(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: row.id, username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: row.role, user: { id: row.id, username: row.username, email: row.email, role: row.role } });
  });
});

// ----- Scan route (protected) -----
app.post('/api/scan', authenticateToken, (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL missing' });
  const exePath = path.join(__dirname, 'build', 'privy_engine.exe');
  const child = spawn(exePath, [url]);
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', d => (stdout += d));
  child.stderr.on('data', d => (stderr += d));
  child.on('close', code => {
    if (code !== 0) {
      console.error('Engine error:', stderr);
      return res.status(500).json({ error: 'Detection engine failed' });
    }
    try {
      const result = JSON.parse(stdout);
      const stmt = db.prepare('INSERT INTO scans (user_id, url, result) VALUES (?,?,?)');
      stmt.run(req.user.id, url, JSON.stringify(result), err => {
        if (err) console.error('DB insert error', err);
      });
      stmt.finalize();
      res.json(result);
    } catch (e) {
      console.error('JSON parse error', e);
      res.status(500).json({ error: 'Invalid engine output' });
    }
  });
});

// ----- History (protected) -----
app.get('/api/history', authenticateToken, (req, res) => {
  db.all('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const history = rows.map(r => ({
      id: r.id,
      url: r.url,
      result: JSON.parse(r.result),
      timestamp: r.timestamp
    }));
    res.json(history);
  });
});

// ----- Admin routes -----
app.get('/api/admin/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
  db.all('SELECT id, username, email, role FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/admin/stats', authenticateToken, authorizeRoles('admin'), (req, res) => {
  const stats = {};
  db.get('SELECT COUNT(*) AS totalUsers FROM users', [], (e1, r1) => {
    if (e1) return res.status(500).json({ error: e1.message });
    stats.totalUsers = r1.totalUsers;
    db.get('SELECT COUNT(*) AS totalScans FROM scans', [], (e2, r2) => {
      if (e2) return res.status(500).json({ error: e2.message });
      stats.totalScans = r2.totalScans;
      db.get('SELECT COUNT(*) AS phishingDetections FROM scans WHERE json_extract(result, "$.isPhishing") = 1', [], (e3, r3) => {
        if (e3) return res.status(500).json({ error: e3.message });
        stats.phishingDetections = r3.phishingDetections;
        res.json(stats);
      });
    });
  });
});

// ----- Serve HTML pages -----
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/signup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});
app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, () => {
  console.log(`PRIVY server listening at http://localhost:${PORT}`);
});

const express = require('express');
const path = require('path');
const { spawn } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Secret for JWT – in production store securely
const JWT_SECRET = 'replace_this_with_a_strong_secret';

app.use(express.json());
app.use(express.static('public'));

// ----- SQLite DB setup -----
const db = new sqlite3.Database(path.join(__dirname, 'privy.db'));

db.serialize(() => {
  // Create users table with email column (if not already present)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user','admin'))
  )`);
  // Add email column if missing (SQLite doesn't support IF NOT EXISTS for column, so attempt ALTER and ignore error)
  db.run(`ALTER TABLE users ADD COLUMN email TEXT`, (err) => {
    // ignore "duplicate column" error
    if (err && !err.message.includes('duplicate column')) {
      console.error('DB schema alteration error:', err.message);
    }
  });
  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    result TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});
// ----- SQLite DB setup -----
const db = new sqlite3.Database(path.join(__dirname, 'privy.db'));

db.serialize(() => {
  // Create users table with email column (if not already present)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user','admin'))
  )`);
  // Add email column if missing (SQLite doesn't support IF NOT EXISTS for column, so attempt ALTER and ignore error)
  db.run(`ALTER TABLE users ADD COLUMN email TEXT`, (err) => {
    // ignore "duplicate column" error
    if (err && !err.message.includes('duplicate column')) {
      console.error('DB schema alteration error:', err.message);
    }
  });
  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    result TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});
const db = new sqlite3.Database(path.join(__dirname, 'privy.db'));

// Ensure users table has email column
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user','admin'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    result TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user','admin'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    result TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// ----- Helper middleware -----
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user; // { id, username, role }
    next();
  });
}

function authorizeRoles(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.user.role)) {
      return res.sendStatus(403);
    }
    next();
  };
}


// ----- Auth routes -----
app.post('/api/register', (req, res) => {
  const { username, password, role, email, adminKey } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  // Admin registration requires correct key
  const ADMIN_REGISTRATION_KEY = 'PRIVYADMIN2026'; // change as needed
  if (role === 'admin') {
    if (!adminKey || adminKey !== ADMIN_REGISTRATION_KEY) {
      return res.status(403).json({ error: 'Invalid admin registration key' });
    }
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)');
  stmt.run(username, passwordHash, role, function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    const token = jwt.sign({ id: this.lastID, username, role }, JWT_SECRET, { expiresIn: '8h' });
    // Return token, role, and basic user info for frontend storage
    res.json({ token, role, user: { id: this.lastID, username, email: email || null, role } });
  });
  stmt.finalize();
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = bcrypt.compareSync(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: row.id, username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '8h' });
    // Return token, role, and user details
    res.json({ token, role: row.role, user: { id: row.id, username: row.username, role: row.role } });
  });
});
app.post('/api/register', (req, res) => {
  const { username, email, password, role, adminKey } = req.body;
  if (!username || !email || !password || !role) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  // Restrict admin creation – require a pre‑shared secret key
  const ADMIN_REG_KEY = 'PRIVY_ADMIN_SECRET'; // replace with env var in production
  if (role === 'admin') {
    if (!adminKey || adminKey !== ADMIN_REG_KEY) {
      return res.status(403).json({ error: 'Invalid admin authorization key' });
    }
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  // Insert user (including email)
  const stmt = db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)');
  stmt.run(username, email, passwordHash, role, function (err) {
    if (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    const token = jwt.sign({ id: this.lastID, username, role }, JWT_SECRET, { expiresIn: '8h' });
    // Return token, role and basic user info for client side convenience
    res.json({ token, role, user: { id: this.lastID, username, email, role } });
  });
  stmt.finalize();
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = bcrypt.compareSync(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: row.id, username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '8h' });
    // Return token, role and user info (including email)
    res.json({ token, role: row.role, user: { id: row.id, username: row.username, email: row.email, role: row.role } });
  });
});

app.post('/api/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)');
  stmt.run(username, passwordHash, role, function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    const token = jwt.sign({ id: this.lastID, username, role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role });
  });
  stmt.finalize();
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = bcrypt.compareSync(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: row.id, username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: row.role });
  });
});

// ----- Scan route (protected) -----
app.post('/api/scan', authenticateToken, (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL missing' });
  const exePath = path.join(__dirname, 'build', 'privy_engine.exe');
  const child = spawn(exePath, [url]);
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', d => (stdout += d));
  child.stderr.on('data', d => (stderr += d));
  child.on('close', code => {
    if (code !== 0) {
      console.error('Engine error:', stderr);
      return res.status(500).json({ error: 'Detection engine failed' });
    }
    try {
      const result = JSON.parse(stdout);
      // Store scan result
      const stmt = db.prepare('INSERT INTO scans (user_id, url, result) VALUES (?,?,?)');
      stmt.run(req.user.id, url, JSON.stringify(result), err => {
        if (err) console.error('DB insert error', err);
      });
      stmt.finalize();
      res.json(result);
    } catch (e) {
      console.error('JSON parse error', e);
      res.status(500).json({ error: 'Invalid engine output' });
    }
  });
});

// ----- History (protected) -----
app.get('/api/history', authenticateToken, (req, res) => {
  db.all('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const history = rows.map(r => ({
      id: r.id,
      url: r.url,
      result: JSON.parse(r.result),
      timestamp: r.timestamp
    }));
    res.json(history);
  });
});

// ----- Admin routes -----
app.get('/api/admin/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
  db.all('SELECT id, username, role FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/admin/stats', authenticateToken, authorizeRoles('admin'), (req, res) => {
  const stats = {};
  db.get('SELECT COUNT(*) AS totalUsers FROM users', [], (e1, r1) => {
    if (e1) return res.status(500).json({ error: e1.message });
    stats.totalUsers = r1.totalUsers;
    db.get('SELECT COUNT(*) AS totalScans FROM scans', [], (e2, r2) => {
      if (e2) return res.status(500).json({ error: e2.message });
      stats.totalScans = r2.totalScans;
      db.get('SELECT COUNT(*) AS phishingDetections FROM scans WHERE json_extract(result, "$.isPhishing") = 1', [], (e3, r3) => {
        if (e3) return res.status(500).json({ error: e3.message });
        stats.phishingDetections = r3.phishingDetections;
        res.json(stats);
      });
    });
  });
});

// ----- Serve HTML pages -----
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/signup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});
app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, () => {
  console.log(`PRIVY server listening at http://localhost:${PORT}`);
});
