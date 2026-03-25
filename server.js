const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const Database   = require('better-sqlite3');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'funtogether_secret_2024';
const PORT       = process.env.PORT || 3000;

// ── Database ──────────────────────────────────
const db = new Database(process.env.DB_PATH || './funtogether.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    uin            TEXT UNIQUE NOT NULL,
    name           TEXT NOT NULL,
    email          TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    age            INTEGER NOT NULL,
    gender         TEXT NOT NULL,
    location       TEXT,
    height         INTEGER,
    body_type      TEXT,
    eye_color      TEXT,
    hair_color     TEXT,
    skin_tone      TEXT,
    marital_status TEXT,
    religion       TEXT,
    smoking        TEXT,
    bio            TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_uin   TEXT NOT NULL,
    receiver_uin TEXT NOT NULL,
    content      TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Middleware ─────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── UIN Generator ─────────────────────────────
function generateUIN() {
  for (let i = 0; i < 20; i++) {
    const uin = String(Math.floor(10000000 + Math.random() * 90000000));
    const exists = db.prepare('SELECT uin FROM users WHERE uin = ?').get(uin);
    if (!exists) return uin;
  }
  throw new Error('UIN generation failed');
}

// ── Auth Middleware ────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Routes ─────────────────────────────────────

// Health check
app.get('/api/healthz', (_, res) => res.json({ status: 'ok', app: 'FunTogether' }));

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, email, password, age, gender,
      location, height, body_type, eye_color,
      hair_color, skin_tone, marital_status,
      religion, smoking, bio
    } = req.body;

    if (!name || !email || !password || !age || !gender)
      return res.status(400).json({ error: 'Missing required fields: name, email, password, age, gender' });

    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    if (age < 18 || age > 120)
      return res.status(400).json({ error: 'Age must be between 18 and 120' });

    const validGenders = ['male', 'female', 'other'];
    if (!validGenders.includes(gender))
      return res.status(400).json({ error: 'Gender must be male, female, or other' });

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const uin           = generateUIN();
    const password_hash = await bcrypt.hash(password, 12);

    db.prepare(`
      INSERT INTO users (
        uin, name, email, password_hash, age, gender,
        location, height, body_type, eye_color, hair_color,
        skin_tone, marital_status, religion, smoking, bio
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      uin, name, email, password_hash, age, gender,
      location || null, height || null, body_type || null,
      eye_color || null, hair_color || null, skin_tone || null,
      marital_status || null, religion || null, smoking || null, bio || null
    );

    const token = jwt.sign({ uin, name }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ uin, name, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ uin: user.uin, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ uin: user.uin, name: user.name, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get my profile
app.get('/api/users/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE uin = ?').get(req.user.uin);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password_hash, ...profile } = user;
  res.json(profile);
});

// Get all users (for search)
app.get('/api/users', authMiddleware, (req, res) => {
  const users = db.prepare(
    'SELECT uin, name, age, gender, location, height, body_type, eye_color, hair_color, skin_tone, marital_status, religion, smoking, bio FROM users WHERE uin != ?'
  ).all(req.user.uin);
  res.json({ users });
});

// Get messages
app.get('/api/messages/:other_uin', authMiddleware, (req, res) => {
  const msgs = db.prepare(`
    SELECT * FROM messages
    WHERE (sender_uin = ? AND receiver_uin = ?)
       OR (sender_uin = ? AND receiver_uin = ?)
    ORDER BY created_at ASC
  `).all(req.user.uin, req.params.other_uin, req.params.other_uin, req.user.uin);
  res.json({ messages: msgs });
});

// ── Socket.io ──────────────────────────────────
const onlineUsers = new Map();

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  const { uin, name } = socket.user;
  onlineUsers.set(uin, socket.id);
  console.log(`✅ ${name} (${uin}) connected`);

  socket.on('send_message', ({ recipientUin, content }) => {
    if (!content?.trim() || !recipientUin) return;
    db.prepare(
      'INSERT INTO messages (sender_uin, receiver_uin, content) VALUES (?, ?, ?)'
    ).run(uin, recipientUin, content.trim());

    const recipientSocket = onlineUsers.get(recipientUin);
    if (recipientSocket) {
      io.to(recipientSocket).emit('new_message', {
        sender_uin: uin, sender_name: name,
        content: content.trim(),
        created_at: new Date().toISOString()
      });
    }
    socket.emit('message_sent', { success: true });
  });

  socket.on('get_messages', ({ otherUin }) => {
    const msgs = db.prepare(`
      SELECT * FROM messages
      WHERE (sender_uin = ? AND receiver_uin = ?)
         OR (sender_uin = ? AND receiver_uin = ?)
      ORDER BY created_at ASC
    `).all(uin, otherUin, otherUin, uin);
    socket.emit('messages_history', { messages: msgs });
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(uin);
    console.log(`❌ ${name} disconnected`);
  });
});

// ── Start ──────────────────────────────────────
server.listen(PORT, () => {
  console.log(`💘 FunTogether Server running on port ${PORT}`);
});
