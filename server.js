const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const Database   = require('better-sqlite3');
const http       = require('http');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'funtogether_secret_2024';
const PORT       = process.env.PORT || 3000;
const db         = new Database(process.env.DB_PATH || './funtogether.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uin TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    age INTEGER NOT NULL, gender TEXT NOT NULL,
    location TEXT, height INTEGER, body_type TEXT,
    eye_color TEXT, hair_color TEXT, skin_tone TEXT,
    marital_status TEXT, religion TEXT, smoking TEXT, bio TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_uin TEXT NOT NULL, receiver_uin TEXT NOT NULL,
    content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(cors({ origin: '*' }));
app.use(express.json());

function generateUIN() {
  for (let i = 0; i < 20; i++) {
    const uin = String(Math.floor(10000000 + Math.random() * 90000000));
    if (!db.prepare('SELECT uin FROM users WHERE uin=?').get(uin)) return uin;
  }
  throw new Error('UIN generation failed');
}

function auth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization||'').replace('Bearer ',''), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

app.get('/api/healthz', (_, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, age, gender, location, height, body_type,
            eye_color, hair_color, skin_tone, marital_status, religion, smoking, bio } = req.body;
    if (!name||!email||!password||!age||!gender)
      return res.status(400).json({ error: 'Missing required fields' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (age < 18 || age > 120) return res.status(400).json({ error: 'Age must be between 18 and 120' });
    if (!['male','female','other'].includes(gender)) return res.status(400).json({ error: 'Invalid gender' });
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email))
      return res.status(409).json({ error: 'Email already registered' });
    const uin = generateUIN();
    const password_hash = await bcrypt.hash(password, 12);
    db.prepare(`INSERT INTO users (uin,name,email,password_hash,age,gender,location,height,
      body_type,eye_color,hair_color,skin_tone,marital_status,religion,smoking,bio)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      uin,name,email,password_hash,age,gender,
      location||null,height||null,body_type||null,eye_color||null,
      hair_color||null,skin_tone||null,marital_status||null,
      religion||null,smoking||null,bio||null);
    const token = jwt.sign({ uin, name }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ uin, name, token });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email||!password) return res.status(400).json({ error: 'Email and password required' });
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!user || !await bcrypt.compare(password, user.password_hash))
      return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ uin: user.uin, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ uin: user.uin, name: user.name, token });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/me', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE uin=?').get(req.user.uin);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password_hash, ...profile } = user;
  res.json(profile);
});

app.patch('/api/users/me', auth, (req, res) => {
  try {
    const { name, age, location, height, body_type, eye_color, hair_color,
            skin_tone, marital_status, religion, smoking, bio } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE uin=?').get(req.user.uin);
    if (!user) return res.status(404).json({ error: 'Not found' });
    db.prepare(`UPDATE users SET
      name=?, age=?, location=?, height=?, body_type=?,
      eye_color=?, hair_color=?, skin_tone=?, marital_status=?,
      religion=?, smoking=?, bio=? WHERE uin=?`).run(
      name||user.name, age||user.age,
      location!==undefined?location:user.location,
      height!==undefined?height:user.height,
      body_type!==undefined?body_type:user.body_type,
      eye_color!==undefined?eye_color:user.eye_color,
      hair_color!==undefined?hair_color:user.hair_color,
      skin_tone!==undefined?skin_tone:user.skin_tone,
      marital_status!==undefined?marital_status:user.marital_status,
      religion!==undefined?religion:user.religion,
      smoking!==undefined?smoking:user.smoking,
      bio!==undefined?bio:user.bio,
      req.user.uin);
    const updated = db.prepare('SELECT * FROM users WHERE uin=?').get(req.user.uin);
    const { password_hash, ...profile } = updated;
    res.json(profile);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users', auth, (req, res) => {
  try {
    const { gender, location, min_age, max_age } = req.query;
    let q = `SELECT uin,name,age,gender,location,height,body_type,eye_color,
      hair_color,skin_tone,marital_status,religion,smoking,bio
      FROM users WHERE uin!=?`;
    const p = [req.user.uin];
    if (gender)   { q += ' AND gender=?';        p.push(gender); }
    if (location) { q += ' AND location LIKE ?';  p.push('%'+location+'%'); }
    if (min_age)  { q += ' AND age>=?';           p.push(parseInt(min_age)); }
    if (max_age)  { q += ' AND age<=?';           p.push(parseInt(max_age)); }
    q += ' ORDER BY created_at DESC';
    res.json({ users: db.prepare(q).all(...p) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/messages/send', auth, (req, res) => {
  try {
    const { receiver_uin, content } = req.body;
    if (!receiver_uin||!content?.trim()) return res.status(400).json({ error: 'Missing fields' });
    db.prepare('INSERT INTO messages (sender_uin,receiver_uin,content) VALUES (?,?,?)')
      .run(req.user.uin, receiver_uin, content.trim());
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/messages/:other', auth, (req, res) => {
  const msgs = db.prepare(`SELECT * FROM messages
    WHERE (sender_uin=? AND receiver_uin=?) OR (sender_uin=? AND receiver_uin=?)
    ORDER BY created_at ASC`).all(req.user.uin,req.params.other,req.params.other,req.user.uin);
  res.json({ messages: msgs });
});

const onlineUsers = new Map();
io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth?.token, JWT_SECRET); next(); }
  catch { next(new Error('Auth error')); }
});
io.on('connection', (socket) => {
  const { uin, name } = socket.user;
  onlineUsers.set(uin, socket.id);
  socket.on('send_message', ({ recipientUin, content }) => {
    if (!content?.trim()||!recipientUin) return;
    db.prepare('INSERT INTO messages (sender_uin,receiver_uin,content) VALUES (?,?,?)')
      .run(uin, recipientUin, content.trim());
    const s = onlineUsers.get(recipientUin);
    if (s) io.to(s).emit('new_message', { sender_uin:uin, sender_name:name, content:content.trim(), created_at:new Date().toISOString() });
    socket.emit('message_sent', { success: true });
  });
  socket.on('get_messages', ({ otherUin }) => {
    const msgs = db.prepare(`SELECT * FROM messages
      WHERE (sender_uin=? AND receiver_uin=?) OR (sender_uin=? AND receiver_uin=?)
      ORDER BY created_at ASC`).all(uin,otherUin,otherUin,uin);
    socket.emit('messages_history', { messages: msgs });
  });
  socket.on('disconnect', () => onlineUsers.delete(uin));
});

server.listen(PORT, () => console.log(`💘 FunTogether on port ${PORT}`));
