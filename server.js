const express    = require("express");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const Database   = require("better-sqlite3");
const http       = require("http");
const { Server } = require("socket.io");
const multer     = require("multer");
const path       = require("path");
const fs         = require("fs");
const webpush    = require("web-push");
const nodemailer = require("nodemailer");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

const JWT_SECRET = process.env.JWT_SECRET || "funtogether_secret_2024";
const PORT       = process.env.PORT || 3000;
const db         = new Database(process.env.DB_PATH || "./funtogether.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uin TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    age INTEGER NOT NULL, gender TEXT NOT NULL,
    location TEXT, height INTEGER, body_type TEXT,
    eye_color TEXT, hair_color TEXT, skin_tone TEXT,
    marital_status TEXT, religion TEXT, smoking TEXT, bio TEXT,
    photo1 TEXT, photo2 TEXT, photo3 TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_uin TEXT NOT NULL, receiver_uin TEXT NOT NULL,
    content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reset_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL, code TEXT NOT NULL,
    expires_at INTEGER NOT NULL, used INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_uin TEXT NOT NULL, blocked_uin TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(blocker_uin, blocked_uin)
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_uin TEXT NOT NULL, reported_uin TEXT NOT NULL,
    reason TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uin TEXT NOT NULL, endpoint TEXT UNIQUE NOT NULL,
    p256dh TEXT NOT NULL, auth TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec("ALTER TABLE users ADD COLUMN photo1 TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN photo2 TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN photo3 TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN religion_attitude TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN hair_style TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN region TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN city TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN hair_type TEXT"); } catch(e) {}

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: function(req, file, cb) { cb(null, uploadsDir); },
  filename: function(req, file, cb) {
    var ext = path.extname(file.originalname).toLowerCase() || ".jpg";
    cb(null, req.user.uin + "_" + Date.now() + ext);
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: function(req, file, cb) {
    var allowed = [".jpg",".jpeg",".png",".webp",".gif"];
    cb(null, allowed.includes(path.extname(file.originalname).toLowerCase()));
  }
});

app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));
app.use("/uploads", express.static(uploadsDir));
app.use(express.static(path.join(__dirname, "public")));

function generateUIN() {
  for (var i = 0; i < 20; i++) {
    var uin = String(Math.floor(10000000 + Math.random() * 90000000));
    if (!db.prepare("SELECT uin FROM users WHERE uin=?").get(uin)) return uin;
  }
  throw new Error("UIN generation failed");
}

function auth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization||"").replace("Bearer ",""), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Invalid token" }); }
}

// ── WEB PUSH ──
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT     = process.env.VAPID_SUBJECT || "mailto:admin@funtogether.app";
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} else {
  console.warn("VAPID keys not set — push notifications disabled. Generate with: npx web-push generate-vapid-keys");
}

// ── EMAIL (SMTP) ──
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;

var mailTransporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
} else {
  console.warn("SMTP not configured — password-reset emails will not be sent. Set SMTP_HOST, SMTP_USER, SMTP_PASS (and optionally SMTP_PORT, SMTP_FROM) in Railway.");
}

async function sendMail(to, subject, html) {
  if (!mailTransporter) return false;
  await mailTransporter.sendMail({ from: SMTP_FROM, to: to, subject: subject, html: html });
  return true;
}

function sendPushToUser(uin, payload) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
  var subs = db.prepare("SELECT * FROM push_subscriptions WHERE uin=?").all(uin);
  subs.forEach(function(sub) {
    var pushSubscription = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
    webpush.sendNotification(pushSubscription, JSON.stringify(payload)).catch(function(err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        db.prepare("DELETE FROM push_subscriptions WHERE endpoint=?").run(sub.endpoint);
      }
    });
  });
}

app.get("/api/healthz", function(req, res) { res.json({ status: "ok" }); });

// ── AUTH ──
app.post("/api/auth/register", async function(req, res) {
  try {
    var b = req.body;
    if (!b.name||!b.email||!b.password||!b.age||!b.gender)
      return res.status(400).json({ error: "Missing required fields" });
    if (b.password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    if (b.age < 18 || b.age > 120) return res.status(400).json({ error: "Age must be 18-120" });
    if (!["male","female","other"].includes(b.gender)) return res.status(400).json({ error: "Invalid gender" });
    if (db.prepare("SELECT id FROM users WHERE email=?").get(b.email))
      return res.status(409).json({ error: "Email already registered" });
    var uin = generateUIN();
    var hash = await bcrypt.hash(b.password, 12);
    db.prepare(`INSERT INTO users (uin,name,email,password_hash,age,gender,location,region,city,height,body_type,
      eye_color,hair_color,hair_style,hair_type,skin_tone,marital_status,religion,religion_attitude,smoking,bio)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      uin,b.name,b.email,hash,b.age,b.gender,
      b.location||null,b.region||null,b.city||null,b.height||null,b.body_type||null,b.eye_color||null,
      b.hair_color||null,b.hair_style||null,b.hair_type||null,b.skin_tone||null,b.marital_status||null,
      b.religion||null,b.religion_attitude||null,b.smoking||null,b.bio||null);
    var token = jwt.sign({ uin:uin, name:b.name }, JWT_SECRET, { expiresIn:"30d" });
    res.status(201).json({ uin:uin, name:b.name, token:token });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/auth/login", async function(req, res) {
  try {
    var b = req.body;
    if (!b.email||!b.password) return res.status(400).json({ error: "Email and password required" });
    var user = db.prepare("SELECT * FROM users WHERE email=?").get(b.email);
    if (!user || !await bcrypt.compare(b.password, user.password_hash))
      return res.status(401).json({ error: "Invalid email or password" });
    var token = jwt.sign({ uin:user.uin, name:user.name }, JWT_SECRET, { expiresIn:"30d" });
    res.json({ uin:user.uin, name:user.name, token:token });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/auth/forgot-password", async function(req, res) {
  try {
    var email = req.body.email;
    if (!email) return res.status(400).json({ error: "Email required" });
    var user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
    if (!user) return res.json({ success: true });
    var code = String(Math.floor(100000 + Math.random() * 900000));
    var expires = Date.now() + 15 * 60 * 1000;
    db.prepare("DELETE FROM reset_codes WHERE email=?").run(email);
    db.prepare("INSERT INTO reset_codes (email, code, expires_at) VALUES (?,?,?)").run(email, code, expires);
    var emailSent = false;
    try {
      emailSent = await sendMail(email,
        "קוד לאיפוס סיסמה ב-FunTogether",
        "<div dir='rtl' style='font-family:sans-serif'>" +
        "<p>שלום " + user.name + ",</p>" +
        "<p>קוד האימות לאיפוס הסיסמה שלך הוא:</p>" +
        "<p style='font-size:28px;font-weight:bold;letter-spacing:4px;'>" + code + "</p>" +
        "<p>הקוד בתוקף ל-15 דקות. אם לא ביקשת לאפס סיסמה, ניתן להתעלם מהודעה זו.</p>" +
        "</div>");
    } catch (mailErr) { console.error("Failed to send reset email:", mailErr.message); }
    var response = { success: true, name: user.name, email_sent: emailSent };
    if (!emailSent) response.code = code; // dev fallback when SMTP isn't configured
    res.json(response);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/auth/reset-password", async function(req, res) {
  try {
    var b = req.body;
    if (!b.email || !b.code || !b.new_password)
      return res.status(400).json({ error: "Missing fields" });
    if (b.new_password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    var record = db.prepare("SELECT * FROM reset_codes WHERE email=? AND code=? AND used=0").get(b.email, b.code);
    if (!record) return res.status(400).json({ error: "קוד שגוי" });
    if (Date.now() > record.expires_at) return res.status(400).json({ error: "הקוד פג תוקף. בקש קוד חדש." });
    var hash = await bcrypt.hash(b.new_password, 12);
    db.prepare("UPDATE users SET password_hash=? WHERE email=?").run(hash, b.email);
    db.prepare("UPDATE reset_codes SET used=1 WHERE id=?").run(record.id);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/auth/change-password", auth, async function(req, res) {
  try {
    var b = req.body;
    if (!b.old_password || !b.new_password)
      return res.status(400).json({ error: "Missing fields" });
    if (b.new_password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    if (!user) return res.status(404).json({ error: "User not found" });
    var match = await bcrypt.compare(b.old_password, user.password_hash);
    if (!match) return res.status(400).json({ error: "סיסמה נוכחית שגויה" });
    var hash = await bcrypt.hash(b.new_password, 12);
    db.prepare("UPDATE users SET password_hash=? WHERE uin=?").run(hash, req.user.uin);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── USERS/ME — חייב לבוא לפני /users/:uin ──
app.get("/api/users/me", auth, function(req, res) {
  var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
  if (!user) return res.status(404).json({ error: "Not found" });
  var result = Object.assign({}, user);
  delete result.password_hash;
  res.json(result);
});

app.patch("/api/users/me", auth, function(req, res) {
  try {
    var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    if (!user) return res.status(404).json({ error: "Not found" });
    var b = req.body;
    db.prepare(`UPDATE users SET name=?,age=?,location=?,region=?,city=?,height=?,body_type=?,
      eye_color=?,hair_color=?,hair_style=?,hair_type=?,skin_tone=?,marital_status=?,religion=?,religion_attitude=?,smoking=?,bio=?
      WHERE uin=?`).run(
      b.name||user.name, b.age||user.age,
      b.location!==undefined?b.location:user.location,
      b.region!==undefined?b.region:user.region,
      b.city!==undefined?b.city:user.city,
      b.height!==undefined?b.height:user.height,
      b.body_type!==undefined?b.body_type:user.body_type,
      b.eye_color!==undefined?b.eye_color:user.eye_color,
      b.hair_color!==undefined?b.hair_color:user.hair_color,
      b.hair_style!==undefined?b.hair_style:user.hair_style,
      b.hair_type!==undefined?b.hair_type:user.hair_type,
      b.skin_tone!==undefined?b.skin_tone:user.skin_tone,
      b.marital_status!==undefined?b.marital_status:user.marital_status,
      b.religion!==undefined?b.religion:user.religion,
      b.religion_attitude!==undefined?b.religion_attitude:user.religion_attitude,
      b.smoking!==undefined?b.smoking:user.smoking,
      b.bio!==undefined?b.bio:user.bio,
      req.user.uin);
    var updated = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    var result = Object.assign({}, updated);
    delete result.password_hash;
    res.json(result);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/users/me", auth, function(req, res) {
  try {
    var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    if (!user) return res.status(404).json({ error: "Not found" });
    ["photo1","photo2","photo3"].forEach(function(col) {
      if (user[col]) {
        var p = path.join(__dirname, user[col]);
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
    });
    db.prepare("DELETE FROM messages WHERE sender_uin=? OR receiver_uin=?").run(req.user.uin, req.user.uin);
    db.prepare("DELETE FROM blocks WHERE blocker_uin=? OR blocked_uin=?").run(req.user.uin, req.user.uin);
    db.prepare("DELETE FROM reports WHERE reporter_uin=? OR reported_uin=?").run(req.user.uin, req.user.uin);
    db.prepare("DELETE FROM users WHERE uin=?").run(req.user.uin);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── PHOTOS — חייב לבוא לפני /users/:uin ──
app.post("/api/users/photo", auth, upload.single("photo"), function(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    var slot = req.body.slot || "1";
    var photoUrl = "/uploads/" + req.file.filename;
    var col = "photo" + slot;
    if (!["photo1","photo2","photo3"].includes(col))
      return res.status(400).json({ error: "Invalid slot" });
    if (user[col]) {
      var oldPath = path.join(__dirname, user[col]);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    db.prepare("UPDATE users SET " + col + "=? WHERE uin=?").run(photoUrl, req.user.uin);
    res.json({ success: true, url: photoUrl, slot: slot });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/users/photo/:slot", auth, function(req, res) {
  try {
    var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    var col = "photo" + req.params.slot;
    if (!["photo1","photo2","photo3"].includes(col))
      return res.status(400).json({ error: "Invalid slot" });
    if (user[col]) {
      var oldPath = path.join(__dirname, user[col]);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    db.prepare("UPDATE users SET " + col + "=NULL WHERE uin=?").run(req.user.uin);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── BLOCK / REPORT — חייב לבוא לפני /users/:uin ──
app.post("/api/users/block", auth, function(req, res) {
  try {
    var blocked_uin = req.body.blocked_uin;
    if (!blocked_uin) return res.status(400).json({ error: "Missing blocked_uin" });
    if (blocked_uin === req.user.uin) return res.status(400).json({ error: "Cannot block yourself" });
    db.prepare("INSERT OR IGNORE INTO blocks (blocker_uin, blocked_uin) VALUES (?,?)").run(req.user.uin, blocked_uin);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/users/report", auth, function(req, res) {
  try {
    var reported_uin = req.body.reported_uin;
    var reason = req.body.reason || "לא צוינה סיבה";
    if (!reported_uin) return res.status(400).json({ error: "Missing reported_uin" });
    db.prepare("INSERT INTO reports (reporter_uin, reported_uin, reason) VALUES (?,?,?)").run(req.user.uin, reported_uin, reason);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── SEARCH ──
app.get("/api/users", auth, function(req, res) {
  try {
    var q = req.query;
    var sql = `SELECT uin,name,age,gender,location,region,city,height,body_type,eye_color,hair_color,hair_style,hair_type,
      skin_tone,marital_status,religion,religion_attitude,smoking,bio,photo1,photo2,photo3
      FROM users WHERE uin!=?
      AND uin NOT IN (SELECT blocked_uin FROM blocks WHERE blocker_uin=?)
      AND uin NOT IN (SELECT blocker_uin FROM blocks WHERE blocked_uin=?)`;
    var params = [req.user.uin, req.user.uin, req.user.uin];
    if (q.gender)   { sql += " AND gender=?";       params.push(q.gender); }
    if (q.location) { sql += " AND location LIKE ?"; params.push("%"+q.location+"%"); }
    if (q.region)   { sql += " AND region=?";        params.push(q.region); }
    if (q.min_age)  { sql += " AND age>=?";          params.push(parseInt(q.min_age)); }
    if (q.max_age)  { sql += " AND age<=?";          params.push(parseInt(q.max_age)); }
    if (q.name)     { sql += " AND name LIKE ?";     params.push("%"+q.name+"%"); }
    if (q.uin)      { sql += " AND uin LIKE ?";      params.push("%"+q.uin+"%"); }
    sql += " ORDER BY created_at DESC";
    res.json({ users: db.prepare(sql).all(...params) });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── GET USER BY UIN — חייב לבוא אחרון! ──
app.get("/api/users/:uin", auth, function(req, res) {
  try {
    var user = db.prepare(`SELECT uin,name,age,gender,location,region,city,height,body_type,
      eye_color,hair_color,hair_style,hair_type,skin_tone,marital_status,religion,religion_attitude,
      smoking,bio,photo1,photo2,photo3 FROM users WHERE uin=?`).get(req.params.uin);
    if (!user) return res.status(404).json({ error: "Not found" });
    res.json(user);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── PUSH SUBSCRIPTIONS ──
app.get("/api/push/vapid-public-key", function(req, res) {
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: "Push notifications not configured" });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

app.post("/api/push/subscribe", auth, function(req, res) {
  try {
    var sub = req.body.subscription;
    if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth)
      return res.status(400).json({ error: "Invalid subscription" });
    db.prepare(`INSERT INTO push_subscriptions (uin, endpoint, p256dh, auth) VALUES (?,?,?,?)
      ON CONFLICT(endpoint) DO UPDATE SET uin=excluded.uin, p256dh=excluded.p256dh, auth=excluded.auth`)
      .run(req.user.uin, sub.endpoint, sub.keys.p256dh, sub.keys.auth);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/push/unsubscribe", auth, function(req, res) {
  try {
    var endpoint = req.body.endpoint;
    if (!endpoint) return res.status(400).json({ error: "Missing endpoint" });
    db.prepare("DELETE FROM push_subscriptions WHERE endpoint=? AND uin=?").run(endpoint, req.user.uin);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/push/send", auth, function(req, res) {
  try {
    var b = req.body;
    if (!b.uin || !b.title) return res.status(400).json({ error: "Missing fields" });
    sendPushToUser(b.uin, { title: b.title, body: b.body || "", url: b.url || "/" });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── MESSAGES ──
app.post("/api/messages/send", auth, function(req, res) {
  try {
    var b = req.body;
    if (!b.receiver_uin||!b.content||!b.content.trim()) return res.status(400).json({ error: "Missing fields" });
    var isBlocked = db.prepare("SELECT id FROM blocks WHERE (blocker_uin=? AND blocked_uin=?) OR (blocker_uin=? AND blocked_uin=?)").get(req.user.uin, b.receiver_uin, b.receiver_uin, req.user.uin);
    if (isBlocked) return res.status(403).json({ error: "לא ניתן לשלוח הודעה למשתמש זה" });
    db.prepare("INSERT INTO messages (sender_uin,receiver_uin,content) VALUES (?,?,?)").run(req.user.uin, b.receiver_uin, b.content.trim());
    sendPushToUser(b.receiver_uin, { title: req.user.name, body: b.content.trim(), url: "/chat/" + req.user.uin });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/conversations", auth, function(req, res) {
  try {
    var rows = db.prepare(`
      SELECT u.uin, u.name,
        (SELECT content FROM messages m WHERE (m.sender_uin=u.uin AND m.receiver_uin=?) OR (m.sender_uin=? AND m.receiver_uin=u.uin) ORDER BY m.created_at DESC LIMIT 1) AS last_content,
        (SELECT created_at FROM messages m WHERE (m.sender_uin=u.uin AND m.receiver_uin=?) OR (m.sender_uin=? AND m.receiver_uin=u.uin) ORDER BY m.created_at DESC LIMIT 1) AS last_at
      FROM users u
      WHERE u.uin IN (
        SELECT sender_uin FROM messages WHERE receiver_uin=?
        UNION
        SELECT receiver_uin FROM messages WHERE sender_uin=?
      )
      ORDER BY last_at DESC
    `).all(req.user.uin, req.user.uin, req.user.uin, req.user.uin, req.user.uin, req.user.uin);
    res.json({ conversations: rows });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/messages/:other", auth, function(req, res) {
  var msgs = db.prepare("SELECT * FROM messages WHERE (sender_uin=? AND receiver_uin=?) OR (sender_uin=? AND receiver_uin=?) ORDER BY created_at ASC")
    .all(req.user.uin, req.params.other, req.params.other, req.user.uin);
  res.json({ messages: msgs });
});

// ── SOCKET ──
var onlineUsers = new Map();
io.use(function(socket, next) {
  try { socket.user = jwt.verify(socket.handshake.auth&&socket.handshake.auth.token, JWT_SECRET); next(); }
  catch(e) { next(new Error("Auth error")); }
});
io.on("connection", function(socket) {
  var uin = socket.user.uin, name = socket.user.name;
  onlineUsers.set(uin, socket.id);
  socket.on("send_message", function(data) {
    if (!data.content||!data.content.trim()||!data.recipientUin) return;
    var isBlocked = db.prepare("SELECT id FROM blocks WHERE (blocker_uin=? AND blocked_uin=?) OR (blocker_uin=? AND blocked_uin=?)").get(uin, data.recipientUin, data.recipientUin, uin);
    if (isBlocked) return;
    db.prepare("INSERT INTO messages (sender_uin,receiver_uin,content) VALUES (?,?,?)").run(uin, data.recipientUin, data.content.trim());
    var s = onlineUsers.get(data.recipientUin);
    if (s) io.to(s).emit("new_message", { sender_uin:uin, sender_name:name, content:data.content.trim(), created_at:new Date().toISOString() });
    else sendPushToUser(data.recipientUin, { title: name, body: data.content.trim(), url: "/chat/" + uin });
    socket.emit("message_sent", { success:true });
  });
  socket.on("disconnect", function() { onlineUsers.delete(uin); });
});

server.listen(PORT, function() { console.log("FunTogether on port " + PORT); });
