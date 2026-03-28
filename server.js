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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

const JWT_SECRET = process.env.JWT_SECRET || "funtogether_secret_2024";
const PORT       = process.env.PORT || 3000;
const db         = new Database(process.env.DB_PATH || "./funtogether.db");

// ── DB SETUP ──
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
`);

// Add photo columns if missing (migration)
try { db.exec("ALTER TABLE users ADD COLUMN photo1 TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN photo2 TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN photo3 TEXT"); } catch(e) {}

// ── UPLOADS DIR ──
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// ── MULTER ──
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
    var ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));
app.use("/uploads", express.static(uploadsDir));

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

// ── ROUTES ──
app.get("/api/healthz", function(req, res) { res.json({ status: "ok" }); });

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
    db.prepare(`INSERT INTO users (uin,name,email,password_hash,age,gender,location,height,body_type,
      eye_color,hair_color,skin_tone,marital_status,religion,smoking,bio)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      uin,b.name,b.email,hash,b.age,b.gender,
      b.location||null,b.height||null,b.body_type||null,b.eye_color||null,
      b.hair_color||null,b.skin_tone||null,b.marital_status||null,
      b.religion||null,b.smoking||null,b.bio||null);
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
    db.prepare(`UPDATE users SET name=?,age=?,location=?,height=?,body_type=?,
      eye_color=?,hair_color=?,skin_tone=?,marital_status=?,religion=?,smoking=?,bio=?
      WHERE uin=?`).run(
      b.name||user.name, b.age||user.age,
      b.location!==undefined?b.location:user.location,
      b.height!==undefined?b.height:user.height,
      b.body_type!==undefined?b.body_type:user.body_type,
      b.eye_color!==undefined?b.eye_color:user.eye_color,
      b.hair_color!==undefined?b.hair_color:user.hair_color,
      b.skin_tone!==undefined?b.skin_tone:user.skin_tone,
      b.marital_status!==undefined?b.marital_status:user.marital_status,
      b.religion!==undefined?b.religion:user.religion,
      b.smoking!==undefined?b.smoking:user.smoking,
      b.bio!==undefined?b.bio:user.bio,
      req.user.uin);
    var updated = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    var result = Object.assign({}, updated);
    delete result.password_hash;
    res.json(result);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── PHOTO UPLOAD ──
app.post("/api/users/photo", auth, upload.single("photo"), function(req, res) {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    var user = db.prepare("SELECT * FROM users WHERE uin=?").get(req.user.uin);
    var slot = req.body.slot || "1";
    var photoUrl = "/uploads/" + req.file.filename;
    var col = "photo" + slot;
    if (!["photo1","photo2","photo3"].includes(col))
      return res.status(400).json({ error: "Invalid slot (1-3)" });
    // Delete old file if exists
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

app.get("/api/users", auth, function(req, res) {
  try {
    var q2 = req.query;
    var sql = "SELECT uin,name,age,gender,location,height,body_type,eye_color,hair_color,skin_tone,marital_status,religion,smoking,bio,photo1,photo2,photo3 FROM users WHERE uin!=?";
    var params = [req.user.uin];
    if (q2.gender)   { sql += " AND gender=?";        params.push(q2.gender); }
    if (q2.location) { sql += " AND location LIKE ?";  params.push("%"+q2.location+"%"); }
    if (q2.min_age)  { sql += " AND age>=?";           params.push(parseInt(q2.min_age)); }
    if (q2.max_age)  { sql += " AND age<=?";           params.push(parseInt(q2.max_age)); }
    sql += " ORDER BY created_at DESC";
    res.json({ users: db.prepare(sql).all.apply(db.prepare(sql), params) });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/messages/send", auth, function(req, res) {
  try {
    var b = req.body;
    if (!b.receiver_uin||!b.content||!b.content.trim()) return res.status(400).json({ error: "Missing fields" });
    db.prepare("INSERT INTO messages (sender_uin,receiver_uin,content) VALUES (?,?,?)").run(req.user.uin, b.receiver_uin, b.content.trim());
    res.json({ success: true });
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
  try { socket.user = jwt.verify(socket.handshake.auth && socket.handshake.auth.token, JWT_SECRET); next(); }
  catch(e) { next(new Error("Auth error")); }
});
io.on("connection", function(socket) {
  var uin = socket.user.uin, name = socket.user.name;
  onlineUsers.set(uin, socket.id);
  socket.on("send_message", function(data) {
    if (!data.content||!data.content.trim()||!data.recipientUin) return;
    db.prepare("INSERT INTO messages (sender_uin,receiver_uin,content) VALUES (?,?,?)").run(uin, data.recipientUin, data.content.trim());
    var s = onlineUsers.get(data.recipientUin);
    if (s) io.to(s).emit("new_message", { sender_uin:uin, sender_name:name, content:data.content.trim(), created_at:new Date().toISOString() });
    socket.emit("message_sent", { success:true });
  });
  socket.on("disconnect", function() { onlineUsers.delete(uin); });
});

server.listen(PORT, function() { console.log("FunTogether on port " + PORT); });
