// index.js - combined backend + static frontend server
const express = require("express");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// DB (file-based)
const adapter = new FileSync("db.json");
const db = low(adapter);
db.defaults({ users: [], resumes: [] }).write();

const JWT_SECRET = process.env.JWT_SECRET || "verysecretkey";

// Helper: generate unique ID
function id() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// Serve static frontend (note lowercase 'public')
app.use(express.static(path.join(__dirname, "public")));

// ---------------------- API Routes ----------------------

// Signup
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const exists = db.get("users").find({ email: email.toLowerCase() }).value();
  if (exists) return res.status(400).json({ error: "User exists" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: id(), email: email.toLowerCase(), password: hashed };
  db.get("users").push(newUser).write();

  const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET);
  res.json({ token });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const user = db.get("users").find({ email: email.toLowerCase() }).value();
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Incorrect password" });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
  res.json({ token });
});

// Middleware: verify JWT
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing token" });

  const token = header.split(" ")[1];
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Create Resume
app.post("/api/resumes", auth, (req, res) => {
  const resume = { id: id(), userId: req.user.id, ...req.body };
  db.get("resumes").push(resume).write();
  res.json(resume);
});

// Get All Resumes for User
app.get("/api/resumes", auth, (req, res) => {
  const resumes = db.get("resumes").filter({ userId: req.user.id }).value();
  res.json(resumes);
});

// Get Resume by ID
app.get("/api/resumes/:id", auth, (req, res) => {
  const resume = db
    .get("resumes")
    .find({ id: req.params.id, userId: req.user.id })
    .value();
  if (!resume) return res.status(404).json({ error: "Resume not found" });
  res.json(resume);
});

// Update Resume
app.put("/api/resumes/:id", auth, (req, res) => {
  const resume = db
    .get("resumes")
    .find({ id: req.params.id, userId: req.user.id })
    .assign(req.body)
    .write();
  res.json(resume);
});

// Delete Resume
app.delete("/api/resumes/:id", auth, (req, res) => {
  db.get("resumes")
    .remove({ id: req.params.id, userId: req.user.id })
    .write();
  res.json({ success: true });
});

// Catch-all route to serve frontend
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
