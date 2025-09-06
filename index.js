// index.js - combined backend + static frontend server
const express = require("express");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// DB (file-based)
const adapter = new FileSync("db.json");
const db = low(adapter);

function initDb() {
  db.defaults({ users: [], resumes: [] }).write();
}

const JWT_SECRET = process.env.JWT_SECRET || "verysecretkey";

// id helper
function id() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// initialize DB
initDb();

// serve static frontend
app.use(express.static(path.join(__dirname, "Public")));

// API routes ---------------------------------------------------

// Signup
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "email and password required" });
  const exists = db.get("users").find({ email: email.toLowerCase() }).value();
  if (exists) return res.status(400).json({ error: "user exists" });
