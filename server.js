"use strict";

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = __dirname;

app.disable("x-powered-by");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(PUBLIC_DIR));

const users = new Map();
const sessions = new Map();
const messages = [];
const MAX_MESSAGES = 100;

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getUser(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;

  const token = header.slice(7);
  const username = sessions.get(token);

  if (!username) return null;
  return users.get(username) || null;
}

function publicUser(user) {
  return { username: user.username };
}

app.get("/api/status", (req, res) => {
  res.json({
    name: "KING DAFFZZ",
    status: "online",
    mode: "public-chat",
    users: users.size,
    messages: messages.length
  });
});

app.post("/api/register", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({
      error: "Username harus 3-24 karakter: huruf, angka, atau underscore."
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: "Password harus 8-128 karakter."
    });
  }

  const key = username.toLowerCase();

  if (users.has(key)) {
    return res.status(409).json({
      error: "Username sudah digunakan."
    });
  }

  const salt = crypto.randomBytes(16).toString("hex");

  const user = {
    username,
    salt,
    passwordHash: hashPassword(password, salt)
  };

  users.set(key, user);

  const token = createToken();
  sessions.set(token, key);

  res.status(201).json({
    message: "Pendaftaran berhasil.",
    token,
    user: publicUser(user)
  });
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const key = username.toLowerCase();
  const user = users.get(key);

  if (
    !user ||
    !crypto.timingSafeEqual(
      Buffer.from(hashPassword(password, user.salt), "hex"),
      Buffer.from(user.passwordHash, "hex")
    )
  ) {
    return res.status(401).json({
      error: "Username atau password salah."
    });
  }

  const token = createToken();
  sessions.set(token, key);

  res.json({
    message: "Login berhasil.",
    token,
    user: publicUser(user)
  });
});

app.get("/api/me", (req, res) => {
  const user = getUser(req);

  if (!user) {
    return res.status(401).json({ error: "Silakan login." });
  }

  res.json({ user: publicUser(user) });
});

app.post("/api/logout", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  sessions.delete(token);
  res.json({ message: "Logout berhasil." });
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token || !sessions.has(token)) {
    return next(new Error("Silakan login terlebih dahulu."));
  }

  const username = sessions.get(token);
  const user = users.get(username);

  if (!user) {
    return next(new Error("Akun tidak ditemukan."));
  }

  socket.data.username = user.username;
  next();
});

io.on("connection", socket => {
  socket.emit("chat:history", messages);

  socket.on("chat:send", payload => {
    if (!payload || typeof payload.message !== "string") return;

    const message = payload.message.trim().slice(0, 1000);
    if (!message) return;

    const item = {
      id: crypto.randomUUID(),
      username: socket.data.username,
      message,
      time: new Date().toISOString()
    };

    messages.push(item);

    while (messages.length > MAX_MESSAGES) {
      messages.shift();
    }

    io.emit("chat:new", item);
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`KING DAFFZZ berjalan di port ${PORT}`);
});