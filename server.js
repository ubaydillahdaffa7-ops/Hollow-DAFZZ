
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
const messages = [];
const MAX_MESSAGES = 100;

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(PUBLIC_DIR));

app.get("/api/status", (req, res) => {
  res.json({
    name: "KING DAFFZZ",
    status: "online",
    mode: "public-chat",
    online: io.engine.clientsCount,
    messages: messages.length
  });
});

io.on("connection", socket => {
  socket.emit("chat:history", messages);

  socket.on("chat:join", username => {
    if (typeof username !== "string") return;

    username = username.trim().slice(0, 24);
    if (!username) return;

    socket.data.username = username;

    socket.emit("chat:joined", {
      username,
      message: "Berhasil masuk ke Public Chat!"
    });
  });

  socket.on("chat:send", payload => {
    if (!socket.data.username) return;
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
