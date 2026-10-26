"use strict";

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const PUBLIC_DIR = path.join(__dirname, "public");

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "20kb" }));
app.use(express.static(PUBLIC_DIR));

app.get("/api/status", (req, res) => {
  res.json({
    name: "KING DAFFZZ",
    status: "online",
    mode: "demo",
    whatsapp: "not-connected"
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`KING DAFFZZ berjalan di port ${PORT}`);
});