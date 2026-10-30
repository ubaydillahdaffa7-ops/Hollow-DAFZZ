'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const pino = require('pino');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 6 * 1024 * 1024 });

const PORT = Number(process.env.PORT || 3000);
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || '';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PRESET_DIR = path.join(DATA_DIR, 'presets');
const CHAT_DIR = path.join(DATA_DIR, 'chat-files');
const WA_DIR = path.join(DATA_DIR, 'whatsapp-auth');

for (const dir of [DATA_DIR, PRESET_DIR, CHAT_DIR, WA_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, 'database.json');
let database = { users: [], chatHistory: [] };

try {
  const saved = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  database = {
    users: Array.isArray(saved.users) ? saved.users : [],
    chatHistory: Array.isArray(saved.chatHistory) ? saved.chatHistory.slice(-100) : []
  };
} catch {}

function saveDatabase() {
  const temp = DB_FILE + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(database, null, 2));
  fs.renameSync(temp, DB_FILE);
}

const authSessions = new Map();

function getBearer(req) {
  const h = String(req.get('authorization') || '');
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}

function userForToken(token) {
  const session = authSessions.get(String(token || ''));
  if (!session || session.expires < Date.now()) {
    authSessions.delete(String(token || ''));
    return null;
  }
  return database.users.find(u => u.id === session.userId) || null;
}

function requireUser(req, res, next) {
  const user = userForToken(getBearer(req));
  if (!user) {
    return res.status(401).json({
      ok: false,
      error: 'Sesi login tidak valid. Silakan login kembali.'
    });
  }
  req.user = user;
  next();
}

function issueAuth(user) {
  const token = crypto.randomBytes(32).toString('hex');
  authSessions.set(token, {
    userId: user.id,
    expires: Date.now() + 7 * 24 * 60 * 60 * 1000
  });
  return token;
}

function safeUsername(value) {
  return String(value || '').trim();
}

function validUsername(value) {
  return /^[a-zA-Z0-9_]{3,24}$/.test(value);
}

function passwordHash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, user) {
  const actual = Buffer.from(passwordHash(password, user.salt), 'hex');
  const expected = Buffer.from(user.passwordHash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const presetLabels = ['DELAY HARD', 'FOR CLOSE', 'SPAM OTP', 'CRASH C1', 'LOCK CHAT'];
const presetMeta = path.join(PRESET_DIR, 'index.json');
let presets = {};
try {
  presets = JSON.parse(fs.readFileSync(presetMeta, 'utf8'));
} catch {
  presets = {};
}

function savePresets() {
  fs.writeFileSync(presetMeta, JSON.stringify(presets, null, 2));
}

function safeLabel(value) {
  return presetLabels.find(
    x => x.toLowerCase() === String(value || '').trim().toLowerCase()
  ) || null;
}

function decodeHeader(value, fallback) {
  try {
    return decodeURIComponent(String(value || fallback));
  } catch {
    return fallback;
  }
}

function cleanFilename(value) {
  const base = path.basename(String(value || 'file.bin'))
    .replace(/[\r\n"\\/]/g, '_')
    .trim();
  return (base || 'file.bin').slice(0, 120);
}

function extension(name) {
  const ext = path.extname(name).toLowerCase();
  return /^\.[a-z0-9]{1,10}$/.test(ext) ? ext : '.bin';
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && aa.length > 0 && crypto.timingSafeEqual(aa, bb);
}

const ownerTokens = new Map();
const loginAttempts = new Map();

function requireOwner(req, res, next) {
  const token = String(req.get('x-owner-token') || '');
  const expires = ownerTokens.get(token);
  if (!token || !expires || expires < Date.now()) {
    ownerTokens.delete(token);
    return res.status(401).json({ ok: false, error: 'Login owner diperlukan.' });
  }
  next();
}

app.post('/api/auth/register', (req, res) => {
  const username = safeUsername(req.body?.username);
  const password = String(req.body?.password || '');

  if (!validUsername(username)) {
    return res.status(400).json({
      ok: false,
      error: 'Username harus 3–24 karakter: huruf, angka, garis bawah.'
    });
  }
  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ ok: false, error: 'Password harus 8–128 karakter.' });
  }
  if (database.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ ok: false, error: 'Username sudah dipakai.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const user = {
    id: crypto.randomUUID(),
    username,
    salt,
    passwordHash: passwordHash(password, salt),
    createdAt: new Date().toISOString()
  };
  database.users.push(user);
  saveDatabase();

  const token = issueAuth(user);
  res.status(201).json({
    ok: true,
    token,
    user: { id: user.id, username: user.username }
  });
});

app.post('/api/auth/login', (req, res) => {
  const username = safeUsername(req.body?.username);
  const password = String(req.body?.password || '');
  const user = database.users.find(
    u => u.username.toLowerCase() === username.toLowerCase()
  );
  if (!user || !verifyPassword(password, user)) {
    return res.status(401).json({ ok: false, error: 'Username atau password salah.' });
  }
  const token = issueAuth(user);
  res.json({ ok: true, token, user: { id: user.id, username: user.username } });
});

app.get('/api/auth/me', requireUser, (req, res) => {
  res.json({ ok: true, user: { id: req.user.id, username: req.user.username } });
});

app.post('/api/auth/logout', (req, res) => {
  authSessions.delete(getBearer(req));
  res.json({ ok: true });
});

app.get('/api/status', (_req, res) => res.json({ ok: true, online: io.engine.clientsCount }));
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, online: io.engine.clientsCount, uptime: Math.floor(process.uptime()) });
});

app.post('/api/owner/login', (req, res) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, until: 0 };
  if (entry.until > now) {
    return res.status(429).json({ ok: false, error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
  }
  if (!OWNER_PASSWORD || OWNER_PASSWORD === 'change-this-to-a-long-private-password') {
    return res.status(503).json({
      ok: false,
      error: 'Atur OWNER_PASSWORD di environment hosting terlebih dahulu.'
    });
  }
  if (!safeEqual(req.body?.password || '', OWNER_PASSWORD)) {
    entry.count += 1;
    if (entry.count >= 5) {
      entry.count = 0;
      entry.until = now + 10 * 60 * 1000;
    }
    loginAttempts.set(ip, entry);
    return res.status(401).json({ ok: false, error: 'Password owner salah.' });
  }
  loginAttempts.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  ownerTokens.set(token, now + 8 * 60 * 60 * 1000);
  res.json({ ok: true, token, expiresIn: 28800 });
});

app.post('/api/owner/logout', (req, res) => {
  ownerTokens.delete(String(req.get('x-owner-token') || ''));
  res.json({ ok: true });
});

app.get('/api/presets', (_req, res) => {
  const list = presetLabels
    .filter(label => presets[label] && fs.existsSync(path.join(PRESET_DIR, presets[label].storedName)))
    .map(name => ({
      name,
      fileName: presets[name].fileName,
      url: `/api/presets/download/${encodeURIComponent(name)}`
    }));
  res.json({ ok: true, presets: list });
});

app.get('/api/presets/download/:label', (req, res) => {
  const label = safeLabel(decodeURIComponent(req.params.label));
  const meta = label && presets[label];
  if (!meta || !meta.storedName || !fs.existsSync(path.join(PRESET_DIR, path.basename(meta.storedName)))) {
    return res.status(404).json({ ok: false, error: 'Preset belum diunggah.' });
  }
  res.download(path.join(PRESET_DIR, path.basename(meta.storedName)), cleanFilename(meta.fileName));
});

app.post(
  '/api/owner/presets/upload',
  requireOwner,
  express.raw({ type: 'application/octet-stream', limit: '5mb' }),
  (req, res) => {
    if (!Buffer.isBuffer(req.body) || !req.body.length) {
      return res.status(400).json({ ok: false, error: 'File kosong atau format upload tidak cocok.' });
    }
    const label = safeLabel(decodeHeader(req.get('x-preset-name'), ''));
    if (!label) return res.status(400).json({ ok: false, error: 'Nama preset tidak valid.' });

    const fileName = cleanFilename(decodeHeader(req.get('x-file-name'), 'upload.bin'));
    const storedName = `${crypto.createHash('sha256').update(label).digest('hex').slice(0, 16)}${extension(fileName)}`;
    fs.writeFileSync(path.join(PRESET_DIR, storedName), req.body);
    presets[label] = {
      fileName,
      storedName,
      size: req.body.length,
      updatedAt: new Date().toISOString()
    };
    savePresets();
    res.json({ ok: true, message: 'Preset berhasil diunggah.', name: label, fileName, size: req.body.length });
  }
);

const chatHistory = database.chatHistory;
const MAX_HISTORY = 100;
const users = new Map();

function safeName(value) {
  return String(value || 'Pengunjung').replace(/[<>\r\n]/g, '').trim().slice(0, 24) || 'Pengunjung';
}

function broadcastPresence() {
  io.emit('presence:count', users.size);
}

io.use((socket, next) => {
  const token = String(socket.handshake.auth?.token || '');
  const user = userForToken(token);
  if (!user) return next(new Error('Login diperlukan untuk chat.'));
  socket.data.user = { id: user.id, username: user.username };
  next();
});

io.on('connection', socket => {
  const username = safeName(socket.data.user.username);
  users.set(socket.id, username);
  socket.emit('chat:history', chatHistory);
  socket.emit('chat:joined', { username });
  broadcastPresence();

  socket.on('chat:send', payload => {
    if (!users.has(socket.id)) return socket.emit('chat:error', { message: 'Login ke panel dulu.' });
    const message = String(payload?.message || '').trim().slice(0, 1000);
    if (!message) return;
    const item = {
      id: crypto.randomUUID(),
      username: users.get(socket.id),
      message,
      kind: 'text',
      time: new Date().toISOString()
    };
    chatHistory.push(item);
    if (chatHistory.length > MAX_HISTORY) chatHistory.shift();
    database.chatHistory = chatHistory;
    saveDatabase();
    io.emit('chat:new', item);
  });

  socket.on('disconnect', () => {
    users.delete(socket.id);
    broadcastPresence();
  });
});

app.post(
  '/api/chat/upload',
  express.raw({ type: 'application/octet-stream', limit: '5mb' }),
  (req, res) => {
    if (!Buffer.isBuffer(req.body) || !req.body.length) {
      return res.status(400).json({ ok: false, error: 'File kosong atau terlalu besar.' });
    }
    const socketId = String(req.get('x-chat-socket') || '');
    const username = users.get(socketId);
    if (!username || !io.sockets.sockets.has(socketId)) {
      return res.status(401).json({ ok: false, error: 'Hubungkan chat terlebih dahulu.' });
    }
    const fileName = cleanFilename(decodeHeader(req.get('x-file-name'), 'chat-file.bin'));
    const id = crypto.randomUUID();
    const storedName = `${id}${extension(fileName)}`;
    fs.writeFileSync(path.join(CHAT_DIR, storedName), req.body);
    const url = `/api/chat/files/${storedName}`;
    const item = {
      id,
      username,
      message: fileName,
      fileName,
      url,
      kind: 'file',
      time: new Date().toISOString()
    };
    chatHistory.push(item);
    if (chatHistory.length > MAX_HISTORY) chatHistory.shift();
    database.chatHistory = chatHistory;
    saveDatabase();
    io.emit('chat:new', item);
    res.json({ ok: true, fileName, url });
  }
);

app.get('/api/chat/files/:file', (req, res) => {
  const file = path.basename(req.params.file);
  const full = path.join(CHAT_DIR, file);
  if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: 'File tidak ditemukan.' });
  res.sendFile(full);
});

// ---------------- WhatsApp / Baileys ----------------
const waSessions = new Map();

function normalizePhone(value) {
  return String(value || '').replace(/\D/g, '');
}

function validClientId(value) {
  return /^[a-f0-9-]{16,100}$/i.test(String(value || ''));
}

function getSession(req) {
  const id = String(req.query.clientId || req.body?.clientId || '');
  const token = String(req.get('x-wa-token') || req.body?.waToken || req.query.waToken || '');
  const session = waSessions.get(id);
  if (!session || !token || !safeEqual(token, session.token)) return null;
  return session;
}

async function startBaileys() {
  return import('@whiskeysockets/baileys');
}

function resolveBaileys(imported) {
  const nested = imported && imported.default && typeof imported.default === 'object'
    ? imported.default
    : null;
  const makeWASocket =
    (typeof imported?.default === 'function' && imported.default) ||
    (typeof imported?.makeWASocket === 'function' && imported.makeWASocket) ||
    (typeof nested?.default === 'function' && nested.default) ||
    (typeof nested?.makeWASocket === 'function' && nested.makeWASocket) || null;
  const useMultiFileAuthState = imported?.useMultiFileAuthState || nested?.useMultiFileAuthState || null;
  const fetchLatestBaileysVersion = imported?.fetchLatestBaileysVersion || nested?.fetchLatestBaileysVersion || null;

  if (typeof makeWASocket !== 'function') throw new TypeError('Baileys tidak mengekspor makeWASocket yang valid.');
  if (typeof useMultiFileAuthState !== 'function') throw new TypeError('Baileys tidak mengekspor useMultiFileAuthState yang valid.');
  if (typeof fetchLatestBaileysVersion !== 'function') {
    throw new TypeError('Baileys tidak mengekspor fetchLatestBaileysVersion yang valid. Periksa versi paket yang terpasang.');
  }
  return { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion };
}

function getDisconnectCode(update) {
  return update?.lastDisconnect?.error?.output?.statusCode ||
    update?.lastDisconnect?.error?.statusCode || null;
}

app.post('/api/whatsapp/pair', async (req, res) => {
  const clientId = String(req.body?.clientId || '');
  const phoneNumber = normalizePhone(req.body?.phoneNumber);

  if (!validClientId(clientId)) return res.status(400).json({ ok: false, error: 'clientId tidak valid.' });
  if (phoneNumber.length < 8 || phoneNumber.length > 16) {
    return res.status(400).json({ ok: false, error: 'Nomor harus memakai kode negara, angka saja.' });
  }

  let session = waSessions.get(clientId);
  if (session && session.phoneNumber !== phoneNumber) {
    return res.status(409).json({ ok: false, error: 'Client ID ini sudah dipakai nomor lain. Buat sesi baru.' });
  }

  if (!session) {
    session = {
      clientId,
      phoneNumber,
      token: crypto.randomBytes(32).toString('hex'),
      status: 'starting',
      pairingCode: null,
      sock: null,
      authDir: path.join(WA_DIR, clientId),
      requesting: false,
      error: null,
      lastDisconnectCode: null
    };
    waSessions.set(clientId, session);
  }

  // Keep the existing frontend contract: respond immediately, then let status polling
  // receive the pairing code or connection error.
  res.json({
    ok: true,
    clientId,
    waToken: session.token,
    status: session.status,
    pairingCode: session.pairingCode,
    message: 'Sesi dimulai. Simpan token sesi ini di perangkatmu.'
  });

  if (session.sock || session.requesting) return;
  session.requesting = true;
  session.status = 'starting';
  session.error = null;

  try {
    const imported = await startBaileys();
    const { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion } = resolveBaileys(imported);
    fs.mkdirSync(session.authDir, { recursive: true });
    const { state, saveCreds } = await useMultiFileAuthState(session.authDir);

    // 405 can happen when the bundled WA Web revision is stale. Fetch the live
    // revision from WhatsApp Web before opening the Baileys socket.
    let waVersion;
    try {
      const latest = await fetchLatestBaileysVersion();
      if (Array.isArray(latest?.version) && latest.version.length === 3 && latest.version.every(Number.isFinite)) {
        waVersion = latest.version;
        console.log('[WA] WhatsApp Web version:', waVersion.join('.'), 'isLatest:', latest.isLatest);
        if (latest.error) console.warn('[WA] Version fetch warning:', latest.error.message || latest.error);
      } else {
        throw new Error(latest?.error?.message || 'Versi WhatsApp Web tidak valid.');
      }
    } catch (versionError) {
      console.error('[WA] Gagal mengambil versi WhatsApp Web terbaru:', versionError?.message || versionError);
      throw new Error('Tidak bisa mengambil versi WhatsApp Web terbaru. Coba lagi beberapa saat.');
    }

    const sock = makeWASocket({
      version: waVersion,
      auth: state,
      logger: pino({ level: 'warn' }),
      browser: ['HOLLOW PANEL', 'Chrome', '1.0.0'],
      printQRInTerminal: false,
      markOnlineOnConnect: false,
      connectTimeoutMs: 60_000,
      defaultQueryTimeoutMs: 60_000
    });

    session.sock = sock;
    let pairingRequested = false;
    let pairingTimer = null;

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', update => {
      if (session.sock !== sock) return;

      if (update.connection === 'connecting') {
        if (session.status !== 'pairing') session.status = 'starting';
      }

      if (update.connection === 'open') {
        if (pairingTimer) clearTimeout(pairingTimer);
        session.status = 'connected';
        session.pairingCode = null;
        session.error = null;
        session.lastDisconnectCode = null;
        session.requesting = false;
        console.log('[WA] Connected:', clientId);
      }

      if (update.connection === 'close') {
        if (pairingTimer) clearTimeout(pairingTimer);
        const statusCode = getDisconnectCode(update);
        const detail = update.lastDisconnect?.error?.message || 'Koneksi ditutup.';
        console.error('[WA] Connection closed. Status code:', statusCode, 'Detail:', detail);
        session.lastDisconnectCode = statusCode;
        session.status = 'disconnected';
        session.sock = null;
        session.requesting = false;
        if (statusCode === 405) {
          session.error = 'WhatsApp menolak proses koneksi (405). Versi Web sudah diperbarui; periksa log dan coba buat sesi baru setelah beberapa saat.';
        } else {
          session.error = `Koneksi WhatsApp terputus${statusCode ? ` (${statusCode})` : ''}. Coba mulai sesi kembali.`;
        }
      }
    });

    if (state.creds.registered) {
      session.status = 'starting';
      session.requesting = false;
      console.log('[WA] Auth tersimpan; menunggu koneksi:', clientId);
    } else {
      // Give the websocket a moment to initialize before asking for a pairing code.
      pairingTimer = setTimeout(async () => {
        if (session.sock !== sock || pairingRequested || state.creds.registered) return;
        pairingRequested = true;
        try {
          const code = await sock.requestPairingCode(phoneNumber);
          if (session.sock !== sock || session.status === 'connected') return;
          session.pairingCode = String(code).replace(/[^A-Z0-9]/gi, '').match(/.{1,4}/g)?.join('-') || String(code);
          session.status = 'pairing';
          session.error = null;
          session.requesting = false;
          console.log('[WA] Pairing code generated for client:', clientId);
        } catch (pairError) {
          console.error('[WA] Pairing-code error:', pairError?.stack || pairError);
          if (session.sock === sock) {
            session.status = 'error';
            session.error = 'Kode pairing gagal dibuat. Periksa log Render untuk detail.';
            session.requesting = false;
          }
        }
      }, 2500);
    }
  } catch (e) {
    console.error('[WA] Failed to start:', e?.stack || e);
    session.status = 'error';
    session.error = e?.message || 'WhatsApp gagal dimulai. Periksa log Render.';
    session.requesting = false;
    if (session.sock) {
      try { session.sock.end(undefined); } catch {}
    }
    session.sock = null;
  }
});

app.get('/api/whatsapp/status', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Token sesi WhatsApp tidak valid.' });
  res.json({
    ok: true,
    status: session.status,
    pairingCode: session.pairingCode,
    error: session.error,
    lastDisconnectCode: session.lastDisconnectCode
  });
});

app.post('/api/whatsapp/disconnect', async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Token sesi WhatsApp tidak valid.' });
  const sock = session.sock;
  session.sock = null;
  session.status = 'disconnected';
  session.pairingCode = null;
  session.requesting = false;
  session.error = null;
  try { if (sock) await sock.logout(); } catch {}
  try { if (sock) sock.end(undefined); } catch {}
  res.json({ ok: true, status: session.status });
});

app.post('/api/whatsapp/send-file', async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Token sesi WhatsApp tidak valid.' });
  if (session.status !== 'connected' || !session.sock) {
    return res.status(409).json({ ok: false, error: 'WhatsApp belum terhubung.' });
  }

  const label = safeLabel(req.body?.presetName);
  const phone = normalizePhone(req.body?.phoneNumber || session.phoneNumber);
  const meta = label && presets[label];
  if (!meta || !meta.storedName || !fs.existsSync(path.join(PRESET_DIR, path.basename(meta.storedName)))) {
    return res.status(404).json({ ok: false, error: 'Preset belum diunggah owner.' });
  }
  if (phone.length < 8 || phone.length > 16) {
    return res.status(400).json({ ok: false, error: 'Nomor tujuan tidak valid.' });
  }
  if (phone !== session.phoneNumber) {
    return res.status(403).json({ ok: false, error: 'Pengiriman hanya diizinkan ke nomor WhatsApp yang ditautkan pada sesi ini.' });
  }

  try {
    const full = path.join(PRESET_DIR, path.basename(meta.storedName));
    const jid = `${phone}@s.whatsapp.net`;
    await session.sock.sendMessage(jid, {
      document: fs.readFileSync(full),
      fileName: cleanFilename(meta.fileName),
      mimetype: 'application/octet-stream',
      caption: `File: ${label}`
    });
    res.json({ ok: true, message: 'File berhasil dikirim.', fileName: meta.fileName });
  } catch (e) {
    console.error('[WA] Send file error:', e?.stack || e);
    res.status(500).json({ ok: false, error: 'Pengiriman gagal. Periksa koneksi WhatsApp dan nomor tujuan.' });
  }
});

app.use((err, _req, res, _next) => {
  if (err?.type === 'entity.too.large' || err?.status === 413) {
    return res.status(413).json({ ok: false, error: 'File maksimal 5 MB.' });
  }
  console.error(err);
  res.status(500).json({ ok: false, error: 'Terjadi kesalahan server.' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`KING DAFFZZ berjalan di port ${PORT}`);
});
