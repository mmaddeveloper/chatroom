
// server.js — Chatroom (SQLite persistence + NAT-friendly rate limiting)
// Features: open/password/request/invite + private visibility, members, per-channel kick/ban/mute,
// join requests + invites, channel settings UI, dark/light theme UI.
//
// Run:
//   npm i
//   npm start
//
// Notes:
// - Uses SQLite for persistence (chatroom.db). This replaces JSON as the storage layer.
// - On first run, if ./data/*.json exists (from older packs), it will import them once.

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');

const compression = require('compression');
const bcrypt = require('bcryptjs');

const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(compression());

// cache static assets (except html) for a short time
app.use((req, res, next) => {
  if (req.method === 'GET' && req.url && !req.url.endsWith('.html')) {
    res.setHeader('Cache-Control', 'public, max-age=300');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/health', async (req,res)=>{
  try{
    const r = await db.get('SELECT 1 as ok');
    res.json({ ok:true, db: !!r, ts: Date.now() });
  }catch(e){
    res.status(500).json({ ok:false, error:'db', ts: Date.now() });
  }
});

function now() { return Date.now(); }
function iso(ts) { return new Date(ts).toISOString(); }

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
ensureDir(path.join(__dirname, 'data')); // for optional legacy import

// -------------------- NAT-friendly rate limiting (in-memory) --------------------
const LOGIN_IP_LIMIT = { windowMs: 2 * 60 * 1000, max: 20 };      // shared IP total
const LOGIN_USER_LIMIT = { windowMs: 2 * 60 * 1000, max: 8 };     // per username
const LOGIN_IPUSER_LIMIT = { windowMs: 2 * 60 * 1000, max: 8 };   // per ip+username
const MSG_SOCKET_LIMIT = { windowMs: 3000, max: 6 };              // per socket
const MSG_USER_LIMIT = { windowMs: 5000, max: 10 };               // per user
const MSG_CHANNEL_LIMIT = { windowMs: 5000, max: 30 };            // per channel

const buckets = new Map(); // key -> {count, resetAt}

function allow(key, rule) {
  const t = now();
  const b = buckets.get(key);
  if (!b || t > b.resetAt) {
    buckets.set(key, { count: 1, resetAt: t + rule.windowMs });
    return true;
  }
  if (b.count >= rule.max) return false;
  b.count += 1;
  return true;
}
function resetBucket(key) { buckets.delete(key); }

// periodic cleanup
setInterval(() => {
  const t = now();
  for (const [k, v] of buckets) {
    if (t > v.resetAt + 60000) buckets.delete(k);
  }
}, 5 * 60 * 1000);

// best-effort real IP behind proxy (optional)
app.set('trust proxy', true);
function getClientIp(socket) {
  // socket.io exposes handshake headers; trust proxy enabled above for express routes,
  // but for socket we parse X-Forwarded-For.
  const h = socket.handshake || {};
  const xff = (h.headers && (h.headers['x-forwarded-for'] || h.headers['X-Forwarded-For'])) || '';
  if (xff) return String(xff).split(',')[0].trim();
  return (h.address ? String(h.address) : 'unknown');
}

// -------------------- SQLite --------------------
let db;

async function initDb() {
  db = await open({
    filename: path.join(__dirname, 'chatroom.db'),
    driver: sqlite3.Database
  });

  await db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA foreign_keys=ON;

    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      is_banned INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      last_seen INTEGER
    );

    CREATE TABLE IF NOT EXISTS channels (
      name TEXT PRIMARY KEY,
      settings_json TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS channel_members (
      channel TEXT NOT NULL,
      username TEXT NOT NULL,
      PRIMARY KEY(channel, username),
      FOREIGN KEY(channel) REFERENCES channels(name) ON DELETE CASCADE,
      FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS channel_bans (
      channel TEXT NOT NULL,
      username TEXT NOT NULL,
      PRIMARY KEY(channel, username),
      FOREIGN KEY(channel) REFERENCES channels(name) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS channel_mutes (
      channel TEXT NOT NULL,
      username TEXT NOT NULL,
      until INTEGER,
      PRIMARY KEY(channel, username),
      FOREIGN KEY(channel) REFERENCES channels(name) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel TEXT NOT NULL,
      sender TEXT NOT NULL,
      text TEXT NOT NULL,
      ts INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_channel_ts ON messages(channel, ts);

    CREATE TABLE IF NOT EXISTS join_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel TEXT NOT NULL,
      username TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_joinreq_channel ON join_requests(channel);

    CREATE TABLE IF NOT EXISTS invites (
      token TEXT PRIMARY KEY,
      channel TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER,
      max_uses INTEGER NOT NULL DEFAULT 1,
      uses INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_invites_channel ON invites(channel);
  `);

  await ensureCoreData();
  await importLegacyJsonIfPresent();
  await pruneInvites();
}

// Default channels
function defaultChannelSettings(owner = 'admin') {
  return {
    visibility: 'public',      // public|private
    joinPolicy: 'open',        // open|password|request|invite
    passwordHash: null,        // bcrypt hash if joinPolicy=password
    allowedRoles: null,        // null => all
    owner,
    mods: []
  };
}

async function ensureCoreData() {
  // Ensure admin exists
  const admin = await db.get(`SELECT username FROM users WHERE username='admin'`);
  if (!admin) {
    // default admin password: admin (change later)
    const hash = bcrypt.hashSync('admin', 10);
    await db.run(
      `INSERT INTO users(username, password_hash, role, is_banned, created_at) VALUES(?,?,?,?,?)`,
      ['admin', hash, 'admin', 0, now()]
    );
  }

  // Ensure some channels exist
  const names = ['General', 'VIP', 'Requests', 'PrivateTeam'];
  for (const name of names) {
    const exists = await db.get(`SELECT name FROM channels WHERE name=?`, [name]);
    if (!exists) {
      let s = defaultChannelSettings('admin');
      if (name === 'VIP') s = { ...s, joinPolicy: 'password', passwordHash: bcrypt.hashSync('1234', 10), allowedRoles: ['vip', 'admin'] };
      if (name === 'Requests') s = { ...s, joinPolicy: 'request' };
      if (name === 'PrivateTeam') s = { ...s, visibility: 'private', joinPolicy: 'invite' };
      await db.run(`INSERT INTO channels(name, settings_json, created_at) VALUES(?,?,?)`, [name, JSON.stringify(s), now()]);
    }
  }

  // Ensure admin is member of the default channels
  for (const name of names) {
    await db.run(`INSERT OR IGNORE INTO channel_members(channel, username) VALUES(?,?)`, [name, 'admin']);
  }
}

async function importLegacyJsonIfPresent() {
  const dataDir = path.join(__dirname, 'data');
  const usersPath = path.join(dataDir, 'users.json');
  const channelsPath = path.join(dataDir, 'channels.json');
  const invitesPath = path.join(dataDir, 'invites.json');
  const joinReqPath = path.join(dataDir, 'join_requests.json');
  const messagesPath = path.join(dataDir, 'messages.json');

  const marker = path.join(dataDir, '.imported_to_sqlite');
  if (fs.existsSync(marker)) return;

  const hasAny =
    fs.existsSync(usersPath) ||
    fs.existsSync(channelsPath) ||
    fs.existsSync(invitesPath) ||
    fs.existsSync(joinReqPath) ||
    fs.existsSync(messagesPath);

  if (!hasAny) return;

  const safeRead = (p, def) => {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return def; }
  };

  // users.json: { username: {passwordHash|password, role, isBanned, created_at, last_seen}}
  if (fs.existsSync(usersPath)) {
    const u = safeRead(usersPath, {});
    for (const [username, rec] of Object.entries(u || {})) {
      if (!username) continue;
      const existing = await db.get(`SELECT username FROM users WHERE username=?`, [username]);
      if (existing) continue;

      let ph = rec.passwordHash;
      if (!ph && typeof rec.password === 'string') ph = bcrypt.hashSync(rec.password, 10);
      if (!ph) continue;

      await db.run(
        `INSERT INTO users(username, password_hash, role, is_banned, created_at, last_seen) VALUES(?,?,?,?,?,?)`,
        [
          username,
          ph,
          rec.role || 'user',
          rec.isBanned ? 1 : 0,
          rec.created_at || now(),
          rec.last_seen || null
        ]
      );
    }
  }

  // channels.json: array of {name, settings, members, bans, mutes}
  if (fs.existsSync(channelsPath)) {
    const arr = safeRead(channelsPath, []);
    for (const ch of (arr || [])) {
      if (!ch || !ch.name) continue;
      const exists = await db.get(`SELECT name FROM channels WHERE name=?`, [ch.name]);
      if (!exists) {
        const s = ch.settings || defaultChannelSettings('admin');
        // migrate channel password to hash if needed
        if (s.joinPolicy === 'password') {
          if (!s.passwordHash && typeof s.password === 'string' && s.password.length) {
            s.passwordHash = bcrypt.hashSync(s.password, 10);
          }
          delete s.password;
        }
        await db.run(`INSERT INTO channels(name, settings_json, created_at) VALUES(?,?,?)`, [ch.name, JSON.stringify(s), now()]);
      }

      // members
      for (const u of (ch.members || [])) {
        await db.run(`INSERT OR IGNORE INTO channel_members(channel, username) VALUES(?,?)`, [ch.name, u]);
      }

      // bans
      for (const u of (ch.bans || [])) {
        await db.run(`INSERT OR IGNORE INTO channel_bans(channel, username) VALUES(?,?)`, [ch.name, u]);
      }

      // mutes: {username:{until}}
      const m = ch.mutes || {};
      for (const [u, rec] of Object.entries(m)) {
        await db.run(`INSERT OR REPLACE INTO channel_mutes(channel, username, until) VALUES(?,?,?)`, [ch.name, u, rec && rec.until ? rec.until : null]);
      }
    }
  }

  // invites.json: array
  if (fs.existsSync(invitesPath)) {
    const inv = safeRead(invitesPath, []);
    for (const it of (inv || [])) {
      if (!it || !it.token || !it.channel) continue;
      await db.run(
        `INSERT OR IGNORE INTO invites(token, channel, created_at, expires_at, max_uses, uses) VALUES(?,?,?,?,?,?)`,
        [it.token, it.channel, it.createdAt || now(), it.expiresAt || null, it.maxUses ?? 1, it.uses ?? 0]
      );
    }
  }

  // join_requests.json: array {channel,username,createdAt}
  if (fs.existsSync(joinReqPath)) {
    const jr = safeRead(joinReqPath, []);
    for (const it of (jr || [])) {
      if (!it || !it.channel || !it.username) continue;
      await db.run(
        `INSERT INTO join_requests(channel, username, created_at) VALUES(?,?,?)`,
        [it.channel, it.username, it.createdAt || now()]
      );
    }
  }

  // messages.json: { channel:[{sender,text,timestamp}] } or {}
  if (fs.existsSync(messagesPath)) {
    const m = safeRead(messagesPath, {});
    for (const [channel, arr] of Object.entries(m || {})) {
      for (const msg of (arr || [])) {
        if (!msg || !msg.sender || !msg.text) continue;
        const ts = msg.ts || msg.timestamp || now();
        await db.run(`INSERT INTO messages(channel, sender, text, ts) VALUES(?,?,?,?)`, [channel, msg.sender, msg.text, ts]);
      }
    }
  }

  fs.writeFileSync(marker, String(now()));
}

// -------------------- Helpers: channels/settings/members --------------------
async function getChannelSettings(channel) {
  const row = await db.get(`SELECT settings_json FROM channels WHERE name=?`, [channel]);
  if (!row) return null;
  try { return JSON.parse(row.settings_json); } catch { return defaultChannelSettings('admin'); }
}

async function setChannelSettings(channel, patch) {
  const cur = await getChannelSettings(channel);
  if (!cur) return false;

  const next = { ...cur, ...patch };

  // Normalize password storage
  if (next.joinPolicy !== 'password') {
    next.passwordHash = null;
  } else {
    // patch can include passwordPlain in patch._passwordPlain
    if (patch && patch._passwordPlain !== undefined) {
      const pw = patch._passwordPlain;
      if (pw === null || pw === '') next.passwordHash = null;
      else next.passwordHash = bcrypt.hashSync(String(pw), 10);
    }
  }

  await db.run(`UPDATE channels SET settings_json=? WHERE name=?`, [JSON.stringify(next), channel]);
  return true;
}

async function listChannelsForClient(me) {
  // Show public channels; plus private channels where user is a member
  const rows = await db.all(`SELECT name, settings_json FROM channels`);
  const memberPriv = await db.all(`SELECT channel FROM channel_members WHERE username=?`, [me?.username || '']);
  const memberSet = new Set(memberPriv.map(r => r.channel));

  const out = [];
  for (const r of rows) {
    let s;
    try { s = JSON.parse(r.settings_json); } catch { s = defaultChannelSettings('admin'); }
    const visibility = s.visibility || 'public';
    if (visibility === 'private' && !memberSet.has(r.name)) continue;

    out.push({
      name: r.name,
      visibility: visibility,
      joinPolicy: s.joinPolicy || 'open',
      allowedRoles: s.allowedRoles || null
    });
  }
  // sort
  out.sort((a,b)=>a.name.localeCompare(b.name));
  return out;
}

async function isMember(channel, username) {
  const r = await db.get(`SELECT 1 FROM channel_members WHERE channel=? AND username=?`, [channel, username]);
  return !!r;
}

async function addMember(channel, username) {
  await db.run(`INSERT OR IGNORE INTO channel_members(channel, username) VALUES(?,?)`, [channel, username]);
}

async function removeMember(channel, username) {
  await db.run(`DELETE FROM channel_members WHERE channel=? AND username=?`, [channel, username]);
}

async function listMembers(channel) {
  const rows = await db.all(`SELECT username FROM channel_members WHERE channel=? ORDER BY username`, [channel]);
  return rows.map(r=>r.username);
}

async function listBans(channel) {
  const rows = await db.all(`SELECT username FROM channel_bans WHERE channel=? ORDER BY username`, [channel]);
  return rows.map(r=>r.username);
}

async function isBanned(channel, username) {
  const r = await db.get(`SELECT 1 FROM channel_bans WHERE channel=? AND username=?`, [channel, username]);
  return !!r;
}

async function banUser(channel, username) {
  await db.run(`INSERT OR IGNORE INTO channel_bans(channel, username) VALUES(?,?)`, [channel, username]);
  await removeMember(channel, username);
}

async function unbanUser(channel, username) {
  await db.run(`DELETE FROM channel_bans WHERE channel=? AND username=?`, [channel, username]);
}

async function getMute(channel, username) {
  const r = await db.get(`SELECT until FROM channel_mutes WHERE channel=? AND username=?`, [channel, username]);
  if (!r) return null;
  if (!r.until) return { until: null };
  if (now() > r.until) {
    await db.run(`DELETE FROM channel_mutes WHERE channel=? AND username=?`, [channel, username]);
    return null;
  }
  return { until: r.until };
}

async function muteUser(channel, username, minutes) {
  const until = minutes ? now() + minutes * 60 * 1000 : null;
  await db.run(`INSERT OR REPLACE INTO channel_mutes(channel, username, until) VALUES(?,?,?)`, [channel, username, until]);
  return until;
}

// -------------------- Invites --------------------
function randomToken(len=20){
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  for(let i=0;i<len;i++) s += chars[Math.floor(Math.random()*chars.length)];
  return s;
}

async function pruneInvites(){
  const t = now();
  await db.run(`DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at < ?`, [t]);
  await db.run(`DELETE FROM invites WHERE max_uses >= 0 AND uses >= max_uses`);
}

setInterval(()=>{ pruneInvites().catch(()=>{}); }, 10*60*1000);

async function findActiveInvite(channel, token){
  await pruneInvites();
  const r = await db.get(`SELECT * FROM invites WHERE token=? AND channel=?`, [token, channel]);
  if (!r) return null;
  if (r.expires_at && now() > r.expires_at) return null;
  if (typeof r.max_uses === 'number' && r.max_uses >= 0 && r.uses >= r.max_uses) return null;
  return r;
}

// -------------------- Join requests --------------------
async function hasPendingJoinRequest(channel, username){
  const r = await db.get(`SELECT 1 FROM join_requests WHERE channel=? AND username=?`, [channel, username]);
  return !!r;
}

async function listJoinRequests(channel){
  const rows = await db.all(`SELECT username, created_at FROM join_requests WHERE channel=? ORDER BY created_at DESC`, [channel]);
  return rows.map(r=>({ username: r.username, createdAt: r.created_at }));
}

async function addJoinRequest(channel, username){
  await db.run(`INSERT INTO join_requests(channel, username, created_at) VALUES(?,?,?)`, [channel, username, now()]);
}

async function removeJoinRequest(channel, username){
  await db.run(`DELETE FROM join_requests WHERE channel=? AND username=?`, [channel, username]);
}

// -------------------- Messages --------------------
async function addMessage(channel, sender, text){
  const ts = now();
  await db.run(`INSERT INTO messages(channel, sender, text, ts) VALUES(?,?,?,?)`, [channel, sender, text, ts]);
  // keep DB from growing forever: keep last 3000 messages per channel (simple)
  await db.run(`
    DELETE FROM messages
    WHERE id IN (
      SELECT id FROM messages
      WHERE channel=?
      ORDER BY ts DESC
      LIMIT -1 OFFSET 3000
    )
  `, [channel]);
  return { channel, sender, text, timestamp: new Date(ts).toLocaleString('fa-IR'), ts };
}

async function getHistory(channel, limit=100){
  const rows = await db.all(`SELECT sender, text, ts FROM messages WHERE channel=? ORDER BY ts DESC LIMIT ?`, [channel, limit]);
  rows.reverse();
  return rows.map(r=>({ sender: r.sender, text: r.text, ts: r.ts, timestamp: new Date(r.ts).toLocaleString('fa-IR') }));
}

// -------------------- Auth / roles --------------------
async function getUser(username){
  return await db.get(`SELECT * FROM users WHERE username=?`, [username]);
}
async function setLastSeen(username){
  await db.run(`UPDATE users SET last_seen=? WHERE username=?`, [now(), username]);
}

function isAdmin(me){ return me && me.role === 'admin'; }

async function canManageChannel(me, channel){
  if (!me) return false;
  if (isAdmin(me)) return true;
  const s = await getChannelSettings(channel);
  if (!s) return false;
  if (s.owner && s.owner === me.username) return true;
  if (Array.isArray(s.mods) && s.mods.includes(me.username)) return true;
  return false;
}

function roleAllowed(settings, role){
  const allowed = settings.allowedRoles;
  if (!allowed || !Array.isArray(allowed) || allowed.length === 0) return true;
  return allowed.includes(role);
}

// -------------------- Socket logic --------------------
const online = new Map(); // socket.id -> {username, role}

function broadcastOnline(){
  const list = Array.from(online.values()).map(u=>({username:u.username, role:u.role}));
  io.emit('user_list', list);
}

let channelsBroadcastTimer = null;
function scheduleChannelsBroadcast(){
  if (channelsBroadcastTimer) return;
  channelsBroadcastTimer = setTimeout(async ()=>{
    channelsBroadcastTimer = null;
    for (const s of io.sockets.sockets.values()){
      const m = s.data.me;
      if (!m) continue;
      try{ await emitChannelsTo(s, m); }catch(e){}
    }
  }, 250);
}

async function emitChannelsTo(socket, me){
  const chs = await listChannelsForClient(me);
  // legacy + v2
  socket.emit('update_channels', chs.map(x=>x.name));
  socket.emit('update_channels_v2', chs);
}

async function joinChannelForce(socket, me, channel, isPrivate=false){
  socket.join(channel);
  socket.emit('channel_joined', { name: channel, isPrivate, canManage: isPrivate ? false : await canManageChannel(me, channel) });
  const hist = await getHistory(channel, 100);
  socket.emit('history', hist);
}

async function handleJoinChannel(socket, me, payload){
  const channel = (typeof payload === 'string') ? payload : payload.channel;
  const password = (payload && payload.password) ? payload.password : null;
  const inviteToken = (payload && payload.inviteToken) ? payload.inviteToken : null;

  const row = await db.get(`SELECT settings_json FROM channels WHERE name=?`, [channel]);
  if (!row) return socket.emit('join_denied', { channel, reason: 'کانال وجود ندارد.' });

  const settings = JSON.parse(row.settings_json || "{}");
  const isPriv = (settings.visibility === 'private');
  const isMem = await isMember(channel, me.username);
  const canMgr = await canManageChannel(me, channel);

  if (!roleAllowed(settings, me.role)) {
    return socket.emit('join_denied', { channel, reason: 'نقش شما اجازه ورود ندارد.' });
  }

  if (await isBanned(channel, me.username)) {
    return socket.emit('join_denied', { channel, reason: 'شما در این کانال بن شده‌اید.' });
  }

  const policy = settings.joinPolicy || 'open';
  // Private visibility rule:
  // - If already member/manager -> normal
  // - If not member and not manager:
  //   - allow request policy (create request)
  //   - allow invite policy (if token valid)
  //   - otherwise deny
  if (isPriv && !isMem && !canMgr) {
    if (policy !== 'invite' && policy !== 'request') {
      return socket.emit('join_denied', { channel, reason: 'این کانال خصوصی است.' });
    }
  }


  if (policy === 'password') {
    if (!settings.passwordHash) {
      return joinChannelForce(socket, me, channel, false);
    }
    if (!password || !bcrypt.compareSync(String(password||''), String(settings.passwordHash))) {
      return socket.emit('join_denied', { channel, reason: 'رمز کانال اشتباه است.', needsPassword: true });
    }
    return joinChannelForce(socket, me, channel, false);
  }

  if (policy === 'invite') {
    if (!inviteToken) return socket.emit('join_denied', { channel, reason: 'توکن دعوت لازم است.', needsInvite: true });
    const inv = await findActiveInvite(channel, inviteToken);
    if (!inv) return socket.emit('join_denied', { channel, reason: 'توکن دعوت نامعتبر یا منقضی است.' });

    // consume
    await db.run(`UPDATE invites SET uses=uses+1 WHERE token=?`, [inviteToken]);
    // add member
    await addMember(channel, me.username);
    return joinChannelForce(socket, me, channel, false);
  }

  if (policy === 'request') {
    const isMem2 = await isMember(channel, me.username);
    if (isMem2) return joinChannelForce(socket, me, channel, false);

    if (await hasPendingJoinRequest(channel, me.username)) {
      return socket.emit('join_pending', { channel, message: 'درخواست شما قبلاً ثبت شده است.' });
    }
    await addJoinRequest(channel, me.username);
    return socket.emit('join_pending', { channel, message: 'درخواست ثبت شد. منتظر تایید مدیر بمانید.' });
  }

  // open
  await addMember(channel, me.username);
  return joinChannelForce(socket, me, channel, false);
}

// Private chat channel name helper
function privateRoom(a,b){
  const [x,y] = [a,b].sort((m,n)=>String(m).localeCompare(String(n)));
  return `__pv__${x}__${y}`;
}

io.on('connection', (socket) => {

  socket.on('login', async ({ username, password }) => {
    try{
      username = (username||'').trim();
      password = (password||'').trim();
      if (!username || !password) return socket.emit('login_error', 'نام کاربری و رمز را وارد کن');

      const ip = getClientIp(socket);
      // NAT-friendly: use 3 buckets
      if (!allow(`login:ip:${ip}`, LOGIN_IP_LIMIT) ||
          !allow(`login:user:${username}`, LOGIN_USER_LIMIT) ||
          !allow(`login:ipuser:${ip}:${username}`, LOGIN_IPUSER_LIMIT)) {
        return socket.emit('login_error', 'تلاش زیاد! لطفاً کمی بعد دوباره امتحان کنید.');
      }

      let u = await getUser(username);
      if (!u) {
        // create
        const hash = bcrypt.hashSync(password, 10);
        await db.run(`INSERT INTO users(username, password_hash, role, is_banned, created_at, last_seen) VALUES(?,?,?,?,?,?)`,
          [username, hash, 'user', 0, now(), now()]
        );
        u = await getUser(username);
      } else {
        if (u.is_banned) return socket.emit('login_error', 'حساب کاربری شما مسدود شده است.');
        const ok = bcrypt.compareSync(password, u.password_hash);
        if (!ok) return socket.emit('login_error', 'رمز عبور اشتباه است.');
        await setLastSeen(username);
      }

      // success -> reset user bucket (so NAT doesn't punish successful auth)
      resetBucket(`login:user:${username}`);
      resetBucket(`login:ipuser:${ip}:${username}`);

      socket.data.me = { username: u.username, role: u.role };
      online.set(socket.id, socket.data.me);
      broadcastOnline();

      // send legacy channels for older clients + v2 meta for our UI
      const meta = await listChannelsForClient(socket.data.me);
      socket.emit('login_success', { username: u.username, role: u.role, channels: meta.map(x=>x.name) });
      socket.emit('update_channels', meta.map(x=>x.name));
      socket.emit('update_channels_v2', meta);

    }catch(e){
      console.error(e);
      socket.emit('login_error', 'خطا در ورود');
    }
  });

  socket.on('get_channels_v2', async ()=>{
    const me = socket.data.me;
    if (!me) return;
    await emitChannelsTo(socket, me);
  });

  socket.on('join_channel', async (payload) => {
    const me = socket.data.me;
    if (!me) return socket.emit('join_denied', { channel: '', reason: 'ابتدا وارد شوید.' });
    await handleJoinChannel(socket, me, payload);
  });

  socket.on('join_private', async (otherUsername) => {
    const me = socket.data.me;
    if (!me) return;
    otherUsername = String(otherUsername||'').trim();
    if (!otherUsername) return;
    const other = await getUser(otherUsername);
    if (!other) return socket.emit('action_error', 'کاربر وجود ندارد');
    const room = privateRoom(me.username, otherUsername);
    await joinChannelForce(socket, me, room, true);
  });

  socket.on('send_message', async (data) => {
    const me = socket.data.me;
    if (!me) return;

    const channel = data && data.channel ? String(data.channel) : null;
    const text = data && data.text ? String(data.text) : '';
    if (!channel || !text.trim()) return;

    // message rate limit: socket + user + channel
    const ip = getClientIp(socket);
    if (!allow(`msg:sock:${socket.id}`, MSG_SOCKET_LIMIT) ||
        !allow(`msg:user:${me.username}`, MSG_USER_LIMIT) ||
        !allow(`msg:chan:${channel}`, MSG_CHANNEL_LIMIT)) {
      return socket.emit('action_error', 'پیام زیاد ارسال شد — لطفاً کمی صبر کنید.');
    }

    // mute check (only for public channels, not pv)
    if (!channel.startsWith('__pv__')) {
      const mute = await getMute(channel, me.username);
      if (mute) {
        socket.emit('muted_in_channel', { channel, until: mute.until || null });
        return;
      }
    }

    const msg = await addMessage(channel, me.username, text.trim());
    io.to(channel).emit('receive_message', msg);
  });

  // ----- Channel settings -----
  socket.on('get_channel_settings', async ({ channel }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    const s = await getChannelSettings(channel);
    if (!s) return socket.emit('action_error', 'کانال پیدا نشد');
    const canManage = await canManageChannel(me, channel);
    const membersCount = (await db.get(`SELECT COUNT(*) as c FROM channel_members WHERE channel=?`, [channel])).c;
    socket.emit('channel_settings', { channel, settings: { ...s, password: null }, canManage, membersCount });
  });

  socket.on('update_channel_settings', async ({ channel, settings }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    // settings from client may include: visibility, joinPolicy, password, allowedRoles, mods
    const patch = {};
    if (settings && (settings.visibility==='public' || settings.visibility==='private')) patch.visibility = settings.visibility;
    if (settings && settings.joinPolicy) patch.joinPolicy = settings.joinPolicy;

    if (settings && Array.isArray(settings.allowedRoles)) patch.allowedRoles = settings.allowedRoles.length ? settings.allowedRoles : null;
    if (settings && settings.allowedRoles === null) patch.allowedRoles = null;

    if (settings && Array.isArray(settings.mods)) patch.mods = settings.mods;

    // channel password: accept settings.password as plain, store only as hash
    if (patch.joinPolicy === 'password') {
      patch._passwordPlain = (settings.password === undefined) ? undefined : (settings.password ?? null);
    }

    await setChannelSettings(channel, patch);

    socket.emit('action_success', `تنظیمات کانال "${channel}" ذخیره شد.`);
    // broadcast updated channel metadata to all
    scheduleChannelsBroadcast();
  });

  // ----- Invites -----
  socket.on('create_invite', async ({ channel, expiresInMinutes, maxUses }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    const token = randomToken(22);
    const expiresAt = expiresInMinutes ? (now() + Number(expiresInMinutes) * 60 * 1000) : null;
    const mu = (typeof maxUses === 'number') ? maxUses : 1;

    await db.run(
      `INSERT INTO invites(token, channel, created_at, expires_at, max_uses, uses) VALUES(?,?,?,?,?,0)`,
      [token, channel, now(), expiresAt, mu]
    );

    socket.emit('invite_created', { channel, token, expiresAt, maxUses: mu });
  });

  // ----- Join requests moderation -----
  socket.on('get_join_requests', async ({ channel }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');
    const list = await listJoinRequests(channel);
    socket.emit('join_requests_list', { channel, list });
  });

  socket.on('approve_join_request', async ({ channel, username, approve }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    username = String(username||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    if (approve) {
      await addMember(channel, username);
    }
    await removeJoinRequest(channel, username);
    socket.emit('action_success', `درخواست ${approve ? 'تایید' : 'رد'} شد.`);
    io.emit('join_requests_update', { channel });
  });

  // ----- Members + moderation -----
  socket.on('get_channel_members', async ({ channel }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    const members = await listMembers(channel);
    const bans = await listBans(channel);
    const can = await canManageChannel(me, channel);

    // mutes map
    const rows = await db.all(`SELECT username, until FROM channel_mutes WHERE channel=?`, [channel]);
    const mutes = {};
    rows.forEach(r => { mutes[r.username] = { until: r.until || null }; });

    socket.emit('channel_members_list', { channel, members, bans, mutes, canManage: can });
  });

  socket.on('channel_kick_user', async ({ channel, username }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    username = String(username||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    await removeMember(channel, username);

    // kick online sockets from room
    io.sockets.sockets.forEach(s=>{
      const m = s.data.me;
      if (m && m.username === username) {
        s.leave(channel);
        s.emit('kicked_from_channel', { channel, message: 'از کانال خارج شدی (kick).' });
      }
    });

    socket.emit('action_success', `کاربر ${username} kick شد.`);
    io.emit('channel_members_update', { channel });
  });

  socket.on('channel_ban_user', async ({ channel, username }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    username = String(username||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    await banUser(channel, username);

    io.sockets.sockets.forEach(s=>{
      const m = s.data.me;
      if (m && m.username === username) {
        s.leave(channel);
        s.emit('kicked_from_channel', { channel, message: 'از کانال خارج شدی (ban).' });
      }
    });

    socket.emit('action_success', `کاربر ${username} ban شد.`);
    io.emit('channel_members_update', { channel });
  });

  socket.on('channel_unban_user', async ({ channel, username }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    username = String(username||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    await unbanUser(channel, username);
    socket.emit('action_success', `کاربر ${username} unban شد.`);
    io.emit('channel_members_update', { channel });
  });

  socket.on('channel_mute_user', async ({ channel, username, minutes }) => {
    const me = socket.data.me;
    if (!me) return;
    channel = String(channel||'');
    username = String(username||'');
    const can = await canManageChannel(me, channel);
    if (!can) return socket.emit('action_error', 'اجازه ندارید');

    const until = await muteUser(channel, username, Number(minutes||0) || 10);

    io.sockets.sockets.forEach(s=>{
      const m = s.data.me;
      if (m && m.username === username) {
        s.emit('muted_in_channel', { channel, until });
      }
    });

    socket.emit('action_success', `میوت کاربر ${username} ثبت شد.`);
    io.emit('channel_members_update', { channel });
  });

  socket.on('disconnect', () => {
    // cleanup socket bucket keys
    buckets.delete(`msg:sock:${socket.id}`);
    online.delete(socket.id);
    broadcastOnline();
  });
});

// -------------------- Start --------------------
const PORT = process.env.PORT || 3000;
initDb().then(()=>{
  server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}).catch((e)=>{
  console.error("DB init failed:", e);
  process.exit(1);
});
