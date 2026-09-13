import express from 'express';
import crypto from 'crypto';
import { execFile } from 'child_process';
import util from 'util';
import fs from 'fs';
import path from 'path';

import { dovecotAuthTest } from './dovecot-auth.mjs';
import pkg from '../package.json' with { type: 'json' };
/**
 * One-shot stderr warning, deduped by context so a persistent fault does not
 * flood the journal. The HTTP response stays generic on purpose -- the browser
 * gets "READ_ERROR", the operator's journal gets the actual reason.
 */
const warnedOnce = new Set();
function warnOnce(context, error) {
  try {
    const kind = error instanceof Error ? error.constructor.name : typeof error;
    const key = `${context}|${kind}`;
    if (warnedOnce.has(key)) return;
    let detail;
    try {
      detail = error instanceof Error ? error.message : String(error);
    } catch {
      // `message` can be a getter that throws. Keep the context, drop the detail.
      detail = kind;
    }
    process.stderr.write(`mailstack-webmail: ${context} failed: ${detail}\n`);
    // Mark reported only after the write succeeds.
    warnedOnce.add(key);
  } catch {
    /* Reporting must never be the reason a request fails. */
  }
}

const execFileAsync = util.promisify(execFile);
const app = express();
const HOST = String(process.env.WEBMAIL_HOST || process.env.HOST || '127.0.0.1').trim();
const PORT = Number(String(process.env.WEBMAIL_PORT || process.env.PORT || 18788).trim());
const SESSION_TTL_MS = Math.max(60_000, Number(process.env.SESSION_TTL || 28800) * 1000);
// Sliding renewal can never extend a session past this absolute lifetime;
// after it, a fresh password (and the current password policy) is required.
const ABSOLUTE_SESSION_MAX_MS = 7 * 24 * 3600 * 1000;
const MAX_SESSIONS = Math.max(1, Number(process.env.MAX_SESSIONS || 5000));
const MAX_MESSAGES = 200;
const MAX_MAILBOX_SCAN = Math.max(MAX_MESSAGES, Math.min(5_000, Number(process.env.MAX_MAILBOX_SCAN || 1000)));
const MAX_LIST_READ_BYTES = 64 * 1024;
const MAX_MESSAGE_BYTES = 1024 * 1024;

if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' https: data: blob:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  next();
});

const currDir = typeof __dirname !== 'undefined' ? __dirname : (process.env.WEBMAIL_DIR || process.cwd());
function resolvePublicDir() {
  const candidates = [process.env.WEBMAIL_PUBLIC_DIR, path.resolve(currDir, 'webmail-public'), path.resolve(currDir, 'public'), path.resolve(currDir, 'webmail/public'), path.resolve(currDir, '../webmail/public'), path.resolve(currDir, '../dist/webmail-public'), path.resolve(currDir, 'dist/webmail-public'), path.resolve(process.cwd(), 'webmail-public'), path.resolve(process.cwd(), 'webmail/public'), path.resolve(process.cwd(), 'dist/webmail-public'), '/opt/mailstack/webmail-public', '/opt/mailstack/ui/dist/webmail-public'];
  for (const candidate of candidates) {
    if (!candidate) continue;
    try { if (fs.statSync(candidate).isDirectory()) return fs.realpathSync(candidate); } catch {}
  }
  warnOnce('locate the webmail static directory', new Error(`none of ${candidates.length} candidates exist`));
  return path.resolve(process.cwd(), 'webmail/public');
}
const pub = resolvePublicDir();
app.use(express.static(pub, { etag: true, maxAge: '1h', dotfiles: 'deny' }));

const sessions = new Map();
const loginAttempts = new Map();
const rateBuckets = new Map();
const now = () => Date.now();
const emailRe = /^[^@\s\r\n]{1,64}@[^@\s\r\n]{1,253}$/;

function parseCookies(req) {
  const out = {};
  for (const item of String(req.headers.cookie || '').split(';')) {
    const i = item.indexOf('=');
    if (i <= 0) continue;
    try { out[decodeURIComponent(item.slice(0, i).trim())] = decodeURIComponent(item.slice(i + 1).trim()); } catch {}
  }
  return out;
}
function secureCookie(req) {
  if (process.env.COOKIE_SECURE === '1') return true;
  if (process.env.COOKIE_SECURE === '0') return false;
  return Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https');
}
function sessionCookie(req, value, maxAge) {
  return `mailstack_webmail_session=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secureCookie(req) ? '; Secure' : ''}`;
}
// Changing or locking a mailbox password (via the admin console's privileged
// helper) bumps this per-user epoch file; sessions minted before the bump are
// dead even if their sliding TTL has not elapsed. /etc/mailstack is 0750
// root:mailstack-admin and not traversable by the webmail account, so the
// file lives in a world-traversable directory as root:mailstack-webmail 0640
// and contains only unix timestamps.
const SESSION_EPOCH_FILE = process.env.MAILSTACK_SESSION_EPOCH_FILE || '/var/lib/mailstack/webmail-session-epoch.json';
let sessionEpochCache = { at: 0, map: {} };
function sessionEpoch(user) {
  const t = now();
  if (t - sessionEpochCache.at > 5000) {
    let map = {};
    try {
      const parsed = JSON.parse(fs.readFileSync(SESSION_EPOCH_FILE, 'utf8'));
      if (parsed && typeof parsed === 'object') map = parsed;
    } catch { /* missing or unreadable means "no invalidations yet" */ }
    sessionEpochCache = { at: t, map };
  }
  return Number(sessionEpochCache.map[user] || 0);
}
function getSession(req) {
  const sid = parseCookies(req).mailstack_webmail_session;
  const session = sessions.get(sid);
  if (!session) return null;
  if (now() >= session.expiresAt) { sessions.delete(sid); return null; }
  if (session.createdAt && now() - session.createdAt > ABSOLUTE_SESSION_MAX_MS) { sessions.delete(sid); return null; }
  if (session.createdAt && sessionEpoch(session.user) * 1000 > session.createdAt) { sessions.delete(sid); return null; }
  session.touched = now();
  return { sid, ...session };
}
function fail(res, status, code, message) { return res.status(status).json({ error: { code, message: message || code } }); }
function auth(req, res, next) {
  const session = getSession(req);
  if (!session) return fail(res, 401, 'AUTH_REQUIRED', 'Authentication session required');
  req.session = session;
  next();
}
function csrf(req, res, next) {
  if (req.get('X-Webmail-CSRF') !== req.session.csrf) return fail(res, 403, 'CSRF_INVALID', 'Invalid CSRF token');
  next();
}
function clientIp(req) { return String(req.ip || req.socket.remoteAddress || '127.0.0.1').slice(0, 128); }
function consumeRate(key, limit, windowMs) {
  const t = now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= t) bucket = { count: 0, resetAt: t + windowMs };
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  return bucket.count <= limit ? null : Math.max(1, Math.ceil((bucket.resetAt - t) / 1000));
}
function rateLimit(req, res, next) {
  const retry = consumeRate(`api:${clientIp(req)}:${req.session?.email || ''}`, 120, 60_000);
  if (retry) { res.setHeader('Retry-After', retry); return fail(res, 429, 'RATE_LIMITED', 'Too many requests'); }
  next();
}

const MANAGED_MAILBOXES_FILE = process.env.MANAGED_MAILBOXES_FILE || '/var/lib/mailstack/managed-mailboxes.json';
async function canonicalMailbox(email) {
  try {
    const all = JSON.parse(await fs.promises.readFile(MANAGED_MAILBOXES_FILE, 'utf8'));
    const mailbox = Array.isArray(all) ? all.find(x => String(x.email || '').toLowerCase() === email) : null;
    if (!mailbox || !/^[a-z_][a-z0-9_-]{0,31}$/.test(String(mailbox.unixUser || ''))) return null;
    const { stdout } = await execFileAsync('getent', ['passwd', mailbox.unixUser], { timeout: 3000 });
    return stdout ? { user: mailbox.unixUser, email: String(mailbox.email).toLowerCase() } : null;
  } catch { return null; }
}
async function userHome(user) {
  try { const { stdout } = await execFileAsync('getent', ['passwd', user], { timeout: 3000 }); return stdout.trim().split(':')[5] || ''; } catch { return ''; }
}
function header(raw, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
  return (unfolded.match(new RegExp(`^${escaped}:\\s*(.*)$`, 'im')) || [])[1] || '';
}
function charsetDecode(buf, charset = 'utf-8') {
  const normalized = String(charset).toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (normalized === 'utf8' || normalized === 'usascii' || normalized === 'ascii' || normalized === 'iso88591' || normalized === 'latin1') return buf.toString(normalized === 'latin1' || normalized === 'iso88591' ? 'latin1' : 'utf8');
  return buf.toString('utf8');
}
function decodeWords(value = '') {
  return value.replace(/=\?([^?\s]+)\?([bq])\?([^?]*)\?=/ig, (whole, charset, encoding, payload) => {
    try {
      const bytes = encoding.toLowerCase() === 'b' ? Buffer.from(payload, 'base64') : Buffer.from(payload.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/ig, (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
      return charsetDecode(bytes, charset);
    } catch { return whole; }
  });
}
function decodeBody(body = '', contentType = '', transferEncoding = '') {
  const enc = transferEncoding.trim().toLowerCase();
  let bytes;
  try {
    if (enc === 'base64') bytes = Buffer.from(body.replace(/\s+/g, ''), 'base64');
    else if (enc === 'quoted-printable') bytes = Buffer.from(body.replace(/=\r?\n/g, '').replace(/=([0-9a-f]{2})/ig, (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
    else bytes = Buffer.from(body, 'utf8');
  } catch { bytes = Buffer.from(body, 'utf8'); }
  const charset = (contentType.match(/charset=["']?([^"';\s]+)/i) || [])[1] || 'utf-8';
  const decoded = charsetDecode(bytes, charset);
  const boundary = (contentType.match(/boundary=["']?([^"';]+)["']?/i) || [])[1];
  if (!boundary) return decoded;
  for (const chunk of decoded.split(`--${boundary}`)) {
    if (!chunk.trim() || chunk.trim() === '--') continue;
    const separator = chunk.search(/\r?\n\r?\n/);
    if (separator < 0) continue;
    const subHead = chunk.slice(0, separator);
    const subBody = chunk.slice(separator).replace(/^\r?\n\r?\n/, '');
    const subType = header(subHead, 'Content-Type') || 'text/plain';
    if (/text\/plain/i.test(subType)) return decodeBody(subBody, subType, header(subHead, 'Content-Transfer-Encoding'));
  }
  return decoded;
}
function extractSnippet(text = '') {
  return String(text).replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '').replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);
}
function parseFrom(value) {
  const decoded = decodeWords(value).replace(/[\r\n]+/g, ' ').trim();
  const match = decoded.match(/<([^<>\s@]+@[^<>\s]+)>/);
  const email = (match ? match[1] : (decoded.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [decoded])[0]).trim().toLowerCase();
  const name = match ? decoded.slice(0, match.index).replace(/^\s*["']|["']\s*$/g, '').trim() : '';
  return { name, email, display: name ? `${name} <${email}>` : email };
}

async function readRegularFileNoFollow(file, maxBytes) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const handle = await fs.promises.open(file, flags);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Not a regular file');
    const length = Math.min(Math.max(1, stat.size), maxBytes);
    const buffer = Buffer.alloc(length);
    let offset = 0;
    while (offset < length) {
      const { bytesRead } = await handle.read(buffer, offset, length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    return buffer.subarray(0, offset).toString('utf8');
  } finally {
    await handle.close();
  }
}

async function safeMaildirFile(user, id, markRead = false) {
  let rel;
  try { rel = Buffer.from(String(id), 'base64url').toString('utf8'); } catch { return null; }
  if (!/^(new|cur)\/[^/]+$/.test(rel)) return null;
  const home = await userHome(user);
  if (!home) return null;
  const base = path.resolve(home, 'Maildir');
  const baseReal = await fs.promises.realpath(base).catch(() => null);
  if (!baseReal) return null;
  let file = path.resolve(baseReal, rel);
  if (!file.startsWith(baseReal + path.sep)) return null;
  const stat = await fs.promises.lstat(file).catch(() => null);
  if (!stat?.isFile()) {
    if (!rel.startsWith('new/')) return null;
    const moved = path.join(baseReal, 'cur', path.basename(rel) + ':2,S');
    const movedStat = await fs.promises.lstat(moved).catch(() => null);
    if (!movedStat?.isFile()) return null;
    file = moved;
  }
  const real = await fs.promises.realpath(file).catch(() => null);
  if (!real || !real.startsWith(baseReal + path.sep)) return null;
  if (markRead && rel.startsWith('new/')) {
    const target = path.join(baseReal, 'cur', path.basename(rel) + ':2,S');
    try {
      const current = await fs.promises.lstat(file);
      if (!current.isFile()) return null;
      await fs.promises.rename(file, target);
      file = target;
    } catch (error) {
      if (error.code !== 'ENOENT') return null;
      const targetStat = await fs.promises.lstat(target).catch(() => null);
      if (!targetStat?.isFile()) return null;
      file = target;
    }
  }
  return file;
}
function parseMessage(raw, item, id) {
  const parts = raw.split(/\r?\n\r?\n/); const head = parts.shift() || ''; const body = parts.join('\n\n').slice(0, MAX_MESSAGE_BYTES);
  const contentType = header(head, 'Content-Type') || 'text/plain';
  const decoded = decodeBody(body, contentType, header(head, 'Content-Transfer-Encoding'));
  const from = parseFrom(header(head, 'From'));
  return { id, from: from.display, fromEmail: from.email, subject: decodeWords(header(head, 'Subject')) || '(no subject)', snippet: extractSnippet(decoded), date: header(head, 'Date'), unread: item ? (item.d === 'new' || !item.name.includes(':2,S')) : false, size: item?.size, mtimeMs: item?.mtimeMs, to: decodeWords(header(head, 'To')), contentType, body: decoded };
}

const VERSION = String(pkg.version || '0.0.0').trim();
const healthHandler = (req, res) => res.json({ ok: true, status: 'ok', service: 'mailstack-webmail', version: VERSION, uptimeSec: Math.floor(process.uptime()), time: new Date().toISOString() });
app.get('/api/webmail/health', healthHandler); app.get('/api/health', healthHandler);

app.post('/api/webmail/auth/login', async (req, res) => {
  const ip = clientIp(req); const email = String(req.body?.email || '').trim().toLowerCase(); const pass = String(req.body?.password || '');
  const key = `${ip}:${email}`; const attempt = loginAttempts.get(key) || { count: 0, until: 0 };
  const retry = Math.max(
    consumeRate('login:global', 500, 60_000) || 0,
    consumeRate(`login:ip:${ip}`, 30, 15 * 60_000) || 0,
    consumeRate(`login:account:${key}`, 10, 15 * 60_000) || 0,
  );
  if (retry || attempt.until > now()) { const wait = Math.max(retry, Math.ceil((attempt.until - now()) / 1000), 1); res.setHeader('Retry-After', wait); return fail(res, 429, 'RATE_LIMITED', 'Too many attempts. Try again later.'); }
  if (!emailRe.test(email) || pass.length < 1 || pass.length > 4096) return fail(res, 400, 'INVALID_CREDENTIALS', 'Invalid email or password format');
  const mailbox = await canonicalMailbox(email); let authSuccess = false;
  if (mailbox) {
    // The password never leaves this process: it is base64-wrapped into the
    // Dovecot auth-client protocol payload inside the unix socket. No
    // doveadm child process exists, so /proc/*/cmdline has nothing to show.
    authSuccess = await dovecotAuthTest(mailbox.user, pass);
    if (!authSuccess) {
      // Indistinguishable from a wrong password at the HTTP layer by design.
      // The journal separates "rejected" from "socket missing or unreachable".
      warnOnce('dovecot auth-client socket login', new Error('authentication rejected or socket unavailable'));
    }
  }
  if (!authSuccess) { attempt.count += 1; if (attempt.count >= 5) { attempt.until = now() + 15 * 60_000; attempt.count = 0; } loginAttempts.set(key, attempt); return fail(res, 401, 'AUTH_FAILED', 'Mailbox authentication failed'); }
  loginAttempts.delete(key); const sid = crypto.randomBytes(32).toString('base64url'); const csrfToken = crypto.randomBytes(24).toString('base64url');
  while (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
  sessions.set(sid, { user: mailbox.user, email: mailbox.email, csrf: csrfToken, touched: now(), createdAt: now(), expiresAt: now() + SESSION_TTL_MS });
  res.setHeader('Set-Cookie', sessionCookie(req, sid, Math.floor(SESSION_TTL_MS / 1000))); res.json({ authenticated: true, email: mailbox.email, csrf: csrfToken });
});
app.get('/api/webmail/auth/session', auth, (req, res) => res.json({ authenticated: true, email: req.session.email, csrf: req.session.csrf }));
app.post('/api/webmail/auth/logout', (req, res) => {
  const sid = parseCookies(req).mailstack_webmail_session;
  const session = sessions.get(sid);
  if (session && req.get('X-Webmail-CSRF') !== session.csrf) return fail(res, 403, 'CSRF_INVALID', 'Invalid CSRF token');
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
  res.json({ ok: true });
});

app.get('/api/webmail/messages', auth, rateLimit, async (req, res) => {
  try {
    const home = await userHome(req.session.user);
    if (!home) return res.json({ messages: [], total: 0, offset: 0, limit: 50, page: 1, hasMore: false });
    const rawLimit = Number(req.query.limit || req.query.pageSize || 50);
    const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(1, Math.trunc(rawLimit)), MAX_MESSAGES) : 50;
    const rawPage = Number(req.query.page || 1);
    const page = Number.isFinite(rawPage) ? Math.max(1, Math.trunc(rawPage)) : 1;
    const rawOffset = req.query.offset === undefined ? (page - 1) * limit : Number(req.query.offset);
    const offset = Number.isFinite(rawOffset) ? Math.max(0, Math.trunc(rawOffset)) : 0;
    const search = String(req.query.search || req.query.q || '').trim().toLowerCase().slice(0, 256);
    const baseReal = await fs.promises.realpath(path.join(home, 'Maildir')).catch(() => null);
    if (!baseReal) return res.json({ messages: [], total: 0, offset, limit, page, hasMore: false });
    const items = [];
    for (const directoryName of ['new', 'cur']) {
      const directory = path.join(baseReal, directoryName);
      const directoryReal = await fs.promises.realpath(directory).catch(() => null);
      if (directoryReal !== directory) continue;
      const names = await fs.promises.readdir(directoryReal).catch(() => []);
      for (const name of names.sort().reverse().slice(0, MAX_MAILBOX_SCAN)) {
        if (!name || name.includes('/') || name.includes('\\')) continue;
        const file = path.join(directoryReal, name);
        const stat = await fs.promises.lstat(file).catch(() => null);
        if (stat?.isFile()) items.push({ d: directoryName, name, file, mtimeMs: stat.mtimeMs, size: stat.size });
      }
    }
    const candidates = items.sort((a, b) => b.mtimeMs - a.mtimeMs).slice(0, MAX_MAILBOX_SCAN);
    const enrich = async (selected) => {
      const output = [];
      for (let index = 0; index < selected.length; index += 16) {
        const batch = await Promise.all(selected.slice(index, index + 16).map(async (item) => {
          try {
            const raw = await readRegularFileNoFollow(item.file, MAX_LIST_READ_BYTES);
            return parseMessage(raw, item, Buffer.from(`${item.d}/${item.name}`).toString('base64url'));
          } catch {
            return null;
          }
        }));
        output.push(...batch.filter(Boolean));
      }
      return output;
    };
    let messages;
    let total;
    if (search) {
      const enriched = await enrich(candidates);
      const filtered = enriched.filter((message) => `${message.subject} ${message.from} ${message.snippet}`.toLowerCase().includes(search));
      total = filtered.length;
      messages = filtered.slice(offset, offset + limit);
    } else {
      total = candidates.length;
      messages = await enrich(candidates.slice(offset, offset + limit));
    }
    res.json({
      messages,
      total,
      offset,
      limit,
      page: Math.floor(offset / limit) + 1,
      hasMore: offset + messages.length < total,
      scanLimited: items.length > MAX_MAILBOX_SCAN,
    });
  } catch (error) {
    warnOnce('read mailbox listing', error);
    fail(res, 500, 'READ_ERROR', 'Unable to read mailbox');
  }
});

app.get('/api/webmail/messages/:id', auth, rateLimit, async (req, res) => {
  const file = await safeMaildirFile(req.session.user, req.params.id, true);
  if (!file) return fail(res, 404, 'MESSAGE_NOT_FOUND', 'Message not found');
  try {
    const raw = await readRegularFileNoFollow(file, MAX_MESSAGE_BYTES);
    res.json(parseMessage(raw, null, req.params.id));
  } catch (error) {
    warnOnce('read message', error);
    fail(res, 500, 'READ_ERROR', 'Unable to read message');
  }
});
app.post('/api/webmail/messages/:id/read', auth, csrf, rateLimit, async (req, res) => { const file = await safeMaildirFile(req.session.user, req.params.id, true); if (!file) return fail(res, 404, 'MESSAGE_NOT_FOUND', 'Message not found'); res.json({ ok: true, id: req.params.id, unread: false }); });

app.post('/api/webmail/send', auth, csrf, rateLimit, async (req, res) => {
  const to = String(req.body?.to || '').trim(); const subject = String(req.body?.subject || '').trim(); const body = String(req.body?.body || '');
  if (!emailRe.test(to) || /[\r\n]/.test(subject) || subject.length > 998 || Buffer.byteLength(body, 'utf8') > MAX_MESSAGE_BYTES || /[\r\n]/.test(to)) return fail(res, 400, 'INVALID_MESSAGE', 'Invalid message recipient, subject, or body');
  const msg = `From: ${req.session.email}\r\nTo: ${to}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${body.replace(/\r?\n/g, '\r\n')}\r\n`; const sendmailBin = fs.existsSync('/usr/sbin/sendmail') ? '/usr/sbin/sendmail' : (fs.existsSync('/usr/bin/sendmail') ? '/usr/bin/sendmail' : 'sendmail');
  try { const child = execFile(sendmailBin, ['-f', req.session.email, '-t', '-i'], { timeout: 15000 }); let settled = false; const finish = (error) => { if (settled) return; settled = true; if (error) return fail(res, 502, 'SUBMISSION_FAILED', 'Local mail delivery submission failed'); res.json({ accepted: true, scope: 'local Postfix submission' }); }; child.once('error', finish); child.once('close', code => finish(code === 0 ? null : new Error('sendmail failed'))); child.stdin.once('error', finish); child.stdin.end(msg, 'utf8'); } catch { fail(res, 502, 'SUBMISSION_FAILED', 'Local mail delivery submission failed'); }
});

setInterval(() => { const t = now(); for (const [id, s] of sessions) if (t >= s.expiresAt) sessions.delete(id); for (const [id, a] of loginAttempts) if (a.until && a.until < t) loginAttempts.delete(id); for (const [id, b] of rateBuckets) if (b.resetAt < t) rateBuckets.delete(id); }, 60_000).unref();
app.use('/api/webmail', (req, res) => fail(res, 404, 'API_NOT_FOUND', 'API endpoint not found'));
app.use((error, req, res, next) => error?.type === 'entity.too.large' ? fail(res, 413, 'PAYLOAD_TOO_LARGE', 'Payload too large') : fail(res, 500, 'INTERNAL_ERROR', 'Internal server error'));
app.get('*', (req, res) => { const idx = path.join(pub, 'index.html'); try { if (fs.statSync(idx).isFile()) return res.sendFile(idx); } catch {} res.status(503).send('Webmail client UI is initializing. Please refresh.'); });
const server = app.listen(PORT, HOST, () => console.log(`MailStack Webmail listening on ${HOST}:${PORT}`));
const shutdown = () => server.close(() => process.exit(0)); process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
