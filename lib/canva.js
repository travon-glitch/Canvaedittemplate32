// Shared logic for the Canva Template Importer.
// Used by the Vercel functions in /api and by the local server (server.js).
// Canva sign-in is kept in encrypted, HTTP-only cookies so it works on
// serverless hosting where nothing persists between requests.

const crypto = require("crypto");

const API = "https://api.canva.com/rest/v1";
const SCOPES = "design:content:write design:meta:read";
// Vercel rejects request bodies over 4.5 MB; locally we allow much larger files.
const MAX_UPLOAD_BYTES = process.env.VERCEL ? 4.4 * 1024 * 1024 : 200 * 1024 * 1024;

function config() {
  const clientId = process.env.CANVA_CLIENT_ID;
  const clientSecret = process.env.CANVA_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw httpError(500, "Server is missing CANVA_CLIENT_ID / CANVA_CLIENT_SECRET. Add them in your environment variables.");
  }
  return { clientId, clientSecret };
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// ---------- request / response helpers ----------
function baseUrl(req) {
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/+$/, "");
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function redirectUri(req) {
  return `${baseUrl(req)}/api/oauth/callback`;
}

function sendJson(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader("Location", location);
  res.end();
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(httpError(413, `File is too large (${Math.floor(limit / 1048576 * 10) / 10} MB max).`));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Wraps a handler so thrown errors become JSON responses.
function handler(fn) {
  return async (req, res) => {
    try {
      await fn(req, res);
    } catch (err) {
      if (!res.headersSent) sendJson(res, err.status || 500, { error: err.message });
    }
  };
}

// ---------- encrypted cookies ----------
function key() {
  const secret = process.env.SESSION_SECRET || "cookie:" + config().clientSecret;
  return crypto.createHash("sha256").update(secret).digest();
}

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function seal(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return base64url(Buffer.concat([iv, cipher.getAuthTag(), data]));
}

function unseal(text) {
  try {
    const buf = Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key(), buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8"));
  } catch {
    return null;
  }
}

function readCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function addCookie(res, name, value, maxAgeSeconds, req) {
  const secure = baseUrl(req).startsWith("https://") ? "; Secure" : "";
  const cookie = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
  const existing = res.getHeader("Set-Cookie") || [];
  res.setHeader("Set-Cookie", [].concat(existing, cookie));
}

// ---------- Canva OAuth ----------
const SESSION_MAX_AGE = 60 * 60 * 24 * 90; // 90 days

function saveSession(req, res, t) {
  const expiresAt = Date.now() + (t.expires_in - 60) * 1000;
  addCookie(res, "canva_at", seal({ t: t.access_token, e: expiresAt }), SESSION_MAX_AGE, req);
  addCookie(res, "canva_rt", seal({ t: t.refresh_token }), SESSION_MAX_AGE, req);
}

function clearSession(req, res) {
  addCookie(res, "canva_at", "", 0, req);
  addCookie(res, "canva_rt", "", 0, req);
}

async function requestToken(params) {
  const { clientId, clientSecret } = config();
  const res = await fetch(`${API}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw httpError(400, body.error_description || body.message || `Canva sign-in failed (${res.status})`);
  return body;
}

// Returns a valid access token, refreshing it (and updating cookies) if needed.
async function accessToken(req, res) {
  const cookies = readCookies(req);
  const at = cookies.canva_at && unseal(cookies.canva_at);
  if (at && Date.now() < at.e) return at.t;
  const rt = cookies.canva_rt && unseal(cookies.canva_rt);
  if (!rt) return null;
  try {
    const t = await requestToken({ grant_type: "refresh_token", refresh_token: rt.t });
    saveSession(req, res, t);
    return t.access_token;
  } catch {
    clearSession(req, res);
    return null;
  }
}

function startLogin(req, res) {
  const { clientId } = config();
  const verifier = base64url(crypto.randomBytes(64));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  const state = base64url(crypto.randomBytes(24));
  addCookie(res, "canva_oauth", seal({ state, verifier }), 600, req);
  const auth = new URL("https://www.canva.com/api/oauth/authorize");
  auth.search = new URLSearchParams({
    code_challenge: challenge,
    code_challenge_method: "s256",
    scope: SCOPES,
    response_type: "code",
    client_id: clientId,
    state,
    redirect_uri: redirectUri(req),
  });
  redirect(res, auth.toString());
}

async function finishLogin(req, res) {
  const url = new URL(req.url, baseUrl(req));
  const pending = unseal(readCookies(req).canva_oauth || "");
  addCookie(res, "canva_oauth", "", 0, req);
  const code = url.searchParams.get("code");
  if (!code || !pending || pending.state !== url.searchParams.get("state")) {
    res.statusCode = 400;
    res.setHeader("Content-Type", "text/plain");
    return res.end("Canva sign-in failed or was cancelled. Go back and try again.");
  }
  const t = await requestToken({
    grant_type: "authorization_code",
    code,
    code_verifier: pending.verifier,
    redirect_uri: redirectUri(req),
  });
  saveSession(req, res, t);
  redirect(res, "/");
}

// ---------- Canva API ----------
async function canva(req, res, pathname, init = {}) {
  const at = await accessToken(req, res);
  if (!at) throw httpError(401, "Not connected to Canva.");
  const r = await fetch(API + pathname, {
    ...init,
    headers: { ...(init.headers || {}), Authorization: `Bearer ${at}` },
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw httpError(r.status, body.message || `Canva API error (${r.status})`);
  return body;
}

async function startImport(req, res) {
  const url = new URL(req.url, baseUrl(req));
  const title = (url.searchParams.get("title") || "Imported design").slice(0, 50);
  const mime = req.headers["x-file-type"] || "application/octet-stream";
  const file = await readBody(req, MAX_UPLOAD_BYTES);
  if (!file.length) throw httpError(400, "Empty file.");

  const metadata = { title_base64: Buffer.from(title, "utf8").toString("base64") };
  if (mime !== "application/octet-stream") metadata.mime_type = mime;

  const body = await canva(req, res, "/imports", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "Import-Metadata": JSON.stringify(metadata) },
    body: file,
  });
  sendJson(res, 200, { jobId: body.job.id, status: body.job.status });
}

async function importStatus(req, res) {
  const id = new URL(req.url, baseUrl(req)).pathname.split("/").pop();
  if (!/^[\w-]+$/.test(id)) throw httpError(400, "Bad job id.");
  const { job } = await canva(req, res, `/imports/${id}`);
  sendJson(res, 200, {
    status: job.status, // in_progress | success | failed
    designs: (job.result?.designs || []).map((d) => ({
      id: d.id,
      title: d.title,
      editUrl: d.urls?.edit_url,
      viewUrl: d.urls?.view_url,
      thumbnail: d.thumbnail?.url,
      pages: d.page_count,
    })),
    error: job.error?.message,
  });
}

async function status(req, res) {
  sendJson(res, 200, { connected: Boolean(await accessToken(req, res)), maxUploadBytes: MAX_UPLOAD_BYTES });
}

function logout(req, res) {
  clearSession(req, res);
  sendJson(res, 200, { ok: true });
}

module.exports = { handler, status, startLogin, finishLogin, logout, startImport, importStatus };
