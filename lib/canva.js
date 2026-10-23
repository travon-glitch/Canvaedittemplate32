// Shared logic for the Canva Template Importer.
// Used by the Vercel functions in /api and by the local server (server.js).
// Canva sign-in is kept in encrypted, HTTP-only cookies so it works on
// serverless hosting where nothing persists between requests.
// All Canva calls and secrets stay server-side; nothing here is sent to the browser.
// @ts-check

const crypto = require("crypto");

const API = "https://api.canva.com/rest/v1";
// Every scope listed here must also be enabled on the integration's Scopes tab in Canva.
const SCOPES = [
  "design:meta:read",
  "design:content:read",
  "design:content:write",
  "asset:read",
  "asset:write",
  "profile:read",
].join(" ");
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

/** @param {number} status @param {string} message @param {string} [code] */
function httpError(status, message, code) {
  /** @type {Error & {status?: number, code?: string}} */
  const e = new Error(message);
  e.status = status;
  if (code) e.code = code;
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
      if (!res.headersSent) {
        const body = { error: err.message };
        if (err.code) body.code = err.code;
        sendJson(res, err.status || 500, body);
      }
    }
  };
}

// Only lets the listed HTTP methods through.
function only(methods, fn) {
  return handler((req, res) => {
    if (!methods.includes(req.method)) {
      res.setHeader("Allow", methods.join(", "));
      throw httpError(405, "Method not allowed.");
    }
    return fn(req, res);
  });
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

// ---------- Canva OAuth (Authorization Code + PKCE S256) ----------
const SESSION_MAX_AGE = 60 * 60 * 24 * 90; // 90 days
// Where the browser may land after sign-in. Fixed list, so it can't be used as an open redirect.
const RETURN_PATHS = ["/", "/dashboard"];

function saveSession(req, res, t) {
  const expiresAt = Date.now() + (t.expires_in - 60) * 1000;
  addCookie(res, "canva_at", seal({ t: t.access_token, e: expiresAt }), SESSION_MAX_AGE, req);
  // Canva rotates refresh tokens: every token response carries a new one, which replaces the old.
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
async function accessToken(req, res, { forceRefresh = false } = {}) {
  const cookies = readCookies(req);
  const at = cookies.canva_at && unseal(cookies.canva_at);
  if (!forceRefresh && at && Date.now() < at.e) return at.t;
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

/** Starts sign-in. `returnTo` must be one of RETURN_PATHS. */
function startLogin(req, res, returnTo = "/") {
  if (!process.env.CANVA_CLIENT_ID || !process.env.CANVA_CLIENT_SECRET) return redirect(res, "/");
  const { clientId } = config();
  const verifier = base64url(crypto.randomBytes(64)); // 86 chars, within PKCE's 43–128
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  const state = base64url(crypto.randomBytes(24));
  const back = RETURN_PATHS.includes(returnTo) ? returnTo : "/";
  addCookie(res, "canva_oauth", seal({ state, verifier, back }), 600, req);
  const auth = new URL("https://www.canva.com/api/oauth/authorize");
  auth.search = new URLSearchParams({
    code_challenge: challenge,
    code_challenge_method: "s256",
    scope: SCOPES,
    response_type: "code",
    client_id: clientId,
    state,
    redirect_uri: redirectUri(req),
  }).toString();
  redirect(res, auth.toString());
}

async function finishLogin(req, res) {
  const url = new URL(req.url, baseUrl(req));
  const pending = unseal(readCookies(req).canva_oauth || "");
  addCookie(res, "canva_oauth", "", 0, req);
  const back = pending && RETURN_PATHS.includes(pending.back) ? pending.back : "/";
  const code = url.searchParams.get("code");
  if (!code || !pending || pending.state !== url.searchParams.get("state")) {
    const reason = url.searchParams.get("error_description") || url.searchParams.get("error") || "";
    return redirect(res, back + "?signin_error=" + encodeURIComponent(reason || "Sign-in was cancelled or expired. Try again."));
  }
  let t;
  try {
    t = await requestToken({
      grant_type: "authorization_code",
      code,
      code_verifier: pending.verifier,
      redirect_uri: redirectUri(req),
    });
  } catch (err) {
    return redirect(res, back + "?signin_error=" + encodeURIComponent(err.message));
  }
  saveSession(req, res, t);
  redirect(res, back);
}

// ---------- Canva API ----------
function canvaError(status, body) {
  if (status === 401) return httpError(401, "Your Canva connection has expired. Please reconnect.", "reconnect");
  if (status === 403) {
    return httpError(403, (body.message || "Canva refused this request.") +
      " If this mentions a scope, enable it on your Canva integration and reconnect.", "forbidden");
  }
  if (status === 429) return httpError(429, "Canva rate limit reached. Wait a moment and try again.", "rate_limited");
  return httpError(status, body.message || `Canva API error (${status})`);
}

async function canva(req, res, pathname, init = {}) {
  let at = await accessToken(req, res);
  if (!at) throw httpError(401, "Not connected to Canva.", "reconnect");
  const call = (token) => fetch(API + pathname, {
    ...init,
    headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` },
  });
  let r = await call(at);
  if (r.status === 401) {
    // Token revoked or expired early: refresh once and retry.
    at = await accessToken(req, res, { forceRefresh: true });
    if (!at) throw canvaError(401, {});
    r = await call(at);
  }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw canvaError(r.status, body);
  return body;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Polls a Canva job until it leaves "in_progress" or the time budget runs out
// (Vercel functions here are capped at 60 s). Returns the last job seen.
async function pollJob(req, res, pathname, budgetMs = 45000) {
  const start = Date.now();
  let delay = 1000;
  for (;;) {
    const { job } = await canva(req, res, pathname);
    if (job.status !== "in_progress" || Date.now() - start + delay > budgetMs) return job;
    await sleep(delay);
    delay = Math.min(delay * 1.5, 4000);
  }
}

const jobIdFrom = (req) => {
  const id = new URL(req.url, baseUrl(req)).pathname.split("/").pop() || "";
  if (!/^[\w-]+$/.test(id)) throw httpError(400, "Bad job id.");
  return id;
};

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
  const { job } = await canva(req, res, `/imports/${jobIdFrom(req)}`);
  sendJson(res, 200, jobResponse(job));
}

// ---------- large files: Vercel Blob + Canva URL import ----------
// Files over Vercel's request limit are uploaded straight from the browser to
// Vercel Blob, Canva imports them from that URL, and the blob is then deleted.
const BLOB_MAX_BYTES = 200 * 1024 * 1024;
const blobEnabled = () => Boolean(process.env.BLOB_READ_WRITE_TOKEN);
const isBlobUrl = (u) => {
  try {
    const { protocol, hostname } = new URL(u);
    return protocol === "https:" && hostname.endsWith(".public.blob.vercel-storage.com");
  } catch {
    return false;
  }
};

async function readJson(req) {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) return req.body;
  const raw = await readBody(req, 1024 * 1024);
  try {
    return JSON.parse(raw.toString("utf8") || "{}");
  } catch {
    throw httpError(400, "Invalid JSON.");
  }
}

async function blobUpload(req, res) {
  if (!blobEnabled()) throw httpError(400, "Large-file uploads aren't set up (no Vercel Blob store connected).");
  const { handleUpload } = require("@vercel/blob/client");
  const body = await readJson(req);
  if (body.type === "blob.generate-client-token" && !(await accessToken(req, res))) {
    throw httpError(401, "Not connected to Canva.", "reconnect");
  }
  const result = await handleUpload({
    body,
    request: req,
    onBeforeGenerateToken: async () => ({
      maximumSizeInBytes: BLOB_MAX_BYTES,
      addRandomSuffix: true,
      validUntil: Date.now() + 60 * 60 * 1000,
    }),
  });
  sendJson(res, 200, result);
}

async function startUrlImport(req, res) {
  const { url, title, mime } = await readJson(req);
  if (!isBlobUrl(url)) throw httpError(400, "Bad file URL.");
  const payload = { title: String(title || "Imported design").slice(0, 255), url };
  if (mime && mime !== "application/octet-stream") payload.mime_type = String(mime).slice(0, 100);
  const body = await canva(req, res, "/url-imports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  sendJson(res, 200, { jobId: body.job.id, status: body.job.status });
}

async function urlImportStatus(req, res) {
  const url = new URL(req.url, baseUrl(req));
  const { job } = await canva(req, res, `/url-imports/${jobIdFrom(req)}`);
  const blob = url.searchParams.get("blob");
  if (job.status !== "in_progress" && blobEnabled() && isBlobUrl(blob)) {
    // Clean up the temporary upload; never let this hold up the response.
    const cleanup = require("@vercel/blob").del(blob).catch(() => {});
    await Promise.race([cleanup, new Promise((r) => setTimeout(r, 5000).unref())]);
  }
  sendJson(res, 200, jobResponse(job));
}

function jobResponse(job) {
  return {
    jobId: job.id,
    status: job.status, // in_progress | success | failed
    designs: (job.result?.designs || []).map(designResponse),
    error: job.error?.message,
  };
}

function designResponse(d) {
  return {
    id: d.id,
    title: d.title,
    editUrl: d.urls?.edit_url,
    viewUrl: d.urls?.view_url,
    thumbnail: d.thumbnail?.url,
    pages: d.page_count,
    updatedAt: d.updated_at,
  };
}

// ---------- dashboard API ----------
async function me(req, res) {
  const { profile } = await canva(req, res, "/users/me/profile");
  sendJson(res, 200, { displayName: profile?.display_name || "" });
}

async function listDesigns(req, res) {
  const url = new URL(req.url, baseUrl(req));
  const params = new URLSearchParams();
  const continuation = url.searchParams.get("continuation");
  const query = (url.searchParams.get("query") || "").trim();
  if (continuation) params.set("continuation", continuation);
  else if (query) params.set("query", query.slice(0, 255));
  const qs = params.toString();
  const body = await canva(req, res, "/designs" + (qs ? "?" + qs : ""));
  sendJson(res, 200, {
    designs: (body.items || []).map(designResponse),
    continuation: body.continuation || null,
  });
}

async function getDesign(req, res) {
  const id = new URL(req.url, baseUrl(req)).pathname.split("/").pop() || "";
  if (!/^[\w-]+$/.test(id)) throw httpError(400, "Bad design id.");
  const { design } = await canva(req, res, `/designs/${id}`);
  sendJson(res, 200, designResponse(design));
}

// Reads one file from a multipart/form-data body, or a raw body with ?name=.
async function readUploadedFile(req, field = "file") {
  const type = String(req.headers["content-type"] || "");
  const raw = await readBody(req, MAX_UPLOAD_BYTES);
  if (!type.startsWith("multipart/form-data")) {
    const url = new URL(req.url, baseUrl(req));
    return { name: url.searchParams.get("name") || "", type: req.headers["x-file-type"] || "", data: raw };
  }
  let form;
  try {
    form = await new Request("http://local/", { method: "POST", headers: { "content-type": type }, body: raw }).formData();
  } catch {
    throw httpError(400, "Couldn't read the uploaded form.");
  }
  const file = form.get(field);
  if (!file || typeof file === "string") throw httpError(400, `No "${field}" file in the upload.`);
  const name = String(form.get("name") || form.get("title") || "") || file.name;
  return { name, type: file.type, data: Buffer.from(await file.arrayBuffer()) };
}

const assetName = (n) => (String(n || "").replace(/\.[^.]+$/, "").trim() || "Uploaded asset").slice(0, 50);

function assetJobResponse(job, kind) {
  const a = job.asset;
  return {
    jobId: job.id,
    kind,
    status: job.status,
    asset: a ? { id: a.id, name: a.name, type: a.type, thumbnail: a.thumbnail?.url, tags: a.tags || [] } : null,
    error: job.error?.message,
  };
}

async function uploadAsset(req, res) {
  const file = await readUploadedFile(req);
  if (!file.data.length) throw httpError(400, "Empty file.");
  const metadata = { name_base64: Buffer.from(assetName(file.name), "utf8").toString("base64") };
  const { job } = await canva(req, res, "/asset-uploads", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "Asset-Upload-Metadata": JSON.stringify(metadata) },
    body: file.data,
  });
  const done = job.status === "in_progress" ? await pollJob(req, res, `/asset-uploads/${job.id}`) : job;
  sendJson(res, done.status === "failed" ? 422 : 200, assetJobResponse(done, "file"));
}

async function uploadAssetFromUrl(req, res) {
  const { url, name } = await readJson(req);
  let parsed;
  try {
    parsed = new URL(String(url || ""));
  } catch {
    throw httpError(400, "Enter a full https:// URL.");
  }
  if (parsed.protocol !== "https:") throw httpError(400, "Only https:// URLs are supported.");
  const fallback = decodeURIComponent(parsed.pathname.split("/").pop() || "");
  const { job } = await canva(req, res, "/url-asset-uploads", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: assetName(name || fallback), url: parsed.toString() }),
  });
  const done = job.status === "in_progress" ? await pollJob(req, res, `/url-asset-uploads/${job.id}`) : job;
  sendJson(res, done.status === "failed" ? 422 : 200, assetJobResponse(done, "url"));
}

// Lets the browser keep polling an asset job that outlived one function call.
async function assetJobStatus(req, res) {
  const kind = new URL(req.url, baseUrl(req)).searchParams.get("kind") === "url" ? "url" : "file";
  const path = kind === "url" ? "/url-asset-uploads/" : "/asset-uploads/";
  const { job } = await canva(req, res, path + jobIdFrom(req));
  sendJson(res, 200, assetJobResponse(job, kind));
}

// One-call import: upload, wait for Canva, return the new design and its edit URL.
async function importAndWait(req, res) {
  const file = await readUploadedFile(req);
  if (!file.data.length) throw httpError(400, "Empty file.");
  const title = (String(file.name || "").replace(/\.[^.]+$/, "").trim() || "Imported design").slice(0, 50);
  const metadata = { title_base64: Buffer.from(title, "utf8").toString("base64") };
  if (file.type && file.type !== "application/octet-stream") metadata.mime_type = file.type;
  const { job } = await canva(req, res, "/imports", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "Import-Metadata": JSON.stringify(metadata) },
    body: file.data,
  });
  const done = job.status === "in_progress" ? await pollJob(req, res, `/imports/${job.id}`) : job;
  sendJson(res, done.status === "failed" ? 422 : 200, jobResponse(done));
}

// ---------- status / sign-out ----------
async function status(req, res) {
  const configured = Boolean(process.env.CANVA_CLIENT_ID && process.env.CANVA_CLIENT_SECRET);
  if (!configured) return sendJson(res, 200, { configured, connected: false });
  sendJson(res, 200, {
    configured,
    connected: Boolean(await accessToken(req, res)),
    maxUploadBytes: MAX_UPLOAD_BYTES,
    largeFiles: blobEnabled() ? { maxBytes: BLOB_MAX_BYTES } : null,
  });
}

function logout(req, res) {
  clearSession(req, res);
  sendJson(res, 200, { ok: true });
}

// GET → clear the session and go to the home page; other methods → JSON.
function logoutAndRedirect(req, res) {
  clearSession(req, res);
  if (req.method === "GET") return redirect(res, "/");
  sendJson(res, 200, { ok: true });
}

module.exports = {
  handler, only, status, startLogin, finishLogin, logout, logoutAndRedirect,
  startImport, importStatus, blobUpload, startUrlImport, urlImportStatus,
  me, listDesigns, getDesign, uploadAsset, uploadAssetFromUrl, assetJobStatus, importAndWait,
};
