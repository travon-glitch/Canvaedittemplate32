// Canva Template Importer — local server
// Uploads PDFs / PPTX / DOCX / AI / PSD files to your Canva account via the
// Canva Connect "Design Import" API and returns an editable design link.
//
// No dependencies: requires Node.js 18+ (uses built-in fetch).
// Usage:  node server.js   then open http://127.0.0.1:3001

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------- config ----------
loadEnvFile(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 3001);
const CLIENT_ID = process.env.CANVA_CLIENT_ID;
const CLIENT_SECRET = process.env.CANVA_CLIENT_SECRET;
const REDIRECT_URI = `http://127.0.0.1:${PORT}/oauth/callback`;
const SCOPES = "design:content:write design:meta:read";
const API = "https://api.canva.com/rest/v1";
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024; // 200 MB
const TOKEN_FILE = path.join(__dirname, ".canva-token.json");

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "\nMissing CANVA_CLIENT_ID / CANVA_CLIENT_SECRET.\n" +
      "Copy .env.example to .env and fill in the values from your Canva integration.\n" +
      "See README.md for the 5-minute setup.\n"
  );
  process.exit(1);
}

// ---------- token storage ----------
let token = readToken(); // { access_token, refresh_token, expires_at }
const pendingAuth = new Map(); // state -> code_verifier

function readToken() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  } catch {
    return null;
  }
}

function saveToken(t) {
  token = {
    access_token: t.access_token,
    refresh_token: t.refresh_token,
    expires_at: Date.now() + (t.expires_in - 60) * 1000,
  };
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(token), { mode: 0o600 });
}

function clearToken() {
  token = null;
  fs.rmSync(TOKEN_FILE, { force: true });
}

async function requestToken(params) {
  const res = await fetch(`${API}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization:
        "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64"),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error_description || body.message || `Token request failed (${res.status})`);
  saveToken(body);
}

async function accessToken() {
  if (!token) return null;
  if (Date.now() < token.expires_at) return token.access_token;
  try {
    await requestToken({ grant_type: "refresh_token", refresh_token: token.refresh_token });
    return token.access_token;
  } catch {
    clearToken();
    return null;
  }
}

// ---------- helpers ----------
function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("File is too large (200 MB max)."));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function canva(pathname, init = {}) {
  const at = await accessToken();
  if (!at) {
    const e = new Error("Not connected to Canva.");
    e.status = 401;
    throw e;
  }
  const res = await fetch(API + pathname, {
    ...init,
    headers: { ...(init.headers || {}), Authorization: `Bearer ${at}` },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const e = new Error(body.message || `Canva API error (${res.status})`);
    e.status = res.status;
    throw e;
  }
  return body;
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

  try {
    // UI
    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return fs.createReadStream(path.join(__dirname, "public", "index.html")).pipe(res);
    }

    // Auth status
    if (req.method === "GET" && url.pathname === "/auth/status") {
      return sendJson(res, 200, { connected: Boolean(await accessToken()) });
    }

    // Start OAuth (PKCE)
    if (req.method === "GET" && url.pathname === "/auth/login") {
      const verifier = base64url(crypto.randomBytes(64));
      const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
      const state = base64url(crypto.randomBytes(24));
      pendingAuth.set(state, verifier);
      const auth = new URL("https://www.canva.com/api/oauth/authorize");
      auth.search = new URLSearchParams({
        code_challenge: challenge,
        code_challenge_method: "s256",
        scope: SCOPES,
        response_type: "code",
        client_id: CLIENT_ID,
        state,
        redirect_uri: REDIRECT_URI,
      });
      res.writeHead(302, { Location: auth.toString() });
      return res.end();
    }

    // OAuth callback
    if (req.method === "GET" && url.pathname === "/oauth/callback") {
      const state = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      const verifier = pendingAuth.get(state);
      pendingAuth.delete(state);
      if (!code || !verifier) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        return res.end("Canva sign-in failed or was cancelled. Go back and try again.");
      }
      await requestToken({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        redirect_uri: REDIRECT_URI,
      });
      res.writeHead(302, { Location: "/" });
      return res.end();
    }

    // Disconnect
    if (req.method === "POST" && url.pathname === "/auth/logout") {
      clearToken();
      return sendJson(res, 200, { ok: true });
    }

    // Upload a file -> start Canva import job
    if (req.method === "POST" && url.pathname === "/api/import") {
      const title = (url.searchParams.get("title") || "Imported design").slice(0, 50);
      const mime = req.headers["x-file-type"] || "application/octet-stream";
      const file = await readBody(req, MAX_UPLOAD_BYTES);
      if (!file.length) return sendJson(res, 400, { error: "Empty file." });

      const metadata = { title_base64: Buffer.from(title, "utf8").toString("base64") };
      if (mime !== "application/octet-stream") metadata.mime_type = mime;

      const body = await canva("/imports", {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "Import-Metadata": JSON.stringify(metadata),
        },
        body: file,
      });
      return sendJson(res, 200, { jobId: body.job.id, status: body.job.status });
    }

    // Poll import job
    const m = url.pathname.match(/^\/api\/import\/([\w-]+)$/);
    if (req.method === "GET" && m) {
      const { job } = await canva(`/imports/${m[1]}`);
      return sendJson(res, 200, {
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

    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, err.status || 500, { error: err.message });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`\nCanva Template Importer running → http://127.0.0.1:${PORT}\n`);
});
