// Local server for the Canva Template Importer.
// On Vercel this file isn't used: public/ is served as static files and
// api/ runs as serverless functions. Locally, this serves both.
//
// No dependencies: requires Node.js 18+ (uses built-in fetch).
// Usage:  npm start   then open http://127.0.0.1:3001

const http = require("http");
const fs = require("fs");
const path = require("path");

loadEnvFile(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 3001);
if (!process.env.APP_URL) process.env.APP_URL = `http://127.0.0.1:${PORT}`;

if (!process.env.CANVA_CLIENT_ID || !process.env.CANVA_CLIENT_SECRET) {
  console.error(
    "\nMissing CANVA_CLIENT_ID / CANVA_CLIENT_SECRET.\n" +
      "Copy .env.example to .env and fill in the values from your Canva integration.\n" +
      "See README.md for the setup.\n"
  );
  process.exit(1);
}

const routes = {
  "/api/auth/status": require("./api/auth/status"),
  "/api/auth/login": require("./api/auth/login"),
  "/api/auth/logout": require("./api/auth/logout"),
  "/api/oauth/callback": require("./api/oauth/callback"),
  "/api/import": require("./api/import/index"),
  "/api/blob-upload": require("./api/blob-upload"),
  "/api/url-import": require("./api/url-import/index"),
};
const importStatus = require("./api/import/[id]");
const urlImportStatus = require("./api/url-import/[id]");

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

http
  .createServer((req, res) => {
    const { pathname } = new URL(req.url, process.env.APP_URL);
    if (routes[pathname]) return routes[pathname](req, res);
    if (/^\/api\/import\/[\w-]+$/.test(pathname)) return importStatus(req, res);
    if (/^\/api\/url-import\/[\w-]+$/.test(pathname)) return urlImportStatus(req, res);
    if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return fs.createReadStream(path.join(__dirname, "public", "index.html")).pipe(res);
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  })
  .listen(PORT, "127.0.0.1", () => {
    console.log(`\nCanva Template Importer running → ${process.env.APP_URL}\n`);
  });
