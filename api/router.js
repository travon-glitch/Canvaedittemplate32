// One serverless function for the dashboard's OAuth and Canva API routes.
// Vercel's Hobby plan allows at most 12 functions per deployment, so these
// routes share this file. vercel.json rewrites /api/canva/* and
// /api/oauth/login|logout here with ?route=<path>.
// @ts-check
const c = require("../lib/canva");

/** @type {Array<[string[], string | RegExp, (req: any, res: any) => any]>} */
const ROUTES = [
  [["GET"], "oauth/login", (req, res) => c.startLogin(req, res, "/dashboard")],
  [["GET", "POST"], "oauth/logout", c.logoutAndRedirect],
  [["GET"], "canva/me", c.me],
  [["GET"], "canva/designs", c.listDesigns],
  [["GET"], /^canva\/designs\/([\w-]+)$/, c.getDesign],
  [["POST"], "canva/assets/upload", c.uploadAsset],
  [["POST"], "canva/assets/from-url", c.uploadAssetFromUrl],
  [["GET"], /^canva\/assets\/jobs\/([\w-]+)$/, c.assetJobStatus],
  [["POST"], "canva/import", c.importAndWait],
];

module.exports = c.handler(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const route = (url.searchParams.get("route") || url.pathname.replace(/^\/api\//, ""))
    .replace(/^\/+|\/+$/g, "");

  for (const [methods, pattern, fn] of ROUTES) {
    const m = typeof pattern === "string" ? (pattern === route ? [route] : null) : route.match(pattern);
    if (!m) continue;
    if (!methods.includes(req.method)) {
      res.setHeader("Allow", methods.join(", "));
      throw c.httpError(405, "Method not allowed.");
    }
    req.routeParams = m[1] ? { id: m[1] } : {};
    return fn(req, res);
  }
  throw c.httpError(404, "Not found.");
});
