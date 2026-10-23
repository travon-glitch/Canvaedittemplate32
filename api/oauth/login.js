const c = require("../../lib/canva");
// GET /api/oauth/login → Canva sign-in (PKCE), then back to /dashboard.
module.exports = c.only(["GET"], (req, res) => c.startLogin(req, res, "/dashboard"));
