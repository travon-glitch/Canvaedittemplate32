const c = require("../../lib/canva");
// GET → clears the Canva session and redirects home. POST → JSON { ok: true }.
module.exports = c.only(["GET", "POST"], c.logoutAndRedirect);
