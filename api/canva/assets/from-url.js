const c = require("../../../lib/canva");
// POST JSON { url, name }.
module.exports = c.only(["POST"], c.uploadAssetFromUrl);
