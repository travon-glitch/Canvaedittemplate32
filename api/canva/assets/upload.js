const c = require("../../../lib/canva");
// POST multipart/form-data with a "file" field (optional "name").
module.exports = c.only(["POST"], c.uploadAsset);
