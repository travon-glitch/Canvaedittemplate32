const c = require("../../../../lib/canva");
// GET /api/canva/assets/jobs/<jobId>?kind=file|url — keeps polling a slow upload.
module.exports = c.only(["GET"], c.assetJobStatus);
