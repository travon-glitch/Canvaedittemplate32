const c = require("../../lib/canva");
// POST multipart/form-data with a "file" field (PDF, PPTX, DOCX, ...). Waits for Canva and returns the design.
module.exports = c.only(["POST"], c.importAndWait);
