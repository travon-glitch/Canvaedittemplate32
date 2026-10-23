const c = require("../../lib/canva");

module.exports = c.handler((req, res) => {
  if (req.method !== "POST") return res.writeHead(405).end();
  return c.startUrlImport(req, res);
});
