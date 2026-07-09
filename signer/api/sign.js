const { execFile } = require("child_process");
const path = require("path");

module.exports = (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { privKeyHex, commitment } = req.body || {};
  if (!privKeyHex || !commitment) {
    return res.status(400).json({ error: "Missing privKeyHex or commitment in request body" });
  }

  const scriptPath = path.resolve(__dirname, "../sign_credential.js");

  execFile("node", [scriptPath, privKeyHex, commitment], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({
        error: `Process error: ${error.message}`,
        stderr: stderr.trim()
      });
    }

    try {
      const parsed = JSON.parse(stdout.trim());
      if (parsed.error) {
        return res.status(500).json({ error: parsed.error });
      }
      return res.status(200).json(parsed);
    } catch (parseError) {
      return res.status(500).json({
        error: "Failed to parse JSON output",
        raw: stdout.trim()
      });
    }
  });
};
