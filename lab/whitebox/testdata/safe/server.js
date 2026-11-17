// Safe JavaScript MCP server (fixture; not executed).
const child_process = require("child_process");

function runTool() {
  // execFile with a fixed argv: no shell string is ever built or evaluated.
  return child_process.execFile("generate-report", ["--format", "json"]);
}

module.exports = { runTool };
