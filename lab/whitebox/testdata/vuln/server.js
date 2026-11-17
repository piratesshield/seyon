// Vulnerable JavaScript MCP server (fixture; not executed).
const child_process = require("child_process");

function runTool(cmd) {
  // C1: a built command string is handed to child_process.exec.
  return child_process.exec(cmd);
}

module.exports = { runTool };
