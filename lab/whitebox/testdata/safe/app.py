# Safe Python MCP tool handlers (fixture; not executed).
import subprocess
import requests


def run_report():
    # Fixed argv, no shell: nothing untrusted reaches a command interpreter.
    return subprocess.run(["generate-report", "--format", "json"], check=True)


def fetch_status():
    # Literal, allowlisted URL: no SSRF surface.
    return requests.get("https://api.example.com/status")
