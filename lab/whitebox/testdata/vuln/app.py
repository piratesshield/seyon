# Vulnerable Python MCP tool handlers (fixture; not executed).
import os
import requests


def run_report(cmd):
    # C1: untrusted command passed to the shell via os.system.
    return os.system(cmd)


def fetch_resource(url):
    # C3: SSRF — an attacker-controlled URL is fetched directly.
    return requests.get(url)
