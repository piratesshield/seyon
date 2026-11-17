#!/bin/bash
set -uo pipefail

SEYON="/Users/apple/Documents/seyon/bin/seyon"
LINKS_FILE="${1:-/Users/apple/Documents/seyon/mcp_github_links.txt}"
RESULTS_DIR="${2:-/Users/apple/Documents/seyon/scan_results}"
MAX_JOBS="${3:-6}"

mkdir -p "$RESULTS_DIR"

running=0

sanitize() {
  echo "$1" | sed 's|https://github.com/||;s|[/. ]|_|g;s|_$||'
}

scan_one() {
  local url="$1"
  local name
  name=$(sanitize "$url")
  local out="$RESULTS_DIR/${name}.json"

  if [ -f "$out" ]; then
    return 0
  fi

  local repo_url="$url"
  # Strip /tree/... paths
  repo_url=$(echo "$repo_url" | sed 's|/tree/.*||')
  # Strip trailing slash
  repo_url=$(echo "$repo_url" | sed 's|/$||')

  if "$SEYON" scan --mode all --out json --repo "$repo_url" > "$out" 2>/dev/null; then
    echo "OK $name"
  else
    echo "{\"error\":\"scan_failed\",\"repo\":\"$url\"}" > "$out"
    echo "FAIL $name"
  fi
}

echo "=== Seyon batch scan ==="
count=0
total=$(wc -l < "$LINKS_FILE" | tr -d ' ')

while IFS= read -r url || [ -n "$url" ]; do
  [ -z "$url" ] && continue
  count=$((count + 1))

  scan_one "$url" &
  running=$((running + 1))

  if [ "$running" -ge "$MAX_JOBS" ]; then
    wait -n 2>/dev/null || wait
    running=$((running - 1))
  fi

  if [ $((count % 50)) -eq 0 ]; then
    echo "--- Progress: $count / $total ---"
  fi
done < "$LINKS_FILE"

wait
echo "=== Done: $count repos processed ==="
