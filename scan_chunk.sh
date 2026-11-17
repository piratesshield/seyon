#!/bin/bash
# Scan repos sequentially (no backgrounding), skipping already-done ones
SEYON="/Users/apple/Documents/seyon/bin/seyon"
LINKS_FILE="${1:-/Users/apple/Documents/seyon/mcp_github_links.txt}"
RESULTS_DIR="${2:-/Users/apple/Documents/seyon/scan_results}"
OFFSET="${3:-0}"
LIMIT="${4:-100}"

mkdir -p "$RESULTS_DIR"

sanitize() {
  echo "$1" | sed 's|https://github.com/||;s|[/. ]|_|g;s|_$||'
}

count=0
done_count=0
fail_count=0
skip_count=0
line_num=0

while IFS= read -r url || [ -n "$url" ]; do
  line_num=$((line_num + 1))
  [ -z "$url" ] && continue
  [ "$line_num" -le "$OFFSET" ] && continue
  [ "$count" -ge "$LIMIT" ] && break

  count=$((count + 1))
  name=$(sanitize "$url")
  out="$RESULTS_DIR/${name}.json"

  if [ -f "$out" ]; then
    skip_count=$((skip_count + 1))
    continue
  fi

  repo_url=$(echo "$url" | sed 's|/tree/.*||;s|/$||;s|\.git$||')

  if "$SEYON" scan --mode all --out json --repo "$repo_url" > "$out" 2>/dev/null; then
    done_count=$((done_count + 1))
    echo "[$count] OK $name"
  else
    echo "{\"error\":\"scan_failed\",\"repo\":\"$url\"}" > "$out"
    fail_count=$((fail_count + 1))
    echo "[$count] FAIL $name"
  fi
done < "$LINKS_FILE"

echo "=== Chunk done: $done_count ok, $fail_count fail, $skip_count skip ==="
