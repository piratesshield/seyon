# Installing Seyon

Step-by-step install and run instructions for the Seyon MCP security scanner.

---

## 1. Requirements

### Build host

| Requirement | Minimum version | Why | How to get it |
|---|---|---|---|
| **Go toolchain** | 1.26.0 | Builds `seyon` and `seyon-web` from source | <https://go.dev/dl/> |
| **git** | 2.x | CLI shallow-clones GitHub targets at scan time | OS package manager |
| **make** | BSD / GNU | `make build`, `make check` | pre-installed on macOS, Linux |

That's the complete required list. Seyon is a single static Go binary — no Python runtime, no Node, no Docker, no system libraries beyond libc.

### Development (optional)

Only needed if you plan to modify the code:

| Tool | Pinned version | Purpose |
|---|---|---|
| **golangci-lint** | **v1.64.8** | Lint stage of the mandatory quality gate |
| **gofmt** | ships with Go | Formatting |
| **go vet** | ships with Go | Static analysis |

Install the pinned linter:

```bash
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
  | sh -s -- -b "$(go env GOPATH)/bin" v1.64.8
```

The project expects it at `~/go/bin/golangci-lint`. `make check` won't pass without it.

### Runtime (optional)

| Service | When you need it | How to configure |
|---|---|---|
| **OpenAI-compatible LLM endpoint** | To enable the L-class semantic analyzer | Set `SEYON_LLM_API_KEY`, optionally override `SEYON_LLM_ENDPOINT` and `SEYON_LLM_MODEL` |
| **OAuth 2.0 token endpoint** | To scan MCP servers that require two-legged M2M auth | Supply client credentials in the Live scan form or CLI flags |

---

## 2. Install from source

```bash
# 1. Install Go 1.26+ and verify
go version

# 2. Clone
git clone https://github.com/piratesshield/seyon.git
cd seyon

# 3. Build both binaries
make build                                 # → bin/seyon        (CLI)
go build -o bin/seyon-web ./cmd/seyon-web  # → bin/seyon-web    (web UI)

# 4. Verify
./bin/seyon --help
./bin/seyon-web --help
```

Build time is under 30 seconds on a modern laptop.

### Install to `$GOPATH/bin`

```bash
go install ./cmd/seyon
go install ./cmd/seyon-web
```

---

## 3. Run

### Web UI

```bash
./bin/seyon-web
# → listening on :9977
```

Open <http://localhost:9977>. Three scan modes:

1. **Source** — paste a public GitHub URL
2. **Upload** — drop a `.zip` of source code (≤ 100 MB)
3. **Live** — point at a running MCP endpoint; fill in bearer token / OAuth / custom headers as needed; toggle individual modules on/off

Change the listen address:

```bash
SEYON_ADDR=":8000" ./bin/seyon-web
```

### CLI

```bash
# Static scan of a local source tree
./bin/seyon scan --path ./my-mcp-server

# Scan a GitHub repo
./bin/seyon scan --git https://github.com/owner/repo

# Live black-box scan
./bin/seyon scan --url https://mcp.example.com/mcp --bearer "$TOKEN"

# Add active probing (needs a scope file authorizing the target)
./bin/seyon scan --url https://mcp.example.com/mcp \
                 --bearer "$TOKEN"                 \
                 --active --scope scope.yaml       \
                 --format html > report.html

# Scan IDE assistant configs on this machine (Cursor, VSCode, Windsurf, Claude Desktop)
./bin/seyon scan --well-known
```

Full flag reference: `./bin/seyon --help`.

---

## 4. Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SEYON_ADDR` | `:9977` | Web UI listen address |
| `SEYON_LLM_API_KEY` | *(unset)* | Enables L-class LLM analyzer when set |
| `SEYON_LLM_ENDPOINT` | `https://api.openai.com/v1/chat/completions` | Chat-completions URL |
| `SEYON_LLM_MODEL` | `gpt-4o-mini` | Model id |
| `SEYON_LLM_TIMEOUT` | `30` | Seconds per LLM call |

When `SEYON_LLM_API_KEY` is unset the scanner reports the LLM stage as skipped and everything else runs normally.

---

## 5. Ground rules — read before active scanning

- **Only scan servers you are authorized to test.**
- **Active probing against third-party servers requires their explicit permission.**
- The scanner refuses to invoke tools on a server not listed in a scope file. See [scope.yaml](scope.yaml) for a working sample.

---

## 6. Development workflow

```bash
gofmt -w .
go vet ./cmd/... ./internal/...
~/go/bin/golangci-lint run ./cmd/... ./internal/...
go test -race ./cmd/... ./internal/...

# Or run the full gate at once:
make check
```

`make check` is the gate that must pass before every commit.

---

## 7. Docker (optional, not shipped)

A minimal multi-stage image:

```dockerfile
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /bin/seyon-web ./cmd/seyon-web

FROM alpine:3.20
COPY --from=build /bin/seyon-web /usr/local/bin/seyon-web
EXPOSE 9977
ENTRYPOINT ["/usr/local/bin/seyon-web"]
```

```bash
docker build -t seyon .
docker run -p 9977:9977 seyon
```

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `go: unknown directive: toolchain` | Go < 1.21 | Upgrade to Go 1.26+ |
| `golangci-lint: command not found` | Linter not in `~/go/bin/` | Reinstall with pinned v1.64.8 (see §1) |
| `make check` fails on lint only | Linter version drift | Reinstall the exact pinned version |
| Web UI returns `Scan failed: mcp: dial failed` | Target requires auth | Fill in Bearer token or OAuth fields and re-scan — the scanner will also run an **unauth posture audit** when the handshake is auth-gated |
| `dial tcp: i/o timeout` on live scan | Target unreachable from this host | Check network routing, firewall, or try from a host that can reach the target |
| Active probe skipped with `scope not authorized` | Target URL not listed in `scope.yaml` | Add the URL to `targets:` in the scope file |
