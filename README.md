<p align="center">
  <img src="docs/banner.webp" alt="Seyon — MCP Security Scanner" width="100%">
</p>

# Seyon

Open-source security scanner for MCP (Model Context Protocol) servers, agent skills, and IDE assistant configurations. Ships a CLI (`seyon`) and a self-hosted web UI (`seyon-web`) that run on a laptop or in CI.

- **Three scan modes** — public GitHub repo, uploaded `.zip`, and live black-box audit of a running MCP server
- **Hundred-plus rules** across the OWASP MCP Top 10, Cisco AITech taxonomy, and 34 deep unauth-audit checks (TLS, HTTP smuggling, HTTP/2 rapid-reset, OAuth open-redirect, JWKS weakness, CT-log enumeration, ports, DNS)
- **Live scanner** negotiates MCP 2.0 `server/discover`, falls back through protocol versions, auto-selects between Streamable HTTP and legacy SSE, and carries bearer/OAuth/custom-header credentials through to every stage
- **GUI with toggles** — each scan module has an on/off switch, scans persist in a sidebar history, keyboard-driven navigation
- **Zero external services** by default — everything runs locally. Optional LLM analyzer plugs into any OpenAI-compatible endpoint (OpenAI, Ollama, OpenRouter, Azure, vLLM, LocalAI)

## Quick start

```bash
# 1. Install Go 1.26 (or newer)
# 2. Clone and build
git clone https://github.com/piratesshield/seyon.git
cd seyon
make build        # produces bin/seyon

# 3. Run the web UI
go build -o bin/seyon-web ./cmd/seyon-web
./bin/seyon-web   # listens on http://localhost:9977
```

Open `http://localhost:9977` in a browser. Three tabs:

- **Source** — paste a public GitHub URL
- **Upload** — drop a `.zip` of source code (≤ 100 MB)
- **Live** — point at a running MCP endpoint; optionally supply a bearer token, custom headers, or OAuth 2.0 client credentials; toggle individual scan modules on/off

## CLI usage

```bash
# Static source scan
./bin/seyon scan --path ./my-mcp-server

# Live black-box scan against an MCP endpoint
./bin/seyon scan --url https://my-mcp.example.com/mcp \
                 --bearer <token>              \
                 --active --scope scope.yaml

# Scan well-known IDE assistant config files on this machine
./bin/seyon scan --well-known

# Output formats
./bin/seyon scan --path ./src --format json > findings.json
./bin/seyon scan --path ./src --format html > report.html
```

Full flag reference: `./bin/seyon --help`.

## What gets checked

Seyon ships with 110+ built-in rules plus optional LLM-backed classification.

| Class | What it covers | Where it comes from |
|---|---|---|
| **B1-B10** | OWASP MCP Top 10 — prompt injection, tool poisoning, data exfiltration, schema poisoning, hidden chars, shadowing, config attacks | Built-in YAML rule packs + Go detectors |
| **D1-D12** | Missing prompt-defense language (12 attack-vector categories) | Deterministic regex analyzer (no LLM required) |
| **R1-R20** | Production readiness — timeouts, retries, idempotency, destructive-op confirms, pagination, rate-limit docs | Operational-posture heuristics |
| **P1-P8** | Live wire-protocol probes — transport, auth challenge, signing, replay, integrity, fail-open, rate-limit, spoofed identity | Safe read-only HTTP probes |
| **U1-U34** | Deep unauth audit — TLS version/ciphers/expiry, HSTS/CSP, CORS, WWW-Authenticate, server fingerprint, OAuth discovery, JWKS keys, sensitive paths, request smuggling, HTTP/2 rapid-reset, CT-log subdomains, alt-port scan, DNS posture, TLS downgrade | Full auditor the Cisco `mcp-scanner protocol` command does not implement |
| **J1-J4** | JWT fuzzing when a bearer token is supplied — alg=none, kid traversal, RS→HS switch, stale-signature bypass | Auth-mode only |
| **L** | Optional LLM semantic classifier — prompt injection, tool poisoning, role-escape, concealment, nuanced tool-shadowing | Requires `SEYON_LLM_API_KEY` |
| **F2-F4** | Active probing / mutation fuzzing on live tools | Needs a scope file authorizing the target |
| **E** | Encoded payload detection (base64, URL-encode, Unicode escapes) | Static + runtime |
| **A** | Black-box recon of auth-gated endpoints | Classifies 401/403/404/dial failures into actionable findings |
| **X** | Cross-mode correlation | Groups related findings across stages |

Every finding carries a stable rule ID, CWE, OWASP MCP Top 10 mapping, Cisco **AITech** taxonomy code, severity, confidence, remediation text, and evidence snippet.

## Prerequisites

### Required

| Tool | Minimum | Notes |
|---|---|---|
| **Go** | 1.26.0 | Required to build from source |
| **git** | any recent | Needed by the CLI to clone GitHub-URL targets |

That's it. No Python runtime, no Docker, no API keys required for the core scanner.

### Optional

| Tool / Service | What it unlocks |
|---|---|
| **OpenAI-compatible LLM endpoint** (OpenAI, Azure OpenAI, OpenRouter, Ollama, vLLM, LocalAI) | Enables the L-class semantic classifier and meta false-positive filter |
| **OAuth 2.0 token endpoint** (client credentials grant) | Lets the scanner auto-fetch tokens for machine-to-machine auth against hosted MCP providers |
| **`golangci-lint`** (v1.64.8 at `~/go/bin/`) | Enables the lint stage of the mandatory quality gate |

## Installation

### From source (Linux, macOS, Windows/WSL)

```bash
# 1. Install Go 1.26+ — https://go.dev/dl/
go version    # verify

# 2. Clone
git clone https://github.com/piratesshield/seyon.git
cd seyon

# 3. Build both binaries
make build                                 # → bin/seyon
go build -o bin/seyon-web ./cmd/seyon-web  # → bin/seyon-web

# 4. (Optional) run the quality gate the project uses in CI
make check            # vet + lint + unit tests
go test -race ./...   # full race detector run
```

### Running the web UI

```bash
./bin/seyon-web
# listens on :9977 by default
# override via SEYON_ADDR=":8000" ./bin/seyon-web
```

Open `http://localhost:9977`.

### Running the CLI

```bash
# Static scan of a local checkout
./bin/seyon scan --path ./my-mcp-server

# Scan a GitHub repo (shallow clone to a temp dir)
./bin/seyon scan --git https://github.com/owner/repo

# Live scan of a running MCP server
./bin/seyon scan --url https://mcp.example.com/mcp --bearer "$TOKEN"

# Add active probing (needs a scope file authorizing the target)
./bin/seyon scan --url https://mcp.example.com/mcp \
                 --bearer "$TOKEN"                 \
                 --active --scope scope.yaml       \
                 --format html > report.html
```

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `SEYON_ADDR` | web UI listen address | `:9977` |
| `SEYON_LLM_API_KEY` | enables the L-class LLM analyzer | unset = disabled |
| `SEYON_LLM_ENDPOINT` | chat-completions URL | `https://api.openai.com/v1/chat/completions` |
| `SEYON_LLM_MODEL` | model identifier | `gpt-4o-mini` |
| `SEYON_LLM_TIMEOUT` | per-LLM-call timeout (seconds) | `30` |

Omitting `SEYON_LLM_API_KEY` leaves the LLM stage disabled — the scanner reports it as skipped and everything else runs normally.

### Docker (optional, build it yourself)

A `Dockerfile` is not shipped. If you want one, a 20-line multi-stage Go build works:

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

Then `docker build -t seyon . && docker run -p 9977:9977 seyon`.

## Scope files

Active probing (`--active`) requires a YAML scope file that explicitly authorizes the target and sets probing budgets.

```yaml
# scope.yaml
allow_active: true
targets:
  - "https://mcp.example.com/mcp"
  - "http://localhost:9977/mcp"
deny_egress: true
max_calls_per_tool: 3
```

The scanner refuses to invoke tools on a server not listed in `targets`, so you can't accidentally fire active probes at the wrong endpoint. [scope.yaml](scope.yaml) in the repo is a working sample.

## Testing the scanner

The repo includes an integration test against the open-source **Damn Vulnerable MCP Server** (DVMCP) by Harish SG:

```bash
# Clone the vulnerable targets
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git dvmcp
cd dvmcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Start challenge 1 (prompt injection)
.venv/bin/python challenges/easy/challenge1/server.py &

# Scan it from Seyon's web UI at http://localhost:9977
# → Live tab → http://localhost:9001/mcp
```

Seyon detects every vulnerability class the DVMCP challenges demonstrate (prompt injection, tool poisoning, excessive permissions, tool shadowing, indirect injection, token theft, RCE primitives).

## Project layout

```
seyon/
├── cmd/
│   ├── seyon/            # CLI binary
│   └── seyon-web/        # self-hosted web UI
├── internal/
│   ├── auth/             # OAuth 2.0 client credentials
│   ├── correlate/        # cross-mode finding correlation
│   ├── detect/           # pattern rule engine + schema-ref + prompt-defense + readiness + LLM analyzer
│   ├── discover/         # IDE assistant config discovery (Cursor, VSCode, Windsurf, Claude Desktop)
│   ├── engine/           # scan orchestrator — BlackScan + WhiteScan + CombinedScan
│   ├── findings/         # Finding schema + severity/confidence + OWASP + AITech taxonomy
│   ├── mcp/              # MCP client with server/discover + fallback, streaming HTTP + SSE
│   ├── probe/            # P-class (protocol), U-class (unauth deep audit), J-class (JWT fuzz), active probing, mutation fuzzing
│   ├── report/           # JSON + HTML report generators
│   ├── rules/            # YAML rule-pack loader
│   ├── sandbox/          # egress isolation for stdio MCP server probing
│   ├── sast/             # static analysis for Go / Python / JS source
│   ├── scope/            # scope-file parser + authorization
│   ├── source/           # local path / git clone / zip extract resolvers
│   ├── surface/          # normalized tool/prompt/resource surface
│   ├── threatdb/         # known-threat registry
│   └── transport/        # Streamable HTTP + legacy SSE (two-URL) + stdio transports
├── Makefile
└── scope.yaml            # sample scope file for active probing
```

## Development

```bash
# Format
gofmt -w .

# Lint
~/go/bin/golangci-lint run ./cmd/... ./internal/...

# Test with race detector
go test -race ./cmd/... ./internal/...

# Full gate (what CI runs)
make check
```

## Design choices

- **Go, not Python** — the CLI is a single static binary; no runtime dependencies on the scanner host
- **No forced LLM calls** — every default rule is deterministic regex or Go code. LLM is opt-in
- **Safe active probing** — a target not listed in a scope file can never receive tool-call traffic
- **Multiple MCP transports** — negotiates protocol versions `2026-07-28 → 2024-11-05`, speaks both Streamable HTTP and legacy two-URL SSE, falls back automatically
- **Posture mode** — when the handshake is auth-gated, the scanner still runs all the TLS / headers / CORS / OAuth / smuggling / rapid-reset / port / DNS checks that don't need a session, so you learn something from every scan
- **Cisco taxonomy interop** — every finding carries AITech-X.Y / AISubtech-X.Y.Z codes so Seyon reports can be ingested by tools built around Cisco's AI Defense threat framework

## License

See `LICENSE`.

## Acknowledgments

- OWASP MCP Top 10 taxonomy
- Cisco AI Defense AITech / AISubtech framework
- Harish SG's [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) for integration testing
- Anthropic Claude Code for pairing on the implementation
