# Polaris

Polaris is a lightweight pure-Rust DoH resolver delivered as a single binary.

It is designed to run behind a separate HTTPS reverse proxy, and Polaris serves plain HTTP internally.

## Features

- RFC 8484 DoH wire-format API
  - `GET /dns-query?dns=...`
  - `POST /dns-query` with `Content-Type: application/dns-message`
- JSON compatibility API (debug/interop)
  - `GET /dns-query?name=...&type=...&do=...&cd=...`
  - `POST /dns-query` with `Content-Type: application/json`
- Direct iterative recursion using Hickory recursor (no upstream recursive forwarding)
- DNSSEC validation enabled
- Custom in-memory filter engine
  - exact allow / exact block
  - suffix allow / suffix block
  - precedence: exact allow > exact block > suffix allow > suffix block > allow
- Pre-resolution filtering (blocked names are answered locally and not resolved upstream)
- Resolver generation swap cache purge model (internal mechanism, admin API is future work)
- Operational probes
  - `GET /healthz`
  - `GET /readyz`

## Architecture

- Runtime: Tokio
- HTTP: Axum (minimal feature set)
- DNS message codec: `hickory-proto`
- Recursion + DNSSEC: `hickory-recursor`
- Filter snapshot swaps: `arc-swap`

Request flow:

1. Parse HTTP request
2. Parse DNS query (wire or JSON)
3. Validate query (single-question, class/type/name checks)
4. Normalize name (lowercase, IDN to A-label, trailing-dot normalization)
5. Filter lookup
6. If blocked: synthesize local response (NXDOMAIN or sinkhole)
7. If allowed: recursive resolve with Hickory
8. Return wire-format response (RFC 8484) or JSON response

## Repository layout

```text
src/
  main.rs        # bootstrap, config load, tracing, server lifecycle
  app.rs         # router wiring
  handlers.rs    # DoH wire/json handlers + health/readiness endpoints
  dns.rs         # DNS parse/validate/response synthesis helpers
  resolver.rs    # Hickory recursor manager + generation swap
  filter.rs      # custom filter engine
  readiness.rs   # readiness state model
  state.rs       # shared app state
  config.rs      # config schema/defaults
```

## Configuration

Default config path:

- `config/polaris.toml`

Override with:

- CLI: `--config /path/to/polaris.toml`
- Env: `POLARIS_CONFIG=/path/to/polaris.toml`

`[filter]` section is optional.  
If omitted, Polaris runs with an empty rule set (effectively allow-all).

### Example

```toml
[server]
bind = "0.0.0.0:8053"

[resolver]
root_hints_path = "config/root.hints"
# trust_anchor_path = "config/root.key"
ns_cache_size = 2048
record_cache_size = 1048576
recursion_limit = 16
ns_recursion_limit = 16
resolve_timeout_ms = 3500
nameserver_allow_cidrs = []
nameserver_deny_cidrs = []

[filter]
exact_allow = []
exact_block = []
suffix_allow = []
suffix_block = []
block_mode = "nx_domain" # nx_domain | sinkhole
sinkhole_ipv4 = "0.0.0.0"
sinkhole_ipv6 = "::"
sinkhole_ttl = 60

[limits]
max_post_body_bytes = 4096
max_get_dns_param_bytes = 8192
max_dns_wire_bytes = 4096
max_json_name_bytes = 255
max_concurrent_requests = 10000
http_request_timeout_ms = 5000

[readiness]
startup_self_check = true
self_check_name = "."

[logging]
json = false
filter = "info,polaris=info"
```

`root_hints_path` is required at runtime.  
If the file is missing or empty, Polaris fails fast on startup.

## Run

```bash
cargo run -- --config config/polaris.toml
```

## Endpoints

### `/dns-query` (wire + JSON compatibility)

- `GET /dns-query?dns=<base64url-dns-message>`
- `POST /dns-query`
  - Header: `Content-Type: application/dns-message`
  - Body: DNS wire message

Response content type:

- `application/dns-message`

JSON compatibility form on the same endpoint:

- `GET /dns-query?name=example.com&type=A&do=1&cd=0`
- `POST /dns-query` with `Content-Type: application/json`

Example JSON request:

```json
{
  "name": "example.com",
  "type": "A",
  "do": true,
  "cd": false
}
```

### Probes

- `GET /healthz` (JSON liveness response)
- `GET /readyz` (JSON readiness response with resolver/trust-anchor/root-hints status)

## Limits and abuse controls

- Max POST body size
- Max GET `dns` parameter size
- Max DNS wire payload size
- Single-question enforcement
- Resolver recursion depth limits (`recursion_limit`, `ns_recursion_limit`)
- Per-request timeout
- Concurrency cap
- Request cancellation via Tokio/Axum task cancellation

## Cache purge strategy

Per-record cache purge is not exposed directly by Hickory recursor.

Polaris uses generation swap:

- Build fresh recursor generation
- Atomically swap active generation
- Existing in-flight requests finish on old generation
- New requests use new cache generation immediately

This internal mechanism is implemented now and can be exposed later via admin API.

## Build and test

```bash
cargo check
cargo test --lib
cargo clippy --all-targets -- -D warnings
```

## Container

`Dockerfile` builds a release binary and runs it in distroless.

Example:

```bash
docker build -t polaris:latest .
docker run --rm -p 8053:8053 polaris:latest
```

## Operational notes

- Deploy behind a separate HTTPS reverse proxy.
- Polaris itself is plain HTTP.
- Keep root hints fresh (`config/root.hints`) as part of ops maintenance.
- If you supply a custom trust anchor file, ensure it is updated and valid.
- JSON DoH endpoint is for compatibility/debugging, not the primary hot path.

## Current status / future work

- [x] Core DoH wire/json query handling
- [x] Recursive DNSSEC validation path
- [x] Custom filter engine
- [x] Health/readiness
- [x] Internal cache generation swap
- [ ] Looking-glass endpoint
- [ ] Admin APIs for filter reload / cache purge trigger
- [ ] Metrics and diagnostics endpoints
- [ ] Broader integration test matrix (networked recursion and DNSSEC scenarios)

## License

MIT
