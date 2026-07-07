# Security PoCs — golab/board

Proof-of-concept exploits for the findings in
[`../../SECURITY_ASSESSMENT.md`](../../SECURITY_ASSESSMENT.md).

> [!WARNING]
> **Authorised, local testing only.** Several of these crash or exhaust the
> target — that is the finding. Run them **only** against a disposable instance
> you own (e.g. `localhost:8080`), never production.

## Running

```
go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml   # disposable target on :8080
go run ./security/poc/harness <id> [-target localhost:8080] [-origin url]
```

Run with no arguments for the list.

- **Local-only** (no server needed): `c2 c5 c6 h6 h7 a1 b1 m4 m7` (`h6` verifies a *mitigation*).
- **Need `-target`** (a live disposable instance): `c1 c3 c4 c7 h1 h2 h3 h4 h5 m2 m3 m5`.
- `b1` also runs end-to-end with `-target` (uploads the poison; then join the room to see it brick).

## Command → finding map

The harness command names are stable mnemonics; the report uses a consolidated
severity taxonomy. This table maps them (see the report's master table for the
authoritative list and status).

| Command | Report ID | What it demonstrates |
|---------|-----------|----------------------|
| `a1` | C-1 | `Board.Set` nil/OOB → whole-server crash via the OGS review goroutine (not recovered). Local: fatal `Board.Move` panic. |
| `b1` | C-2 | Colon-less `LB` label → **persistent poison-pill**, board bricked on every load, survives restart (`frame.go:131`). |
| `c6` | C-3 | Deeply nested SGF → `parseBranch` **stack overflow** (whole-server crash). |
| `h7` | C-4 | Deep linear tree → `toSGF` **stack overflow** via `Merge` (whole-server crash). |
| `c3` | C-5 | `update_settings` huge `size` → `NewBoard` **OOM** (RSS 80→626 MB at size 20000). |
| `c5` | C-6 | **Zip bomb** — 536 MB from a 510 KB archive. |
| `c7` | C-7 | Unauthenticated `POST /api/v1/room` — state control + crash delivery. |
| `h1` | H-1 | **CSWSH** — cross-origin WebSocket accepted (no `Origin` check). |
| `h2` | H-2 | Unbounded room creation (rooms 1 → 501). |
| `h3` | H-3 | No connection/rate limits (1000 concurrent connections). |
| `c4`/`h4` | H-4 | No max WS message size / no read deadline (buffering + slow-loris). |
| `h5` | H-5 | Twitch webhook accepts a forged event when the secret is empty. |
| `m3` | M-1 | `GET /b/{id}/debug` leaks any room's full state, unauthenticated. |
| `m4` | M-2 | **SSRF** — fetch follows cross-host redirects, no timeout (pivots to an "internal" service). |
| `m5` | M-7 | Twitch challenge echoed before signature verification. |
| `m2` | M-8 | Unbounded HTTP request body (server buffers 40 MB). |
| `c1`,`c2`,`m7` | M-10 | Unchecked-input panics on the request path — **recovered** by net/http (per-connection). |
| `h6` | (mitigation) | Verifies the `FromSGF` `size>19` clamp — the NGF/SGF board-OOM path is **not** exploitable. |

Findings verified by code inspection only (no runnable command) — H-6, H-7, H-8,
M-3, M-4, M-5, M-6, M-9, and the Low items — are described in the report.

## Notes on the deployment column (report §1, master table)

The report rates each finding for a realistic posture (no direct server access,
Kubernetes, reverse proxy). Two facts, checked with these PoCs:

- **The proxy caps HTTP bodies but tunnels WebSocket.** `c6`'s 12 MB array-upload,
  blocked as a 12 MB HTTP POST by a 1 MB cap, still crashes the server over the
  WebSocket. So the proxy body cap is not a mitigation for the crash bugs.
- **K8s auto-restart heals transient crashes but not persisted state.** The OOM /
  stack-overflow crashes are repeatable transient DoS; `b1` (poison-pill) and the
  label-escape corruption survive the restart. `m4` (SSRF) is an *egress* problem
  the ingress proxy does not touch.

## Cleanup

The DoS PoCs leave the target crashed or with junk rooms/connections — just
restart the disposable server. Nothing is written outside the target process;
with the in-memory config nothing persists.
