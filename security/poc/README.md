# Security PoCs — golab/board

Proof-of-concept exploits for the Critical and High findings in
[`../../SECURITY_ASSESSMENT.md`](../../SECURITY_ASSESSMENT.md).

> [!WARNING]
> **Authorised, local testing only.** Several of these crash or exhaust the
> target — that is the finding. Run them **only** against a disposable instance
> you own and control (e.g. `localhost:8080`). Do not point them at production or
> any system you are not authorised to test.

## What's here

| Path | What it is |
|------|------------|
| `harness/main.go` | Go harness with one subcommand per finding. Reuses the server's exact wire framing and calls real vulnerable code paths. |
| `web/h1_cswsh.html` | Browser PoC for H-1 (cross-site WebSocket hijacking). |

## Running the harness

```
go run ./security/poc/harness <finding-id> [-target host:port] [-origin url]
```

Run with no arguments for the list. Finding IDs: `c1 c2 c3 c4 c5 c6 c7 h1 h2 h3 h4 h5 h6 h7` plus the second-pass `a1 b1`.

- **Local-only** (no server needed): `c2 c5 c6 h6 h7 a1 b1` (`h6` verifies a *mitigation*).
- **Need `-target`** (a live disposable instance): `c1 c3 c4 c7 h1 h2 h3 h4 h5`. `b1` also runs e2e with `-target` (uploads the poison; then join the room to see it brick).

### Second-pass PoCs (see assessment §10)

- **`a1`** — `Board.Set` nil/out-of-bounds → **whole-server crash via the OGS review goroutine** (not recovered by net/http). Local call reproduces the fatal `Board.Move` panic; end-to-end delivery uses an attacker-authored online-go.com review + `request_sgf`.
- **`b1`** — colon-less `LB` label → **persistent poison-pill** that bricks a board on every join and survives restart (`frame.go:131`). Local call reproduces the `GenerateFullFrame` panic; `-target` uploads it unauthenticated.

### Medium-finding PoCs (see assessment §5, verified)

- **`m2`** — unbounded HTTP request body (`io.ReadAll`, no `MaxBytesReader`); sends 40 MB, server buffers it all.
- **`m3`** ★ — `GET /b/{id}/debug` leaks any room's full state unauthenticated (incl. password rooms).
- **`m4`** ★ — SSRF: `internal/fetch` follows cross-host redirects with no timeout; self-contained demo pivots to an "internal" service. Egress problem — see §11 for the K8s impact.
- **`m5`** ★ — Twitch webhook echoes the `challenge` before any signature check.
- **`m7`** — `coord`/board out-of-range panic in the request path (recovered per-connection; same defect family as `a1`).
- `c1`/`c2` cover the two Criticals downgraded to Medium (recovered panics).

### Deployment effectiveness (assessment §11)

§11 rates every Critical/High/Medium finding for whether it still works when the
attacker has **no direct server access, the app runs in Kubernetes, and traffic
is behind a reverse proxy**. Key results, empirically checked here: the crash
bugs are deliverable over the **tunneled WebSocket** (bypassing `client_max_body_size`
— confirmed with C-6 over WS), K8s auto-restart makes crashes a *repeatable
transient* DoS **except** the persisted poison-pill `b1`, and SSRF (`m4`) is an
**egress** problem the ingress proxy does not touch.

### Spinning up a disposable target

```
go build -o /tmp/board ./cmd
/tmp/board -f config/config-memory.yaml     # in-memory DB, listens on localhost:8080
```

Then, e.g.:

```
go run ./security/poc/harness h1 -target localhost:8080     # CSWSH
go run ./security/poc/harness c6                            # local: fatal stack overflow
```

## Validation status (empirically confirmed on 2026-07-07)

These PoCs were **run** against a local instance. The results **corrected**
several severities from the initial static review — see
[§0 of the assessment](../../SECURITY_ASSESSMENT.md#0-poc-validation-results).
Key points:

- **Confirmed unauthenticated whole-server crashes:** `c6` and `h7` (fatal stack
  overflow) and `c3` / `c5` (memory exhaustion). These bypass Go's `recover()`.
- **`c6` / `h7` delivery detail:** the `upload_sgf` *string* branch caps decoded
  input at 1 MiB, but the **array branch has no cap**. The working request is:

  ```
  POST /api/v1/room/{board}
  Content-Type: application/json

  {"event":"upload_sgf","value":["<base64 of '(' repeated 12,000,000 times>"]}
  ```

  (Two entries in the list instead of one triggers the `toSGF` variant, H-7.)
  No authentication is required; the process dies with `fatal error: stack overflow`.

- **Corrected — panics are recovered:** `c1`, `c2`, and the panic in `c7` fire as
  expected, **but** they occur inside the request goroutine, which Go's
  `net/http` server recovers (`http: panic serving ...`). They drop the single
  offending connection and spam logs — they do **not** crash the whole server.
  Reclassified to Medium. (The same unchecked assertions **are** fatal when
  reached from a spawned goroutine such as the OGS plugin loop.)

- **Corrected — `h6` is mitigated:** `state.FromSGF` rejects `size > 19`, so the
  NGF/SGF board-size path never reaches an oversized `NewBoard`. The `h6` command
  verifies this. The real, unclamped board-size DoS is **`c3`** (`update_settings`).

- **Corrected — `c4` mechanism:** there is no instant 4 GB allocation; the read
  buffer grows only as fast as the attacker sends. The real defect is the absence
  of any maximum message size and any read deadline (unbounded buffering +
  slow-loris).

- **Confirmed as-is:** `h1` (cross-origin socket accepted), `h2` (rooms grew
  1→501), `h3` (1000 concurrent connections, no cap), `h5` (forged Twitch webhook
  with an invalid signature accepted, 200 OK, when the secret is empty).

## Cleanup

The DoS PoCs leave the target crashed or with many junk rooms/connections. Just
restart the disposable server. Nothing is written outside the target process and
(for the in-memory config) nothing is persisted.
