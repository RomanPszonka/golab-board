# Security Assessment — golab/board

**Target:** `golab-board` (multi-user Go board web application)
**Assessment date:** 2026-07-07
**Scope:** Full source review of the Go backend (~10k LOC): HTTP/WebSocket routing, event handling, file-format parsers (SGF/GIB/NGF/ZIP), room/state management, OGS and Twitch integrations, persistence layer, and deployment configuration.
**Method:** Manual source-code audit (white-box). No live/dynamic testing was performed against a running instance.

---

## 1. Executive summary

The application is a no-login, no-signup collaborative Go board. Any anonymous client can open a WebSocket, create rooms, upload files, and drive board state. This is a large, fully **unauthenticated attack surface**, and the codebase currently trusts client input in many places where it should not.

The single most important structural weakness is that **there is no `recover()` anywhere in the process, and per-connection work runs in goroutines that make many unchecked assumptions about client input.** In Go, an unrecovered panic in *any* goroutine terminates the *entire* process. As a result, a large number of individually small bugs (unchecked type assertions, out-of-range slice indexing, unbounded recursion) each escalate into a **single-request, unauthenticated, whole-server crash (DoS)**. Several of these are trivially triggerable by anyone who can reach the service.

Alongside the crash bugs, there are multiple **memory-exhaustion** vectors (attacker-controlled allocation sizes with no caps), missing WebSocket **origin validation** (cross-site WebSocket hijacking), unbounded **room/connection creation**, and a **Twitch webhook authentication bypass** when the signing secret is unset.

None of the findings are theoretical-only; most are reachable by an unauthenticated remote attacker. Before exposing this on a public website, the items in [§3 Critical](#3-critical-findings) and [§4 High](#4-high-findings) should be remediated, and the deployment hardening in [§7](#7-deployment--configuration-hardening) applied.

### Severity counts

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 7 |
| Medium | 8 |
| Low / Hardening | 9 |

### Highest-priority fixes (do these first)

1. **Add panic recovery** around every per-connection / per-request handler goroutine, *and* replace unchecked type assertions with comma-ok checks (C-1). This alone neutralizes a whole class of remote crashes.
2. **Cap all attacker-controlled allocation sizes**: WebSocket frame length (C-4), board size (C-3), ZIP output (C-5), NGF/SGF board size (H-6).
3. **Bound recursion depth** in the SGF parser and tree operations (C-6, H-7).
4. **Bounds-check GIB coordinates** before indexing (C-2).
5. **Authenticate/limit the HTTP `/api/v1/room/{board}` endpoint** and cap its body size (C-7).
6. **Validate the WebSocket `Origin`** header (H-1) and **fail-closed on an empty Twitch secret** (H-5).

---

## 2. Findings overview

| ID | Severity | Title | Location |
|----|----------|-------|----------|
| C-1 | Critical | Unrecovered panics crash the whole server (unchecked type assertions) | `pkg/room/handlers.go`, process-wide |
| C-2 | Critical | Index-out-of-range panic on malformed GIB coordinates | `pkg/core/parser/gibparser.go:280` |
| C-3 | Critical | Board-size memory exhaustion via `update_settings` | `pkg/room/handlers.go:243`, `pkg/core/board/board.go:61` |
| C-4 | Critical | Unbounded WebSocket frame allocation (~4 GB) | `pkg/event/channel.go:88-126` |
| C-5 | Critical | ZIP bomb — unbounded in-memory decompression | `internal/zip/zip.go:37-46` |
| C-6 | Critical | Stack overflow via deeply nested SGF (unbounded recursion) | `pkg/core/parser/sgfparser.go:214-255` |
| C-7 | Critical | Unauthenticated state manipulation + crash via HTTP API | `pkg/hub/apiv1router.go` |
| H-1 | High | No WebSocket Origin check → cross-site WebSocket hijacking (CSWSH) | `pkg/hub/socketrouter.go:35-43` |
| H-2 | High | Unbounded room creation → resource exhaustion | `pkg/hub/hub.go:275-291` |
| H-3 | High | No connection limits / rate limiting | `pkg/hub/hub.go`, `socketrouter.go` |
| H-4 | High | No WebSocket read timeout → slow-loris | `pkg/event/channel.go` |
| H-5 | High | Twitch webhook HMAC bypass when secret is empty | `internal/twitch/twitch.go:72-82` |
| H-6 | High | Unbounded board size from NGF/SGF → OOM | `pkg/core/parser/ngfparser.go:122` |
| H-7 | High | Stack overflow in tree `Copy`/`toSGF` recursion | `pkg/core/tree/tree.go:149-170` |
| M-1 | Medium | No HTTP server timeouts → slow-loris at HTTP layer | `cmd/main.go:79` |
| M-2 | Medium | Unbounded HTTP request body | `pkg/hub/apiv1router.go` |
| M-3 | Medium | `/debug` endpoint leaks full room state unauthenticated | `pkg/hub/webrouter.go` |
| M-4 | Medium | SSRF via redirect + unbounded/untimed fetch | `internal/fetch/fetch.go` |
| M-5 | Medium | Twitch: challenge echoed pre-verification; no replay protection | `pkg/hub/twitchrouter.go:150-171` |
| M-6 | Medium | OGS plugin: unchecked assertions panic in goroutine | `pkg/room/plugin/ogs.go` |
| M-7 | Medium | Board/coord out-of-range panics | `pkg/core/board/board.go`, `pkg/core/coord/coord.go:249` |
| M-8 | Medium | 1-hour heartbeat keeps abandoned rooms alive (amplifies H-2) | `pkg/hub/hub.go:95,190` |
| L-1 | Low | GET requests with side effects (CSRF) | `pkg/hub/extrouter.go` |
| L-2 | Low | Missing HTTP security headers (CSP, X-Frame-Options, etc.) | `pkg/app/app.go` |
| L-3 | Low | Container runs as root | `Dockerfile` |
| L-4 | Low | Postgres default creds + `sslmode=disable` committed | `config/config-docker-compose.yaml` |
| L-5 | Low | Grafana default admin password | `docker-compose.yaml` |
| L-6 | Low | Deprecated `golang.org/x/net/websocket` library | `go.mod` |
| L-7 | Low | No dependency/security scanning in CI | `.github/workflows/` |
| L-8 | Low | Predictable `math/rand` room names | `pkg/core/util.go` |
| L-9 | Low | bcrypt on every `checkpassword` — CPU DoS vector | `pkg/room/handlers.go:96` |

---

## 3. Critical findings

### C-1. Unrecovered panics crash the whole server

**Locations:** `pkg/room/room.go:454` (`Handle` loop → `HandleAny`), `pkg/room/handlers.go` (multiple), process-wide (`grep -r "recover()"` returns nothing).

Each WebSocket connection is serviced by its own goroutine that loops on `HandleAny(evt)` with **no `recover()`** anywhere in the call chain. In Go, an unrecovered panic in any goroutine terminates the entire process — so a panic triggered by one malicious client drops **all** rooms and **all** connected users, and the server exits.

The handlers make numerous **unchecked type assertions** on attacker-controlled JSON, each of which panics on a mismatched type. Examples:

- `pkg/room/handlers.go:243-256` — `handleUpdateSettings`:
  ```go
  sMap := evt.Value().(map[string]any)          // panics if value isn't an object
  buffer := int64(sMap["buffer"].(float64))     // panics if missing / wrong type
  size := int(sMap["size"].(float64))
  nickname := sMap["nickname"].(string)
  black := sMap["black"].(string)  // ... etc.
  ```
  Sending `{"type":"update_settings","value":{}}` (or with `size` as a string) panics → server crash.
- `pkg/room/handlers.go:160` — `handleUploadSGF` array branch: `str := ifc.(string)` panics if the array contains a non-string.
- `pkg/room/handlers.go` `logEventValue`: `evt.Value().(string)` panics for a non-string value.
- `pkg/room/room.go:498` — `RegisterPlugin`: `key := args["key"].(string)`.

**Impact:** Unauthenticated remote denial of service of the entire service with a single crafted message. For an unprotected (freshly created) room, `authorized` middleware does not block this because a room with no password authorizes everyone.

**Remediation:**
1. Wrap the per-connection handler loop (and any goroutine that touches client data — OGS plugin loop, message loop) in `defer func(){ if r := recover(); r != nil { /* log, close conn */ } }()`.
2. Replace **every** `x.(T)` on decoded client input with the comma-ok form (`v, ok := x.(T); if !ok { return errorEvent }`), and check map-key presence before use. Treat the whole `handlers.go` / `ogs.go` surface as untrusted-input parsing.

Recovery is defense-in-depth; the type checks are the real fix. Do both.

---

### C-2. Index-out-of-range panic on malformed GIB coordinates

**Location:** `pkg/core/parser/gibparser.go:280` — `value := string([]byte{alphabet[x], alphabet[y]})` (`alphabet` is 19 chars).

The GIB parser reads `STO` move coordinates and indexes a 19-character alphabet with `x`/`y` parsed straight from the file. The values are validated only for *parseability* as integers (lines 263-274), never for range. A GIB upload such as:

```
\HS\HE\GS
STO 0 0 1 25 0
\GE
```

makes `alphabet[25]` (or a negative index) panic. The file-type detector only needs the `\HS` prefix to route into this parser.

**Impact:** Unauthenticated single-file-upload crash of the whole process (see C-1 for why a parser panic is fatal). File uploads are accepted over both the WebSocket `upload_sgf` handler and the HTTP API.

**Remediation:** After parsing, bounds-check: `if x < 0 || x >= len(alphabet) || y < 0 || y >= len(alphabet) { continue }` before indexing.

---

### C-3. Board-size memory exhaustion via `update_settings`

**Locations:** `pkg/room/handlers.go:243` (`size := int(sMap["size"].(float64))`) → `pkg/room/handlers.go:271` (`state.NewState(settings.Size)`) → `pkg/core/board/board.go:61-71` (`NewBoard`).

`handleUpdateSettings` reads `size` directly from the client and passes it, unbounded, to `NewBoard`, which allocates a `size × size` slice-of-slices (`O(size²)` memory). There is **no** range check on this path (the `size > 19` guard in `pkg/state/state.go:196` is only in the SGF-parse path, not here).

A client sending `size = 100000` requests ~10 billion cells → immediate OOM / crash.

**Impact:** Unauthenticated remote memory-exhaustion DoS. Reachable on any password-less room, and via the HTTP API (C-7) against any room.

**Remediation:** Validate `size ∈ {9, 13, 19}` (or `1 ≤ size ≤ maxBoardSize`) in `handleUpdateSettings` before use, and defensively clamp/reject in `NewBoard`.

---

### C-4. Unbounded WebSocket frame allocation (~4 GB)

**Location:** `pkg/event/channel.go:88-126` (`readPacket` / `readBytes`).

The wire framing reads a 4-byte little-endian length prefix that is fully client-controlled (up to `0xFFFFFFFF` ≈ 4 GB) and then reads that many bytes, with **no maximum-size check**:

```go
length := binary.LittleEndian.Uint32(lengthArray)
if length > 1024 {
    data, err = ec.readBytes(int(length))   // grows toward attacker-declared size
} else {
    data = make([]byte, length)
}
```

A single 4-byte frame declaring a huge length drives a multi-GB allocation per connection. The 1 MB check in `handleUploadSGF` runs *after* this, so it does not protect the framing layer. (Additionally, the fixed-size read uses `ec.ws.Read(data)` and ignores the returned count — a short read silently trusts a partial/zeroed buffer; use `io.ReadFull`.)

**Impact:** Unauthenticated memory-exhaustion DoS; trivially amplified across connections.

**Remediation:** Reject `length > maxMessageBytes` (e.g. 1–2 MB) **before** allocating or entering `readBytes`, and close the connection on violation. Use `io.ReadFull` for both the header and the body.

---

### C-5. ZIP bomb — unbounded in-memory decompression

**Location:** `internal/zip/zip.go:37-46` (`io.ReadAll(rc)` per entry, appended into a slice, no caps).

`Decompress` opens every entry and `io.ReadAll`s it with no per-entry limit, no total limit, and no entry-count limit, retaining every entry's bytes in the returned slice. A few-KB "zip bomb" that inflates to gigabytes (or an archive declaring millions of entries) exhausts memory. The 1 MB check upstream applies to the *compressed* upload only — decompression ratio is unbounded.

Note: there is no zip-slip (path-traversal) risk here because entry names are never used to write files — good — but the resource-exhaustion risk is real.

**Impact:** Unauthenticated OOM DoS from a tiny upload.

**Remediation:** Enforce a per-entry cap via `io.LimitReader(rc, maxPerFile)`, a running total-bytes budget, and a maximum entry count (reject `len(zipReader.File) > N`). Consult `file.UncompressedSize64` and reject before reading when it exceeds the budget.

---

### C-6. Stack overflow via deeply nested SGF (unbounded recursion)

**Location:** `pkg/core/parser/sgfparser.go:214-255` (`parseBranch` recurses per `(`); reachable from both the clean and dirty SGF paths.

`parseBranch` calls itself for every `(` with no depth cap. An SGF file that is simply `(` repeated a few hundred thousand times overflows the goroutine stack. A Go **stack overflow is a `fatal error` that `recover()` cannot catch** — so even the C-1 recovery does not save you here.

**Impact:** Unauthenticated single-upload hard crash of the process.

**Remediation:** Thread a depth counter through `parseBranch` and error out past a hard cap (e.g. 1000), or rewrite iteratively with an explicit heap stack.

---

### C-7. Unauthenticated state manipulation + crash via HTTP API

**Location:** `pkg/hub/apiv1router.go` — `POST /api/v1/room/{board}`.

```go
room := h.GetOrCreateRoom(board)
data, err := io.ReadAll(r.Body)        // no size limit
evt, err := event.EventFromJSON(data)
evt = room.HandleAny(evt)              // arbitrary event type, no auth
```

This endpoint lets **any unauthenticated HTTP client** create a room and dispatch **any event** to it — `update_settings`, `upload_sgf`, `graft`, board commands — with no authentication and no request-body size limit. It is a clean, scriptable trigger for every crash/exhaustion bug above (C-1, C-3, etc.) without even needing a WebSocket, and its `io.ReadAll(r.Body)` is itself an unbounded-memory vector (see M-2).

**Impact:** Full unauthenticated control over any room's state and a one-line `curl` DoS.

**Remediation:** Decide whether this API should be public at all. If yes: require authentication/authorization, wrap the body in `http.MaxBytesReader`, apply the same event-validation and panic-recovery as the WebSocket path, and rate-limit it.

---

## 4. High findings

### H-1. No WebSocket Origin check → cross-site WebSocket hijacking (CSWSH)

**Location:** `pkg/hub/socketrouter.go:35-43` — `websocket.Server{ Handshake: nil, ... }`.

With `Handshake: nil`, the `golang.org/x/net/websocket` server performs **no origin validation**. Any web page a victim visits can open a socket to `/socket/b/{boardID}` and read/drive boards in the victim's context. Because there is no per-user authentication, the practical impact is that any third-party site can silently connect visitors to arbitrary rooms and inject moves/settings.

**Remediation:** Supply a `Handshake` function that validates the `Origin` header host against an allow-list of trusted origins; reject mismatches.

### H-2. Unbounded room creation → resource exhaustion

**Location:** `pkg/hub/hub.go:275-291` (`GetOrCreateRoom`).

Any connection (or HTTP call, or `/ext/upload`) to an arbitrary, never-seen `boardID` creates a new `Room` and spawns a `go h.Heartbeat(...)` goroutine. IDs are only `Sanitize`d (alphanumeric + hyphen), so an attacker can mint effectively unlimited rooms, each holding state, a goroutine, and (via M-8) at least an hour of residency.

**Remediation:** Cap total rooms, evict idle/empty rooms promptly, and/or only auto-create for a bounded set of IDs. Consider requiring a lightweight token to create rooms.

### H-3. No connection limits / rate limiting

**Location:** `pkg/hub/hub.go:305-328`, `pkg/hub/socketrouter.go`.

There is no global, per-room, or per-IP cap on concurrent WebSocket connections and no request rate limiting anywhere. Each connection consumes a goroutine and (per C-4) potentially large buffers.

**Remediation:** Add a global max-connection semaphore, per-room and per-IP caps, and rate limiting (e.g. `chi`'s `httprate`), returning 429/503 when exceeded.

### H-4. No WebSocket read timeout → slow-loris

**Location:** `pkg/event/channel.go` (all `ec.ws.Read` calls block indefinitely).

No read/idle deadline exists. An attacker opens a connection, sends a large length prefix, then trickles bytes forever — pinning a goroutine and a partial buffer per connection at near-zero cost.

**Remediation:** Set a read deadline before each read and a max time to assemble a full message; close on timeout.

### H-5. Twitch webhook HMAC bypass when secret is empty

**Location:** `internal/twitch/twitch.go:72-82`.

```go
func Verify(secret, message, signature string) bool {
    if len(secret) == 0 {
        return true   // fails OPEN
    }
    ...
}
```

If the Twitch secret is unset (a common misconfiguration the code silently permits), **every** POST to `/apps/twitch/callback` passes verification. An attacker fully controls the JSON body, so they can satisfy the `broadcaster == chatter` authorization check (`twitchrouter.go:221`) and issue `!setboard <roomID>` / `!branch <branch>` to hijack room mappings and inject events into arbitrary rooms.

**Remediation:** Fail **closed** — return `false` when `secret == ""`, and refuse to start the Twitch integration without a configured secret.

### H-6. Unbounded board size from NGF/SGF → OOM

**Location:** `pkg/core/parser/ngfparser.go:122` (`size, err := p.parseInt()`), flowing to `board.NewBoard`.

The NGF board size is read from the file and never range-checked (unlike `numMoves`, which *is* bounded). An NGF whose size line is e.g. `999999999` drives an `O(size²)` allocation → OOM. (SGF clamps to `> 19` but this is a separate path.)

**Remediation:** Validate `1 ≤ size ≤ maxBoardSize` immediately after parsing, and clamp defensively in `NewBoard`.

### H-7. Stack overflow in tree `Copy`/`toSGF` recursion

**Location:** `pkg/core/tree/tree.go:149-170` (`Copy`), `pkg/core/parser/parser.go:51-83` (`toSGF`).

A long linear game (`(;;;;…)` with hundreds of thousands of nodes) produces a deep tree. `Copy` and `toSGF` recurse once per level (unlike `Fmap`, which is iterative), overflowing the stack — an unrecoverable `fatal error`. `Merge` calls `toSGF`, so this is reachable from the multi-file upload path.

**Remediation:** Rewrite `Copy` and `toSGF` iteratively, or enforce the same depth cap as C-6 at parse time.

---

## 5. Medium findings

### M-1. No HTTP server timeouts → slow-loris
`cmd/main.go:79` uses `http.ListenAndServe(url, a.Router)` with no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or `IdleTimeout`. Clients can hold connections open indefinitely. **Fix:** construct an `http.Server{}` with explicit timeouts (at minimum `ReadHeaderTimeout`).

### M-2. Unbounded HTTP request body
`pkg/hub/apiv1router.go` (and `/ext/upload` form parsing) read the body with no size cap. **Fix:** wrap with `http.MaxBytesReader`.

### M-3. `/debug` endpoint leaks full room state unauthenticated
`pkg/hub/webrouter.go` exposes `GET /b/{boardID}/debug`, which marshals and returns the entire internal `StateJSON` for any room to anyone. This is a development aid left reachable in production. **Fix:** gate behind `config.Mode == test`, or remove it, or require auth.

### M-4. SSRF via redirect + unbounded/untimed fetch
`internal/fetch/fetch.go` restricts `ApprovedFetch` to a hostname allow-list, but uses `http.DefaultClient`, which **follows redirects** and has **no timeout**; `Fetch` `io.ReadAll`s the response with **no size limit**. An open redirect on any approved host (e.g. a CDN) can pivot the server-side request to an internal address, and a large/slow response ties up resources. `OGSCheckEnded`/`FetchOGS` call `Fetch` after only a hostname check. **Fix:** use a client with a timeout and a redirect policy that re-validates each hop's host against the allow-list; cap the response with `io.LimitReader`.

### M-5. Twitch: challenge echoed pre-verification; no replay protection
`pkg/hub/twitchrouter.go:150-171` — the `webhook_callback_verification` challenge is echoed **before** the HMAC check, letting any party auto-confirm subscriptions; and the signed message ID/timestamp are never validated for freshness or de-duplicated, allowing replay of captured `!setboard`/`!branch` requests. **Fix:** verify the signature before handling the challenge; reject stale timestamps (~10 min window) and cache seen message IDs.

### M-6. OGS plugin: unchecked assertions panic in goroutine
`pkg/room/plugin/ogs.go` consumes OGS socket frames and `gamedata` with unchecked type assertions and map indexing (e.g. `gamedata["width"].(float64)`, `arr[1].(map[string]any)`) inside goroutines with no `recover()`. A malformed upstream frame crashes the process. **Fix:** comma-ok assertions, presence checks, and a `recover()` in the plugin loop.

### M-7. Board/coord out-of-range panics
`pkg/core/board/board.go` `Set` (line 128) has no nil/bounds check, so an in-`[0,18]`-but-past-`Size` coord, or a `nil` coord from `board.FromString` on an over-long line (`board.go:73-96`), panics. `coord.FromInterface` (`coord.go:249`, `int(v.(float64))`) panics on non-numeric JSON array elements. **Fix:** make `Set` nil- and bounds-checked (mirror `Get`); use comma-ok in `FromInterface`; cap `sz` in `FromString`.

### M-8. 1-hour heartbeat keeps abandoned rooms alive
`pkg/hub/hub.go:95,190` — `heartbeatInterval = 3600s`, so an immediately-abandoned room lingers ~1 hour with a live goroutine and map entry, directly amplifying H-2. The heartbeat also holds a stale `*Room` reference across the interval. **Fix:** shorter check interval or activity-driven timer; re-fetch the room each iteration.

---

## 6. Low findings / hardening

- **L-1 — GET with side effects (CSRF):** `pkg/hub/extrouter.go` `GET /ext/upload` creates a room and triggers a server-side fetch. State-changing actions should be POST with CSRF protection.
- **L-2 — Missing security headers:** No CSP, `X-Content-Type-Options`, `X-Frame-Options`, or `Referrer-Policy` are set (`pkg/app/app.go`). Templates use `html/template` (auto-escaping — good), but the board renders user-supplied URLs, so a CSP is valuable defense-in-depth. Add a headers middleware.
- **L-3 — Container runs as root:** `Dockerfile` has no `USER` directive and works out of `/root`. Add a non-root user.
- **L-4 — Committed DB creds / `sslmode=disable`:** `config/config-docker-compose.yaml` ships `postgres:postgres` and disables TLS to the DB. Use secrets and enable TLS in real deployments.
- **L-5 — Grafana default admin password:** `docker-compose.yaml` defaults `GF_SECURITY_ADMIN_PASSWORD` to `admin`. Require an explicit value.
- **L-6 — Deprecated WebSocket library:** `golang.org/x/net/websocket` is deprecated and lacks modern controls (origin, deadlines, message caps). Consider migrating to `nhooyr.io/websocket` or `gorilla/websocket`, which make H-1/H-4/C-4 easier to get right.
- **L-7 — No security scanning in CI:** `.github/workflows/` runs tests/lint but no `govulncheck` or `gosec`. Add both.
- **L-8 — Predictable room names:** `pkg/core/util.go` uses `math/rand` seeded by time for `RandomBoardName`. Room names are guessable; since rooms are unauthenticated and world-readable, an attacker can enumerate/join active rooms. Low impact given the design, but note it — use `crypto/rand` if room names are meant to be unguessable.
- **L-9 — bcrypt DoS on `checkpassword`:** `pkg/room/handlers.go:96` runs bcrypt on every password check with no rate limit; an attacker can force expensive hashing. Rate-limit auth attempts per connection/IP.

---

## 7. Deployment & configuration hardening

Because this will front a public website, in addition to the code fixes:

- Terminate TLS and run behind a reverse proxy (nginx/Caddy) that enforces request-size limits, connection limits, and timeouts — this provides a second layer for M-1/M-2/H-3 while the code fixes land.
- Run the process as a non-root user in a read-only container with resource limits (memory/CPU cgroups) so a single OOM attempt is contained rather than fatal to the host.
- Set the Twitch secret (H-5) and DB credentials via environment/secrets, never committed config.
- Add per-IP rate limiting and a WAF/edge protection layer for the unauthenticated endpoints.

---

## 8. Suggested remediation order

1. **Stop the bleeding (crashes):** C-1 (recovery + comma-ok), C-2, C-6, H-7, M-6, M-7 — these are the trivially-triggerable unauthenticated hard crashes.
2. **Cap allocations:** C-3, C-4, C-5, H-6, M-2, M-4.
3. **Lock down the surface:** C-7, H-1, H-2, H-3, H-4, M-1, M-3.
4. **Integration auth:** H-5, M-5.
5. **Hardening:** all Low items + §7.

---

## 9. Scope, caveats & positives

**Reviewed as safe / done well:**
- Passwords are hashed with **bcrypt** (`pkg/core/verify.go`) and compared in constant time — correct.
- **SQL is fully parameterized** in `pkg/loader/dbloader.go` — no SQL injection found. (One non-security portability note: `dbloader.go:382` uses double-quoted string literals that would break on Postgres.)
- HTML templates use `html/template` auto-escaping.
- ZIP extraction does not write to disk from entry names — **no zip-slip**.
- No hardcoded secrets are committed in the app config (aside from the sample Postgres/Grafana defaults noted in L-4/L-5).
- No `InsecureSkipVerify` / disabled TLS verification anywhere in outbound clients.

**Caveats:** This was a static/manual review; findings were not confirmed against a running instance. Line numbers reference the state of the repository at assessment time. Third-party dependency internals were not audited beyond version identification.
