# Security Assessment — golab/board

**Target:** `golab-board` — a no-login, multi-user Go board web app (Go backend, ~10k LOC): HTTP/WebSocket routing, event handling, file parsers (SGF/GIB/NGF/ZIP), room/state management, OGS + Twitch integrations, persistence, deployment config.
**Method:** White-box source review with dynamic proof-of-concept validation. Every Critical, High, and Medium finding below is either **reproduced** with a runnable PoC (in [`security/poc/`](security/poc/)) or **confirmed** by code inspection; the status is stated per finding.
**Assessment date:** 2026-07-07.

---

## 1. Executive summary

Every client is anonymous and can open a WebSocket, create rooms, upload files, and drive board state — a large, fully **unauthenticated** attack surface. The findings fall into these groups:

- **Whole-server crashes (8 Critical) + one stored-XSS Critical (9 total).** A single unauthenticated request can abort the entire process via **unbounded recursion** (SGF parse / tree serialize → `fatal error: stack overflow`), **unbounded allocation** (board size, zip bomb → OOM), a **panic in a spawned goroutine** (the OGS review plugin, which `net/http` does not recover), or a **concurrent-map data race** (`fatal error: concurrent map iteration and map write` via the nicknames map — also not recoverable). All were reproduced.
- **One unrecoverable board (persistent poison-pill).** A crafted label (`LB[z]`) is committed and persisted, then panics on every load — the board is permanently unjoinable and the poison **survives restarts** (see C-2).
- **Concurrency: data races & lock-held-during-I/O (§6).** Beyond the crash race, several torn-slice races (`fatal`/SIGSEGV) and — confirmed — **one stuck-reading client freezes an entire room** because `Broadcast` holds `r.mu` across the blocking socket write (escalating hub-wide via `SendMessages`).
- **Authorization bypass (§6).** The `/api/v1` HTTP path trusts the client-supplied `userid`, so an attacker can replay an authenticated occupant's connection UUID and take over a **password-protected** room; and enabling a password grandfathers every currently-connected (incl. hostile) socket.
- **Memory / goroutine / fd leaks (§6).** Room teardown never ends registered plugins; OGS reader goroutines can block forever on a channel send; unbounded per-room maps.
- **Secrets & crypto (§6).** The Postgres DSN (with password) is logged in plaintext at startup; a password over 72 bytes silently disables room protection.
- **Information disclosure (§6).** A "protected" room streams full state/moves to any anonymous socket; raw internal fetch errors (internal IPs/DNS, an SSRF oracle) are broadcast to clients and JSON-injected into `/api/v1` responses.
- **Resource-exhaustion & integrity (High/Medium).** No origin check (CSWSH), no room/connection/rate caps, missing timeouts, an unauthenticated `graft` handler, SSRF, and an info-leaking `/debug` endpoint.
- **Deployment hardening (Low).** Root container, committed default credentials, no security headers, no CI scanning.

**Reading crash severity — the `net/http` recover boundary.** Go's `net/http` wraps each request in `recover()`, and the WebSocket handler runs *inside* that request goroutine. So a plain type-assertion/index panic reached from a request is **contained** — it drops one connection, not the server. Only three things abort the whole process: (a) **fatal runtime errors** (stack overflow, OOM), (b) panics in **`go`-spawned goroutines** (OGS plugin loop, heartbeat, message loop), and (c) a **persisted poison pill** re-triggered on reload. Findings are rated on that basis: unchecked-input panics on the request path are Medium (contained); the same defect in a spawned goroutine is Critical.

**Deployment threat model (column "Behind proxy / K8s").** The rightmost table column rates each finding for a realistic production posture: attacker has **no direct/shell access**, the app runs in **Kubernetes** (memory limit → `OOMKilled`; liveness probe → auto-restart; in-memory room state ⇒ effectively single-instance; shared DB survives restarts), and traffic is behind a **reverse proxy / ingress** (HTTP body cap ~1 MB, ~60 s timeouts, but it **tunnels WebSocket**). Two facts drive most verdicts, both verified here:
1. **The proxy caps HTTP bodies but tunnels WebSocket** — every crash reachable via `upload_sgf`/the WS framing is deliverable over the socket regardless of `client_max_body_size` (confirmed: the 12 MB C-3 array-upload crashes the server over WS).
2. **K8s auto-restart heals *transient* crashes but not *persisted* state** — OOM/overflow crashes become a repeatable transient DoS; the poison-pill (C-2) and label corruption (M-5) survive the restart. **SSRF (M-2)** is worse in K8s (cluster-internal services + cloud IAM metadata) and is an *egress* problem the ingress proxy does not touch.

---

## 2. Findings — master table

**Status:** `PoC` = reproduced with the named harness command (`go run ./security/poc/harness <cmd>`) · `race†` = reproduced under the race detector (`go test -race ./security/poc/race/`) · `gl1*` = the leak's root cause is reproduced (`gl1`); the OGS-socket portion needs live egress to online-go.com · `insp.` = confirmed by code inspection.
**Behind proxy / K8s:** `Yes` = effective as-is · `WS` = effective via the tunneled WebSocket (HTTP vector capped) · `↻` = crashes but the pod auto-restarts (repeatable transient DoS) · `⚑` = persists across restarts · `Partly` = blunted, not prevented · `Cond.` = needs a precondition · `Proxy-mitigated` = the proxy largely prevents it · `Per-conn` = affects only the attacker's own connection.

| # | Sev | Finding | Status (PoC) | Behind proxy / K8s |
|----|-----|---------|--------------|--------------------|
| C-1 | Critical | Whole-server crash via the OGS review plugin goroutine (`Board.Set` nil/OOB + unchecked assertions, not recovered) | PoC `a1` | Cond.(OGS) → Yes ↻ |
| C-2 | Critical | Persistent poison-pill: colon-less `LB` label bricks a board on every load | PoC `b1` | Yes ⚑ |
| C-3 | Critical | SGF parse stack overflow (unbounded `parseBranch` recursion) | PoC `c6` | Yes (WS) ↻ |
| C-4 | Critical | Tree-serialize stack overflow (`toSGF`/`Copy` recursion via `Merge`) | PoC `h7` | Yes (WS) ↻ |
| C-5 | Critical | Board-size memory exhaustion (`update_settings` size unbounded) | PoC `c3` | Yes ↻ |
| C-6 | Critical | ZIP bomb — unbounded in-memory decompression | PoC `c5` | Yes (WS) ↻ |
| C-7 | Critical | Unauthenticated state control + crash delivery (`POST /api/v1/room`, uncapped `upload_sgf` array branch) | PoC `c7` | Yes / Partly |
| XSS-1 | Critical | Stored XSS via board labels (SVG `<text>.innerHTML`) — arbitrary JS in every viewer, in the embedding site's origin | PoC `xss_label.js` | Yes |
| H-1 | High | No WebSocket `Origin` check → cross-site WebSocket hijacking (CSWSH) | PoC `h1` | Yes |
| H-2 | High | Unbounded room creation | PoC `h2` | Yes |
| H-3 | High | No connection / rate limits | PoC `h3` | Partly |
| H-4 | High | No max WS message size + no read deadline (buffering + slow-loris) | PoC `c4`/`h4` | Partly |
| H-5 | High | Twitch webhook HMAC bypass when the secret is empty | PoC `h5` | Cond. |
| H-6 | High | `graft` handler bypasses `authorized` + rate-limit middleware | PoC `graft` | Yes |
| H-7 | High | Unbounded per-room tree growth + quadratic full-frame rebroadcast | PoC `grow` | Yes ↻ |
| H-8 | High | OGS plugin fd + goroutine leak on every `request_sgf` | PoC `gl1`* | Cond.(OGS) ↻ |
| M-1 | Medium | `/debug` leaks full room state unauthenticated (incl. password rooms) | PoC `m3` | Yes |
| M-2 | Medium | SSRF via redirect-following + untimed/unbounded fetch | PoC `m4` | Cond.; high in K8s |
| M-3 | Medium | `update_nickname` no auth / no length cap → N² rebroadcast | PoC `nick` | Yes |
| M-4 | Medium | Unbounded per-room `auth`/`notified` maps (never pruned) | PoC `authleak` | Yes |
| M-5 | Medium | SGF label escaping not round-trip safe → persisted corruption | PoC `sgfesc` | Yes ⚑ |
| M-6 | Medium | 1-hour heartbeat keeps abandoned rooms alive (amplifier) | insp. | Yes |
| M-7 | Medium | Twitch: challenge echoed before verify; no replay protection | PoC `m5` | Yes (low) |
| M-8 | Medium | Unbounded HTTP request body (`io.ReadAll`, no `MaxBytesReader`) | PoC `m2` | Proxy-mitigated |
| M-9 | Medium | No HTTP server timeouts (`http.ListenAndServe`, no `http.Server{}`) | insp. | Proxy-mitigated |
| M-10 | Medium | Unchecked-input panics on the request path (type assertions, coord/board OOB) — contained by net/http | PoC `c1`,`c2`,`m7` | Per-conn |
| L-1 | Low | `GET /ext/upload` has side effects (CSRF, server-side fetch) | insp. | Yes |
| L-2 | Low | No HTTP security headers (CSP, X-Frame-Options, …) | insp. | Yes |
| L-3 | Low | Container runs as root | insp. | n/a |
| L-4 | Low | Postgres default creds + `sslmode=disable` committed | insp. | n/a |
| L-5 | Low | Grafana default admin password | insp. | n/a |
| L-6 | Low | Deprecated `golang.org/x/net/websocket` | insp. | n/a |
| L-7 | Low | No dependency / security scanning in CI | insp. | n/a |
| L-8 | Low | Predictable `math/rand` room names | insp. | Yes |
| L-9 | Low | bcrypt on every `checkpassword` — CPU-amplification | insp. | Partly |
| DR-1 | Critical | Data race: concurrent map iteration+write on `r.nicks` via `/api/v1` → fatal crash | PoC `dr1` | Yes ↻ |
| DL-2 | High | Lock held during socket write: one slow reader freezes the whole room (and hub) | PoC `dl2` | Yes (hang) |
| DL-1 | High | Hub holds `h.mu` across room calls: stuck client + `GET /api/stats` freezes the server | PoC `dl1` | Yes (hang) |
| AZ-1 | High | `/api/v1` trusts client `userid` → authz bypass / password-room takeover | PoC `az1` | Yes |
| AZ-2 | High | Enabling a password grandfathers all connected (incl. hostile) sockets (`SetAuthAll`) | PoC `az2` | Yes |
| GL-1 | High | `Room.Close` never ends plugins → OGS goroutine + fd + room-graph leak | PoC `gl1` | Cond.(OGS) ↻ |
| DR-2 | High | Initial full-frame marshaled outside `r.mu` (aliases tree slices) → torn read/SIGSEGV | PoC `race`† | Yes ↻ |
| DR-3 | High | `Current().AllFields()` iterated outside `r.mu` during mutation → torn read | PoC `race`† | Cond. ↻ |
| CS-1 | High | Postgres DSN (with password) logged in plaintext at startup | PoC `cs1` | n/a (log access) |
| CS-2 | Medium | Password > 72 bytes silently disables room protection | PoC `cs2` | n/a (owner footgun) |
| DR-4 | Medium | `OGSConnector.Exit` read without lock (written under lock) | insp. | Cond.(OGS) |
| GL-2 | Medium | `readSocketToChan` blocks forever on channel send after game-over → goroutine leak | insp. | Cond.(OGS) |
| ID-1 | Medium | Password gates writes only — anon socket reads a protected room's full state/moves | PoC `id1` | Yes |
| ID-2 | Medium | Raw internal fetch/parser errors broadcast to clients (internal IPs/DNS, SSRF oracle) | insp. | Yes |
| ID-3 | Medium | Hand-rolled JSON on `/api/v1` interpolates raw error/value → JSON injection + infoleak | PoC `id3` | Yes |
| DL-3 | Low | `Room.Close` holds `r.mu` across `conn.Close` → room/goroutine/fd leak on a stalled client | insp. | Cond. |
| GL-3 | Low | Postgres pool bounds unset → transient connection exhaustion | insp. | n/a |
| AZ-3 | Low | `outsideBuffer` throttle keyed on client `userid` (bypassable; not authz) | insp. | Yes |
| AZ-4 | Low | `GetAuth` returns key-existence → `SetAuth(id,false)` revocation is a silent no-op | insp. | Per-conn |
| ID-4 | Low | `ApprovedFetch` allowlist-enumeration oracle + requested-host reflection | PoC `id3` | Yes |
| ID-5 | Low | Twitch OAuth callback echoes internal client errors | insp. | Cond. |
| CJ-1 | Medium | No `X-Frame-Options` / CSP → clickjacking + no XSS backstop (embedding use case) | PoC `clickjacking.js` | Yes |

**Remaining `insp.` findings** are either configuration facts (M-6 the 1-hour heartbeat constant; M-9 the missing `http.Server` timeouts) or require live egress to `online-go.com` to reproduce at runtime (H-8 socket-close, DR-4, GL-2, ID-2); their root causes are confirmed in source and, where applicable, by a related PoC (`gl1`, `id3`).

**Not exploitable / mitigated** (documented so they are not re-raised): NGF/SGF oversized-board OOM (clamped by `FromSGF`), `remove_mark value[:2]` and the GIB `alphabet[x]` panic (recovered per-connection; GIB is never persisted). See [§9](#9-not-exploitable--mitigated).

---

## 3. Critical findings

### C-1 — Whole-server crash via the OGS review plugin goroutine · PoC `a1`
- **Location:** `pkg/core/board/board.go:127` (`Board.Set`, no nil/bounds guard) reached from `pkg/room/plugin/ogs.go` (`loop` at `:198`, move parsing `:327-349`, and the assertion cluster `:264,306,310,318,362-364,390-421`).
- **Mechanism:** `request_sgf` for an `online-go.com` review/demo spawns `go o.loop(...)` — a goroutine **outside** `net/http`'s recover. It parses the review's data with unchecked type assertions and plays its moves via `Board.Move`. `Move`→`Legal` calls the *guarded* `Get` first (returns `Empty` for a nil/off-board coord, so the move is **not** rejected) then the **unguarded** `Set` → panic. There is no `recover()` anywhere in `pkg/`, so this aborts the whole process. Also panics on variant `gamedata` (e.g. a rengo game whose `players.black` isn't `{username,rank}`).
- **Trigger (unauthenticated):** create a review on a free OGS account with an off-board move or a pass (`".."` → nil coord); open a WS to any password-less room; send `{"event":"request_sgf","value":"https://online-go.com/review/<id>"}`.
- **Reproduced:** `a1` — `Board.Move((1000,1000))` and `((-1,-1))` → `runtime error: invalid memory address or nil pointer dereference`.
- **Behind proxy / K8s:** conditional on the OGS feature + egress to online-go.com (both default-on); the trigger is a tiny request the proxy forwards. Crash → pod auto-restart → repeatable.
- **Fix:** guard `Board.Set` (`c != nil && c.Valid(size)`) and reject nil/off-board coords in `Legal` before `Set`; comma-ok every assertion in `loop`/`gamedata*`; wrap `loop()` in `defer recover()` (that wrap alone downgrades the whole OGS class to contained).

### C-2 — Persistent poison-pill: colon-less `LB` label bricks a board on every load · PoC `b1`
- **Location:** `pkg/state/frame.go:131` — `generateMarks` does `spl := strings.SplitN(lb, ":", 2); text := spl[1]` with **no length guard** (the PX branch at `:142` correctly guards).
- **Mechanism:** `FromSGF` accepts a label with no colon (`LB[z]`) and stores it — parse succeeds. `UploadSGF` calls `SetState` (**commits** the state) *before* generating a frame, so the subsequent `GenerateFullFrame` panic never rolls it back. `ToSGFIX` writes `LB[z]` back verbatim and `Hub.Save` persists it. On restart, `Hub.Load → room.Load → FromSGF` re-poisons the room; it loads clean and then **panics on the first `RegisterConnection → GenerateFullFrame`** — every join panics. If the room has the OGS plugin active, the same `generateMarks` runs in the OGS spawned goroutine → whole-server crash.
- **Trigger (unauthenticated):** `POST /api/v1/room/{id}` (or WS) with `{"event":"upload_sgf","value":"KDtHTVsxXUZGWzRdU1pbMTldTEJbel0p"}` (base64 of `(;GM[1]FF[4]SZ[19]LB[z])`).
- **Reproduced:** `b1` — `FromSGF` OK, then `GenerateFullFrame` → `index out of range [1] with length 1`.
- **Behind proxy / K8s:** tiny payload passes any cap; poison lives in the **shared DB**, so **auto-restart reloads it** — the standout under this model, because self-healing does not help.
- **Fix:** `if len(spl) != 2 { continue }` at `frame.go:131`; validate `LB` values in `FromSGF` so malformed marks are never committed or persisted.

### C-3 — SGF parse stack overflow (unbounded recursion) · PoC `c6`
- **Location:** `pkg/core/parser/sgfparser.go:214` — `parseBranch` recurses once per `(` with no depth cap.
- **Mechanism:** a deeply nested SGF overflows the goroutine stack. A Go stack overflow is a **fatal error** `recover()` cannot catch, so this is a whole-process crash even from the request path.
- **Trigger (unauthenticated):** the `upload_sgf` *string* branch caps decoded input at 1 MiB (which bounds depth safely), but the **array branch has no cap** (see C-7). Send `{"event":"upload_sgf","value":["<base64 of '(' × 12,000,000>"]}` to `POST /api/v1/room/{id}` or over WS.
- **Reproduced:** `c6` (and end-to-end over both HTTP and WebSocket) → `fatal error: stack overflow`, process dead.
- **Behind proxy / K8s:** the 12 MB HTTP POST is capped by the proxy, but the same payload over the **tunneled WebSocket** crashes the server (verified). Pod restarts; repeatable.
- **Fix:** depth-cap `parseBranch` (error past ~1000) or rewrite iteratively; apply the 1 MiB cap to the array branch.

### C-4 — Tree-serialize stack overflow (`toSGF`/`Copy` recursion) · PoC `h7`
- **Location:** `pkg/core/parser/parser.go:51` (`SGFNode.toSGF`), `pkg/core/tree/tree.go:149` (`TreeNode.Copy`).
- **Mechanism:** `parser.Merge` (reached when **≥2** SGFs are uploaded) serializes via the recursive `toSGF`; a deep linear tree overflows the stack (fatal, not recovered). `Fmap`/`MaxDepth` are iterative — this is specifically the serialize path.
- **Trigger (unauthenticated):** `{"event":"upload_sgf","value":["<b64 of '(' + ';'×12,000,000 + ')'>","<same>"]}` via the uncapped array branch.
- **Reproduced:** `h7` (and end-to-end) → crash trace shows `(*SGFNode).toSGF`, process dead.
- **Behind proxy / K8s:** as C-3 (WS delivery), transient.
- **Fix:** rewrite `toSGF`/`Copy` iteratively or depth-cap at parse time; cap the array branch.

### C-5 — Board-size memory exhaustion (`update_settings`) · PoC `c3`
- **Location:** `pkg/room/handlers.go:243` (`size := int(sMap["size"].(float64))`) → `state.NewState` → `pkg/core/board/board.go:61` (`NewBoard` allocates `size × size`). No range check on this path (the `size > 19` clamp is only in `state.FromSGF`).
- **Mechanism:** a client-chosen `size` drives an `O(size²)` allocation. `size = 200000` ⇒ ~320 GB ⇒ OOM (fatal, bypasses recover).
- **Trigger (unauthenticated):** `update_settings` with `"size":200000` on any password-less room, or via `POST /api/v1/room/{id}`.
- **Reproduced:** `c3` — one request with `size:20000` grew server RSS 80 MB → 626 MB and retained it; `size:200000` OOM-kills.
- **Behind proxy / K8s:** the request is *tiny* (a small JSON), so it passes every body cap; OOMKilled → restart → repeatable.
- **Fix:** validate `size ∈ {9,13,19}` in `handleUpdateSettings`; clamp defensively in `NewBoard`.

### C-6 — ZIP bomb (unbounded in-memory decompression) · PoC `c5`
- **Location:** `internal/zip/zip.go:37-46` — `io.ReadAll` per entry with no per-entry, total, or entry-count cap.
- **Mechanism:** a tiny archive inflates to gigabytes in memory; the upstream 1 MB check applies only to the *compressed* upload, and only on the string branch.
- **Trigger (unauthenticated):** upload a zip via `upload_sgf` (`zip.IsZipFile` routes it to `Decompress`).
- **Reproduced:** `c5` — a 510 KB archive decompressed to **536 MB** (≈1000×).
- **Behind proxy / K8s:** larger bombs via the WS branch; OOM → restart → repeatable.
- **Fix:** `io.LimitReader` per entry, a running total-bytes budget, and a max entry count.

### C-7 — Unauthenticated state control + crash delivery · PoC `c7`
- **Location:** `pkg/hub/apiv1router.go` (`POST /api/v1/room/{board}` — no auth, `io.ReadAll` with no size limit) and `pkg/room/handlers.go:150` (the `upload_sgf` **array branch**, which skips the 1 MiB cap the string branch enforces).
- **Mechanism:** any unauthenticated HTTP client can create a room and dispatch **any** event (`update_settings`, `upload_sgf`, `graft`, board commands). This is the scriptable delivery vector for C-3/C-4/C-5/C-6; the uncapped array branch is what makes the recursion crashes reachable at crash scale.
- **Trigger (unauthenticated):** `curl -XPOST /api/v1/room/x -d '{"event":"upload_sgf","value":["<huge>"]}'`.
- **Reproduced:** `c7` (the endpoint drives arbitrary state and delivers C-3/C-4). Note: a *panic*-type payload here is recovered by net/http; the crashes come from the overflow/OOM payloads.
- **Behind proxy / K8s:** unauth state control passes the proxy; large crash bodies are capped on HTTP → deliver over WS instead.
- **Fix:** authenticate/limit the endpoint, wrap the body in `http.MaxBytesReader`, and cap the array branch.

---

## 4. High findings

### H-1 — No WebSocket `Origin` check → CSWSH · PoC `h1`
- **Location:** `pkg/hub/socketrouter.go:35` — `websocket.Server{Handshake: nil}` performs no origin validation.
- **Impact:** any website a victim visits can open a socket to `/socket/b/{id}` in the victim's context and read/drive boards. Reproduced (`h1`): a cross-origin dial is accepted and receives the initial frame. **Behind proxy / K8s:** Yes — the proxy forwards the browser-set `Origin`; the most relevant risk for "board on my website."
- **Fix:** validate `Origin` against an allow-list in a `Handshake` function.

### H-2 — Unbounded room creation · PoC `h2`
- **Location:** `pkg/hub/hub.go:275` (`GetOrCreateRoom`). Any WS/HTTP hit to a new `boardID` creates a room + a heartbeat goroutine; IDs are only sanitized. Reproduced (`h2`): rooms grew 1 → 501. Amplified by the 1 h heartbeat (M-6). **Behind proxy / K8s:** Yes (single in-memory replica accumulates). **Fix:** cap total rooms; evict idle/empty rooms quickly.

### H-3 — No connection / rate limits · PoC `h3`
- **Location:** `pkg/hub/hub.go`, `socketrouter.go`. No global/per-room/per-IP connection cap or rate limiting. Reproduced (`h3`): 1000 concurrent connections, no throttle. **Behind proxy / K8s:** Partly — an ingress with per-IP connection limits may cap the flood. **Fix:** connection semaphore + per-IP limits + `httprate`.

### H-4 — No max WS message size + no read deadline · PoC `c4`/`h4`
- **Location:** `pkg/event/channel.go:88` (`readPacket`/`readBytes`). A client-controlled 4-byte length has no ceiling and no read deadline; the buffer grows as bytes arrive (not an instant 4 GB — it grows incrementally), and the 1 MB check runs only later, inside `handleUploadSGF`. Enables unbounded per-connection buffering and a slow-loris hold. **Behind proxy / K8s:** Partly — the proxy idle-timeout (~60 s) closes a silent socket, but a slow drip keeps it alive and buffering. **Fix:** reject `length > maxMessageBytes` before reading; set a read deadline; use `io.ReadFull`.

### H-5 — Twitch webhook HMAC bypass on empty secret · PoC `h5`
- **Location:** `internal/twitch/twitch.go:72` — `Verify` returns `true` when the secret is empty (fails open). Reproduced (`h5`): a forged notification with an **invalid** signature returned `200 OK`. Lets an attacker forge `channel.chat.message` events (`!setboard`/`!branch`) and hijack room mappings. **Behind proxy / K8s:** conditional — only if the Twitch integration is enabled and the secret is unset; the webhook is public, so a forged POST is accepted. **Fix:** `Verify` returns `false` on an empty secret; refuse to start the integration without one.

### H-6 — `graft` bypasses `authorized` + `outsideBuffer` · insp.
- **Location:** `pkg/room/handlers.go:74` — `"graft": chain(r.handleEvent, r.broadcastFullFrameAfter)` is the only mutating handler with **neither** the password gate nor the rate-limit buffer. So `graft` mutates even **password-protected** rooms without `checkpassword`, unthrottled. This is the multiplier under H-7. **Behind proxy / K8s:** Yes. **Fix:** add `r.authorized` and `r.outsideBuffer` to the graft chain.

### H-7 — Unbounded tree growth + quadratic full-frame rebroadcast · insp.
- **Location:** `pkg/state/edit.go:271` (`smartGraft` inserts each move into `s.nodes`, no cap) + `pkg/room/handlers.go:387` (`broadcastFullFrameAfter` re-serializes the *entire* tree — two O(n) `Fmap`s — and broadcasts to every connection). Diverging graft sequences grow the tree without bound → `O(k²·conns)` CPU and heap → OOM; the persisted SGF also inflates every future `Load`. **Behind proxy / K8s:** Yes (tiny grafts; OOM → restart, and the growing persisted blob is a creeping escalation). **Fix:** per-room node cap; incremental frames for graft.

### H-8 — OGS fd + goroutine leak on every `request_sgf` · insp.
- **Location:** `pkg/room/plugin/ogs.go:204` — `End()`/`closeOGS` set `o.Exit=true` but never call `o.Socket.Close()`. After deregister, `readSocketToChan` stays parked in `Socket.Read` and `loop` on `<-socketchan`; `Exit` cannot wake them. Net leak per event: **2 goroutines + 1 TCP fd** to online-go.com, unthrottled. **Behind proxy / K8s:** conditional on OGS egress; leak → OOM/fd-exhaustion → restart. **Fix:** `o.Socket.Close()` in `End()`; read deadline; cap connectors per room.

---

## 5. Medium findings

### M-1 — `/debug` leaks full room state unauthenticated · PoC `m3`
`pkg/hub/webrouter.go` exposes `GET /b/{id}/debug` → `SaveState()` JSON (SGF, location, prefs) for **any** room, including password-protected ones, with no auth. Reproduced (`m3`). **Behind proxy / K8s:** Yes (normal GET), unless ops explicitly block the path. **Fix:** gate behind test mode or remove it.

### M-2 — SSRF via redirect-following + untimed/unbounded fetch · PoC `m4`
`internal/fetch` uses `http.DefaultClient` (follows redirects, no timeout) and `io.ReadAll`s the body (no size cap); `ApprovedFetch` checks only the **first** hop's hostname. Reproduced (`m4`): `Fetch` followed a redirect to an "internal" service. Reachability needs an open-redirect on an approved host (or the `OGSCheckEnded`/`FetchOGS` direct-`Fetch` paths). **Behind proxy / K8s:** this is an **egress** problem the ingress proxy does not touch; blast radius in K8s includes cluster-internal ClusterIP services and `169.254.169.254` (cloud IAM metadata). **Fix:** a client with a timeout and a redirect policy that re-validates each hop's host against the allow-list; `io.LimitReader` the body; add an egress `NetworkPolicy`.

### M-3 — `update_nickname` no auth / no length cap → N² rebroadcast · PoC `nick`
`pkg/room/handlers.go:63` — `update_nickname` has no `authorized`, no `outsideBuffer`, and no length cap; an oversized nick is held in `r.nicks` and the full N-entry map is re-marshalled to all N connections on every join/leave/nick-change. **Behind proxy / K8s:** Yes. **Fix:** length-cap nicks; gate the handler.

### M-4 — Unbounded per-room `auth`/`notified` maps · PoC `authleak`
`pkg/room/room.go:198` — `SetAuth`/`SetAuthAll` write `r.auth[uuid]=true` but nothing ever `delete`s from `auth` (or `message.notified`); `DeregisterConnection` prunes only `conns`. Reconnects (fresh UUIDs) grow the maps for the room's ~24 h life — an OOM accelerant across flooded rooms. (`lastMessages` is dead code — never written.) **Behind proxy / K8s:** Yes (slow). **Fix:** delete `auth`/`notified` entries on disconnect.

### M-5 — SGF label escaping not round-trip safe → persisted corruption · PoC `sgfesc`
The `label` command stores raw client text into `LB` (`commands.go:238`), and both serializers escape `]`→`\]` but **not** a literal `\` (`state.go:144`, `parser.go:64`). A label ending in `\` serializes to `[value\]`; on reload the parser consumes the `\]` as an escaped literal and the field swallows the following one. On the standard `ToSGFIX` save (trailing `IX[n]` supplies a terminator) this **corrupts** labels/indices on reload rather than hard-failing; a genuinely terminal field reparses to an error and the board is dropped. **Behind proxy / K8s:** Yes, persistent. **Fix:** also escape `\` in both serializers.

### M-6 — 1-hour heartbeat keeps abandoned rooms alive · insp.
`pkg/hub/hub.go:95` — `heartbeatInterval = 3600 s`, so an abandoned room (and its goroutine) lingers ≥1 h, amplifying H-2. **Behind proxy / K8s:** Yes (amplifier on the single replica). **Fix:** shorter/activity-driven interval; re-fetch the room each tick.

### M-7 — Twitch challenge echoed before verify; no replay protection · PoC `m5`
`pkg/hub/twitchrouter.go:150` writes back the `webhook_callback_verification` challenge **before** the HMAC check, and signed message IDs/timestamps are never validated for freshness or de-duplicated. Reproduced (`m5`): a challenge is reflected unauthenticated. **Behind proxy / K8s:** Yes (low impact — reflection / subscription auto-confirm / replay). **Fix:** verify the signature before handling the challenge; reject stale timestamps and dedupe message IDs.

### M-8 — Unbounded HTTP request body · PoC `m2`
`pkg/hub/apiv1router.go` (and `/ext/upload`) read the body with no cap. Reproduced (`m2`): the server buffered a 40 MB body. **Behind proxy / K8s:** proxy-mitigated on HTTP (`client_max_body_size`); the uncapped equivalent is the WS path (H-4). **Fix:** `http.MaxBytesReader`.

### M-9 — No HTTP server timeouts · insp.
`cmd/main.go` uses `http.ListenAndServe` with no `http.Server{}` timeouts (`ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`). **Behind proxy / K8s:** proxy-mitigated (the front proxy has its own timeouts and shields the origin). **Fix:** construct an `http.Server{}` with explicit timeouts anyway.

### M-10 — Unchecked-input panics on the request path (contained by net/http) · PoC `c1`,`c2`,`m7`
A class of type-assertion / index panics on attacker JSON that each **kill only the issuing connection** (net/http recovers them) — but are latent whole-server crashes if ever reached from a spawned goroutine, so they are worth fixing:
- `handleUpdateSettings` unchecked assertions — `evt.Value().(map[string]any)`, `sMap["buffer"].(float64)`, etc. (`handlers.go:243`) — PoC `c1`.
- GIB `STO` coordinate → `alphabet[x]` index panic (`gibparser.go:280`) — PoC `c2`.
- `coord.FromInterface` (`coord.go:249`, `int(v.(float64))`) and `remove_mark value[:2]` (`commands.go:256`) on crafted command args — PoC `m7`.

**Behind proxy / K8s:** Per-conn (no shared/prod impact). **Fix:** comma-ok every assertion on client input; bounds-check slice indices; treat `handlers.go`/`command_decoder.go` as untrusted-input parsers.

---

## 6. Extended review: concurrency, memory, crypto, authz & disclosure

These are the results of a dedicated review of issue classes beyond DoS/parsing. Two facts of the runtime model apply throughout: a **data race that trips the Go runtime** (`concurrent map …`, torn slice header) is a **fatal error**, not a panic, so — like a stack overflow — `net/http` cannot recover it; and code that holds a mutex across a **blocking socket write** (there is **no write deadline anywhere** — empty `websocket.Config{}`, no `http.Server` timeouts) lets a single non-reading client stall every other holder of that lock.

### Data races

**DR-1 — Concurrent map iteration+write on `r.nicks` → fatal whole-server crash · Critical · PoC `dr1`**
`handleUpdateNickname` returns `event.NewEvent("connected_users", r.Nicks())`, and `Room.Nicks()` (`room.go:237`) returns the **live** map, not a copy. The `/api/v1` handler then `json.Marshal`s that event at `apiv1router.go:27` **outside `r.mu`**, iterating the map, while a concurrent request's `SetNick` (`room.go:250`) writes it under the lock. Reproduced: a burst of concurrent `POST /api/v1/room/x {"event":"update_nickname",...}` (no auth on this handler) kills the server with `fatal error: concurrent map iteration and map write` — not recoverable. **Fix:** `Nicks()` returns a copy built under the lock; never marshal events that alias live room state.

**DR-2 — Initial full-frame marshaled outside `r.mu`, aliasing tree field slices → torn read/SIGSEGV · High · `go test -race ./security/poc/race/`.** `RegisterConnection` (`room.go`) releases `r.mu`, then `SendEvent`→`json.Marshal` walks `Metadata.Fields`/`Comments`, which alias `s.root`/`s.current` field slices (`AllFields`/`GetField` return the slice, no copy). A concurrent `update_settings`/comment on another connection appends/overwrites the same backing array → torn 24-byte slice header → out-of-bounds read/SIGSEGV (fatal). **Fix:** marshal the initial frame inside a locked method, or deep-copy `Fields`/`Comments` in `GenerateFullFrame`.

**DR-3 — `Current().AllFields()` iterated outside the lock during mutation → torn read · High · race test.** `Room.Current()` (`room.go:621`) returns a shallow copy whose embedded `fields.Fields` slice still aliases the live node; `logAfter` (`handlers.go:493`) then ranges `current.AllFields()` and `strings.Join(field.Values,…)` with `r.mu` released, while another client's mark/label command (`commands.go:153/172/194`) appends under the lock. **Fix:** deep-copy fields in `Current()`, or format inside a locked method.

**DR-4 — `OGSConnector.Exit` read without a lock · Medium.** `End()` writes `o.Exit` under `o.mu` (`ogs.go:202`), but `loop()`/`readSocketToChan()` read it with no lock (`ogs.go:187,243`) — the author fixed the ping site with `isExited()` but missed these. **Fix:** use `isExited()` at both sites or make `Exit` an `atomic.Bool`. (`go test -race` on the shipped suite is clean because the tests don't exercise these concurrent paths.)

### Deadlocks / lock-held-during-I/O

**DL-2 — One slow reader freezes the whole room (and hub) · High · PoC `dl2`.** `Broadcast`/`SendTo`/`BroadcastHubMessage` (`room.go:361-392`) hold `r.mu` while calling `SendEvent` → `ws.Write` with no deadline. Reproduced: with one stuck-reading client, `r.Size()` (and thus every join/move/frame) blocks indefinitely. Escalation: `Hub.SendMessages` (`hub.go`) holds `h.mu` while broadcasting to every room, so a single stuck reader can stall the global message loop. **Fix:** snapshot the connection list under the lock, unlock, then write; add per-write deadlines and drop slow clients.

**DL-1 — Hub freeze via `h.mu` held across room calls · High · PoC `dl1`.** `ConnCount`/`RoomCount` (`hub.go:132`) lock `h.mu` and call `r.NumConns()` (which needs `r.mu`); if a broadcast has pinned some `r.mu` (DL-2), an unauthenticated `GET /api/stats` wedges while holding `h.mu`, and then every new WS (`GetOrCreateRoom`) and board load (`GetRoom`) blocks. **Fix:** never call room methods under `h.mu` — snapshot, release, then call.

**DL-3 — `Room.Close` holds `r.mu` across `conn.Close` → room leak · Low.** `Close()` (`room.go:281`) writes a close frame to each connection under `r.mu`; a stalled client blocks it forever, so `Close` never returns and `DeleteRoom`/`db.DeleteRoom` never run — the room, its goroutines, and fds leak. **Fix:** snapshot and close outside the lock with a deadline.

### Memory / goroutine / fd leaks

**GL-1 — `Room.Close` never ends registered plugins · High · PoC `gl1`.** `Close()` closes only `r.conns`, never iterates `r.plugins`/`p.End()`. On idle expiry the Heartbeat calls `Close` then `DeleteRoom`, after which no event can reach `closeOGS` — so the OGS `loop`/`ping`/`readSocketToChan` goroutines run forever, pinning the whole room object graph and a TCP fd. Drivable unauthenticated by minting rooms with an OGS plugin (`GET /ext/upload?url=…online-go.com/review/<id>` per request). **Fix:** iterate and `End()` all plugins in `Close()`; combine with the socket-close fix.

**GL-2 — `readSocketToChan` blocks on a channel send after game-over · Medium.** When `loop()` returns on game-over, nothing drains `socketchan`; the next byte parks `readSocketToChan` on the unbuffered send (`ogs.go:185`), which the socket-close fix cannot interrupt. **Fix:** `select { case socketchan <- b: case <-done: return }`.

**GL-3 — Postgres pool bounds unset · Low.** `SetMaxOpenConns`/`ConnMaxLifetime` are never set on the Postgres loader (the sqlite loader sets `SetMaxOpenConns(1)`); combined with per-room Heartbeat `DeleteRoom` running outside `h.mu`, mass room expiry can transiently spike connections. (Corrected from "leak" to transient exhaustion — `database/sql` closes idle conns by default.) **Fix:** set symmetric pool bounds.

### Crypto / secrets

**CS-1 — Postgres DSN logged in plaintext at startup · High · PoC `cs1`.** `dbConfig.redact()` (`config.go:84`) is an empty no-op while `Config.Redact()` masks only Twitch, so `cmd/main.go:52` logs the running config including `DB.Path` — for Postgres, the DSN `postgres://user:pass@…` with the password. Requires log access, not remote. **Fix:** implement `dbConfig.redact()` (strip userinfo) or a `slog.LogValuer` that redacts.

**CS-2 — Password > 72 bytes silently disables protection · Medium · PoC `cs2`.** bcrypt rejects inputs > 72 bytes with `ErrPasswordTooLong`; `core.Hash` (`verify.go:17`) discards the error and returns `""`. The guard is only `password != ""` (`handlers.go:313`), so a long password stores an empty hash → `HasPassword()==false` → the room is open to everyone while the owner believes it is protected (persists across restarts). Reproduced: `Hash(73×"A") == ""`. **Fix:** propagate the bcrypt error and reject the setting. (Room-name predictability from `math/rand` is tracked as L-8; the constant-time Twitch HMAC and, for ≤72-byte inputs, bcrypt usage are correct.)

### Authorization / TOCTOU

**AZ-1 — `/api/v1` trusts client `userid` → password-room takeover · High · PoC `az1`.** The WS path binds identity server-side (`evt.SetUser(ec.ID())`), but the HTTP handler (`apiv1router.go`) takes `evt.User()` verbatim from the attacker's JSON `userid` (`event.go:36`, `json:"userid"`) and never re-sets it. `authorized` checks `GetAuth(evt.User())`, and `connected_users` broadcasts every occupant's connection UUID — so an attacker idling in the room harvests an authenticated owner's UUID and replays it: `POST /api/v1/room/myroom {"event":"trash","userid":"<ownerUUID>"}` (or `update_settings`/`upload_sgf`). Full authz bypass on a **password-protected** room. **Fix:** never trust client `userid` as identity on the HTTP path; bind auth to server-issued tokens, not broadcast UUIDs.

**AZ-2 — Enabling a password grandfathers all connected sockets · High · PoC `az2`.** `handleUpdateSettings` calls `SetAuthAll()` immediately before `SetPassword` (`handlers.go:330`), setting `auth[connID]=true` for every current connection — including a hostile one idling since the room was still open. Protection thus fails **open** for occupants present at set-time (and never evicts them; `auth` is never cleared), and combined with AZ-1 the attacker replays that grandfathered UUID indefinitely. **Fix:** clear `auth` in `SetPassword`; force re-`checkpassword`.

**AZ-3 — `outsideBuffer` throttle keyed on client `userid` · Low.** The anti-flood gate compares `GetLastUser() != evt.User()`; on `/api/v1` the attacker controls `userid`, so pinning `lastUser` to their own id skips the throttle on subsequent privileged POSTs. It is a per-action throttle, not an authz control — an amplifier for the upload/OOM DoS. **Fix:** don't key throttling on client identity.

**AZ-4 — `GetAuth` returns key-existence → revocation is a no-op · Low (latent).** `GetAuth` does `_, ok := r.auth[user]; return ok` (`room.go:204`), discarding the stored bool, so `SetAuth(id,false)` leaves the key and the user stays authorized. No live revocation path today, but a latent footgun. **Fix:** return the stored value.

### Information disclosure

**ID-1 — Password gates writes only; anyone reads a protected room · Medium · PoC `id1`.** `Handle` accepts any WS with no auth check and `RegisterConnection` immediately pushes `GenerateFullFrame(Full)`; `Broadcast` relays every move and `connected_users` (UUIDs) to all connections. `authorized` gates only mutating handlers, never the connect/read path — so an anonymous socket to a "protected" room receives the full board, every live move, and occupant UUIDs. **Fix:** gate the connect/read path if read-privacy is intended (and note this feeds AZ-1's UUID harvest).

**ID-2 — Raw internal fetch/parser errors broadcast to clients · Medium.** `Fetch` returns the verbatim `*url.Error` (rewritten internal OGS API URL, resolved backend IP, local resolver `127.0.0.53:53`), wrapped into `ErrorEvent` and broadcast to every connection (`handlers.go:209/250`). Discloses internal request topology and gives an SSRF/liveness oracle (DNS-fail vs conn-refused vs parse-error are distinguishable). **Fix:** generic client messages; log details server-side only.

**ID-3 — Hand-rolled JSON on `/api/v1` → JSON injection + infoleak · Medium · PoC `id3`.** `apiv1router.go` builds responses with `fmt.Sprintf(\`{"error":"%s"}\`, …)` interpolating the raw error/value (which for a failed `request_sgf` is a `*url.Error` containing quotes and `dial tcp <ip>:<port>`). The unescaped quotes break out of the JSON string (response injection) and leak internals. **Fix:** build a struct and `json.Marshal`; map errors to a generic message.

**ID-4 — Allowlist-enumeration oracle + host reflection · Low · PoC `id3`.** `ApprovedFetch` returns `"unapproved URL. contact us to add <host>"` for a disallowed host vs a raw dial error for an allowed-but-unreachable one — a distinguisher that lets an attacker enumerate `okList` and reflects an arbitrary host into a client-visible broadcast. **Fix:** generic message, no host reflection.

**ID-5 — Twitch OAuth callback echoes internal errors · Low.** `twitchrouter.go` returns `http.Error(w, err.Error(), 403)` on the state/exchange path, echoing internal client errors to the caller. **Fix:** generic messages.

---

## 7. Client-side (frontend) & HTTP headers

The ~7,200-line frontend (`pkg/frontend/js`) renders user data broadcast to every room participant. The obvious sinks are escaped (nicknames and comments use the `textContent`→`innerHTML` trick; player names use `htmlencode`, `common.js:162`), but board **labels** are not — and no HTTP security headers are set. (A broader client-side sweep is ongoing; additional findings will be added here.)

### XSS-1 — Stored XSS via board labels · **Critical** · PoC `security/poc/browser/xss_label.js` (reproduced in Chromium)
- **Sink:** `pkg/frontend/js/boardgraphics/boardgraphics.js:516` — `text.innerHTML = txt` on an SVG `<text>` element, reached from `draw_custom_label` → `draw_centered_text` → `svg_draw_centered_text` with the **raw** label text (no escaping on this path, unlike nicknames/comments/player-names).
- **Source / delivery (unauthenticated):** a `label` event (`{"event":"label","value":{"coords":[x,y],"label":"<payload>"}}`) over the WebSocket **or** the unauthenticated `POST /api/v1/room/{id}`, or an uploaded SGF with a crafted `LB` field. The label is broadcast to all participants and **persisted in room state**, so it re-fires on every future connect.
- **Payload:** `<img src=x onerror="/* attacker JS */">` (SVG `<text>.innerHTML` executes injected event handlers — confirmed for `<img onerror>`, `<foreignObject>`, `<animate onbegin>`, `<set onbegin>`).
- **Impact:** arbitrary JavaScript in **every** viewer's browser, **in the origin the board is embedded in**. For the intended "board on my website" use, this is full compromise of any visitor's session on that site (session/cookie theft, defacement, request forgery, pivot). Persisted → affects everyone who later opens the room.
- **Verified:** end-to-end in real Chromium — an API-injected label executed `onerror` in a victim board page (`window.__xss` was set to the page origin).
- **Fix:** escape the label text (use `textContent` / the existing `htmlencode`, or set `text.textContent = txt`) in `svg_draw_centered_text`; never assign untrusted strings to `innerHTML`. Add a CSP (below) as defense-in-depth.

### CJ-1 — No framing protection (clickjacking) & no CSP · **Medium** · PoC `security/poc/browser/clickjacking.js`
- **Location:** `pkg/app/app.go` — the middleware chain is only `StripSlashes` + the request logger; no security-header middleware anywhere.
- **Detail:** responses set **no `X-Frame-Options`, no `Content-Security-Policy`**, no `X-Content-Type-Options`, no `Referrer-Policy`. Confirmed by response headers (only `Content-Type` is set). Any site can iframe the board (clickjacking / UI-redress), and the absent CSP means there is no second layer to blunt XSS-1. This is especially relevant because the board is meant to be embedded in a third-party site.
- **Fix:** add a headers middleware setting `Content-Security-Policy` (at least `default-src 'self'`; note the app currently pulls Bootstrap from a CDN, so allow that host or vendor it), `X-Frame-Options`/`frame-ancestors` scoped to the embedding site(s), `X-Content-Type-Options: nosniff`, and a `Referrer-Policy`.

---

## 8. Low findings / hardening

- **L-1 — `GET /ext/upload` has side effects** (`pkg/hub/extrouter.go`): creates a room and triggers a server-side fetch → CSRF-able. Make it POST with CSRF protection.
- **L-2 — Missing security headers** (`pkg/app/app.go`): no CSP/`X-Frame-Options`/`X-Content-Type-Options`/`Referrer-Policy`. Add a headers middleware (templates already auto-escape via `html/template`).
- **L-3 — Container runs as root** (`Dockerfile`, no `USER`). Add a non-root user; read-only FS; resource limits.
- **L-4 — Committed DB creds / `sslmode=disable`** (`config/config-docker-compose.yaml`: `postgres:postgres`, TLS off). Use secrets; enable TLS.
- **L-5 — Grafana default admin password** (`docker-compose.yaml` defaults to `admin`). Require an explicit value.
- **L-6 — Deprecated `golang.org/x/net/websocket`.** Migrate to `nhooyr.io/websocket`/`gorilla` (makes H-1/H-4 easier to get right).
- **L-7 — No CI security scanning** (`.github/workflows/`). Add `govulncheck` and `gosec`.
- **L-8 — Predictable `math/rand` room names** (`pkg/core/util.go`): rooms are unauthenticated and world-readable, so names are guessable/enumerable. Use `crypto/rand` if names are meant to be unguessable.
- **L-9 — bcrypt on every `checkpassword`** (`handlers.go`): no rate limit → CPU-amplification. Rate-limit auth attempts per IP/connection.

---

## 9. Not exploitable / mitigated

Documented so a re-audit does not re-raise them:
- **Oversized board via NGF/SGF upload** — the NGF parser only stores `size` as a string; the sole path to `NewBoard` from parsed SGF/NGF is `state.FromSGF`, which **clamps `size > 19`** (`state.go:196`) and errors before allocating. Verified: `FromSGF("(;SZ[50000])")` → `"unsupported board size"`. (The unclamped board-size DoS is C-5, via `update_settings`.)
- **`remove_mark value[:2]` and GIB `alphabet[x]` panics** — real panics, but recovered per-connection (M-10 class); GIB is never persisted (rooms store clean SGF), so no poison-pill.
- **WebSocket "instant 4 GB" allocation** — not a thing; `readBytes` grows incrementally as bytes arrive (the real issue is H-4: no ceiling, no deadline).

---

## 10. Reviewed and clean (positives)

- Passwords hashed with **bcrypt** and compared in constant time (`pkg/core/verify.go`).
- **SQL fully parameterized** (`pkg/loader/dbloader.go`) — no injection. (Portability nit: `dbloader.go:382` uses double-quoted string literals that break on Postgres.)
- HTML templates use `html/template` auto-escaping.
- ZIP extraction never writes entry names to disk → **no zip-slip**.
- No `InsecureSkipVerify` / disabled TLS verification in outbound clients.
- No hardcoded app secrets committed (aside from the sample Postgres/Grafana defaults in L-4/L-5).

---

## 11. Remediation priority

1. **Fix the stored XSS (highest impact for embedding).** Escape the label text in `svg_draw_centered_text` (`boardgraphics.js:516`) — use `textContent`/`htmlencode`, never `innerHTML` for untrusted data — and add a `Content-Security-Policy` + `X-Frame-Options` headers middleware (XSS-1, CJ-1). This is the one that compromises your website's visitors.
2. **Close the confirmed whole-server crashes.** Guard `Board.Set` + `recover()` in the OGS `loop` (C-1); add `len(spl)!=2` at `frame.go:131` + validate `LB` in `FromSGF` (C-2); depth-cap `parseBranch` and `toSGF`/`Copy` (C-3/C-4); cap board size (C-5) and zip output/entry count (C-6); cap the `upload_sgf` **array branch** (C-7); make `Nicks()` return a copy so `/api/v1` can't race the live map (DR-1).
2. **Fix the concurrency model.** Never hold `r.mu`/`h.mu` across a socket write — snapshot connections, unlock, then write; add per-write deadlines and drop slow clients (DL-1/DL-2/DL-3). Deep-copy field slices marshaled outside the lock (DR-2/DR-3); atomic/locked `OGSConnector.Exit` (DR-4).
3. **Fix authorization.** Stop trusting client `userid` on `/api/v1` — bind identity to a server-issued token (AZ-1/AZ-3); clear `auth` on `SetPassword` and re-require `checkpassword` (AZ-2); authenticate/limit `POST /api/v1/room` + `MaxBytesReader` (C-7); add `authorized`+`outsideBuffer` to `graft` (H-6); validate `Origin` (H-1).
4. **Stop the leaks.** End plugins in `Room.Close` (GL-1) and fix the OGS channel-send/socket-close (GL-2/H-8); room/connection/rate caps + shorter heartbeat (H-2/H-3/M-6); prune `auth`/`notified` maps (M-4); Postgres pool bounds (GL-3).
5. **Secrets, integrations & info leaks.** Implement `dbConfig.redact()` (CS-1) and propagate the bcrypt error (CS-2); fail-closed on empty Twitch secret + verify-before-challenge (H-5/M-7); gate `/debug` (M-1) and the read/connect path if rooms are meant to be private (ID-1); return generic error messages and `json.Marshal` responses (ID-2/ID-3/ID-4/ID-5); redirect-revalidating fetch client + egress `NetworkPolicy` (M-2).
6. **Robustness & hardening.** Comma-ok all client-input assertions + escape `\` in serializers (M-10/M-5); Low items L-1…L-9; the deployment hardening implied by the K8s model (non-root, secrets, single-instance or shared state, egress policy).

---

## 12. Running the PoCs

```
go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml   # disposable target on :8080
go run ./security/poc/harness <id> [-target localhost:8080]                # one id per finding
```

Run with no arguments for the full list of harness commands. Data races use `go test -race ./security/poc/race/`. **Browser PoCs** (need Node + Playwright + Chromium, and the server running): `node security/poc/browser/xss_label.js` (stored XSS) and `node security/poc/browser/clickjacking.js`. Several PoCs crash or exhaust the target — **authorised local testing only**; see [`security/poc/README.md`](security/poc/README.md).

*Caveats: line numbers reference the repository at assessment time; dynamic validation ran against the default in-memory config; items marked `insp.` are confirmed by code inspection rather than a runnable exploit.*
