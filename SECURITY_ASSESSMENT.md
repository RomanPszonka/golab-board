# Security Assessment — golab/board

**Target:** `golab-board` — a no-login, multi-user Go board web app (Go backend, ~10k LOC): HTTP/WebSocket routing, event handling, file parsers (SGF/GIB/NGF/ZIP), room/state management, OGS + Twitch integrations, persistence, deployment config.
**Method:** White-box source review with dynamic proof-of-concept validation. Every Critical, High, and Medium finding below is either **reproduced** with a runnable PoC (in [`security/poc/`](security/poc/)) or **confirmed** by code inspection; the status is stated per finding.
**Assessment date:** 2026-07-07.

---

## 1. Executive summary

Every client is anonymous and can open a WebSocket, create rooms, upload files, and drive board state — a large, fully **unauthenticated** attack surface. The findings fall into four groups:

- **Whole-server crashes (7 Critical).** A single unauthenticated request can abort the entire process via **unbounded recursion** (SGF parse / tree serialize → `fatal error: stack overflow`), **unbounded allocation** (board size, zip bomb → OOM), or a **panic in a spawned goroutine** (the OGS review plugin, which `net/http` does not recover). All were reproduced.
- **One unrecoverable board (persistent poison-pill).** A crafted label (`LB[z]`) is committed and persisted, then panics on every load — the board is permanently unjoinable and the poison **survives restarts** (see C-2).
- **Resource-exhaustion and integrity issues (High/Medium).** No origin check (CSWSH), no room/connection/rate caps, missing timeouts, an unauthenticated `graft` handler, goroutine/fd leaks, SSRF, and an info-leaking `/debug` endpoint.
- **Deployment hardening (Low).** Root container, committed default credentials, no security headers, no CI scanning.

**Reading crash severity — the `net/http` recover boundary.** Go's `net/http` wraps each request in `recover()`, and the WebSocket handler runs *inside* that request goroutine. So a plain type-assertion/index panic reached from a request is **contained** — it drops one connection, not the server. Only three things abort the whole process: (a) **fatal runtime errors** (stack overflow, OOM), (b) panics in **`go`-spawned goroutines** (OGS plugin loop, heartbeat, message loop), and (c) a **persisted poison pill** re-triggered on reload. Findings are rated on that basis: unchecked-input panics on the request path are Medium (contained); the same defect in a spawned goroutine is Critical.

**Deployment threat model (column "Behind proxy / K8s").** The rightmost table column rates each finding for a realistic production posture: attacker has **no direct/shell access**, the app runs in **Kubernetes** (memory limit → `OOMKilled`; liveness probe → auto-restart; in-memory room state ⇒ effectively single-instance; shared DB survives restarts), and traffic is behind a **reverse proxy / ingress** (HTTP body cap ~1 MB, ~60 s timeouts, but it **tunnels WebSocket**). Two facts drive most verdicts, both verified here:
1. **The proxy caps HTTP bodies but tunnels WebSocket** — every crash reachable via `upload_sgf`/the WS framing is deliverable over the socket regardless of `client_max_body_size` (confirmed: the 12 MB C-3 array-upload crashes the server over WS).
2. **K8s auto-restart heals *transient* crashes but not *persisted* state** — OOM/overflow crashes become a repeatable transient DoS; the poison-pill (C-2) and label corruption (M-5) survive the restart. **SSRF (M-2)** is worse in K8s (cluster-internal services + cloud IAM metadata) and is an *egress* problem the ingress proxy does not touch.

---

## 2. Findings — master table

**Status:** `PoC` = reproduced with the named harness command · `insp.` = confirmed by code inspection.
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
| H-1 | High | No WebSocket `Origin` check → cross-site WebSocket hijacking (CSWSH) | PoC `h1` | Yes |
| H-2 | High | Unbounded room creation | PoC `h2` | Yes |
| H-3 | High | No connection / rate limits | PoC `h3` | Partly |
| H-4 | High | No max WS message size + no read deadline (buffering + slow-loris) | PoC `c4`/`h4` | Partly |
| H-5 | High | Twitch webhook HMAC bypass when the secret is empty | PoC `h5` | Cond. |
| H-6 | High | `graft` handler bypasses `authorized` + rate-limit middleware | insp. | Yes |
| H-7 | High | Unbounded per-room tree growth + quadratic full-frame rebroadcast | insp. | Yes ↻ |
| H-8 | High | OGS plugin fd + goroutine leak on every `request_sgf` | insp. | Cond.(OGS) ↻ |
| M-1 | Medium | `/debug` leaks full room state unauthenticated (incl. password rooms) | PoC `m3` | Yes |
| M-2 | Medium | SSRF via redirect-following + untimed/unbounded fetch | PoC `m4` | Cond.; high in K8s |
| M-3 | Medium | `update_nickname` no auth / no length cap → N² rebroadcast | insp. | Yes |
| M-4 | Medium | Unbounded per-room `auth`/`notified` maps (never pruned) | insp. | Yes |
| M-5 | Medium | SGF label escaping not round-trip safe → persisted corruption | insp. | Yes ⚑ |
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

**Not exploitable / mitigated** (documented so they are not re-raised): NGF/SGF oversized-board OOM (clamped by `FromSGF`), `remove_mark value[:2]` and the GIB `alphabet[x]` panic (recovered per-connection; GIB is never persisted). See [§7](#7-not-exploitable--mitigated).

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

### M-3 — `update_nickname` no auth / no length cap → N² rebroadcast · insp.
`pkg/room/handlers.go:63` — `update_nickname` has no `authorized`, no `outsideBuffer`, and no length cap; an oversized nick is held in `r.nicks` and the full N-entry map is re-marshalled to all N connections on every join/leave/nick-change. **Behind proxy / K8s:** Yes. **Fix:** length-cap nicks; gate the handler.

### M-4 — Unbounded per-room `auth`/`notified` maps · insp.
`pkg/room/room.go:198` — `SetAuth`/`SetAuthAll` write `r.auth[uuid]=true` but nothing ever `delete`s from `auth` (or `message.notified`); `DeregisterConnection` prunes only `conns`. Reconnects (fresh UUIDs) grow the maps for the room's ~24 h life — an OOM accelerant across flooded rooms. (`lastMessages` is dead code — never written.) **Behind proxy / K8s:** Yes (slow). **Fix:** delete `auth`/`notified` entries on disconnect.

### M-5 — SGF label escaping not round-trip safe → persisted corruption · insp.
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

## 6. Low findings / hardening

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

## 7. Not exploitable / mitigated

Documented so a re-audit does not re-raise them:
- **Oversized board via NGF/SGF upload** — the NGF parser only stores `size` as a string; the sole path to `NewBoard` from parsed SGF/NGF is `state.FromSGF`, which **clamps `size > 19`** (`state.go:196`) and errors before allocating. Verified: `FromSGF("(;SZ[50000])")` → `"unsupported board size"`. (The unclamped board-size DoS is C-5, via `update_settings`.)
- **`remove_mark value[:2]` and GIB `alphabet[x]` panics** — real panics, but recovered per-connection (M-10 class); GIB is never persisted (rooms store clean SGF), so no poison-pill.
- **WebSocket "instant 4 GB" allocation** — not a thing; `readBytes` grows incrementally as bytes arrive (the real issue is H-4: no ceiling, no deadline).

---

## 8. Reviewed and clean (positives)

- Passwords hashed with **bcrypt** and compared in constant time (`pkg/core/verify.go`).
- **SQL fully parameterized** (`pkg/loader/dbloader.go`) — no injection. (Portability nit: `dbloader.go:382` uses double-quoted string literals that break on Postgres.)
- HTML templates use `html/template` auto-escaping.
- ZIP extraction never writes entry names to disk → **no zip-slip**.
- No `InsecureSkipVerify` / disabled TLS verification in outbound clients.
- No hardcoded app secrets committed (aside from the sample Postgres/Grafana defaults in L-4/L-5).

---

## 9. Remediation priority

1. **Close the confirmed whole-server crashes.** Guard `Board.Set` + `recover()` in the OGS `loop` (C-1); add `len(spl)!=2` at `frame.go:131` + validate `LB` in `FromSGF` (C-2); depth-cap `parseBranch` and `toSGF`/`Copy` (C-3/C-4); cap board size (C-5) and zip output/entry count (C-6); cap the `upload_sgf` **array branch** (the delivery path).
2. **Lock down the unauthenticated surface.** Authenticate/limit `POST /api/v1/room` + `MaxBytesReader` (C-7); add `authorized`+`outsideBuffer` to `graft` (H-6); validate `Origin` (H-1).
3. **Bound resources.** Room/connection/rate caps + shorter heartbeat (H-2/H-3/M-6); WS message-size cap + read deadline (H-4); prune `auth`/`notified` maps (M-4); close the OGS socket in `End()` (H-8); node cap + incremental frames for graft (H-7).
4. **Integrations & info leaks.** Fail-closed on empty Twitch secret + verify-before-challenge + replay protection (H-5/M-7); gate `/debug` (M-1); redirect-revalidating fetch client + egress `NetworkPolicy` (M-2).
5. **Robustness & hardening.** Comma-ok all client-input assertions + escape `\` in serializers (M-10/M-5); Low items L-1…L-9; the deployment hardening implied by the K8s model (non-root, secrets, single-instance or shared state, egress policy).

---

## 10. Running the PoCs

```
go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml   # disposable target on :8080
go run ./security/poc/harness <id> [-target localhost:8080]                # one id per finding
```

Run with no arguments for the list. **Local-only** (no server): `c2 c5 c6 h6 h7 a1 b1 m4 m7`. **Need `-target`:** `c1 c3 c4 c7 h1 h2 h3 h4 h5 m2 m3 m5`. Several PoCs crash or exhaust the target — **authorised local testing only**; see [`security/poc/README.md`](security/poc/README.md).

*Caveats: line numbers reference the repository at assessment time; dynamic validation ran against the default in-memory config; items marked `insp.` are confirmed by code inspection rather than a runnable exploit.*
