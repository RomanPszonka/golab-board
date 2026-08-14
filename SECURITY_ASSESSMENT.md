# Security Assessment — golab/board

**Target:** `golab-board` — a no-login, multi-user Go board web app (Go backend, ~10k LOC): HTTP/WebSocket routing, event handling, file parsers (SGF/GIB/NGF/ZIP), room/state management, OGS + Twitch integrations, persistence, deployment config.
**Method:** White-box source review with dynamic proof-of-concept validation. Every Critical, High, and Medium finding is either **reproduced** with a runnable PoC (in [`security/poc/`](security/poc/)) or **confirmed** by code inspection; the status is stated per finding.
**Assessment date:** 2026-07-09.

This report is organized by **priority** (Critical → High → Medium → Low) and split into two tracks:
- **[§3 Server-side (Go)](#3-server-side-findings-go)** — crashes, resource exhaustion, concurrency, authorization, disclosure, leaks.
- **[§4 Client-side (browser)](#4-client-side-findings-browser)** — XSS and HTTP response headers (what reaches the site the board is embedded in).

---

## 1. Executive summary

Every client is anonymous and can open a WebSocket, create rooms, upload files, and drive board state — a large, fully **unauthenticated** attack surface.

**Headline risk for an embedding site:** a **stored XSS** via a board label runs arbitrary JavaScript in every viewer's browser **in your site's origin**, and there is **no `Content-Security-Policy`** to contain it. Fixing the frontend sinks + adding a CSP is the single highest-value change (see [§4](#4-client-side-findings-browser) and [§5 remediation](#5-remediation-priority)).

**Server-side, 10 findings can abort the whole process or brick a board unauthenticated:**
- **Whole-server crashes.** A single request aborts the process via **unbounded recursion** (SGF parse / tree serialize → `fatal error: stack overflow`), **unbounded allocation** (board size, zip bomb, or **exponential copy/paste amplification** — each `copy`+`clipboard` pair doubles the tree → OOM), a **panic in a spawned goroutine** (two distinct OGS paths, which `net/http` does not recover), or a **concurrent-map data race** (`fatal error: concurrent map iteration and map write`).
- **Persistent poison-pills.** A crafted `LB` or `TR`/`SQ` mark is committed and persisted, then panics on every load — the board is permanently unjoinable and the poison **survives restarts**.

**High/Medium clusters:** authorization bypass (the `/api/v1` path trusts client-supplied `userid`; enabling a password grandfathers connected sockets), lock-held-during-I/O (one stuck reader freezes a whole room and the hub), memory/goroutine/fd leaks (room teardown never ends plugins), and information disclosure (a "protected" room streams full state to any anonymous socket; internal fetch errors leak internal IPs and JSON-inject `/api/v1`).

**Reading crash severity — the `net/http` recover boundary.** Go's `net/http` wraps each request in `recover()`, and the WebSocket handler runs *inside* that request goroutine, so a plain type-assertion/index panic reached from a request is **contained** — it drops one connection, not the server. Only three things abort the whole process: (a) **fatal runtime errors** (stack overflow, OOM, concurrent-map access), (b) panics in **`go`-spawned goroutines** (OGS plugin loop, heartbeat, message loop), and (c) a **persisted poison-pill** re-triggered on reload. Findings are rated on that basis: an unchecked-input panic on the request path is Medium (contained); the same defect in a spawned goroutine is Critical.

**Deployment threat model (column "Prod").** The "Prod (proxy/K8s)" column rates each finding for a realistic production posture: attacker has **no shell access**, the app runs in **Kubernetes** (memory limit → `OOMKilled`; liveness probe → auto-restart; in-memory room state ⇒ effectively single-instance; shared DB survives restarts), and traffic is behind a **reverse proxy / ingress** (HTTP body cap ~1 MB, ~60 s timeouts, but it **tunnels WebSocket**). Two facts drive most verdicts, both verified:
1. **The proxy caps HTTP bodies but tunnels WebSocket** — every crash reachable via `upload_sgf`/the WS framing is deliverable over the socket regardless of `client_max_body_size` (confirmed: the 12 MB C-3 array-upload crashes the server over WS).
2. **K8s auto-restart heals *transient* crashes but not *persisted* state** — OOM/overflow crashes become a repeatable transient DoS, but the poison-pills (C-2/C-2b), the size-poison (M-11) and the label-escape corruption (M-5) survive the restart. SSRF (M-2) is an *egress* problem the ingress proxy does not touch.

---

## 2. Findings — master table

**Area:** `Go` = server-side · `Web` = browser/JS/HTTP-headers.
**PoC / status:** `PoC x` = reproduced with harness command `go run ./security/poc/harness x` · `race` = reproduced under `go test -race ./security/poc/race/` · `test` = reproduced with a Go test · `browser` = reproduced in real Chromium (Playwright, [`security/poc/browser/`](security/poc/browser/)) · `insp.` = confirmed by code inspection.
**Prod (proxy/K8s):** `Yes` = effective as-is · `WS` = effective via the tunneled WebSocket (HTTP vector capped) · `↻` = crashes but the pod auto-restarts (repeatable transient DoS) · `⚑` = persists across restarts · `Partly` = blunted, not prevented · `Cond.` = needs a precondition · `Proxy-mit.` = the proxy largely prevents it · `Per-conn` = affects only the attacker's own connection.

| # | Sev | Area | Finding | PoC / status | Prod |
|----|-----|------|---------|--------------|------|
| C-1 | Critical | Go | Whole-server crash via the OGS review goroutine (`Board.Set` nil/OOB, not recovered) | `PoC a1` | Cond.(OGS) ↻ |
| C-2 | Critical | Go | Persistent poison-pill: colon-less `LB` label bricks a board on every load | `PoC b1` | Yes ⚑ |
| C-3 | Critical | Go | SGF parse stack overflow (unbounded `parseBranch` recursion) | `PoC c6` | WS ↻ |
| C-4 | Critical | Go | Tree-serialize stack overflow (`toSGF`/`Copy` recursion via `Merge`) | `PoC h7` | WS ↻ |
| C-5 | Critical | Go | Board-size memory exhaustion (`update_settings` size unbounded) | `PoC c3` | Yes ↻ |
| C-6 | Critical | Go | ZIP bomb — unbounded in-memory decompression | `PoC c5` | WS ↻ |
| C-7 | Critical | Go | Unauthenticated state control + crash delivery (`POST /api/v1/room`, uncapped array branch) | `PoC c7` | Yes/Partly |
| C-8 | Critical | Go | Copy/paste exponential state amplification (each `copy`+`clipboard` doubles the tree) → OOM | `PoC copybomb` | WS ↻ |
| DR-1 | Critical | Go | Concurrent map iteration+write on `r.nicks` via `/api/v1` → fatal crash | `PoC dr1` | Yes ↻ |
| XSS-1 | Critical | Web | Stored XSS via board labels (SVG `<text>.innerHTML`) — arbitrary JS in every viewer, in the embedding origin | `browser` | Yes |
| C-2b | High | Go | Persistent poison-pill: empty/invalid/**compressed** `TR`/`SQ` mark → nil-deref in `GenerateFullFrame` (Critical if OGS active) | `PoC b2` | Yes ⚑ |
| H-1 | High | Go | No WebSocket `Origin` check → cross-site WebSocket hijacking (CSWSH) | `PoC h1` | Yes |
| H-2 | High | Go | Unbounded room creation | `PoC h2` | Yes |
| H-3 | High | Go | No connection / rate limits | `PoC h3` | Partly |
| H-4 | High | Go | No max WS message size + no read deadline (buffering + slow-loris) | `PoC c4`/`h4` | Partly |
| H-5 | High | Go | Twitch webhook HMAC bypass when the secret is empty | `PoC h5` | Cond. |
| H-6 | High | Go | `graft` handler bypasses `authorized` + rate-limit middleware | `PoC graft` | Yes |
| H-7 | High | Go | Unbounded per-room tree growth + quadratic full-frame rebroadcast | `PoC grow` | Yes ↻ |
| H-8 | High | Go | OGS plugin fd + goroutine leak on every `request_sgf` | `PoC gl1` | Cond.(OGS) ↻ |
| H-9 | High | Go | OGS gamedata→SGF assertion cascade panics the read-loop goroutine (Critical if OGS active) | `test` | Cond.(OGS) ↻ |
| DL-1 | High | Go | Hub holds `h.mu` across room calls: stuck client + `GET /api/stats` freezes the server | `PoC dl1` | Yes (hang) |
| DL-2 | High | Go | Lock held during socket write: one slow reader freezes the whole room (and hub) | `PoC dl2` | Yes (hang) |
| DR-2 | High | Go | Initial full-frame marshaled outside `r.mu` (aliases tree slices) → torn read/SIGSEGV | `race` | Yes ↻ |
| DR-3 | High | Go | `Current().AllFields()` iterated outside `r.mu` during mutation → torn read | `race` | Cond. ↻ |
| AZ-1 | High | Go | `/api/v1` trusts client `userid` → authz bypass / password-room takeover | `PoC az1` | Yes |
| AZ-2 | High | Go | Enabling a password grandfathers all connected (incl. hostile) sockets | `PoC az2` | Yes |
| GL-1 | High | Go | `Room.Close` never ends plugins → OGS goroutine + fd + room-graph leak | `PoC gl1` | Cond.(OGS) ↻ |
| CS-1 | High | Go | Postgres DSN (with password) logged in plaintext at startup | `PoC cs1` | Log access |
| XSS-1b | High | Web | Second board-label XSS sink (digit-prefixed label) — a fix to the first sink alone misses it | `browser` | Yes |
| XSS-2 | High | Web | Reflected XSS broadcast to all room members via a malformed `request_sgf` URL → error modal | `browser` | Yes |
| XSS-3 | High | Web | Reflected XSS: Twitch callback echoes `challenge` with no `Content-Type` → sniffed as `text/html` | `browser` | Yes |
| M-1 | Medium | Go | `/debug`, `/sgf`, `/sgfix` download a password-protected room's full game/state, no password | `PoC m3` | Yes |
| M-2 | Medium | Go | SSRF via redirect-following + untimed/unbounded fetch | `PoC m4` | Cond.; high in K8s |
| M-3 | Medium | Go | `update_nickname` no auth / no length cap → N² rebroadcast | `PoC nick` | Yes |
| M-4 | Medium | Go | Unbounded per-room `auth`/`notified` maps (never pruned) | `PoC authleak` | Yes |
| M-5 | Medium | Go | SGF text-field escaping not round-trip safe (`\`) → persisted corruption | `PoC sgfesc` | Yes ⚑ |
| M-6 | Medium | Go | 1-hour heartbeat keeps abandoned rooms alive (amplifier) | insp. | Yes |
| M-7 | Medium | Go | Twitch: challenge echoed before verify; no replay protection | `PoC m5` | Yes (low) |
| M-8 | Medium | Go | Unbounded HTTP request body (`io.ReadAll`, no `MaxBytesReader`) | `PoC m2` | Proxy-mit. |
| M-9 | Medium | Go | No HTTP server timeouts (`http.ListenAndServe`, no `http.Server{}`) | insp. | Proxy-mit. |
| M-10 | Medium | Go | Unchecked-input panics on the request path (type assertions, coord/board OOB) — recovered | `PoC c1`,`c2`,`m7` | Per-conn |
| M-11 | Medium | Go | `update_settings` size >19 persists `SZ[20]`; `FromSGF` rejects it on restart → room silently dropped | `PoC sizepoison` | Yes ⚑ |
| M-12 | Medium | Go | `FromSGF`/paste are O(N²) → a single ~20 KB `upload_sgf` pins a core ~1 min | `PoC sgfquad` | WS ↻ |
| CS-2 | Medium | Go | Password > 72 bytes silently disables room protection (bcrypt error swallowed) | `PoC cs2` | Owner footgun ⚑ |
| DR-4 | Medium | Go | `OGSConnector.Exit` read without lock (written under lock) | insp. | Cond.(OGS) |
| GL-2 | Medium | Go | `readSocketToChan` blocks forever on channel send after game-over → goroutine leak | insp. | Cond.(OGS) |
| ID-1 | Medium | Go | Password gates writes only — anon socket reads a protected room's full state/moves | `PoC id1` | Yes |
| ID-2 | Medium | Go | Raw internal fetch/parser errors broadcast to clients (internal IPs/DNS, SSRF oracle) | insp. | Yes |
| ID-3 | Medium | Go | Hand-rolled JSON on `/api/v1` interpolates raw error/value → JSON injection + infoleak | `PoC id3` | Yes |
| CJ-1 | Medium | Web | No CSP / `X-Frame-Options` / `nosniff` / `Referrer-Policy` → no XSS backstop + clickjacking | `browser` | Yes |
| L-1 | Low | Go | `GET /ext/upload` has side effects (CSRF, server-side fetch) | insp. | Yes |
| L-2 | Low | Web | No HTTP security headers (see CJ-1 for impact) | insp. | Yes |
| L-3 | Low | Go | Container runs as root | insp. | n/a |
| L-4 | Low | Go | Postgres default creds + `sslmode=disable` committed | insp. | n/a |
| L-5 | Low | Go | Grafana default admin password | insp. | n/a |
| L-6 | Low | Go | Deprecated `golang.org/x/net/websocket` | insp. | n/a |
| L-7 | Low | Go | No dependency / security scanning in CI | insp. | n/a |
| L-8 | Low | Go | Predictable `math/rand` room names (guessable/enumerable) | insp. | Yes |
| L-9 | Low | Go | bcrypt on every `checkpassword` — CPU-amplification | insp. | Partly |
| L-10 | Low | Go | `MemoryLoader` not mutex-protected → concurrent-map crash (memory-mode only) | `race` | Cond. ↻ |
| L-11 | Low | Go | `GET /api/stats` is unauthenticated (occupancy oracle; DL-1 lever) | insp. | Yes |
| L-12 | Low | Go | Twitch `!setboard`/`!branch` remap a room from chat (no new capability) | insp. | Cond. |
| L-13 | Low | Go | `right()`/nav reads `Down[PreferredChild]` with no bounds check (latent) | insp. | Per-conn |
| DL-3 | Low | Go | `Room.Close` holds `r.mu` across `conn.Close` → room/goroutine/fd leak on a stalled client | insp. | Cond. |
| GL-3 | Low | Go | Postgres pool bounds unset → transient connection exhaustion | insp. | n/a |
| AZ-3 | Low | Go | `outsideBuffer` throttle keyed on client `userid` (bypassable; not authz) | insp. | Yes |
| AZ-4 | Low | Go | `GetAuth` returns key-existence → `SetAuth(id,false)` revocation is a silent no-op | insp. | Per-conn |
| ID-4 | Low | Go | `ApprovedFetch` allowlist-enumeration oracle + requested-host reflection | `PoC id3` | Yes |
| ID-5 | Low | Go | Twitch OAuth callback echoes internal client errors | insp. | Cond. |

**Not exploitable / mitigated** (documented so they are not re-raised): NGF/SGF oversized-board OOM (clamped by `FromSGF`); `remove_mark value[:2]` and the GIB `alphabet[x]` panic (recovered per-connection). See [§6](#6-not-exploitable--mitigated).

---

## 3. Server-side findings (Go)

### 3.1 Critical

#### C-1 — Whole-server crash via the OGS review plugin goroutine · `PoC a1`
- **Location:** `pkg/core/board/board.go:127` (`Board.Set`, no nil/bounds guard) reached from `pkg/room/plugin/ogs.go` (`loop` at `:198`, move parsing `:327-349`).
- **Mechanism:** `request_sgf` for an `online-go.com` review/demo spawns `go o.loop(...)` — a goroutine **outside** `net/http`'s recover. It plays the review's moves via `Board.Move`; `Move`→`Legal` calls the *guarded* `Get` first (returns `Empty` for a nil/off-board coord, so the move is **not** rejected) then the **unguarded** `Set` → panic. There is no `recover()` anywhere in `pkg/`, so this aborts the whole process.
- **Trigger (unauthenticated):** create a review on a free OGS account with an off-board move or a pass (`".."` → nil coord); open a WS to any password-less room; send `{"event":"request_sgf","value":"https://online-go.com/review/<id>"}`.
- **Reproduced:** `a1` — `Board.Move((1000,1000))` and `((-1,-1))` → `runtime error: invalid memory address or nil pointer dereference`.
- **Prod:** conditional on the OGS feature + egress to online-go.com (both default-on); the trigger is a tiny request the proxy forwards. Crash → pod auto-restart → repeatable.
- **Fix:** guard `Board.Set` (`c != nil && c.Valid(size)`) and reject nil/off-board coords in `Legal` before `Set`; wrap `loop()` in `defer recover()` (that wrap alone downgrades the whole OGS goroutine class to contained).

#### C-2 — Persistent poison-pill: colon-less `LB` label bricks a board on every load · `PoC b1`
- **Location:** `pkg/state/frame.go:131` — `generateMarks` does `spl := strings.SplitN(lb, ":", 2); text := spl[1]` with **no length guard** (the PX branch at `:142` correctly guards).
- **Mechanism:** `FromSGF` accepts a label with no colon (`LB[z]`) and stores it — parse succeeds. `UploadSGF` calls `SetState` (**commits** the state) *before* generating a frame, so the subsequent `GenerateFullFrame` panic never rolls it back. `ToSGFIX` writes `LB[z]` back verbatim and `Hub.Save` persists it. On restart, `Hub.Load → room.Load → FromSGF` re-poisons the room; it loads clean, then **panics on the first `RegisterConnection → GenerateFullFrame`** — every join panics. If the room has the OGS plugin active, the same `generateMarks` runs in the OGS spawned goroutine → whole-server crash.
- **Trigger (unauthenticated):** `POST /api/v1/room/{id}` (or WS) with `{"event":"upload_sgf","value":"KDtHTVsxXUZGWzRdU1pbMTldTEJbel0p"}` (base64 of `(;GM[1]FF[4]SZ[19]LB[z])`).
- **Reproduced:** `b1` — `FromSGF` OK, then `GenerateFullFrame` → `index out of range [1] with length 1`.
- **Prod:** tiny payload passes any cap; poison lives in the **shared DB**, so **auto-restart reloads it** — the standout under this model, because self-healing does not help.
- **Fix:** `if len(spl) != 2 { continue }` at `frame.go:131`; validate `LB` values in `FromSGF` so malformed marks are never committed or persisted.

#### C-3 — SGF parse stack overflow (unbounded recursion) · `PoC c6`
- **Location:** `pkg/core/parser/sgfparser.go:214` — `parseBranch` recurses once per `(` with no depth cap.
- **Mechanism:** a deeply nested SGF overflows the goroutine stack. A Go stack overflow is a **fatal error** `recover()` cannot catch, so this is a whole-process crash even from the request path.
- **Trigger (unauthenticated):** the `upload_sgf` *string* branch caps decoded input at 1 MiB (which bounds depth safely), but the **array branch has no cap** (see C-7). Send `{"event":"upload_sgf","value":["<base64 of '(' × 12,000,000>"]}` to `POST /api/v1/room/{id}` or over WS.
- **Reproduced:** `c6` (and end-to-end over both HTTP and WebSocket) → `fatal error: stack overflow`, process dead.
- **Prod:** the 12 MB HTTP POST is capped by the proxy, but the same payload over the **tunneled WebSocket** crashes the server (verified). Pod restarts; repeatable.
- **Fix:** depth-cap `parseBranch` (error past ~1000) or rewrite iteratively; apply the 1 MiB cap to the array branch.

#### C-4 — Tree-serialize stack overflow (`toSGF`/`Copy` recursion) · `PoC h7`
- **Location:** `pkg/core/parser/parser.go:51` (`SGFNode.toSGF`), `pkg/core/tree/tree.go:149` (`TreeNode.Copy`).
- **Mechanism:** `parser.Merge` (reached when **≥2** SGFs are uploaded) serializes via the recursive `toSGF`; a deep linear tree overflows the stack (fatal, not recovered). `Fmap`/`MaxDepth` are iterative — this is specifically the serialize path.
- **Trigger (unauthenticated):** `{"event":"upload_sgf","value":["<b64 of '(' + ';'×12,000,000 + ')'>","<same>"]}` via the uncapped array branch.
- **Reproduced:** `h7` (and end-to-end) → crash trace shows `(*SGFNode).toSGF`, process dead.
- **Prod:** as C-3 (WS delivery), transient.
- **Fix:** rewrite `toSGF`/`Copy` iteratively or depth-cap at parse time; cap the array branch.

#### C-5 — Board-size memory exhaustion (`update_settings`) · `PoC c3`
- **Location:** `pkg/room/handlers.go:294` (`size := int(sMap["size"].(float64))`) → `state.NewState` → `pkg/core/board/board.go:61` (`NewBoard` allocates `size × size`). No range check on this path (the `size > 19` clamp is only in `state.FromSGF`).
- **Mechanism:** a client-chosen `size` drives an `O(size²)` allocation. `size = 200000` ⇒ ~320 GB ⇒ OOM (fatal, bypasses recover).
- **Trigger (unauthenticated):** `update_settings` with `"size":200000` on any password-less room, or via `POST /api/v1/room/{id}`.
- **Reproduced:** `c3` — one request with `size:20000` grew server RSS 80 MB → 626 MB and retained it; `size:200000` OOM-kills.
- **Prod:** the request is *tiny* (a small JSON), so it passes every body cap; OOMKilled → restart → repeatable.
- **Fix:** validate `size ∈ {9,13,19}` in `handleUpdateSettings`; clamp defensively in `NewBoard`.

#### C-6 — ZIP bomb (unbounded in-memory decompression) · `PoC c5`
- **Location:** `internal/zip/zip.go:37-46` — `io.ReadAll` per entry with no per-entry, total, or entry-count cap.
- **Mechanism:** a tiny archive inflates to gigabytes in memory; the upstream 1 MB check applies only to the *compressed* upload, and only on the string branch.
- **Trigger (unauthenticated):** upload a zip via `upload_sgf` (`zip.IsZipFile` routes it to `Decompress`).
- **Reproduced:** `c5` — a 510 KB archive decompressed to **536 MB** (≈1000×).
- **Prod:** larger bombs via the WS branch; OOM → restart → repeatable.
- **Fix:** `io.LimitReader` per entry, a running total-bytes budget, and a max entry count.

#### C-7 — Unauthenticated state control + crash delivery · `PoC c7`
- **Location:** `pkg/hub/apiv1router.go` (`POST /api/v1/room/{board}` — no auth, `io.ReadAll` with no size limit) and `pkg/room/handlers.go:150` (the `upload_sgf` **array branch**, which skips the 1 MiB cap the string branch enforces).
- **Mechanism:** any unauthenticated HTTP client can create a room and dispatch **any** event (`update_settings`, `upload_sgf`, `graft`, board commands). This is the scriptable delivery vector for C-3/C-4/C-5/C-6; the uncapped array branch is what makes the recursion crashes reachable at crash scale.
- **Trigger (unauthenticated):** `curl -XPOST /api/v1/room/x -d '{"event":"upload_sgf","value":["<huge>"]}'`.
- **Reproduced:** `c7` (drives arbitrary state and delivers C-3/C-4). A *panic*-type payload here is recovered by net/http; the crashes come from the overflow/OOM payloads.
- **Prod:** unauth state control passes the proxy; large crash bodies are capped on HTTP → deliver over WS instead.
- **Fix:** authenticate/limit the endpoint, wrap the body in `http.MaxBytesReader`, and cap the array branch.

#### C-8 — Copy/paste exponential state amplification → OOM · `PoC copybomb`
- **Location:** `pkg/state/commands.go:486` (`copyCommand.Execute` → `s.clipboard = s.current.Copy()`, a **deep** copy of the whole subtree under `current`) and `pkg/state/edit.go:398` (`paste()` → appends another `s.clipboard.Copy()` under `s.current`). Wired via `command_decoder.go:197` (`copy`→`NewCopyCommand`, `clipboard`→`NewPasteCommand`); both route to the `_` default handler.
- **Mechanism:** neither `copy` nor `clipboard` advances `s.current`. With `current` pinned at the root, **every `copy` captures the entire tree and every `clipboard` appends another copy of it** — so each `copy`+`clipboard` pair doubles the node count: N → 2N. `k` alternating pairs ⇒ **2ᵏ nodes**.
- **Why the rate limit does not help:** `outsideBuffer` only throttles *different* users interleaving; after the attacker's first event `setTimeAfter` pins `lastUser = attacker`, so all their subsequent events skip the buffer check. `authorized` is a no-op on an open (default) room.
- **Trigger (unauthenticated):** open `ws /socket/b/{id}` and send `~28` alternating `{"event":"copy"}` / `{"event":"clipboard"}`. 2²⁸ ≈ 2.7×10⁸ `TreeNode`s → multi-GB heap → **fatal Go OOM** (not recovered).
- **Reproduced:** `copybomb` drives the real room handler chain and shows exact doubling: `2, 4, 8, …, 262144` nodes over 18 cycles (78 MiB live at 2¹⁸). Capped at 18 so the PoC stays safe; the extrapolation to ~28 → OOM is arithmetic.
- **Prod:** WS delivery (tiny events; no HTTP body to cap). OOM → restart. Escalation: stopping just short of OOM leaves a room persisting a huge SGF that is slow/again-fatal to reload (ties into M-12).
- **Fix:** advance `current` into the pasted branch (or forbid paste onto an ancestor of the clipboard), and enforce a per-room node cap (shared with H-7).

#### DR-1 — Concurrent map iteration+write on `r.nicks` → fatal whole-server crash · `PoC dr1`
- **Location:** `pkg/room/room.go:237` (`Nicks()` returns the **live** map, not a copy) → `pkg/hub/apiv1router.go:27` (`json.Marshal` of the `connected_users` event, outside `r.mu`), racing `SetNick` (`room.go:250`, writes under the lock).
- **Mechanism:** `handleUpdateNickname` returns `event.NewEvent("connected_users", r.Nicks())`; the `/api/v1` handler marshals that event outside the lock, iterating the map while a concurrent request writes it. A map iteration+write is a **fatal runtime error**, not a panic — `net/http` cannot recover it.
- **Reproduced:** `dr1` — a burst of concurrent `POST /api/v1/room/x {"event":"update_nickname",...}` (no auth on this handler) → `fatal error: concurrent map iteration and map write`.
- **Prod:** unauthenticated; crash → restart → repeatable.
- **Fix:** `Nicks()` returns a copy built under the lock; never marshal events that alias live room state.

### 3.2 High

#### C-2b — Persistent poison-pill via empty/invalid/compressed `TR`/`SQ` marks · **High** (Critical if OGS active) · `PoC b2`
- **Sink:** `pkg/state/frame.go:112/121` — `generateMarks` does `cs.Add(coord.FromLetters(v))` for the `TR` and `SQ` mark fields; `coord.FromLetters` returns **nil** for any value whose length ≠ 2 (`coord.go`), and `CoordSet.Add` derefs `c.Index()` with **no nil-check** (`coord.go:44`) → nil-pointer dereference.
- **Delivery (unauthenticated):** upload an SGF whose current node has an empty or malformed mark — `(;SZ[19]SQ[])`, `(;TR[])`, `(;SQ[!])`. `FromSGF` accepts it and `UploadSGF` commits the state **before** frame generation; `ToSGFIX` writes the bad mark back, so it **persists** and re-bricks the room on every join/reload (whole-server crash if the room's OGS plugin is active).
- **Structural scope:** the trigger is broader than malformed input — a **spec-valid compressed rectangle** `TR[aa:cc]` (a range that KGS, OGS, Sabaki, gomill all emit) is length 5 → nil → same crash. **So an honest SGF with a marked region bricks the board — no attacker needed** (an interop bug). Auditing *every* mark/annotation property bounds the sink to exactly `{TR, SQ, LB}`: `CR`, `MA`, `SL`, `AR`, `LN`, `DD` are stored but never rendered by `generateMarks`, so they do not crash (verified as `b2`'s controls). The command path cannot deliver the poison — `triangle`/`square`/`label` bounds-check the coord and emit a valid 2-letter point; **delivery is upload-only**.
- **Fix:** nil-check in `CoordSet.Add` (and skip nil coords in `generateMarks`); validate `TR`/`SQ`/`LB` in `FromSGF`; **expand compressed `aa:cc` ranges** before `FromLetters`. (The single `CoordSet.Add` guard closes the whole `FromLetters`→`Add` family.)

#### H-1 — No WebSocket `Origin` check → CSWSH · `PoC h1`
- **Location:** `pkg/hub/socketrouter.go:35` — `websocket.Server{Handshake: nil}` performs no origin validation. Any website a victim visits can open a socket to `/socket/b/{id}` in the victim's context and read/drive boards. Reproduced (`h1`): a cross-origin dial is accepted and receives the initial frame.
- **Prod:** Yes — the proxy forwards the browser-set `Origin`; the most relevant risk for "board on my website."
- **Fix:** validate `Origin` against an allow-list in a `Handshake` function.

#### H-2 — Unbounded room creation · `PoC h2`
`pkg/hub/hub.go:275` (`GetOrCreateRoom`) — any WS/HTTP hit to a new `boardID` creates a room + a heartbeat goroutine; IDs are only sanitized. Reproduced (`h2`): rooms grew 1 → 501. Amplified by the 1 h heartbeat (M-6). **Prod:** Yes (single in-memory replica accumulates). **Fix:** cap total rooms; evict idle/empty rooms quickly.

#### H-3 — No connection / rate limits · `PoC h3`
`pkg/hub/hub.go`, `socketrouter.go` — no global/per-room/per-IP connection cap or rate limiting. Reproduced (`h3`): 1000 concurrent connections, no throttle. **Prod:** Partly — an ingress with per-IP connection limits may cap the flood. **Fix:** connection semaphore + per-IP limits + `httprate`.

#### H-4 — No max WS message size + no read deadline · `PoC c4`/`h4`
`pkg/event/channel.go:88` (`readPacket`/`readBytes`) — a client-controlled 4-byte length has no ceiling and no read deadline; the buffer grows as bytes arrive, and the 1 MB check runs only later inside `handleUploadSGF`. Enables unbounded per-connection buffering and a slow-loris hold. **Prod:** Partly — the proxy idle-timeout closes a silent socket, but a slow drip keeps it alive and buffering. **Fix:** reject `length > maxMessageBytes` before reading; set a read deadline; use `io.ReadFull`.

#### H-5 — Twitch webhook HMAC bypass on empty secret · `PoC h5`
`internal/twitch/twitch.go:72` — `Verify` returns `true` when the secret is empty (fails open). Reproduced (`h5`): a forged notification with an **invalid** signature returned `200 OK`. Lets an attacker forge `channel.chat.message` events (`!setboard`/`!branch`) and hijack room mappings. **Prod:** conditional — only if the Twitch integration is enabled and the secret is unset; the webhook is public. **Fix:** `Verify` returns `false` on an empty secret; refuse to start the integration without one.

#### H-6 — `graft` bypasses `authorized` + `outsideBuffer` · `PoC graft`
`pkg/room/handlers.go:74` — `"graft": chain(r.handleEvent, r.broadcastFullFrameAfter)` is the only mutating handler with **neither** the password gate nor the rate-limit buffer, so `graft` mutates even **password-protected** rooms without `checkpassword`, unthrottled. This is the multiplier under H-7. **Prod:** Yes. **Fix:** add `r.authorized` and `r.outsideBuffer` to the graft chain.

#### H-7 — Unbounded tree growth + quadratic full-frame rebroadcast · `PoC grow`
`pkg/state/edit.go:271` (`smartGraft` inserts each move into `s.nodes`, no cap) + `pkg/room/handlers.go:387` (`broadcastFullFrameAfter` re-serializes the *entire* tree — two O(n) `Fmap`s — and broadcasts to every connection). Diverging graft sequences grow the tree without bound → `O(k²·conns)` CPU and heap → OOM; the persisted SGF also inflates every future `Load`. **Prod:** Yes (tiny grafts; OOM → restart, and the growing persisted blob is a creeping escalation). **Fix:** per-room node cap; incremental frames for graft.

#### H-8 — OGS fd + goroutine leak on every `request_sgf` · `PoC gl1`
`pkg/room/plugin/ogs.go:204` — `End()`/`closeOGS` set `o.Exit=true` but never call `o.Socket.Close()`. After deregister, `readSocketToChan` stays parked in `Socket.Read` and `loop` on `<-socketchan`; `Exit` cannot wake them. Net leak per event: **2 goroutines + 1 TCP fd** to online-go.com, unthrottled. **Prod:** conditional on OGS egress; leak → OOM/fd-exhaustion → restart. (`gl1` reproduces the root-cause plugin-teardown leak; the socket-close portion needs live egress to online-go.com.) **Fix:** `o.Socket.Close()` in `End()`; read deadline; cap connectors per room.

#### H-9 — OGS gamedata→SGF assertion cascade crashes the read-loop goroutine · `test`
- **Location:** `pkg/room/plugin/ogs.go:358-437` (`gamedataToSGF`/`gameInfoToSGF`/`initStateToSGF`) and the loop reader `ogs.go:264-318`, all executed inside `go o.loop(...)` (`ogs.go:198`).
- **Mechanism:** the connector converts **online-go.com-controlled JSON** into SGF using dozens of *unchecked* type assertions — `gamedata["width"].(float64)`, `players["black"].(map[string]any)`, `move[0].(float64)`, … — with no `, ok` guard. Any unexpected shape panics; because the panic is in a **plugin-spawned goroutine**, `net/http`'s recover does **not** catch it → whole-server crash (Critical-class when OGS is active — same boundary as C-1, distinct root cause).
- **Attacker control:** the attacker chooses which OGS game/review the (open) room attaches to via an unauthenticated `request_sgf`. A **rengo (team) game** — public and common, where `players.black` is null or an array rather than `{username, rank}` — is enough; so is a game missing `width` or a truncated socket frame.
- **Reproduced:** `go test -tags poc -run TestOGSGamedataCrash_1c ./pkg/room/plugin/` feeds 10 attacker-reachable shapes to the conversion path — **all panic**; a well-formed 1v1 control does not. (End-to-end delivery needs live egress to online-go.com; the test reproduces the fatal panic deterministically without it.)
- **Prod:** conditional on OGS egress; then crash → restart, repeatable.
- **Fix:** comma-ok every assertion on OGS JSON and bail out on a mismatch; wrap `o.loop` in a `recover()` that tears the connector down; treat `ogs.go` as an untrusted-input parser.

#### DL-1 — Hub freeze via `h.mu` held across room calls · `PoC dl1`
`ConnCount`/`RoomCount` (`hub.go:132`) lock `h.mu` and call `r.NumConns()` (which needs `r.mu`); if a broadcast has pinned some `r.mu` (DL-2), an unauthenticated `GET /api/stats` (see L-11) wedges while holding `h.mu`, and then every new WS (`GetOrCreateRoom`) and board load (`GetRoom`) blocks. **Prod:** Yes (hub-wide hang). **Fix:** never call room methods under `h.mu` — snapshot, release, then call.

#### DL-2 — One slow reader freezes the whole room (and hub) · `PoC dl2`
`Broadcast`/`SendTo`/`BroadcastHubMessage` (`room.go:361-392`) hold `r.mu` while calling `SendEvent` → `ws.Write` with **no write deadline** (empty `websocket.Config{}`). Reproduced: with one stuck-reading client, `r.Size()` (and thus every join/move/frame) blocks indefinitely. Escalation: `Hub.SendMessages` holds `h.mu` while broadcasting to every room, so a single stuck reader can stall the global message loop. **Prod:** Yes (hang). **Fix:** snapshot the connection list under the lock, unlock, then write; add per-write deadlines and drop slow clients.

#### DR-2 — Initial full-frame marshaled outside `r.mu`, aliasing tree slices → torn read/SIGSEGV · `race`
`RegisterConnection` (`room.go`) releases `r.mu`, then `SendEvent`→`json.Marshal` walks `Metadata.Fields`/`Comments`, which alias `s.root`/`s.current` field slices (`AllFields`/`GetField` return the slice, no copy). A concurrent `update_settings`/comment on another connection appends/overwrites the same backing array → torn 24-byte slice header → out-of-bounds read/SIGSEGV (fatal). Reproduced under `go test -race`. **Fix:** marshal the initial frame inside a locked method, or deep-copy `Fields`/`Comments` in `GenerateFullFrame`.

#### DR-3 — `Current().AllFields()` iterated outside the lock during mutation → torn read · `race`
`Room.Current()` (`room.go:621`) returns a shallow copy whose embedded `fields.Fields` slice still aliases the live node; `logAfter` (`handlers.go:493`) then ranges `current.AllFields()` and `strings.Join(field.Values,…)` with `r.mu` released, while another client's mark/label command appends under the lock. Reproduced under `go test -race`. **Fix:** deep-copy fields in `Current()`, or format inside a locked method.

#### AZ-1 — `/api/v1` trusts client `userid` → password-room takeover · `PoC az1`
The WS path binds identity server-side (`evt.SetUser(ec.ID())`), but the HTTP handler (`apiv1router.go`) takes `evt.User()` verbatim from the attacker's JSON `userid` (`event.go:36`, `json:"userid"`) and never re-sets it. `authorized` checks `GetAuth(evt.User())`, and `connected_users` broadcasts every occupant's connection UUID — so an attacker idling in the room harvests an authenticated owner's UUID and replays it: `POST /api/v1/room/myroom {"event":"trash","userid":"<ownerUUID>"}`. Full authz bypass on a **password-protected** room. **Prod:** Yes. **Fix:** never trust client `userid` as identity on the HTTP path; bind auth to server-issued tokens, not broadcast UUIDs.

#### AZ-2 — Enabling a password grandfathers all connected sockets · `PoC az2`
`handleUpdateSettings` calls `SetAuthAll()` immediately before `SetPassword` (`handlers.go:330`), setting `auth[connID]=true` for every current connection — including a hostile one idling since the room was still open. Protection thus fails **open** for occupants present at set-time (and never evicts them; `auth` is never cleared); combined with AZ-1 the attacker replays that grandfathered UUID indefinitely. **Prod:** Yes. **Fix:** clear `auth` in `SetPassword`; force re-`checkpassword`.

#### GL-1 — `Room.Close` never ends registered plugins · `PoC gl1`
`Close()` closes only `r.conns`, never iterates `r.plugins`/`p.End()`. On idle expiry the Heartbeat calls `Close` then `DeleteRoom`, after which no event can reach `closeOGS` — so the OGS `loop`/`ping`/`readSocketToChan` goroutines run forever, pinning the whole room object graph and a TCP fd. Drivable unauthenticated by minting rooms with an OGS plugin (`GET /ext/upload?url=…online-go.com/review/<id>` per request). **Prod:** conditional on OGS egress; leak → OOM → restart. **Fix:** iterate and `End()` all plugins in `Close()`; combine with the socket-close fix (H-8).

#### CS-1 — Postgres DSN logged in plaintext at startup · `PoC cs1`
`dbConfig.redact()` (`config.go:84`) is an empty no-op while `Config.Redact()` masks only Twitch, so `cmd/main.go:52` logs the running config including `DB.Path` — for Postgres, the DSN `postgres://user:pass@…` with the password. Requires log access, not remote. **Fix:** implement `dbConfig.redact()` (strip userinfo) or a `slog.LogValuer` that redacts.

### 3.3 Medium

#### M-1 — `/debug`, `/sgf`, `/sgfix` leak a password-protected room's full game/state · `PoC m3`
`pkg/hub/webrouter.go` `HandleOp` serves `GET /b/{id}/debug` → `SaveState()` JSON, `/sgf` → `ToSGF()`, `/sgfix` → `ToSGFIX()` for **any** room with **no password check**. Reproduced: a room with `isprotected: true` (password `hunter2`) still returned its full game — player names, every move — and its full `StateJSON`, to an unauthenticated caller. The password gates *writes* only (see ID-1). **Prod:** Yes. **Fix:** gate `/debug` behind test mode; gate `/sgf`/`/sgfix` on the room password if rooms are meant to be private (or accept world-readable rooms and document it).

#### M-2 — SSRF via redirect-following + untimed/unbounded fetch · `PoC m4`
`internal/fetch` uses `http.DefaultClient` (follows redirects, no timeout) and `io.ReadAll`s the body (no size cap); `ApprovedFetch` checks only the **first** hop's hostname. Reproduced (`m4`): `Fetch` followed a redirect to an "internal" service. Reachability needs an open-redirect on an approved host (or the `OGSCheckEnded`/`FetchOGS` direct-`Fetch` paths). **Prod:** an **egress** problem the ingress proxy does not touch; blast radius in K8s includes cluster-internal ClusterIP services and `169.254.169.254` (cloud IAM metadata). **Fix:** a client with a timeout and a redirect policy that re-validates each hop against the allow-list; `io.LimitReader` the body; add an egress `NetworkPolicy`.

#### M-3 — `update_nickname` no auth / no length cap → N² rebroadcast · `PoC nick`
`pkg/room/handlers.go:63` — `update_nickname` has no `authorized`, no `outsideBuffer`, and no length cap; an oversized nick is held in `r.nicks` and the full N-entry map is re-marshalled to all N connections on every join/leave/nick-change. **Prod:** Yes. **Fix:** length-cap nicks; gate the handler.

#### M-4 — Unbounded per-room `auth`/`notified` maps · `PoC authleak`
`pkg/room/room.go:198` — `SetAuth`/`SetAuthAll` write `r.auth[uuid]=true` but nothing ever `delete`s from `auth` (or `message.notified`); `DeregisterConnection` prunes only `conns`. Reconnects (fresh UUIDs) grow the maps for the room's ~24 h life — an OOM accelerant across flooded rooms. **Prod:** Yes (slow). **Fix:** delete `auth`/`notified` entries on disconnect.

#### M-5 — SGF text-field escaping not round-trip safe → persisted corruption · `PoC sgfesc`
Both serializers escape `]`→`\]` but **not** a literal `\` (`state.go:144`, applied to every field value; `parser.go:64`). A text field ending in `\` serializes to `[value\]`; on reload the parser consumes the `\]` as an escaped literal and the field swallows the following one. On the standard `ToSGFIX` save (trailing `IX[n]` supplies a terminator) this **corrupts** labels/indices; a genuinely terminal field reparses to an error and the board is dropped. Reachable via any uploaded text field (`C`, `LB`, `PB`/`PW`/`GN` — including GIB/NGF-sourced names, since those formats are auto-detected inside `upload_sgf`); the `label` command is the direct WS vector. **Prod:** Yes, persistent. **Fix:** also escape `\` in both serializers.

#### M-6 — 1-hour heartbeat keeps abandoned rooms alive · insp.
`pkg/hub/hub.go:95` — `heartbeatInterval = 3600 s`, so an abandoned room (and its goroutine) lingers ≥1 h, amplifying H-2. **Prod:** Yes (amplifier on the single replica). **Fix:** shorter/activity-driven interval.

#### M-7 — Twitch challenge echoed before verify; no replay protection · `PoC m5`
`pkg/hub/twitchrouter.go:150` writes back the `webhook_callback_verification` challenge **before** the HMAC check, and signed message IDs/timestamps are never validated for freshness or de-duplicated. Reproduced (`m5`): a challenge is reflected unauthenticated. **Prod:** Yes (low impact — reflection / subscription auto-confirm / replay). **Fix:** verify the signature before handling the challenge; reject stale timestamps and dedupe message IDs. (Also the source of XSS-3.)

#### M-8 — Unbounded HTTP request body · `PoC m2`
`pkg/hub/apiv1router.go` (and `/ext/upload`) read the body with no cap. Reproduced (`m2`): the server buffered a 40 MB body. **Prod:** proxy-mitigated on HTTP (`client_max_body_size`); the uncapped equivalent is the WS path (H-4). **Fix:** `http.MaxBytesReader`.

#### M-9 — No HTTP server timeouts · insp.
`cmd/main.go` uses `http.ListenAndServe` with no `http.Server{}` timeouts (`ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`). **Prod:** proxy-mitigated (the front proxy has its own timeouts). **Fix:** construct an `http.Server{}` with explicit timeouts anyway.

#### M-10 — Unchecked-input panics on the request path (contained by net/http) · `PoC c1`,`c2`,`m7`
A class of type-assertion / index panics on attacker JSON that each **kill only the issuing connection** (net/http recovers them) — but are latent whole-server crashes if ever reached from a spawned goroutine:
- `handleUpdateSettings` unchecked assertions — `evt.Value().(map[string]any)`, `sMap["buffer"].(float64)`, etc. (`handlers.go:292`) — `c1`.
- GIB `STO` coordinate → `alphabet[x]` index panic (`gibparser.go:280`) — `c2`.
- `coord.FromInterface` (`coord.go:249`) and `remove_mark value[:2]` (`commands.go:256`) on crafted command args — `m7`.

**Prod:** Per-conn (no shared/prod impact). **Fix:** comma-ok every assertion on client input; bounds-check slice indices; treat `handlers.go`/`command_decoder.go` as untrusted-input parsers.

#### M-11 — `update_settings` size >19 → room silently dropped on restart · `PoC sizepoison`
`pkg/room/handlers.go:294` reads `size` with **no bounds check** and, when it differs, does `SetState(state.NewState(size))` — and `NewState` does **not** clamp. Size `20` costs trivial memory (this is *not* C-5's OOM), so the change succeeds silently and the room persists as `SZ[20]`. On restart `Hub.Load → room.Load → state.FromSGF` **rejects** any `size > 19` (`state.go:196`), so `Hub.Load` skips the room (`hub.go:172-175`): its entire persisted history is **destroyed**. `authorized` is a no-op on an open room, so this is unauthenticated. Reproduced (`sizepoison`). **Prod:** Yes, `⚑` — the damage lands *on* the restart. **Fix:** bounds-check `size` in `handleUpdateSettings`; make `NewState`/`FromSGF` agree on the allowed range.

#### M-12 — `FromSGF`/paste are O(N²) → single-upload CPU DoS · `PoC sgfquad`
`pkg/state/util.go:119` (`computeDiffSetup`) calls `gotoIndex` (`nav.go:52`) for **every** setup node, and `gotoIndex` rewinds to the root and walks forward one node at a time (`O(depth)` per node) — so a linear chain of N setup nodes is `O(N²)` to build. Reproduced (`sgfquad`): 1000/2000/4000/8000 empty nodes take ~0.09/0.4/1.9/10.2 s (~4× per doubling). A ~20 000-node SGF is ~20 KB (well under the 1 MB cap) yet pins one core ~1 min; parallel uploads pin every core. **Prod:** WS delivery, `↻`. **Fix:** track the board incrementally during load instead of a root-rewind per node; cap node count per upload.

#### CS-2 — Password > 72 bytes silently disables protection · `PoC cs2`
bcrypt rejects inputs > 72 bytes with `ErrPasswordTooLong`; `core.Hash` (`verify.go:17`) discards the error and returns `""`. The guard is only `password != ""` (`handlers.go:313`), so a long password stores an empty hash → `HasPassword()==false` → the room is open to everyone while the owner believes it is protected (persists across restarts). Reproduced: `Hash(73×"A") == ""`. **Fix:** propagate the bcrypt error and reject the setting.

#### DR-4 — `OGSConnector.Exit` read without a lock · insp.
`End()` writes `o.Exit` under `o.mu` (`ogs.go:202`), but `loop()`/`readSocketToChan()` read it with no lock (`ogs.go:187,243`) — the author fixed the ping site with `isExited()` but missed these. **Fix:** use `isExited()` at both sites or make `Exit` an `atomic.Bool`.

#### GL-2 — `readSocketToChan` blocks on a channel send after game-over · insp.
When `loop()` returns on game-over, nothing drains `socketchan`; the next byte parks `readSocketToChan` on the unbuffered send (`ogs.go:185`), which the socket-close fix cannot interrupt. **Fix:** `select { case socketchan <- b: case <-done: return }`.

#### ID-1 — Password gates writes only; anyone reads a protected room · `PoC id1`
`Handle` accepts any WS with no auth check and `RegisterConnection` immediately pushes `GenerateFullFrame(Full)`; `Broadcast` relays every move and `connected_users` (UUIDs) to all connections. `authorized` gates only mutating handlers, never the connect/read path — so an anonymous socket to a "protected" room receives the full board, every live move, and occupant UUIDs. **Fix:** gate the connect/read path if read-privacy is intended (this also feeds AZ-1's UUID harvest).

#### ID-2 — Raw internal fetch/parser errors broadcast to clients · insp.
`Fetch` returns the verbatim `*url.Error` (rewritten internal OGS API URL, resolved backend IP, local resolver `127.0.0.53:53`), wrapped into `ErrorEvent` and broadcast to every connection (`handlers.go:209/250`). Discloses internal request topology and gives an SSRF/liveness oracle (DNS-fail vs conn-refused vs parse-error are distinguishable). **Fix:** generic client messages; log details server-side only.

#### ID-3 — Hand-rolled JSON on `/api/v1` → JSON injection + infoleak · `PoC id3`
`apiv1router.go` builds responses with `fmt.Sprintf(` `{"error":"%s"}` `, …)` interpolating the raw error/value (for a failed `request_sgf`, a `*url.Error` containing quotes and `dial tcp <ip>:<port>`). The unescaped quotes break out of the JSON string (response injection) and leak internals. **Fix:** build a struct and `json.Marshal`; map errors to a generic message.

### 3.4 Low / hardening

- **L-1 — `GET /ext/upload` has side effects** (`pkg/hub/extrouter.go`): creates a room and triggers a server-side fetch → CSRF-able. Make it POST with CSRF protection.
- **L-3 — Container runs as root** (`Dockerfile`, no `USER`). Add a non-root user; read-only FS; resource limits.
- **L-4 — Committed DB creds / `sslmode=disable`** (`config/config-docker-compose.yaml`: `postgres:postgres`, TLS off). Use secrets; enable TLS.
- **L-5 — Grafana default admin password** (`docker-compose.yaml` defaults to `admin`). Require an explicit value.
- **L-6 — Deprecated `golang.org/x/net/websocket`.** Migrate to `nhooyr.io/websocket`/`gorilla` (makes H-1/H-4 easier to get right).
- **L-7 — No CI security scanning** (`.github/workflows/`). Add `govulncheck` and `gosec`.
- **L-8 — Predictable `math/rand` room names** (`pkg/core/util.go`): rooms are unauthenticated and world-readable, so names are guessable/enumerable. Use `crypto/rand` if names are meant to be unguessable.
- **L-9 — bcrypt on every `checkpassword`** (`handlers.go`): no rate limit → CPU-amplification. Rate-limit auth attempts per IP/connection.
- **L-10 — `MemoryLoader` is not mutex-protected** (`pkg/loader/memoryloader.go:17`): `rooms`/`twitch` maps and the `messages` slice are read/written from every room goroutine + the persist loop with **no lock** → `fatal error: concurrent map …`. Reproduced under `go test -race -run TestL10 ./security/poc/race/`. Low only because it is **memory-mode only** — the assessed production posture uses a sqlite/postgres loader (concurrency-safe via `database/sql`); *if the in-memory loader is the configured backend, this is a Critical-class unauthenticated crash*. Fix: guard the loader with a `sync.Mutex`, or don't run memory mode in production.
- **L-11 — `GET /api/stats` is unauthenticated** (`pkg/hub/apirouter.go:45`): returns live room + connection counts to anyone (occupancy oracle; the lock-contention lever in DL-1). Fix: gate it or drop it.
- **L-12 — Twitch `!setboard`/`!branch` remap a room from chat** (`pkg/hub/twitchrouter.go:211-235`): a broadcaster's chat command re-points/branches a room — but grants **no new capability** (rooms are already world-writable over the WS) and needs the Twitch integration active (and, absent H-5, a valid signature). Fix follows H-5/M-7.
- **L-13 — navigation reads `Down[PreferredChild]` with no bounds check** (`pkg/state/nav.go` `right()`; `SetPrefs` at `util.go:58` copies persisted prefs without validating them against `len(Down)`). Confirmed to panic (`index out of range [99] with length 1`) when a pref exceeds the child count. Latent only: `FromSGF` resets all prefs to 0 and normal navigation keeps them in range, so no client-reachable path to persist an out-of-range pref was found. Fix: clamp in `right()`/`down()` and validate in `SetPrefs`.
- **DL-3 — `Room.Close` holds `r.mu` across `conn.Close`** (`room.go:281`): a stalled client blocks the close frame forever, so `Close` never returns and `DeleteRoom`/`db.DeleteRoom` never run — the room, its goroutines, and fds leak. Fix: snapshot and close outside the lock with a deadline.
- **GL-3 — Postgres pool bounds unset** (`SetMaxOpenConns`/`ConnMaxLifetime` never set; the sqlite loader sets `SetMaxOpenConns(1)`): combined with per-room Heartbeat `DeleteRoom` running outside `h.mu`, mass room expiry can transiently spike connections (transient exhaustion, not a leak — `database/sql` closes idle conns). Fix: set symmetric pool bounds.
- **AZ-3 — `outsideBuffer` throttle keyed on client `userid`** (bypassable; an amplifier for the upload/OOM DoS, not an authz control). Fix: don't key throttling on client identity.
- **AZ-4 — `GetAuth` returns key-existence** (`room.go:204`, `_, ok := r.auth[user]; return ok`): discards the stored bool, so `SetAuth(id,false)` leaves the key and the user stays authorized. No live revocation path today; latent footgun. Fix: return the stored value.
- **ID-4 — `ApprovedFetch` allowlist-enumeration oracle + host reflection** (`PoC id3`): returns `"unapproved URL. contact us to add <host>"` for a disallowed host vs a raw dial error for an allowed-but-unreachable one — a distinguisher that enumerates the allow-list and reflects an arbitrary host into a client-visible broadcast. Fix: generic message, no host reflection.
- **ID-5 — Twitch OAuth callback echoes internal errors** (`twitchrouter.go`, `http.Error(w, err.Error(), 403)`): echoes internal client errors on the state/exchange path. Fix: generic messages.

---

## 4. Client-side findings (browser)

The ~7,200-line frontend (`pkg/frontend/js`) renders user data broadcast to every room participant. Most sinks are correctly escaped (see below), but **board labels** and **broadcast error strings** reach `innerHTML` unescaped, and there are **no HTTP security headers** — so a confirmed XSS has no CSP backstop. All findings below were reproduced end-to-end in real Chromium (Playwright PoCs in [`security/poc/browser/`](security/poc/browser/)). **These are the findings that reach the site the board is embedded in.**

### 4.1 Critical

#### XSS-1 — Stored XSS via board labels · `security/poc/browser/xss_label.js`
- **Sink:** `pkg/frontend/js/boardgraphics/boardgraphics.js:516` — `text.innerHTML = txt` on an SVG `<text>` element, reached from `draw_custom_label` → `draw_centered_text` → `svg_draw_centered_text` with the **raw** label text (no escaping on this path, unlike nicknames/comments/player-names).
- **Source / delivery (unauthenticated):** a `label` event (`{"event":"label","value":{"coords":[x,y],"label":"<payload>"}}`) over the WebSocket **or** the unauthenticated `POST /api/v1/room/{id}`, or an uploaded SGF with a crafted `LB` field. `command_decoder.go:109` accepts an arbitrary string and `commands.go:237` stores it unsanitized; `broadcastAfter` rebroadcasts it and `frame.go` re-emits it in full frames, so it is **broadcast + persisted** and re-fires on every future connect. The client's 3-char UI cap is bypassed by a raw frame.
- **Payload:** `<img src=x onerror="/*JS*/">` (fired in this Chromium); the robust cross-browser form is `<foreignObject><img src=x onerror="/*JS*/"></foreignObject>` or SMIL `<animate onbegin="/*JS*/">`.
- **Impact:** arbitrary JavaScript in **every** viewer's browser, **in the origin the board is embedded in** → full compromise of any visitor's session on that site (session/cookie theft, defacement, request forgery, pivot). Persisted → affects everyone who later opens the room.
- **Fix:** set `text.textContent = txt` (SVG `<text>` renders `textContent` natively) at :516; length/charset-validate the label server-side in `NewAddLabelCommand`.

### 4.2 High

#### XSS-1b — Second board-label sink (digit-prefixed label) · `security/poc/browser/xss_label.js`
- **Sink:** `boardgraphics.js:540` — a **second** `text.innerHTML = txt`, in `svg_draw_text`. A fix limited to :516 leaves this exploitable.
- **Delivery:** a label whose text **begins with a digit**, e.g. `1<foreignObject><img src=x onerror=…></foreignObject>`. `place_label` (`state.js:1022`) does `parseInt("1<…>") === 1`, takes the numeric branch, and forwards the **raw** `lb.text` (not the parsed int) to `_draw_manual_number` → `draw_number` → `svg_draw_text`. Same `label`/SGF `LB` delivery as XSS-1.
- **Fix:** `text.textContent = txt` at :540 **and** pass `String(i)` (not raw `lb.text`) on the numeric branch in `place_label`.

#### XSS-2 — Reflected XSS broadcast to all room members via the error modal · `security/poc/browser/xss_error_modal.js`
- **Sink:** `pkg/frontend/js/modals.js:183` — `span.innerHTML = "&nbsp;" + message` in `show_error_modal` (same unescaped pattern at `:211` `show_info_modal`, `:219` `show_prompt_modal`).
- **Source / delivery (unauthenticated, no victim interaction):** a `request_sgf` with a malformed URL. Go's `url.Parse` returns a `*url.Error` whose `Error()` `%q`-formats the raw input — `%q` escapes `"` and control chars but **not** `<`, `>`, or spaces. `handleRequestSGF` wraps it as `ErrorEvent(err.Error())` and `broadcastAfter` sends it to **every** connection; `network_handler.js` routes `error` → `show_error_modal`, which auto-shows.
- **Payload (no `"`):** `{"event":"request_sgf","value":"http://<img src=x onerror=alert(document.domain)>"}` (WS or `POST /api/v1/room/{id}`). Reproduced: the alert fired in a victim page that never interacted.
- **Fix:** render `message` as a text node (`textContent`/`htmlencode`) at :183/:211/:219; stop broadcasting raw internal error strings (also ID-2/ID-3).

#### XSS-3 — Reflected XSS via the Twitch callback challenge + MIME sniffing · `security/poc/browser/xss_twitch_sniff.js`
- **Sink:** `pkg/hub/twitchrouter.go:151` — `w.Write([]byte(req.Challenge))` with **no `Content-Type`** (the only `Content-Type` line, :129, is commented out), echoed **before** (and regardless of) the HMAC check. Go's `DetectContentType` sniffs a `<script>`-leading body as `text/html`.
- **Delivery (unauthenticated, cross-site):** a page auto-submits a `text/plain` form POST to `/apps/twitch/callback` whose body decodes to `{"challenge":"<script>…</script>"}`; the top-level navigation renders the sniffed `text/html` and executes. Reproduced: `document.contentType === 'text/html'` and the script ran on the board origin.
- **Impact:** arbitrary script on the app origin; bounded by the app being no-login (no session cookie to steal on the board itself), but it abuses the embedding context.
- **Fix:** set `Content-Type: text/plain; charset=utf-8` and `X-Content-Type-Options: nosniff` before writing, and move the challenge echo **after** `twitch.Verify` succeeds.

### 4.3 Medium

#### CJ-1 — Missing security headers (no CSP, clickjacking, no `nosniff`/`Referrer-Policy`) · `security/poc/browser/clickjacking.js`
- **Location:** `pkg/app/app.go:40-41` — middleware is only `StripSlashes` + logger; a repo-wide grep confirms **no** `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy` is ever set.
- **The material part — no CSP:** with the confirmed XSS-1/1b/2/3, a `Content-Security-Policy` is the difference between contained and full compromise of the embedding origin. Also: **no `nosniff`** enables the XSS-3 sniff pivot; **no `Referrer-Policy`** leaks the board URL (the only room-access token in a no-login app) via `Referer`; **no `X-Frame-Options`/`frame-ancestors`** makes the board iframe-able (clickjacking — low on its own, since an anonymous app grants no privilege to redress, but it removes a control).
- **Fix:** add a headers middleware in `app.New()`: `Content-Security-Policy` (`default-src 'self'` + `cdn.jsdelivr.net` for Bootstrap, or vendor it; `frame-ancestors` scoped to permitted embedders), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `X-Frame-Options: SAMEORIGIN` where embedding allows.

### 4.4 Correctly escaped (verified, not vulnerable)
Comments (`textContent`→`innerHTML`), nicknames (same, `update_users_modal`), player names/komi (`htmlencode`, body context), `show_toast` (fed only by operator `global` messages a client cannot broadcast), and the `letter`/`number` websocket commands (decoder enforces integer/single-letter typing). Only the `label` command / SGF `LB` and the broadcast error strings are unescaped. The unapproved-host reflection (`fetch.go:131` → `modals.js:183`) is HTML-injection/content-spoofing only — Go's host parser strips the chars needed for an attribute-bearing tag, so no script (closed by the XSS-2 fix). The Twitch `oauth_state` cookie sets `HttpOnly`+`Secure` but no `SameSite` (not exploitable — a 2-minute one-time CSRF nonce; add `SameSite=Lax`).

---

## 5. Remediation priority

1. **Fix the client-side XSS + add a CSP (highest impact for embedding).** These are the findings that compromise your site's visitors.
   - `text.textContent` (not `innerHTML`) at **both** label sinks `boardgraphics.js:516`/`:540`, and `String(i)` on the numeric branch of `place_label` — XSS-1/XSS-1b.
   - Render modal messages as text nodes at `modals.js:183/211/219` and stop broadcasting raw error strings — XSS-2.
   - `Content-Type: text/plain` + `nosniff` and verify-before-echo on the Twitch challenge — XSS-3.
   - Add a `Content-Security-Policy` + security-headers middleware — CJ-1.
2. **Close the whole-server crashes & poison-pills.** Guard `Board.Set` + `recover()` in the OGS `loop`, and comma-ok every OGS `gamedata` assertion (C-1/H-9); `len(spl)!=2` at `frame.go:131` + nil-check `CoordSet.Add` + expand compressed ranges + validate marks in `FromSGF` (C-2/C-2b); depth-cap `parseBranch` and `toSGF`/`Copy` (C-3/C-4); cap board size (C-5) and zip output/entry count (C-6); make `paste` advance `current` + per-room node cap (C-8/H-7); cap the `upload_sgf` array branch (C-7); make `Nicks()` return a copy (DR-1).
3. **Fix the concurrency model.** Never hold `r.mu`/`h.mu` across a socket write — snapshot connections, unlock, then write; add per-write deadlines and drop slow clients (DL-1/DL-2/DL-3). Deep-copy field slices marshaled outside the lock (DR-2/DR-3); atomic/locked `OGSConnector.Exit` (DR-4); mutex on `MemoryLoader` (L-10).
4. **Fix authorization.** Stop trusting client `userid` on `/api/v1` — bind identity to a server-issued token (AZ-1/AZ-3); clear `auth` on `SetPassword` and re-require `checkpassword` (AZ-2); authenticate/limit `POST /api/v1/room` + `MaxBytesReader` (C-7); add `authorized`+`outsideBuffer` to `graft` (H-6); validate `Origin` (H-1).
5. **Stop the leaks & resource exhaustion.** End plugins in `Room.Close` (GL-1) and fix the OGS channel-send/socket-close (GL-2/H-8); room/connection/rate caps + shorter heartbeat (H-2/H-3/M-6); prune `auth`/`notified` maps (M-4); Postgres pool bounds (GL-3).
6. **Secrets, integrations & info leaks.** Implement `dbConfig.redact()` (CS-1) and propagate the bcrypt error (CS-2); fail-closed on empty Twitch secret (H-5/M-7); gate `/debug` and the read/connect path if rooms are private (M-1/ID-1); `json.Marshal` responses + generic error messages (ID-2/ID-3/ID-4/ID-5); redirect-revalidating fetch client + egress `NetworkPolicy` (M-2).
7. **Robustness & hardening.** Comma-ok all client-input assertions + escape `\` in serializers (M-10/M-5); bounds-check `update_settings` size (M-11); make SGF load track the board incrementally (M-12); bounds-check `Down[PreferredChild]` (L-13); Low items L-1…L-12; deployment hardening implied by the K8s model (non-root, secrets, single-instance or shared state, egress policy).

---

## 6. Not exploitable / mitigated

Documented so a re-audit does not re-raise them:
- **Oversized board via NGF/SGF upload** — the NGF parser only stores `size` as a string; the sole path to `NewBoard` from parsed SGF/NGF is `state.FromSGF`, which **clamps `size > 19`** (`state.go:196`) and errors before allocating. Verified: `FromSGF("(;SZ[50000])")` → `"unsupported board size"`. (The unclamped board-size DoS is C-5, via `update_settings`.)
- **`remove_mark value[:2]` and the GIB `alphabet[x]` panic** — real panics, but recovered per-connection (M-10 class). GIB/NGF *are* reachable (auto-detected inside `upload_sgf`), but the parser's **output** is clean SGF coordinates never re-parsed as GIB, so the coordinate panic itself is not a poison-pill. (GIB/NGF-sourced `PB`/`PW`/`GN` text still rides the M-5 `\`-escaping like any other text field.)
- **The command path cannot deliver a mark poison** — `triangle`/`square`/`letter`/`number`/`label` all bounds-check the coord and emit a valid 2-letter point; C-2/C-2b are upload-only.
- **The scoring path is robust** — `score`/`markdead` reach `Board.Score`/`FindGroup`/`FindArea`, but the flood-fills use an explicit stack (no recursion → no stack overflow) and the atari-dame loop is monotonic (terminates). No crash on empty/adversarial boards.
- **WebSocket "instant 4 GB" allocation** — not a thing; `readBytes` grows incrementally as bytes arrive (the real issue is H-4: no ceiling, no deadline).

---

## 7. Reviewed and clean (positives)

- Passwords hashed with **bcrypt** and compared in constant time (`pkg/core/verify.go`).
- **SQL fully parameterized** (`pkg/loader/dbloader.go`) — no injection. (Portability nit: `dbloader.go:382` uses double-quoted string literals that break on Postgres.)
- HTML templates use `html/template` auto-escaping.
- ZIP extraction never writes entry names to disk → **no zip-slip**.
- No `InsecureSkipVerify` / disabled TLS verification in outbound clients.
- No hardcoded app secrets committed (aside from the sample Postgres/Grafana defaults in L-4/L-5).

---

## 8. Running the PoCs

```
go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml   # disposable target on :8080
go run ./security/poc/harness <id> [-target localhost:8080]                # one id per finding
```

Run the harness with no arguments for the full command list. Other reproductions:
- **Data races & the memory-loader crash:** `go test -race ./security/poc/race/` (DR-2/DR-3 and L-10).
- **OGS gamedata crash (H-9):** `go test -tags poc -run TestOGSGamedataCrash_1c ./pkg/room/plugin/`.
- **Pipeline fuzzing:** `go test -run x -fuzz FuzzSGFPipeline ./pkg/state/` drives the full `FromSGF → GenerateFullFrame → serialize → reload` path and finds the mark poison-pill in seconds. (The repo's parser-only fuzzers — `FuzzSGFParser`/`FuzzFromSGF` — never render or round-trip the tree, so they miss the poison class entirely; this target closes that gap.)
- **Browser PoCs** (Node + Playwright + Chromium, server running): `node security/poc/browser/xss_label.js`, `xss_error_modal.js`, `xss_twitch_sniff.js`, `clickjacking.js`.

Several PoCs crash or exhaust the target — **authorised local testing only**; see [`security/poc/README.md`](security/poc/README.md).

*Caveats: line numbers reference the repository at assessment time; dynamic validation ran against the default in-memory config; items marked `insp.` are confirmed by code inspection rather than a runnable exploit.*
