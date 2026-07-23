# Remediation Plan — golab/board

A hardening plan organized by **systemic gap**, not per-finding. It is the actionable
companion to [`SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md) (69 findings) and
[`SECURITY_ADDENDUM.md`](SECURITY_ADDENDUM.md) (21 findings) — consult those for the full
per-finding detail, PoCs, and reasoning behind every item below.

**Why gaps, not findings:** the ~90 findings collapse to **7 root-cause gaps**. Each gap is a
single missing engineering discipline replicated across many call sites; fixing the discipline
closes the whole cluster. This plan is designed to be followed outside the review conversation:
each gap has a concrete checklist (file + location + action) and a verification step.

**Line numbers reference commit `12030bc` (PR #2 head).** They may drift; locate by
symbol/content if so. Every item cross-references its finding IDs (e.g. `C-3`, `N-1`) so you can
pull exact detail from the two reports.

---

## The one decision that sets the scope: the access model (Gap G5)

Everything except G5 is bounded, mechanical hardening. **G5 is a product decision** you must make
before scoping:

> **Do rooms need real privacy (accounts / private games), or is "rooms are world-readable and
> world-writable unless you know the URL" acceptable?**

- **Acceptable** → G5 is a half-day of quick wins + documenting the model. Whole project ≈ **1–1.5
  focused weeks**.
- **Need real privacy** → add a genuine auth subsystem (server-issued sessions, identity binding,
  per-room ACLs): **+1–3 weeks**, and the only place worth pricing an alternative before committing.

The current room "password" is a shared secret with no identity binding — it is **not** an auth
system and cannot be made private-grade by patching. Decide this first.

**Deployment assumption for this plan:** the app runs **sandboxed on its own origin/subdomain**,
containerized with memory/CPU limits + auto-restart (e.g. Kubernetes), behind a reverse proxy.
This assumption is load-bearing — several gaps rely on it and it is itself a Phase-0 task.

---

## Gap G1 — Untrusted-input handling (panics → errors)

**Root cause:** client/OGS data is consumed with unchecked type assertions (`x.(T)`), unchecked
indexing (`arr[i]`), and coords that decode to `nil` without an error — each a runtime panic.
**Closes:** C-1, H-9, M-10, N-5, N-7, N-9, N-10, N-11 (and contains latent N-2).

- [ ] **Highest-leverage single change:** wrap every `go`-spawned goroutine in `recover()` — the OGS
  loop (`pkg/room/plugin/ogs.go:198` `go o.loop(...)`), the per-room heartbeat, and any hub message
  loop. This alone downgrades the entire "panic in a goroutine → whole-server crash" class (C-1,
  H-9, and N-2 if ever unblocked) from **fatal** to **contained**.
- [ ] Guard `Board.Set` (`pkg/core/board/board.go:127`) with `c != nil && c.Valid(size)`, and reject
  nil/off-board coords in `Board.Legal` (`:240`) **before** it calls `Set`. (C-1, N-9)
- [ ] Make `coord.FromInterface` (`pkg/core/coord/coord.go:234`) return an **error** when
  `NewCoord` yields nil (off-board), and nil-check `cmd.crd` at the top of each command `Execute`
  (`pkg/state/commands.go` add_stone/remove_stone/triangle/square/letter/number/label/goto_coord/
  markdead). (N-5)
- [ ] Length-check the `draw` decoder before indexing `vals[0..4]` (`pkg/state/command_decoder.go:153`
  — `if len(vals) != 5 { return error }`). (N-10)
- [ ] Comma-ok the `upload_sgf` array element assertion (`pkg/room/handlers.go`, `ifc.(string)`) and
  the `handleUpdateSettings` map/field assertions. (N-11, M-10/c1)
- [ ] Tolerate a missing `s.nodes[i]` map entry in `graft`/`smartGraft` (`pkg/state/commands.go` node
  lookup) and re-index (or reject duplicate/out-of-range) uploaded `IX` indices at load. (N-7)
- [ ] Bounds-check the column letter against board size in `coord.FromAlphanumeric`
  (`pkg/core/coord/coord.go`) so graft on 9×9/13×13 can't reach the unguarded `Board.Set`. (N-9)

**Verify:** `go run ./security/poc/harness c1 c2 m7 a1` and the addendum core suite
(`security/addendum/_pocs/`, copy into `zzpoc/` / `zz_verify/`, `go test`) should all report the
panic is now a returned error / recovered — the server stays up. Add `recover()` regression tests.

---

## Gap G2 — Resource limits & bounds (anti-DoS)

**Root cause:** no caps exist anywhere — recursion depth, allocation size, message size, body size,
connection/room counts, fetch size. **Closes:** C-3, C-4, C-5, C-6, C-8, H-2, H-3, H-4, H-7, M-8,
M-11, M-12, N-3.

- [ ] Depth-cap `parseBranch` (`pkg/core/parser/sgfparser.go:214`) — error past ~1000 nesting — or
  convert it to an iterative implementation. (C-3)
- [ ] Depth-cap or convert `SGFNode.toSGF` / `TreeNode.Copy` to iterative (serialize path via
  `parser.Merge`). (C-4)
- [ ] Validate board size to a whitelist (`{9,13,19}`) in `handleUpdateSettings`
  (`pkg/room/handlers.go`) **and** clamp defensively in `NewBoard` (`pkg/core/board/board.go:61`);
  make `NewState`/`FromSGF` agree on the range so a size-20 room can't be silently dropped on
  restart. (C-5, M-11)
- [ ] Cap zip output: `io.LimitReader` per entry (`internal/zip/zip.go:42`) + a running total-byte
  budget + a max entry count. (C-6)
- [ ] Advance `current` into the pasted branch (or forbid paste onto an ancestor of the clipboard)
  and enforce a **per-room node cap** — the same cap bounds runaway `graft`. (C-8, H-7)
- [ ] `internal/fetch/fetch.go:107`: `io.ReadAll(io.LimitReader(resp.Body, 1<<20))` + a truncation
  error, and use an `http.Client{Timeout: …}` with a redirect policy that re-validates each hop's
  host against the allow-list. Mirror the 1 MiB cap in `handleRequestSGF` and `FetchOGS`. (N-3, M-2)
- [ ] Reject `length > maxMessageBytes` **before** reading, and set a read deadline in
  `pkg/event/channel.go` (`readPacket`/`readBytes`). Wrap HTTP bodies in `http.MaxBytesReader`
  (`pkg/hub/apiv1router.go`, `/ext/upload`). (H-4, M-8)
- [ ] Add global/per-room/per-IP connection caps + rate limiting (e.g. `httprate`); cap total rooms
  and evict idle/empty rooms quickly; shorten the 1-hour heartbeat. (H-2, H-3, M-6)
- [ ] Fix the O(N²) load: track the board incrementally during `FromSGF` instead of a root-rewind
  per setup node (`gotoIndex` in `pkg/state/nav.go`), and cap node count per upload. (M-12)

**Verify:** `go run ./security/poc/harness c3 c5 c6 copybomb grow sgfquad` (+ `c6`/`copybomb` over
WS) should no longer crash/hang; `n_in_requestsgf_poc_test.go` should return a truncation error
instead of a fatal stack overflow.

---

## Gap G3 — SGF / game-state integrity (poison-pills, round-trip safety)

**Root cause:** parsed SGF/NGF/OGS data is treated as trusted — no schema validation, not
round-trip-safe, and a hand-rolled OGS frame parser that isn't JSON-aware. Several defects
**persist across restart** (⚑), so auto-restart does not heal them. **Closes:** C-2, C-2b, M-5,
N-2, N-4, N-6, N-8.

- [ ] Nil-check `CoordSet.Add` (`pkg/core/coord/coord.go:43`) and skip nil coords in
  `generateMarks`; **expand compressed point ranges** (`aa:cc`) before `FromLetters`. Validate
  `TR`/`SQ`/`LB` values (and length-guard the `LB` colon split) in `FromSGF` so malformed marks are
  never committed or persisted. (C-2, C-2b)
- [ ] Escape a literal `\` (not just `]`) in the SGF serializer (`pkg/state/state.go`, `toSGF`) so
  text fields (`C`/`LB`/`PB`/`PW`/`GN`) are round-trip-safe. (M-5)
- [ ] In the NGF parser, accept only `B`/`W` as move keys (`pkg/core/parser/ngfparser.go:219` /
  `parseMove`); validate property **keys** (uppercase letters) at `FromSGF`/serialize so a raw byte
  can't become an SGF property key that breaks reload. (N-6)
- [ ] Reject non-finite floats (`math.IsNaN`/`math.IsInf`) in the `PX` pen branch
  (`pkg/state/frame.go:145`) and at `FromSGF`; log (don't silently drop) `SendEvent`/marshal
  errors. (N-8)
- [ ] Replace the byte-counting OGS frame parser (`pkg/room/plugin/ogs.go:141` `readFrameFromChan`)
  with a real `encoding/json` decoder over the socket stream — **and in the same change**
  SGF-escape all interpolated OGS strings (`[ ] ( ) ; \`) in `gameInfoToSGF`/`initStateToSGF`
  (`ogs.go:402`). Doing both together fixes N-4 without unmasking the (currently N-4-blocked) N-2
  injection. (N-4, N-2)

**Verify:** `go run ./security/poc/harness b1 b2` and the addendum tests
(`core_top3_verify_test.go`, `ngf_test.go`, `nan_test.go`, `ogs_frame_parser_stall_test.go`,
`n2_reach_blocked_test.go`) should all report "no panic / rejected". Keep the pipeline fuzzer green:
`go test -run x -fuzz FuzzSGFPipeline ./pkg/state/`.

---

## Gap G4 — Concurrency discipline (never hold a lock across I/O)

**Root cause:** mutexes are held across blocking socket writes and across cross-lock calls, and
shared slices are marshaled without copying. **Closes:** DL-1, DL-2, DL-3, DR-1, DR-2, DR-3, DR-4,
L-10.

- [ ] Restructure `Broadcast`/`SendTo`/`BroadcastHubMessage` (`pkg/room/room.go:361…`): **snapshot** the
  connection list under `r.mu`, **unlock**, then write — with a per-write deadline and drop of slow
  clients. (DL-2, DL-3)
- [ ] Never call room methods (`r.NumConns()` etc.) while holding `h.mu` in the hub
  (`pkg/hub/hub.go` `ConnCount`/`RoomCount`) — snapshot, release, then call. (DL-1)
- [ ] Return **copies** from `Room.Nicks()` and deep-copy `Fields`/`Comments` in `GenerateFullFrame`
  / `Current()` so nothing marshaled outside `r.mu` aliases live state. (DR-1, DR-2, DR-3)
- [ ] Make `OGSConnector.Exit` an `atomic.Bool` (or read via `isExited()` everywhere). (DR-4)
- [ ] Add a `sync.Mutex` to `MemoryLoader` (`pkg/loader/memoryloader.go`) — memory-mode concurrent
  map crash. (L-10)

**Verify:** `go run ./security/poc/harness dr1 dl1 dl2` no longer crashes/hangs; `go test -race
./security/poc/race/` reports **no** data race (currently fires DR-2/DR-3/L-10).

---

## Gap G5 — Identity & authorization model  ⚠️ decision point (see top)

**Root cause:** no server-side identity; the room password is broadcast in cleartext and the HTTP
path trusts a client-supplied `userid`. **Closes:** N-1, AZ-1, AZ-2, AZ-3, AZ-4, ID-1, M-1, N-17,
N-19 (and H-1, H-6 live here).

**G5-quick (do regardless — cheap, high-value):**
- [ ] **Stop broadcasting the password.** In `handleUpdateSettings` (`pkg/room/handlers.go:291…`)
  scrub `sMap["password"]` (or broadcast the server-side `Settings`, which holds only the hash)
  before the event is returned to `broadcastAfter`. (N-1 — *serious; passive observers currently
  receive the plaintext secret*)
- [ ] **Stop trusting client `userid`** on `/api/v1` (`pkg/hub/apiv1router.go`) — bind identity
  server-side, never from JSON. (AZ-1)
- [ ] Do **not** grandfather connected sockets when a password is set: drop `SetAuthAll()`
  (`pkg/room/handlers.go:330`), clear `auth` in `SetPassword`, and force re-`checkpassword`.
  (AZ-2); return the stored bool from `GetAuth` so revocation works (AZ-4).
- [ ] Add `authorized` (+ `outsideBuffer`) to the `graft` handler chain (`pkg/room/handlers.go`) so
  it can't mutate password rooms unauthenticated. (H-6)
- [ ] Validate the WebSocket `Origin` against an allow-list in the socket `Handshake`
  (`pkg/hub/socketrouter.go`). (H-1)
- [ ] Sanitize room IDs consistently: run `core.Sanitize` on the `/api/v1` `{board}` param
  (`apiv1router.go`) and derive the WS room from chi's `{boardID}`, not the raw request target.
  (N-16, N-17)
- [ ] Gate `update_nickname` on `authorized` and prune `nicks` entries with no live connection.
  (N-19)

**G5-full (only if private games are a product requirement):**
- [ ] Introduce server-issued session tokens / accounts, bind every action to a verified identity,
  and add per-room read/write ACLs. Then gate the connect/read path and the
  `/debug`·`/sgf`·`/sgfix` download endpoints (`pkg/hub/webrouter.go`) on it. (ID-1, M-1)

**Verify:** `go run ./security/poc/harness az1 az2 id1 m3` + `poc_password_broadcast.go` — the
observer must **no longer** receive the plaintext password, and spoofed-`userid` actions must be
rejected.

---

## Gap G6 — Frontend output-encoding + CSP (protect the embedding origin) 🚩 launch blocker

**Root cause:** broadcast user data reaches `innerHTML` unescaped, and there is no CSP backstop.
**This is the only class that directly endangers *your* site's visitors.** **Closes:** XSS-1, XSS-1b,
XSS-2, XSS-3, CJ-1, N-15.

- [ ] `text.textContent = txt` (not `innerHTML`) at **both** SVG label sinks
  `pkg/frontend/js/boardgraphics/boardgraphics.js:516` **and** `:540`, and pass `String(i)` (not raw
  `lb.text`) on the numeric branch of `place_label` (`state.js`). Length/charset-validate the label
  server-side in `NewAddLabelCommand`. (XSS-1, XSS-1b)
- [ ] Render modal messages as text nodes (`textContent`/`htmlencode`) at `pkg/frontend/js/modals.js:183`
  (`show_error_modal`), `:211` (`show_info_modal`), and the prompt modal; and **stop broadcasting raw
  internal error strings** server-side. (XSS-2)
- [ ] Twitch callback (`pkg/hub/twitchrouter.go:151`): set `Content-Type: text/plain; charset=utf-8`
  + `X-Content-Type-Options: nosniff`, and echo the challenge **only after** `twitch.Verify`
  succeeds. (XSS-3, M-7)
- [ ] Add a **security-headers middleware** in `app.New()` (`pkg/app/app.go:40`, next to
  `StripSlashes`): `Content-Security-Policy` (`default-src 'self'` + the Bootstrap CDN or vendor it;
  `frame-ancestors` scoped to your embedder), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options`. (CJ-1)
- [ ] Server-side-validate the pen `draw` color against `^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$`. (N-15)

**Verify:** the browser PoCs must no longer fire —
`node security/poc/browser/{xss_label,xss_error_modal,xss_twitch_sniff,clickjacking}.js`
(needs Node + Playwright + Chromium + a running server).

---

## Gap G7 — Deployment & secrets hardening (config, not code)

**Root cause:** the container/compose/config ship with insecure defaults and leak secrets.
**Closes:** N-13, N-14, L-3, L-4, L-5, CS-1, CS-2, M-9, N-18, N-20, L-8. Do this alongside the
Phase-0 origin isolation.

- [ ] Run the app on a **separate origin/subdomain** from your main site, containerized with
  memory/CPU limits + auto-restart, behind a reverse proxy (this is what turns the DoS crashes into
  self-healing annoyances). Add an **egress `NetworkPolicy`** (bounds SSRF blast radius — M-2).
- [ ] `Dockerfile`: add a non-root `USER`, read-only FS; bump the pinned toolchain
  (`golang:1.24.0-alpine` → latest 1.24 patch). (L-3, N-20)
- [ ] `docker-compose.yaml`: remove the host `ports:` mappings for **Postgres** (`5432:5432`, gated
  to the `monitoring` profile — N-14) and **Loki** (`3100:3100` — N-13); set `auth_enabled: true` on
  Loki if it must be published. Rotate the committed `postgres/postgres` (L-4) and Grafana `admin`
  (L-5) defaults into secrets; enable TLS.
- [ ] Implement `dbConfig.redact()` (`pkg/config/config.go:84`, currently an empty no-op) so the
  Postgres DSN-with-password isn't logged at startup. (CS-1)
- [ ] Propagate the bcrypt error in `core.Hash` (`pkg/core/verify.go:17`) and reject the setting —
  a >72-byte password currently stores an empty hash and silently opens the room. (CS-2)
- [ ] Construct an `http.Server{}` with explicit timeouts instead of `http.ListenAndServe`. (M-9)
- [ ] Refresh `lastActive` in `HandleAny`/`RegisterConnection` (not only the `"_"` chain) so
  API/Twitch-driven rooms aren't reaped + DB-deleted at 24h. (N-18)
- [ ] Use `crypto/rand` for room names if they're meant to be unguessable (L-8); add `govulncheck`
  + `gosec` to CI (L-7, N-20).

**Verify:** `docker compose config` shows no host-published DB/Loki; `go run ./security/poc/harness
cs1 cs2` confirm the DSN is redacted and the long-password footgun is closed.

---

## Phased roadmap

**Phase 0 — launch blockers (must ship before any public embed):**
1. **G6** in full — XSS sinks + CSP + security headers.
2. **Separate-origin sandbox deployment** (start of G7) — origin isolation + resource-limited,
   auto-restarting container behind a proxy.
3. **G5-quick subset:** N-1 (password broadcast) and AZ-1 (`userid` trust) — cheap and serious.

**Phase 1 — availability (a few days):** G1 (recover() wraps + validation) and G2 (caps). Kills the
trivial unauthenticated whole-server crashes.

**Phase 2 — integrity & robustness (a few days):** G3 (poison-pills — *persist across restart*, so
K8s doesn't heal them) and G4 (concurrency).

**Phase 3 — operational:** the rest of G7; the rest of G5-quick.

**Decision gate before scoping:** the **G5** access-model question (top of this doc). Only "G5-full"
turns this from a ~1–1.5 week job into a multi-week one.

---

## Verification & regression strategy

The proof-of-concept exploits from the review double as a **regression suite** — a fix is done when
its PoC flips from "reproduces" to "blocked":

- **Harness (PR #2 findings):** `go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml`
  then `go run ./security/poc/harness <id>` (run with no args for the list;
  `security/poc/README.md`).
- **Addendum PoCs:** `security/addendum/_pocs/` — copy each `_test.go` into its target package and
  `go test` (see that dir's `README.md`).
- **Concurrency:** `go test -race ./security/poc/race/` must be clean (G4).
- **Parser/state fuzzing:** `go test -run x -fuzz FuzzSGFPipeline ./pkg/state/` (G3).
- **Browser:** the Playwright PoCs under `security/poc/browser/` (G6).
- **CI:** add `go test ./...`, `go test -race ./...`, `go vet`, `govulncheck`, and `gosec` gates so
  regressions don't creep back.

Keep `go build/vet/test ./...` green throughout (it is green at the current head).

---

## Reassessment (the honest bottom line)

- **The work is bounded and mechanical.** Six of the seven gaps are known-pattern fixes, verifiable
  against the existing PoCs. The valuable, hard-to-replicate part — the go-game / SGF / tree-state
  logic — is where **none** of the bugs live; the fixes are concentrated in the input-handling and
  deployment layers, which are the well-understood parts.
- **Effort:** hardening everything *except* real auth ≈ **1–1.5 focused weeks** for one competent Go
  dev, including testing. Real auth (G5-full) adds **1–3 weeks** and is the only place worth pricing
  an alternative.
- **Residual risk after Phases 0–2, on a separate origin behind a proxy + auto-restart:**
  **low-to-moderate and largely self-healing** — a reasonable bar for embedding a non-critical
  interactive widget.
- **Two non-code decisions:** (1) **fork vs. upstream** — if upstream won't take the hardening PRs,
  you fork and own the posture going forward (budget ongoing maintenance); (2) **criticality** —
  this is a widget, not a system of record; scope the effort accordingly.

*Full per-finding detail, PoCs, and severity reasoning: `SECURITY_ASSESSMENT.md` and
`SECURITY_ADDENDUM.md` (see its §7 for the independent re-verification and corrections).*
