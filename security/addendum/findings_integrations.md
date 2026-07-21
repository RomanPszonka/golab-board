# Findings — Integrations / Persistence / Deployment / Browser-Extension audit

Scope: `pkg/room/plugin/{plugin.go,ogs.go}`, `internal/{twitch,fetch,zip}`, `pkg/loader/*`,
`pkg/config/config.go` + `config/*.yaml`, `Dockerfile`, `docker-compose.yaml`,
`.github/workflows/*`, `.golangci.yml`, `monitoring/**`, `extensions/{chrome,firefox}`,
`loadtest/`, `integration/`, `go.mod` dependency review.

All items below are **NEW** relative to `SECURITY_ASSESSMENT.md` (C-*, H-*, M-*, L-*, GL-*,
DR-*, CS-*, ID-*, AZ-*, XSS-*). PoCs are under `security/addendum/_pocs/` (copy into the
named package, or `go test -tags poc`).

> **Re-verification note:** the consolidated + independently re-verified report is
> [`SECURITY_ADDENDUM.md`](../../SECURITY_ADDENDUM.md); see its **§7** for corrections. In
> particular **N-IN-1 (= N-2) was downgraded High/Critical → Low**: the OGS injection is
> **not reachable end-to-end** — the game-name payload must contain `]`, which N-IN-2 (= N-4)'s
> frame parser truncates before `gameInfoToSGF` is ever called (both PoCs bypass that path by
> calling `gamedataToSGF` directly). It remains a latent defect to fix alongside the N-4 fix.
> N-IN-6 (= N-14, host-published Postgres) is gated behind the `monitoring` compose profile.

---

## N-IN-1 — SGF injection via unescaped OGS game metadata (game name) — stored-XSS & poison-pill delivery through the "trusted" OGS integration

**Severity:** High (Critical when the OGS integration is used — crash is in an unrecovered spawned goroutine and the poison persists)

**Location:** `pkg/room/plugin/ogs.go:402-404` (`gameInfoToSGF`), sink fan-out at `ogs.go:292-294` (`loop` → `Room.UploadSGF`)

**Root cause.** `gameInfoToSGF` splices OGS-supplied strings into an SGF document with
`fmt.Sprintf("...GN[%s]", ...)` and **no escaping/validation**. `game_name` is free text
chosen by the OGS game creator (free OGS account), so `]` / `[` bytes in the name break out
of the `GN` property and inject arbitrary SGF properties into the document that
`OGSConnector.loop` then feeds to `Room.UploadSGF` → `state.FromSGF` → `Room.SetState`
(commit + persist) → `GenerateFullFrame` — **all inside the spawned `go o.loop(...)`
goroutine** (`ogs.go:198`), which has no panic recovery.

**Attacker-reachable trigger.**
1. Attacker creates a free OGS account and creates a game named, e.g. `x]TR[` (the
   `gameInfoToSGF` template supplies the closing `]`, producing `...GN[x]TR[];B[dd])` — a
   *valid* SGF containing an **empty `TR[]` mark** = the C-2b poison pill), or
   `x]LB[aa:<img src=x onerror=alert(document.domain)>` (injects a stored label = the
   XSS-1 sink).
2. Any golab room (unauthenticated) sends `request_sgf` with
   `https://online-go.com/game/<id>` (also reachable via GET `/ext/upload?url=...`). OGS
   pushes `game/<id>/gamedata` frames containing the malicious name; golab converts and
   commits them.

**Impact.**
- **Whole-server crash:** the injected `TR[]` makes `generateMarks` nil-deref
  (`coord.FromLetters("")` → nil → `CoordSet.Add(nil)`) **inside the OGS goroutine** —
  unrecovered → fatal. Confirmed in PoC.
- **Persistence / board bricking:** `SetState` commits before the panic (same commit-then-
  panic pattern as C-2); the poisoned SGF is written by the heartbeat/`Hub.Save`, so the
  room re-bricks on every join after a restart.
- **Stored XSS** in the board origin (and any embedding origin per XSS-2) for every viewer
  of the room, delivered through a channel that survives the XSS-1 fixes proposed in the
  report (frontend `textContent` + validating the `label` **command**) — this vector
  enters via `FromSGF` of OGS-fetched data, not via the label command or `upload_sgf`.

**Why not a duplicate.** C-2/C-2b/XSS-1 cover the *sinks* (render-time mark panics,
label XSS) reachable via `upload_sgf`. This is a **different root cause**: missing escaping
when splicing untrusted OGS metadata into SGF (`ogs.go:402-404`). Fixing only the reported
items (validate labels in `FromSGF` for the colon-less case, server-side label validation in
`NewAddLabelCommand`, frontend `textContent`) does **not** close this path: a well-formed
`LB[aa:<payload>]` injected via OGS is valid SGF, passes the proposed `FromSGF` checks,
and reaches the frontend through full frames. The `TR[]` crash also fires in the OGS
goroutine — the escalation the report itself flags as Critical — but delivered remotely
without any `upload_sgf`.

**PoC (runnable).** `/tmp/golab/_pocs/n_in_ogs_poc_test.go` → `TestNINSGFInjection`
(copy into `pkg/room/plugin/`, `go test -tags poc -run TestNINSGFInjection -v ./pkg/room/plugin/`).
Observed output:
```
generated SGF: (;GM[1]FF[4]CA[UTF-8]SZ[19]PB[b]PW[w]BR[1d]WR[1d]RU[japanese]KM[6.500000]GN[x]TR[];B[dd])
FromSGF ACCEPTED the injected TR[] mark (state would be committed+persisted)
CONFIRMED: GenerateFullFrame PANIC: runtime error: invalid memory address or nil pointer dereference
   in production this runs inside `go o.loop(...)` => unrecovered => whole-server crash
CONFIRMED: injected LB label with XSS payload survives parse+render -> frontend innerHTML sink
```
(In-tree copy: `pkg/room/plugin/n_in_poc_test.go`.)

**Suggested fix.** SGF-escape all interpolated OGS strings in `gameInfoToSGF` /
`initStateToSGF` (strip or backslash-escape `[`, `]`, `(`, `)`, `;`, `\`) before splicing;
defense-in-depth: reject `LB`/`TR`/`SQ` marks with malformed values in `FromSGF` (report's
C-2 fix) **and** wrap `o.loop` in a `defer recover()` that logs and deregisters the plugin.

---

## N-IN-2 — OGS websocket frame parser counts `[`/`]` inside JSON strings → permanent integration stall + unbounded buffer growth in the spawned goroutine

**Severity:** Medium

**Location:** `pkg/room/plugin/ogs.go:141-172` (`readFrameFromChan`), called from `loop` (`ogs.go:244`)

**Root cause.** `readFrameFromChan` re-implements JSON frame framing by counting raw `[` /
`]` bytes with no notion of quoted strings. OGS sends JSON arrays over the socket whose
string values can contain bracket characters (e.g. a `game_name` of `[[[` or `]]]` — free
text on OGS). Two failure modes:
- **`[` in a string:** depth never returns to 0, so the frame never "ends". The goroutine
  stays inside `readFrameFromChan` forever; every subsequent byte OGS sends (move frames,
  gamedata pushes) is appended to the `data` slice — **unbounded memory growth** in the
  spawned goroutine — and no message is ever processed again (silent integration death;
  the game-over `winner` frame is never seen, so the connector never exits).
- **`]` in a string:** the frame terminates early; the remainder doesn't start with `[`,
  so the next call returns `invalid starting byte` and `loop()` **breaks** — the connector
  dies silently (integration DoS).

Because the loop is stuck inside `readFrameFromChan` (not between frames), `End()` /
`DeregisterPlugin` cannot unwind it: `o.Exit` is only checked between frames
(`ogs.go:243`) — making the H-8/GL-2 leaks unrecoverable through the intended path.

**Attacker-reachable trigger.** Free OGS account → create a game whose name contains `[`
or `]` → any golab room sends `request_sgf` for `https://online-go.com/game/<id>` → the
first gamedata frame carries the name. (Attacker can attach their own room and share the
link; any room that follows their public game is also hit.)

**Impact.** Permanent per-room OGS integration DoS; slow, unbounded memory growth in a
spawned goroutine (traffic-driven; the ping loop keeps the socket alive so bytes keep
arriving); connector goroutine + socket become undrainable even via `DeregisterPlugin`.

**Why not a duplicate.** H-9 covers *type-assertion* panics in `loop`/`gamedataToSGF`;
H-8/GL-2 cover the socket/`readSocketToChan` blocking leaks; C-1 covers `Board.Set`. This
is a distinct root cause — a hand-rolled framing parser that is not string-aware
(`readFrameFromChan`, ogs.go:141-172) — with distinct effects (mis-framing, stall,
retention) rather than assertion panics or socket blocking.

**PoC (runnable).** `/tmp/golab/_pocs/n_in_ogs_poc_test.go` → `TestNINFrameParserBracketsInStrings`.
Observed:
```
CONFIRMED: readFrameFromChan NEVER RETURNED for a frame with '[' in a string;
   the OGS loop goroutine is now permanently stuck, buffering all future bytes (unbounded growth).
']' in string -> early return after 38 of 56 bytes: "[\"game/123/gamedata\", {\"game_name\": \"]"
CONFIRMED: frame cut short; leftover bytes fail ('invalid starting byte') -> loop() breaks -> connector dies.
control OK: clean frame returned intact
```

**Suggested fix.** Delete the byte-counting parser; decode with `encoding/json` directly
from the socket (`json.Decoder` on the `io.Reader`), or at minimum track in-string state
(including `\` escapes) while scanning.

---

## N-IN-3 — `request_sgf` fetch path has no response-size cap → unauthenticated whole-server crash (stack overflow) / OOM via allow-listed hosts serving attacker-controlled content

**Severity:** High

**Location:** `internal/fetch/fetch.go:99-112` (`Fetch`: bare `io.ReadAll`), `:125-137`
(`ApprovedFetch`); no compensating check in `pkg/room/handlers.go:248-254`
(`handleRequestSGF` → `Room.UploadSGF`)

**Root cause.** The 1 MiB cap added for `upload_sgf` (`handlers.go:137`) exists **only** in
`handleUploadSGF`'s string branch. The `request_sgf` path performs a server-side download
(`ApprovedFetch` → `Fetch` → `io.ReadAll`, no `LimitReader`, no `http.MaxBytesReader`, no
client timeout) and hands the entire body to `state.FromSGF`. The hostname allow-list is
not a content control: **`raw.githubusercontent.com` (any public repo file) and
`cdn.discordapp.com` (any uploaded attachment) serve fully attacker-controlled bytes** —
no redirect, open-redirect, or SSRF required.

**Attacker-reachable trigger (any of):**
- WS/POST `request_sgf` with `https://raw.githubusercontent.com/<attacker>/<repo>/main/bomb.sgf`
  where `bomb.sgf` is ~12 MB of `(` → `parseBranch` recursion → **fatal stack overflow**
  (confirmed dynamically; the PoC child process died with `fatal error: stack overflow`
  inside `handleRequestSGF`).
- Same URL via **plain GET** `/ext/upload?url=...` — i.e. an `<img src>` CSRF beacon on any
  web page crashes the server when *anyone* views it.
- A multi-GB "SGF" from the same hosts → OOM (`io.ReadAll` + parser copies).

The attacker's own request is a few hundred bytes, so reverse-proxy request-size caps
(§6 recommendation) are irrelevant — the payload volume is on the server-side **download**.

**Impact.** Unauthenticated, remotely-triggered fatal crash (stack overflow — not
recoverable) or OOM of the entire board server; trivially repeatable.

**Why not a duplicate.** M-2 is about *redirect-following to internal hosts* (SSRF) and
mentions unbounded fetch only in that context; C-7 is the missing cap in the WS **array**
branch; C-3's shown vector is a 12 MB WS message. This finding is the missing cap **in the
fetch/response path itself**: no redirect is involved, the content comes from hosts that
are *supposed* to be fetched, and the C-3/C-7 fixes as written (depth-cap parseBranch is
still open; cap the array branch) would leave this delivery wide open unless the fetch
path is capped too.

**PoC (runnable).** `/tmp/golab/_pocs/n_in_requestsgf_poc_test.go` → `TestNINRequestSGFNoCap`
(copy into `pkg/room/`, `go test -tags poc -run TestNINRequestSGFNoCap -v ./pkg/room/`).
Uses the real `ApprovedFetch` + real `handleRequestSGF` chain with a stub HTTP client
emulating the allow-listed host. Observed:
```
ApprovedFetch returned 12000000 bytes with NO size cap (hostname allow-list passed)
runtime: goroutine stack exceeds 1000000000-byte limit
fatal error: stack overflow
CONFIRMED: died with a FATAL stack overflow inside handleRequestSGF (whole-server crash, unauthenticated).
```

**Suggested fix.** `io.ReadAll(io.LimitReader(resp.Body, 1<<20))` in `Fetch` (error when
truncated), a sane `http.Client{Timeout: ...}` for the default fetcher, plus an explicit
size check in `handleRequestSGF` mirroring the 1 MiB rule — and apply the same cap to
`FetchOGS`/`OGSCheckEnded`.

---

## N-IN-4 — Twitch `!branch` chat command is missing the `broadcaster == chatter` authorization check that `!setboard` has

**Severity:** Medium

**Location:** `pkg/hub/twitchrouter.go:240-255` (`case "branch"`), contrast `:220-221`
(`case "setboard"` gates on `broadcaster == chatter`)

**Root cause.** The `branch` case of the EventSub chat-command handler never verifies that
the chatter is the broadcaster. **Any viewer in the broadcaster's Twitch chat** can send
`!branch <moves>` and have the server graft those moves onto the broadcaster's mapped room
(`TwitchGetRoom(broadcaster)` → `GetOrCreateRoom` → `HandleAny("graft")`). Graft itself
also bypasses room authorization (H-6), so this works even on password-protected rooms,
and the chatter never needs to know the room ID.

**Attacker-reachable trigger.** Post `!branch q16` in the Twitch chat of any streamer who
linked their room via `!setboard` (a normal Twitch chat message from any account; the
EventSub webhook delivers it with valid Twitch signatures).

**Impact.** Unauthorized modification/defacement of a live broadcaster's board by any
viewer (griefing at scale, spam-grafting). Note L-12's "no new capability" reasoning was
predicated on the commands being *the broadcaster's*; the missing check widens the actor
set from "broadcaster" to "every Twitch viewer", including on rooms whose IDs are not
public and rooms with passwords (via H-6).

**Why not a duplicate.** L-12 documents the existence/reachability of the Twitch chat
commands and rates them Low assuming the broadcaster is the actor; H-5 is the
signature-verification bypass (unauthenticated forgery). This is a distinct authorization
omission in the handler itself (`twitchrouter.go:240`): with *valid* Twitch delivery and a
*valid* secret, a non-broadcaster chatter is still authorized to mutate the room.

**PoC (runnable).** `/tmp/golab/_pocs/n_in_twitch_poc_test.go` → `TestNINTwitchBranchAuthz`
(copy into `pkg/hub/`, `go test -tags poc -run TestNINTwitchBranchAuthz -v ./pkg/hub/`).
Observed:
```
control OK: !setboard from a non-broadcaster chatter is refused (broadcaster==chatter gate)
nodes before/after a random chatter's !branch: 1 -> 2
CONFIRMED: any chatter can graft moves onto the broadcaster's room
```

**Suggested fix.** Apply the same `broadcaster == chatter` gate to `branch` (or restrict
`branch` to a broadcaster-configured allow-list of moderators).

---

## N-IN-5 — Loki log store: `auth_enabled: false` and port 3100 published on all interfaces

**Severity:** Medium

**Location:** `monitoring/loki/loki-config.yaml:1` (`auth_enabled: false`);
`docker-compose.yaml` (`loki` service: `ports: - "3100:3100"` — binds 0.0.0.0)

**Root cause / impact.** When the `monitoring`/`prod` compose profiles are deployed, the
Loki HTTP API is reachable by any host that can reach the machine with **no
authentication**: full log query (`GET /loki/api/v1/query_range`), label enumeration, log
injection (`POST /loki/api/v1/push` — forged log entries), and stream deletion. If the
operator ships the app logs through the provided Alloy pipeline (the intended design;
`${LOG_PATH:-./logs}`), the shipped content includes everything the app logs at Info level
— which includes the full DB DSN **with password** at startup (CS-1), internal errors,
room IDs and nicknames. Conditional chain: app currently logs to stdout, so the DSN
reaches Loki only if the operator redirects stdout into `$LOG_PATH` — the exposure of the
Loki API itself is unconditional.

**Why not a duplicate.** L-5 covers **Grafana** default admin credentials; L-7 covers
missing CI scanning. The Loki service's missing auth + host-wide port publication is a
separate service/configuration surface not mentioned anywhere in the report.

**Suggested fix.** Don't publish `3100` on the host (drop the `ports:` entry — Alloy and
Grafana reach Loki over the compose network), or front it with the same authenticated
reverse proxy as Grafana; if it must be published, enable `auth_enabled: true` with a
tenant header injected by an authenticating proxy.

---

## N-IN-6 — docker-compose publishes Postgres `5432:5432` on all interfaces (with the committed default credentials)

**Severity:** Medium

**Location:** `docker-compose.yaml` (`postgres` service: `ports: - "5432:5432"`,
`POSTGRES_USER=postgres`, `POSTGRES_PASSWORD=postgres`)

**Root cause / impact.** L-4 documents the committed default credentials; what turns them
into a *remote* compromise is this service-level port publication: Docker binds
`0.0.0.0:5432`, so the database is directly reachable from the LAN/internet (host firewall
permitting) with `postgres/postgres` — full read/write of the room store (including bcrypt
room-password hashes and all room content) and Postgres superuser primitives
(`COPY ... FROM PROGRAM`, `LOAD`) for container-level code execution. The app itself only
needs Postgres on the internal compose network.

**Why not a duplicate.** L-4 flags the *credentials in the config file*; this is the
*network exposure* of the database service in the compose deployment — a different
configuration location and the precondition that makes L-4 remotely exploitable (the
compose file is the production deployment recipe; nothing in the report notes that 5432 is
host-published).

**Suggested fix.** Remove the `ports:` mapping for `postgres` (keep inter-service DNS), or
bind to localhost (`127.0.0.1:5432:5432`) only when local tooling needs it; rotate the
default credentials.

---

## N-IN-7 — Dependency/toolchain advisories: chi v5.2.2 open-redirect fix available; Dockerfile pins unpatched Go toolchain

**Severity:** Low (informational; no in-app exploit path identified for the chi item)

**Details.**
- `github.com/go-chi/chi/v5 v5.2.2` — GO-2026-4316 (open redirect in `RedirectSlashes`)
  fixed in **v5.2.4**. The app uses `middleware.StripSlashes` (`pkg/app/app.go:40`), which
  performs no redirect (verified against the vendored source: it rewrites `RoutePath`
  in place), so the app is **not** affected; bump anyway.
- `Dockerfile:1` pins `golang:1.24.0-alpine`. `govulncheck -mode=source ./...` (run in this
  repo with go1.24.5) reports **27 reachable standard-library advisories** fixed in
  1.24.6–1.24.12, including server-relevant packages the app exercises (`net/http`,
  `crypto/tls`, `crypto/x509`, `net/url`, `encoding/pem`, `database/sql`,
  `archive/zip`...). Rebuilding on the latest 1.24.x patch image clears them; no app code
  change needed. (x/net@v0.47.0 / x/crypto@v0.45.0 module-level advisories — x/net/html,
  openpgp, ssh/agent — are in packages the app does not import-call; govulncheck confirms
  no vulnerable symbol is reachable.)

**Why not a duplicate.** L-6 flags the deprecated `x/net/websocket` package specifically;
L-7 flags missing CI scanning. Neither records the chi v5.2.4 security fix or the
unpatched toolchain pinned by the Dockerfile.

**Suggested fix.** Bump chi to ≥ v5.2.4; pin the image to the latest `golang:1.24-alpine`
patch (or `golang:1-alpine`) and rebuild; optionally add `govulncheck` to CI (which would
also satisfy L-7).

---

## N-IN-8 — Self-referential fetch amplification: the board's own domain is on the fetch allow-list (`golab.gg`), enabling one-request→many-rooms fan-out

**Severity:** Low

**Location:** `internal/fetch/fetch.go:30-31` (`"golab.gg"`, `"test.golab.gg"` in `okList`);
`pkg/hub/extrouter.go:23-44` (`Upload`)

**Root cause / impact.** Because the board's own host is fetch-approved, a single
unauthenticated GET
`/ext/upload?url=https://golab.gg/ext/upload?url=https://golab.gg/ext/upload?url=...`
(nested K deep — no encoding needed since `?` is legal inside a query value; total length
bounded only by the ~1 MB header limit) makes each `/ext/upload` handler synchronously
create a room (heartbeat goroutine + memory) **and** fire the next nested server-side
fetch. One small request therefore creates K rooms and K internal HTTP round-trips —
multiplying the H-2 room-creation DoS from "1 connection : 1 room" to "1 request : K rooms
+ K fetches", each nested call additionally subject to the uncapped download of N-IN-3.

**Why not a duplicate.** H-2 covers unbounded room creation via many connections; M-2
covers redirect-based SSRF. This is direct (no redirect) self-referential fan-out enabled
by the allow-list contents (`golab.gg` self-entry) — a distinct configuration root cause
and amplification ratio.

**Suggested fix.** Remove the server's own public hostnames from `okList` (or refuse
`request_sgf`/`/ext/upload` URLs that resolve to the server's own URL); enforce a per-room
and per-request fan-out/depth limit.

---

## Rejected candidates (investigated, not reported)

- **`OGSConnector.connect`/`chatConnect` nil-deref on `o.Creds.User` (ogs.go:123,135-137):**
  would require OGS `ui/config` to return `user: null` for the unauthenticated fetch; in
  practice it returns an anonymous user object (the integration demonstrably works), and
  any failure returns an error event, not a crash. Not shown reachable.
- **Type assertions in `loop`/`gamedataToSGF` (ogs.go:264-318, 362-401)** — inside H-9's
  stated location/class.
- **`PushHead` with out-of-range OGS move coords** — C-1 (`Board.Set` nil/OOB).
- **`GetColorAt(f)` / `AddStonesToTrunk(f, ...)` with attacker-controlled `f`
  (ogs.go:321,349):** `TreeNode.TrunkNum` guards the walk and returns -1; both fail safe.
- **`coord.ToLetters` on nil coord (pass moves `[-1,-1]` from OGS):** `NewCoord` returns
  nil and `ToLetters` is nil-safe (`ogs.go` path yields `;B[]`); no panic. Normal OGS pass
  moves are safe.
- **`twitch.DefaultTwitchClient.Subscribe` unchecked assertions
  (`s["data"].([]any)` etc., twitch.go:366-375):** reachable only with a malicious
  *Twitch API* response (trusted upstream), and any panic is on the OAuth callback request
  path → recovered by net/http → per-connection at most.
- **fetch scheme confusion (`file://`, `gopher://`)**: `http.Client.Get` rejects non-http(s)
  schemes; allow-list check also precedes. Dead end.
- **Allow-list bypass via userinfo / trailing dot / case / decimal-hex IP / DNS rebinding:**
  `okList` matches exact hostnames; userinfo variants either fail URL validation downstream
  or only expose the attacker's own credentials; host casing/trailing dot fail closed;
  allow-listed names are fixed third parties whose DNS the attacker does not control.
- **Extension `anchor.href` concatenation of `window.location.href` (chrome/firefox
  golab.js:44):** unencoded, so `&`/`#` in an OGS URL cause query-param pollution on
  `/ext/upload`, but Go's `FormValue` takes the first `url` value and the endpoint has no
  other dangerous params — no exploitable outcome. `innerHTML` uses only static strings.
- **Extension manifest issues:** `*://*.online-go.com/*` content-script match (includes
  http) and missing Firefox icon file are hygiene nits, not vulnerabilities.
- **`MemoryLoader.AddMessage`/`MessageCount` without mutex:** same root cause as L-10.
- **`BaseLoader.SaveRoom`/`TwitchSetRoom` select-then-insert TOCTOU:** races yield a PK
  error (surfaced to caller) or fail closed (`TwitchGetRoom` requires exactly 1 row); no
  corruption or security impact found.
- **`sqliteloader.mkDirs` uses `os.ModePerm` (0777):** umask-bounded, host-local; low value.
- **SQL injection re-verification (independent):** all loader queries are parameterized
  (`?`→`$N` rebind for postgres); only constant SQL strings are passed to `rebind`, so its
  blind `?`→`$N` rewrite cannot corrupt literals. Clean — matches the report's conclusion.
- **CI workflows (`main.yml`, `pr.yml`, `test.yml`):** no `pull_request_target`, no secrets,
  no `github.event.*` interpolation into `run:` steps — no script-injection surface.
- **`.air.toml` / `.dockerignore`:** air config is dev-only; the Dockerfile ADDs only
  `internal/ pkg/ cmd/ config/<file> go.mod go.sum`, so stray secret files aren't swept
  into the image by a broad `ADD .`.
- **`OGSCheckEnded`/`FetchOGS` URL string surgery (`strings.Replace` on ".com"/"game"):**
  can only redirect the request *within* `online-go.com` (allow-listed anyway) or produce
  invalid URLs that error out; no cross-host escape found because `ApprovedFetch` gates on
  the parsed hostname before surgery.
- **`loadtest/` and `integration/`:** not compiled into the production binary
  (Dockerfile builds only `cmd/*`); no prod reachability.
