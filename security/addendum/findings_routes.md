# Findings — Routes / HTTP / WebSocket layer (golab-board PR #2)

**Auditor scope:** `pkg/hub/*`, `pkg/room/{room,handlers}.go`, `pkg/event/*`, `pkg/config/config.go`, `pkg/app/app.go`, `cmd/main.go` (+ `internal/fetch`, `internal/twitch`, `pkg/logx`, `pkg/message` read for context).
**Method:** full white-box read + dynamic validation against a locally built server (`go build ./cmd`, run with memory config on :8093) using `curl` and purpose-built Go WebSocket clients (`/tmp/golab/pocs/`).
**Exclusions cross-checked against:** `SECURITY_ASSESSMENT.md` in the PR (C-*, H-*, DR-*, DL-*, AZ-*, GL-*, ID-*, M-*, L-*, CS-*, XSS-*, CJ-1). Only genuinely distinct issues are reported.

---

## N-RT-1 — Plaintext room password broadcast to every room occupant in the `update_settings` echo

- **Severity:** High
- **Location:** `pkg/room/handlers.go:291-333` (`handleUpdateSettings` returns the input event unmodified) + `pkg/room/handlers.go:379-385` (`broadcastAfter` → `r.Broadcast`) wired in the chain at `handlers.go:67-73`.
- **Root cause:** The settings payload the real UI sends (`pkg/frontend/js/modals/settings.js:141-157`, `make_settings()`) always contains `"password": <plaintext>`. `handleUpdateSettings` hashes the password into `r.password` but never removes the plaintext from `evt.Value()`; it returns the **same event object**. The chain's `broadcastAfter` middleware then broadcasts that event — including `"password":"<plaintext>"` — to **every connection in the room**. Any anonymous socket can join and read any room (no auth on connect/read — see excluded ID-1), so a passive listener receives the secret in clear text.
- **Attacker-reachable trigger (verified live, both vectors):**
  1. Attacker opens `ws /socket/b/<room>` (no auth needed) and waits.
  2. The room owner (WS) — or any API client (`POST /api/v1/room/<room>`) — sends the standard settings update:
     `{"event":"update_settings","value":{"buffer":250,"size":19,"password":"hunter2","nickname":"owner","black":"b","white":"w","komi":"6.5"}}`
  3. The attacker receives:
     `{"event":"update_settings","value":{...,"password":"hunter2",...},"userid":"<ownerUUID>",...}` (captured verbatim; PoC below).
- **Impact:** Complete disclosure of the room's only credential to any anonymous occupant, at the exact moment the owner believes they are locking the room down. Worse than AZ-2 (grandfathered sockets) — and **defeats AZ-2's suggested fix**: even if `auth` were cleared on `SetPassword`, the attacker simply re-authenticates with the leaked password (from any device, and can share it). The leak also *repeats*: the stock client stores the received password (`state.js:191`, `set_password()` puts it back into the password bar), so every subsequent settings change by any client re-broadcasts it. It also self-propagates to every connected client's `state.password`.
- **PoC:** `/tmp/golab/pocs/passleak/main.go` (two WS connections; owner sends `update_settings` with `password:"hunter2"`; attacker prints the broadcast). Observed output:
  `[attacker] sees: {"event":"update_settings","value":{"black":"b","buffer":250,"komi":"6.5","nickname":"owner","password":"hunter2","size":19,"white":"w"},...}`
  API vector: `curl -XPOST localhost:8093/api/v1/room/apivect2 -d '{"event":"update_settings","value":{...,"password":"s3cr3t-api",...},"userid":"api-caller"}'` while a WS listener (`/tmp/golab/pocs/wslisten`) idles in `apivect2` → listener receives `"password":"s3cr3t-api"`.
- **Why not a duplicate:** AZ-2 is stale `auth` map entries (same-file but different mechanism: authorization state, not data disclosure; its fix — clearing `auth` — does nothing here). ID-1 covers read-access to board state, not credential disclosure. No exclusion covers event-payload sanitization before broadcast.
- **Suggested fix:** In `handleUpdateSettings`, delete/blank `sMap["password"]` (and rebuild the outbound event) before returning, e.g. return a `NewEvent("update_settings", sanitizedMap)`; never broadcast client-supplied secrets.

## N-RT-2 — WebSocket room identity derived from the raw request-target (query string / absolute-form authority), not the route parameter

- **Severity:** Low
- **Location:** `pkg/hub/hub.go:293-303` (`HandlerWrapper` uses `ws.Request().URL.String()` + `ParseURL`, `hub.go:32-45`) instead of chi's `{boardID}` param.
- **Root cause:** `ParseURL` splits the *full* URL string. `URL.String()` includes the **query string**, and for proxy-style absolute-form request-targets it includes scheme+authority. Chi matched only `/socket/b/{boardID}`, but the handler re-derives the room from the raw string. `core.Sanitize` strips punctuation but keeps alphanumerics, so query/authority text is *folded into* the room id.
- **Attacker-reachable trigger (verified live):**
  - `ws://host/socket/b/alpha?x=1` and `?x=2` create **separate** rooms `alphax1`, `alphax2` (plus `alpha` itself): `/api/stats` showed 3 rooms for one board name.
  - Absolute-form: `curl --request-target "http://attacker.example/socket/b/absform" <upgrade headers>` → HTTP 101 and a new room **`attackerexample`** (authority text!), confirmed via `/b/attackerexample/debug`.
- **Impact:** Room-space multiplication for a single board name (amplifies the unbounded-room-creation issue H-2 beyond distinct names); room-identity confusion — two clients who believe they are on the same board (`/socket/b/x?a` vs `/socket/b/x?b`) are in different rooms; identity can be driven by arbitrary authority/query text, which proxies may forward or log differently than the app.
- **PoC:** commands above; client: `/tmp/golab/pocs/wsclient` (dial with query), curl with `--request-target` for absolute-form.
- **Why not a duplicate:** H-2 is "any new boardID creates a room" (no cap). This is a different root cause — the WS handler *mis-parses its own route* (path vs query vs authority), which H-2's fix (a room cap) would not address: the split/confusion remains.
- **Suggested fix:** Pass chi's `URLParam(r,"boardID")` through to `Handler` (e.g. wrap the `websocket.Handler` per-request) instead of re-parsing `URL.String()`; at minimum, parse with `url.Parse` and use only the path segment.

## N-RT-3 — `POST /api/v1/room/{board}` skips `core.Sanitize` → room-ID divergence from the WS/web identity; orphaned, unjoinable rooms

- **Severity:** Low
- **Location:** `pkg/hub/apiv1router.go:23-25` (`GetOrCreateRoom(board)` directly) vs `pkg/hub/hub.go:308-312` (WS path sanitizes) and `pkg/hub/webrouter.go:124-132` (`/b/{boardID}` 400s on unsanitized ids).
- **Root cause:** The HTTP API path creates rooms under the *raw* URL segment (case-sensitive, special chars kept), while every other entry point maps board names through `core.Sanitize` (lowercase, `[a-z0-9-]` only). One logical board therefore has multiple distinct room objects depending on entry path.
- **Attacker-reachable trigger (verified live):**
  - `curl -XPOST /api/v1/room/MixedCase -d '{"event":"update_nickname","value":"x","userid":"u1"}'` → creates room `MixedCase`.
  - `ws /socket/b/MixedCase` → sanitizes to **`mixedcase`** — a *different*, brand-new room (`/api/stats` increments again).
  - `/b/MixedCase/debug` → `HandleOp` lowercases → reads `mixedcase` (the WS room); the API-created `MixedCase` room (with its own state, incl. planted nicks) is unreachable from web/WS/debug — an orphan consuming memory (and being persisted on `Hub.Save`) until the 24 h idle reaper.
- **Impact:** Shadow/orphan rooms: API automation silently operates on rooms no web user can see (data written via API is invisible in the UI and vice versa); unbounded accumulation of unreachable rooms beyond the intended name space; inconsistent security posture between API and UI (e.g. a password set via API on `MixedCase` does not protect the room web users actually join, `mixedcase`).
- **PoC:** commands above against a live server; observed `{"rooms":5}` → `{"rooms":6}` after the WS join of the "same" name.
- **Why not a duplicate:** C-7 covers unauthenticated state control + uncapped body on `/api/v1`; AZ-1 covers trusting `userid`. Neither covers the missing `Sanitize` on the *room id* — different field, different effect (identity divergence/orphaning), different fix.
- **Suggested fix:** `board = core.Sanitize(chi.URLParam(r, "board"))` at the top of `apiv1router.handler` (reject when the result differs from the input, as `/b/{boardID}` does).

## N-RT-4 — `lastActive` is only refreshed by board-command events → API-/Twitch-driven rooms are reaped (with DB deletion) after 24 h despite continuous activity

- **Severity:** Low
- **Location:** `pkg/hub/hub.go:190-221` (`Heartbeat` → `r.Close()` + `DeleteRoom` + `db.DeleteRoom`); `pkg/room/handlers.go:368-377` (`setTimeAfter`) is only in the `"_"` chain (`handlers.go:77-82`); `pkg/room/room.go:420-446` (`RegisterConnection` does not refresh `lastActive`).
- **Root cause:** Activity tracking assumes all meaningful traffic goes through the default board-command chain. `upload_sgf`, `request_sgf`, `trash`, `update_nickname`, `update_settings`, `graft`, `checkpassword`, `ping` — and therefore **all** `/api/v1`, `/ext/upload`, and Twitch `!branch` traffic — never call `SetLastActive`.
- **Attacker/user-reachable trigger (code inspection; needs 24 h to fire):** drive a room exclusively via `POST /api/v1/room/<id>` (e.g. hourly `graft` sync of an ongoing game) or Twitch `!branch`; at `creation+24h` the heartbeat breaks, closes the room, removes it from the hub and **deletes the persisted row**, even though the room was in active use minutes earlier. Live WS connections to the old room object keep working against an unmapped room (split-brain: next join creates a fresh empty room under the same id).
- **Impact:** Silent loss of an actively-used room and its entire persisted game history; split-brain duplicate rooms after reaping with live connections.
- **PoC:** code inspection (timers too long to fire in a test window): `grep -n setTimeAfter pkg/room/handlers.go` shows it wraps only the `"_"` chain; `Heartbeat` deletes on `now.Sub(GetLastActive()) > timeout`.
- **Why not a duplicate:** M-6 is the opposite defect (heartbeat interval too *long*, abandoned rooms linger). H-2/M-6 do not cover premature reaping of *active* rooms due to incomplete activity tracking.
- **Suggested fix:** Update `lastActive` in `HandleAny`/`RegisterConnection` (or in a middleware applied to every chain), not just in the board-command chain.

## N-RT-5 — Phantom users: `/api/v1` `update_nickname`/`update_settings` plants permanent, unauthenticated entries in the room's `nicks` map, broadcast to all clients

- **Severity:** Low
- **Location:** `pkg/room/handlers.go:274-283` (`handleUpdateNickname` — note: **no** `authorized`/`outsideBuffer` middleware, `handlers.go:63-66`) and `handlers.go:311` (`SetNick` in `handleUpdateSettings`); removal exists only in the WS teardown path `pkg/room/room.go:466-470`.
- **Root cause:** Both handlers key `r.nicks` on the *client-supplied* `userid`. On the WS path the id is the server-generated connection UUID and is deleted when the socket closes; on the unauthenticated `/api/v1` path the attacker picks arbitrary ids that have no connection and are **never** removed (room lifetime ≈ 24 h).
- **Attacker-reachable trigger (verified live):** `curl -XPOST /api/v1/room/apivect2 -d '{"event":"update_settings","value":{...,"nickname":"apiuser"},"userid":"api-caller"}'` → every room client immediately receives `connected_users` containing `"api-caller":"apiuser"`, and it persists for the room's lifetime. Repeat with millions of distinct userids (no auth, no throttle on `update_nickname`).
- **Impact:** (a) permanent spoofed occupants in every room's user list — incl. names like "moderator" — a social-engineering/display-integrity issue; (b) unbounded growth of the `nicks` map from unauthenticated requests, amplifying the O(N²) `connected_users` rebroadcast cost on every join/leave/nick change (compounds M-3); (c) works even on **password-protected** rooms since `update_nickname` has no `authorized` middleware.
- **PoC:** curl above against a live server; observed broadcast `"api-caller":"apiuser"` received by a WS listener.
- **Why not a duplicate:** AZ-1 is authz bypass via replaying *existing* users' UUIDs. M-4 covers the `auth`/`notified` maps, explicitly not `nicks` ("`DeregisterConnection` prunes only `conns`" — for `nicks` there *is* a prune path, but only for WS connections; the API path bypasses it). M-3 is nick length/broadcast cost on the WS path. This finding is the *persistence* of attacker-chosen, connection-less identities in `nicks` — different map, different lifecycle defect.
- **Suggested fix:** Gate `update_nickname` (and the `SetNick` in `handleUpdateSettings`) on `authorized`; on the apiv1 path either reject nickname updates or key them to a server-issued, expiring identity; prune `nicks` entries that have no live connection.

---

## Rejected candidates (investigated, not reported)

- **Static-file traversal** (`/static/{static}` → `http.ServeFileFS`, `/js/*` → `http.FileServer(http.FS(embed))`): blocked — `serveFile` rejects `..` in the decoded path (verified: `/static/..`, `/static/..%2f..%2fgo.mod` → 400 `invalid URL path`); single-segment chi param can't contain `/`; embed FS rejects invalid paths.
- **Open redirect / header injection via `POST /new` and `/ext/upload`:** redirect targets are `core.Sanitize`d ids prefixed with `/b/` (verified `board_id=javascript:alert(1)` → `/b/javascriptalert1`; `..` → random name). No attacker data in any response header anywhere in scope.
- **Twitch subscribe/unsubscribe redirect:** URL built from config only (`cfg.Server.URL`, `ClientID`, uuid state); not attacker-controlled.
- **HTTP method confusion:** chi returns 405 for wrong methods on all probed routes (PUT/GET/DELETE on `/api/v1/room/x`, POST `/api/stats`, DELETE `/b/x`). `/ext/upload` GET side effects = excluded L-1.
- **`board.html` / template injection:** all templates execute with `nil` data (`webrouter.go:90-106`); only `{{template}}` includes; html/template autoescapes anyway.
- **Concurrent writes to one `websocket.Conn`:** all `SendEvent` sites audited (`room.go:357/371/389/443`); `x/net/websocket` `Conn.Write` is serialized by the connection's `wrio` mutex per message, so interleaved frame corruption is not possible. (DL-2 already covers the blocking-write aspect.)
- **`logEventValue` / `logAfter` unchecked assertions** (`handlers.go:470,488`) and `upload_sgf` array `ifc.(string)` (`handlers.go:161`): same root-cause class as excluded M-10 (recovered, per-connection panic on the request path).
- **`SetAuthAll()` runs on *every* `update_settings` (re-grandfathering on later settings changes, not just at set-time):** same line/root cause as excluded AZ-2 (`handlers.go:330`); AZ-2's fix covers it.
- **`checkpassword` echo:** on success the plaintext password is returned only to the submitting connection (`SendTo(evt.User(), evt)`), never broadcast.
- **`isprotected` disclosure:** required by the client flow; trivial.
- **Host-header attacks / cache poisoning:** no Host-derived output (relative redirects; config-based URLs); no caching layer.
- **Soft-404/400:** `page400`/`page404` return HTTP 200 — cosmetic only.
- **chi `StripSlashes` bypass:** strips exactly one *trailing* slash (chi v5.2.2 `middleware/strip.go`); no double-slash routing confusion found; encoded `%2F` stays inside one segment and reaches no file sink.
- **`cmd/main.go`:** no pprof/metrics endpoints; `http.ListenAndServe` without timeouts = excluded M-9; failed-listen leaves an idle process (ops nit, not a vuln); graceful shutdown saves under locks (safe).
- **`config.New` YAML:** local CLI-specified file only; no remote influence. `dbConfig.redact()` no-op = excluded CS-1.
- **`internal/fetch` allowlist matching:** exact `u.Hostname()` map lookup — no suffix/userinfo bypass (redirect-following SSRF = excluded M-2; error broadcast = ID-2/ID-4).
- **`readPacket` short-read on the 4-byte length prefix:** attacker can only desync their *own* connection → disconnect; no cross-client impact (no size cap = excluded H-4).
- **Twitch `Parse`/`Verify` internals:** covered by H-5/M-7/L-12; webhook-path panics would be recovered by net/http.
- **`/api/version`, `/api/ping`:** static strings, no issue.
- **`/api/v1` response `fmt.Fprintf` without Content-Type:** body starts with `{"` → sniffed `text/plain`; injection into the JSON itself = excluded ID-3.
- **Absolute-form request-target on non-WS routes:** chi routes on the path only; params unaffected (WS case reported as N-RT-2).
- **`Hub.Save` holding `h.mu` across DB writes:** reachable only at shutdown; lock-held-during-IO class already covered by DL-1/DL-2.
