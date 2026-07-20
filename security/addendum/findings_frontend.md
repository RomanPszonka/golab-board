# Frontend (browser JS / templates) — NEW security findings

Scope: `pkg/frontend/js/**`, `pkg/frontend/html/**`, `pkg/frontend/embed.go`, plus
`pkg/hub/webrouter.go` / `pkg/app/app.go` / the event-broadcast path only insofar as
server data reaches the browser. Baseline: PR #2 head (`12030bc`). Exclusions honored:
`SECURITY_ASSESSMENT.md` (XSS-1, XSS-1b, XSS-2, XSS-3, CJ-1, M-3, and the
verified-escaped sinks: comments, nicknames, player names/komi, `show_toast`,
letter/number commands, unapproved-host reflection).

**2 new findings.** Every JS file and every HTML template in scope was read in full.

---

## N-FE-1 — Plaintext room password is broadcast to every room connection (incl. unauthenticated observers); clients store and silently replay it → full password-room takeover

**Severity: High** (authorization bypass of the only access-control mechanism the app has; no victim interaction beyond a normal settings change; leak repeats on every settings update)

### Locations
- Server (root cause): `pkg/room/handlers.go:291-341` (`handleUpdateSettings` returns the original event unchanged) → `pkg/room/handlers.go:379-385` (`broadcastAfter` → `r.Broadcast(evt)`) → `pkg/room/room.go:361-373` (`Broadcast` iterates **all** `r.conns`, no auth filter) → `pkg/event/channel.go:49` (plain `json.Marshal(evt)` onto the wire).
- Client (amplification): `pkg/frontend/js/state.js:191` (`this.password = settings["password"]`), `pkg/frontend/js/network_handler.js:241-243` (auto-`checkpassword` of the stored password on `isprotected`), `pkg/frontend/js/network_handler.js:256-258` (stores the echoed password from the `checkpassword` response), `pkg/frontend/js/modals/settings.js:140-158` (`make_settings` re-sends the saved password on *every* settings change).

### Root cause
`handleUpdateSettings` reads the plaintext password out of the client's settings map,
hashes it for storage — but then returns the **original event object** whose
`value` map still contains `"password": "<plaintext>"`. The middleware chain for
`update_settings` ends in `broadcastAfter`, which broadcasts that raw event to every
WebSocket in the room. `Room.Broadcast` does not distinguish authorized editors from
unauthenticated observers (by design, observers watch the game — ID-1). The frame on
the wire is literally:

```json
{"event":"update_settings","value":{"buffer":250,"size":19,"password":"<PLAINTEXT>","nickname":"...","black":"","white":"","komi":""},"userid":"...","eventid":"..."}
```

The client makes it worse: on receiving `update_settings`, every browser stores
`settings["password"]` into `state.password`; on the next connect (or any
`isprotected` challenge) it **automatically** answers `checkpassword` with the leaked
value (`network_handler.js:241-243`). And because `make_settings()` always includes
the saved password, *every subsequent settings change by any authorized user*
(moving the input-buffer slider, setting a nickname, changing komi) re-broadcasts the
plaintext password to everyone then connected.

### Attacker-reachable trigger (unauthenticated, remote)
1. Attacker opens the protected (or about-to-be-protected) board URL as an observer — no password needed (ID-1: reads are unauthenticated).
2. Wait for either (a) the owner to **set** the password, or (b) any authorized user to change **any** setting. Both produce a room-wide `update_settings` broadcast.
3. Read the plaintext password out of the attacker's own WebSocket traffic (or just let the stock client do it: it stores the password and auto-authenticates on the next `isprotected` challenge).
4. Send `{"event":"checkpassword","value":"<leaked>"}` once → `r.SetAuth(user, true)` → full write access (moves, labels, trash, settings, password change → lockout).

### Impact
Complete defeat of the room-password authorization model: any passive observer gains
permanent write access to a "protected" board, and can rotate the password to lock
out the owner. The password is also laid down in the DOM (`#settings-modal-password-bar`
value) and JS state of every observer's browser.

### PoC
`/tmp/golab/pocs/nfe1_password_broadcast.py` (Python + `websockets`; the client
protocol is a 4-byte LE length message followed by the JSON message):

```bash
go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml &   # :8080
python3 /tmp/golab/pocs/nfe1_password_broadcast.py localhost:8080
```

The script connects an **observer** (never authenticates) and an **editor** that sets
`password = s3cr3t-pw-…` via one `update_settings` frame. Expected output:

```
[+] OBSERVER received plaintext password in update_settings broadcast: s3cr3t-pw-…
[+] OBSERVER authenticated with the LEAKED password (checkpassword accepted) -> full write access
```

Minimal manual repro (any WS client):
```
# frame 1 (4-byte LE length, then JSON):
{"event":"update_settings","value":{"buffer":250,"size":19,"password":"hunter2","nickname":"","black":"","white":"","komi":""}}
# every other connection in the room immediately receives the same frame verbatim,
# including "password":"hunter2".
```
(Static-verified against PR head `12030bc`; the Go toolchain is unavailable in this
auditor's container, so the script was not executed here — the broadcast chain
`handlers.go:291→379→room.go:361→channel.go:49` has no branching that could alter the
outcome.)

### Why this is not a duplicate of the exclusions
- **AZ-1** (`/api/v1` trusts client `userid`): different mechanism (forged identity vs. secret disclosure).
- **AZ-2** (enabling a password grandfathers connected sockets): that is the `r.SetAuthAll()` call at `handlers.go:330` — *who is authorized*. N-FE-1 is the *password value itself being disclosed*, which persists, replays, and works for observers who join later.
- **ID-1** (anyone can *read* a protected room): this finding is precisely what turns that read access into *write* access.
- **CS-2** (bcrypt >72-byte truncation): unrelated.
- Nothing in `SECURITY_ASSESSMENT.md` mentions password disclosure to clients.

### Suggested fix
- In `handleUpdateSettings`, scrub the event before returning it: `evt.SetValue(map[string]any{"buffer":…,"size":…,"password":""})` — or broadcast the server-side `Settings` struct (which contains only the hash; better: a boolean "protected" flag).
- Client: never take `password` from a broadcast (`state.js:191`); keep the password strictly client-side and only ever *send* it in `checkpassword`/`update_settings`.
- Longer term: replace the shared-password model with server-issued per-connection tokens (also fixes AZ-1/AZ-2).

---

## N-FE-2 — Stored + broadcast CSS injection into SVG `stroke` via the unvalidated pen (`draw`) color

**Severity: Low** (arbitrary CSS value on one SVG element in every viewer's browser; external-URL fetch/beacon in Firefox; no script execution)

### Locations
- Sink: `pkg/frontend/js/boardgraphics/boardgraphics.js:494` — `path.style.stroke = hexColor` inside `svg_draw_polyline`.
- Live path: `pkg/frontend/js/network_handler.js:224-227` (`draw` event) → `pkg/frontend/js/state.js:550-564` (`draw_pen`) → `boardgraphics.js:878-897` → `:494`.
- Persisted path: server stores the color in the tree as an SGF `PX` field (`pkg/state/commands.go:431-444`), re-emits it in full frames as `marks.pens` (`pkg/state/frame.go:138-156`) → client `state.js:931-944` (`handle_marks` → `draw_pen`) → same sink.

### Root cause
The server decoder for `draw` (`pkg/state/command_decoder.go:153-194`) only type-checks
that element 4 is a string — **any** string is accepted as the pen color, rebroadcast
verbatim, and persisted. The client assigns it directly to an SVG path's `stroke` CSS
property. `update_settings`-style sanitization does not exist anywhere on this path.

### Attacker-reachable trigger (unauthenticated, remote)
- WS frame in an open room (or the unauthenticated `POST /api/v1/room/{id}`):
```json
{"event":"draw","value":[0.1,0.1,0.5,0.5,"url(//attacker.example/beacon.svg#p)"]}
```
- Persisted variant (survives reloads/reconnects via the `PX` SGF field): same frame.
  (`frame.go:141` splits `PX` on `:` and requires exactly 5 parts, so the persisted
  color cannot contain `:` — a protocol-relative `url(//host/…)` works; the live
  broadcast has no such constraint.)

### Impact
- The pen path in **every room viewer's** browser gets
  `style.stroke = "url(//attacker.example/beacon.svg#p)"`. Firefox resolves external
  SVG paint-server references cross-origin → an outbound request disclosing viewer
  IPs/viewer count timing to the attacker (a tracking beacon baked into the shared
  document). Chromium stores the value but does not fetch external paint servers.
  Other values give cosmetic control of one element's stroke (defacement-grade, not script).
- Setting `el.style.stroke` cannot smuggle additional CSS properties (the value is
  parsed as a single property value; `;` invalidates it) and `url()` paint references
  do not execute script, so this is honestly **Low**.

### PoC
`/tmp/golab/pocs/nfe2_pen_css.js` (Node + Playwright, mirrors the repo's
`security/poc/browser/*.js` harness):
```bash
node /tmp/golab/pocs/nfe2_pen_css.js http://localhost:8080
# [+] N-FE-2 pen-color CSS injection: CONFIRMED — path.style.stroke = url(//attacker.example/beacon.svg#p)
```
The script injects the `draw` event via the unauthenticated API, then loads the board
as a fresh victim and reads `svg#pen path.style.stroke` from the DOM — proving the
attacker string survived the server round trip, the SGF persistence, and landed as a
live CSS value. (Static-verified; same container limitation as N-FE-1.)

### Why this is not a duplicate of the exclusions
All four excluded client XSS findings are **HTML-into-`innerHTML`** sinks
(`boardgraphics.js:516`/`:540`, `modals.js:183/211/219`, Twitch challenge echo). This is
a different sink class (CSSOM property assignment), a different attacker-controlled
field (pen color, never mentioned in the report — the report's pen discussion is only
about coordinates in M-10/L-classes), and a different impact (external-reference
injection/viewer tracking rather than script execution).

### Suggested fix
- Validate the color server-side in `NewDrawCommand`/`DecodeToCommand`: accept only
  `^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$` (the stock client only ever sends `#rrggbb`
  from `<input type="color">`).
- Defense in depth client-side: in `draw_pen`, fall back to the default pen color
  unless `/^#[0-9a-fA-F]{6,8}$/.test(pen_color)`.

---

## Rejected candidates (investigated, not reported)

- **`show_toast` innerHTML (`modals.js:109`)** — reachable only from the `global` event, which originates from the operator-only DB `messages` table (`pkg/hub/hub.go:223-271`, `pkg/loader/dbloader.go:350-377`); no client-controllable route inserts messages. Matches the exclusion's verified-safe note.
- **`update_users_modal` / nickname rendering (`modals.js:227-237`)** — uses the `textContent`→`innerHTML` copy idiom; properly escaped (exclusion verified-safe).
- **`update_gameinfo_modal` (`modals.js:239-250`) and `set_gameinfo` fields (PB/PW/BR/WR/RE/KM/DT/RU)** — all rendered via `textContent` copy idiom or `htmlencode()`; `komi` goes through `parseFloat` (number coercion) before `innerHTML`. Escaped (PB/PW/KM are explicitly excluded; RE/DT/RU share the same escaped sink).
- **Tree explorer `text.innerHTML` (`treegraphics.js:834`)** — value is always `node.coord.x.toString()`, a client-computed integer; no attacker string reaches it.
- **`set_password` stars (`modals/settings.js:42,133`)** — writes only `"*".repeat(len)`; the plaintext is assigned to `password_bar.value` (DOM property, no parsing) and shown via `textContent` (`:802`).
- **`common.js:90` `new_text_button` innerHTML** — all call sites pass static literals ("Set"/"Cancel"/"Remove"/"Show").
- **Bootstrap tooltips with `data-bs-html="true"` (`common.js:105-117`)** — every `add_tooltip` call uses a static string; `edit_tooltip` has no callers; Bootstrap 5.3's default sanitizer also strips event handlers.
- **Client `update_buffer` event → missing `state.update_buffer` method** — server never emits this event (no such command server-side; only the client sends it), and if forged it is a per-message TypeError only (WS stays up). Robustness nit, not security.
- **Frame `tree.up`/graft handling (`state.js:853-869`)** — a forged/missing `up` node yields a caught-by-nothing `TypeError` for that one frame; WS and subsequent frames unaffected. Client robustness; the server-side graft auth issue is H-6.
- **`update_settings` client handling of a huge `size`** — client-side cost is dominated by the server-side C-5 memory-exhaustion finding (the broadcast only exists if the server survives); not a distinct issue.
- **`draw` coordinate values (Infinity/NaN/huge floats)** — produce degenerate SVG path data only; cosmetic.
- **HTML templates (`board.html`, `index.html`, `header.html`, `test.html`, etc.)** — rendered with `nil` data everywhere (`renderSinglePage`/`includeCommon` in `webrouter.go`); zero `{{.}}` interpolations exist, so no template/JS-string injection is possible. Board ID reaches JS only via `window.location` (same-origin path).
- **`newBoard` redirect (`webrouter.go:136-145`)** — always redirects to a relative `/b/{sanitized}` path; `core.Sanitize` strips non-alphanumerics; no open redirect / header injection.
- **`state.download()` / `get_sgf_link()` / gameinfo share-input** — built from `window.location.href` (same-origin), written to `href` of a programmatically-clicked `<a download>` or a disabled input; no `javascript:` URL vector.
- **postMessage / eval / document.write / outerHTML / insertAdjacentHTML / cookie sinks** — none exist in the frontend (grepped).
- **DOM clobbering / prototype pollution via frames** — node indices are server-generated integers; `nodes["__proto__"] = node` is not reachable because keys come from `map[int]`-style server serialization; `connected_users`/`marks` keys are server IDs/coords.
- **OGS / Twitch plugin-originated data** — both flow into the room as frames/fields/comments that hit the already-assessed sinks (labels → XSS-1 excluded; comments/fields escaped; OGS error strings → XSS-2/ID-2 excluded).
