# Security Addendum — golab/board: NEW findings beyond PR #2

**Target:** `golab-board` at PR #2 head (`12030bc`), the same tree assessed by [`SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md).
**Relationship to prior work:** PR #2 documents 69 findings (C-*, H-*, DR-*, DL-*, AZ-*, GL-*, CS-*, ID-*, M-*, L-*, XSS-*, CJ-1) plus explicit "not exploitable" and "reviewed clean" lists. **Every finding in this addendum was cross-checked against that catalog and is a distinct root cause, sink, or exposure — none are re-statements of the existing items.** Where a finding is adjacent to an excluded item, the exact delta is spelled out in a "Why not a duplicate" paragraph.
**Method:** four parallel white-box audits (frontend JS/templates; Go HTTP/WS routes & handlers; parsers/state/tree/board core; integrations/persistence/deployment/extensions) followed by independent dynamic re-verification. **Every High and Medium code finding was reproduced** — either end-to-end against a live server (WebSocket / `POST /api/v1` / GET vectors) or in Go tests driving the real handler/parser chain (N-13/N-14 are deployment-config items verified by inspection). Live protocol: 4-byte little-endian length prefix + JSON frame.
**Assessment date:** 2026-07-21. **PoCs:** [`security/addendum/_pocs/`](security/addendum/_pocs/) (runnable; see [`security/addendum/_pocs/README.md`](security/addendum/_pocs/README.md)).

---

## 1. Executive summary

The prior assessment rated the room **password** as the app's one working access-control mechanism and documented several ways it fails (AZ-1/AZ-2/CS-2/ID-1). This review finds the password is **simply broadcast, in plaintext, to every connected client** (N-1) — no replay, forgery, or timing required; any passive observer of a room receives the secret the moment anyone changes any setting.

Three other themes emerge:

- **The "trusted" third-party integrations mishandle attacker-influenced metadata.** OGS game metadata is spliced into SGF with `fmt.Sprintf` and no escaping (N-2) — a genuine injection defect. However, independent re-verification (§7) shows the end-to-end attack is **currently blocked by N-4**: the only production path to the vulnerable `gameInfoToSGF` runs through the OGS socket frame parser (N-4), whose JSON-blind bracket counter truncates any game name containing `]` — which every SGF-injection payload requires — before it is ever parsed. So N-2 is a **latent** defect (downgraded to Low), exploitable only if N-4 is fixed without also escaping the interpolated strings. N-4 itself is real: one bracket in a game name permanently stalls the connector with slow unbounded memory growth (Medium).
- **The fetch path defeats the upload caps.** PR #2's 1 MiB cap exists only in the `upload_sgf` string branch; `request_sgf`/`/ext/upload` download from allow-listed hosts with **no response-size cap at all**, and two allow-listed hosts (`raw.githubusercontent.com`, `cdn.discordapp.com`) serve attacker-controlled bytes — an unauthenticated fatal stack overflow/OOM with no redirect or SSRF needed (N-3).
- **New poison-pills and panic sinks in the core.** Five parser/state defects the C-2/M-10/L-13 sweep missed: an NGF move byte becomes an SGF property **key** and silently destroys the room on restart (N-6); a `PX[NaN:…]` pen makes every frame JSON-unmarshalable and freezes the room persistently (N-8); off-board coordinates decode to nil-without-error and panic 9 command types (N-5); `IX` index collisions + `cut` + `graft` nil-deref (N-7); `graft` with off-board letters on 9×9/13×13 hits the unguarded `Board.Set` (N-9); plus two decoder assertion/length sinks (N-10, N-11).

Deployment review adds unauthenticated Loki (N-13), a host-published Postgres with default creds (N-14), an authorization asymmetry in Twitch chat commands (N-12), and dependency/toolchain advisories (N-20).

**Totals (after independent re-verification, §7): 21 new findings — 2 High, 10 Medium, 9 Low.** (As originally filed: 3 High / 10 Medium / 8 Low; on re-verification **N-2 was downgraded High→Low** for lack of end-to-end reachability. N-10/N-11 stay Medium per the project's "recovered request-path panic = Medium" rubric, but are flagged as M-10-class instances a stricter triage could fold in.) Every finding's root cause was independently reproduced (live server or Go test) or confirmed by code/config inspection in this review; §7 records the per-finding results and the reachability/severity corrections. Status is marked per finding.

## 2. Master table

**Status:** `live` = reproduced end-to-end against a running server · `test` = reproduced in Go tests driving the real code (×2 = two independent PoCs) · `insp.` = code/config inspection. All `live`/`test` items were re-verified by the lead reviewer in a second environment (see §6).

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| N-1 | High | Go/WS | Plaintext room password broadcast to every room connection (incl. unauthenticated observers) → full room takeover | live |
| N-2 | ~~High†~~ **Low** | Go/OGS | Unescaped OGS game metadata is spliced into SGF (`fmt.Sprintf`, no escaping) — a real interpolation defect, but **latent**: the injection is blocked end-to-end by N-4's frame parser (any `]` truncates the frame first). Both PoCs bypass that path. **Downgraded on independent re-verification (§7).** | test (isolated only) |
| N-3 | High | Go/fetch | `request_sgf`/`/ext/upload` download has no response-size cap; allow-listed hosts serve attacker bytes → fatal stack overflow / OOM | test |
| N-4 | Medium | Go/OGS | OGS frame parser counts `[`/`]` inside JSON strings → permanent connector stall + unbounded buffer growth | test (×2) |
| N-5 | Medium | Go/core | Off-board coordinates decode to nil `*Coord` with nil error → nil-deref panic in 9 command types | test |
| N-6 | Medium ⚑ | Go/parser | NGF parser emits raw move byte as SGF property **key** → persisted SGFIX unparseable → room destroyed on restart | test |
| N-7 | Medium | Go/state | Uploaded `IX` index collision + `cut` + `graft` → `s.nodes[i]` nil-deref | test |
| N-8 | Medium ⚑ | Go/state | `PX[NaN:…]`/`+Inf` passes the pen guard → `json.Marshal` fails on every frame → room silently frozen; persists across restart | test |
| N-9 | Medium | Go/core | `graft` with off-board letter on 9×9/13×13 → unguarded `Board.Set` index-OOB panic | test |
| N-10 | Medium | Go/decoder | `draw` command indexes `vals[0..4]` with no length check → index-OOB panic (recovered per-connection — **M-10 class**; a stricter triage would fold it into M-10, §7) | live |
| N-11 | Medium | Go/handler | `upload_sgf` array branch `ifc.(string)` without comma-ok → conversion panic (recovered per-connection — **M-10 class**; §7) | live |
| N-12 | Low | Go/Twitch | `!branch` lacks the `broadcaster == chatter` check that `!setboard` has → any chat viewer grafts onto a streamer's room | test |
| N-13 | Medium | Deploy | Loki `auth_enabled: false` + port 3100 published on 0.0.0.0 | insp. |
| N-14 | Medium | Deploy | docker-compose publishes Postgres `5432:5432` host-wide with committed default creds | insp. |
| N-15 | Low | Web/Go | Pen (`draw`) color unvalidated → stored+broadcast CSS injection into SVG `stroke` (external-ref fetch in Firefox) | live (server half) |
| N-16 | Low | Go/WS | WS room identity derived from raw request-target (query string / absolute-form authority), not the route param | live |
| N-17 | Low | Go/api | `POST /api/v1/room/{board}` skips `core.Sanitize` → room-ID divergence, orphaned unjoinable rooms | live |
| N-18 | Low | Go/hub | `lastActive` refreshed only by the `"_"` command chain → API-/Twitch-driven rooms reaped + DB-deleted at 24 h despite activity | insp. |
| N-19 | Low | Go/api | Phantom users: unauthenticated `/api/v1` nickname updates plant permanent entries in `r.nicks`, broadcast room-wide | live |
| N-20 | Low | Deps | chi v5.2.2→v5.2.4 security fix pending; Dockerfile pins unpatched `golang:1.24.0-alpine` (27 reachable stdlib advisories) | insp. (govulncheck) |
| N-21 | Low | Go/fetch | `golab.gg` on its own fetch allow-list → one GET fans out to K rooms + K nested self-fetches | insp. |

⚑ = persists across restarts.

---

## 3. High findings

### N-1 — Plaintext room password is broadcast to every room connection (incl. unauthenticated observers) → full password-room takeover

- **Severity:** High · **Status:** reproduced **live** (routes audit + lead verification, two environments; independently identified by the frontend audit from static analysis)
- **Location:** `pkg/room/handlers.go:291-333` (`handleUpdateSettings` returns the input event unmodified) → `broadcastAfter` (`handlers.go:379-385`) → `Room.Broadcast` (`pkg/room/room.go:361-373`, no auth filter) → `json.Marshal` onto every socket (`pkg/event/channel.go:49`). Client amplification: `pkg/frontend/js/state.js:191`, `network_handler.js:241-243,256-258`, `modals/settings.js:140-158`.
- **Root cause:** The stock client's `make_settings()` always includes `"password": <plaintext>` in the `update_settings` payload. The handler hashes it into `r.password` but never scrubs the event's value map; it returns the **same event object**, which the chain's `broadcastAfter` then broadcasts to **every connection in the room** — and rooms accept anonymous read connections by design (ID-1). The client worsens it: every browser stores the received password (`state.js:191`), auto-answers `checkpassword` with it on `isprotected`, and re-sends it on every later settings change — so the leak **repeats and self-propagates** (move the buffer slider → the password is re-broadcast to everyone).
- **Trigger (unauthenticated):** open `ws /socket/b/<room>` as an observer and wait for anyone to set/change any setting; read `"password"` out of your own WS traffic; `{"event":"checkpassword","value":"<leaked>"}` → full write access (and password rotation → owner lockout).
- **Captured live (this review):** observer received verbatim
  `{"event":"update_settings","value":{"black":"","buffer":300,"komi":"","nickname":"owner","password":"Sup3rSecretPW!","size":19,"white":""},"userid":"<ownerUUID>",...}`
  — the observer never authenticated. Also reproducible via the unauthenticated `POST /api/v1/room/{id}` vector (any API caller's settings update is broadcast with the plaintext password).
- **Impact:** complete defeat of the room-password model — notably it **defeats AZ-2's proposed fix**: even if `auth` were cleared when the password is set, the attacker simply re-authenticates with the leaked secret, from anywhere, and can share it.
- **Why not a duplicate:** AZ-1 = forged `userid`; AZ-2 = stale `auth` entries; ID-1 = read access by design; CS-2 = bcrypt length. None discloses the password **value** to other clients; no excluded item covers event-payload sanitization before broadcast.
- **PoC:** `security/addendum/_pocs/poc_password_broadcast.go` (two WS connections; observer prints the leaked password from the broadcast).
- **Fix:** scrub before returning — e.g. `sMap["password"]=""` and rebuild the outbound event (or broadcast the server-side `Settings`, which holds only the hash/boolean); never broadcast client-supplied secrets. Client: never read `password` from broadcasts; keep it strictly outbound-only.

### N-2 — Unescaped OGS game metadata spliced into SGF (latent injection — **currently blocked by N-4**)

> **Downgraded to Low on independent re-verification (§7).** The interpolation defect is real, but the claimed unauthenticated High/Critical end-to-end injection **does not hold in the current code**: the only production path to `gameInfoToSGF` is gated by N-4's frame parser, which truncates any injection payload before it is parsed. Both PoCs bypass that gate by calling `gamedataToSGF` directly, so they demonstrate the isolated conversion defect, not end-to-end reachability.

- **Severity:** ~~High (Critical when OGS active)~~ **Low** (latent / defense-in-depth; would be unmasked by an N-4 fix that does not also escape the interpolated strings) · **Status:** the *isolated* conversion defect is reproduced in Go tests; the *end-to-end* path is **refuted** (see "Reachability" below).
- **Location:** `pkg/room/plugin/ogs.go:402-404` (`gameInfoToSGF`); fan-out at `ogs.go:292-294` (`loop` → `Room.UploadSGF`), all inside `go o.loop(...)` (`ogs.go:198`).
- **Root cause (real):** OGS-supplied strings (`game_name`, usernames, rules) are spliced into an SGF document with `fmt.Sprintf("...GN[%s]", ...)` and **no escaping/validation**. In isolation, a `]` byte breaks out of the `GN` property and injects arbitrary SGF properties (e.g. an empty `TR[]` = the C-2b sink, or an `LB[aa:<payload>]` label).
- **Reachability — blocked by N-4 (the decisive correction):** `gameInfoToSGF` is reached in production **only** via the `game/<id>/gamedata` socket frame (`ogs.go:292`), which first passes through `readFrameFromChan` (`ogs.go:141-172`) — the JSON-blind bracket counter that **is N-4**. Every SGF-injection payload must contain `]` (to close `GN[`); at a scalar `game_name` value the parser is at bracket depth 1, so the first `]` drives depth to 0 and returns a **truncated** frame, `json.Unmarshal` then fails, and `loop` does `continue` (`ogs.go:260-263`) — the malicious name never reaches `gameInfoToSGF`. **N-2 and N-4 are mutually exclusive on the same data path.** A `[`-only name triggers N-4's other mode (permanent stall) instead. Verified this review by feeding a full `gamedata` frame through the real `readFrameFromChan` (PoC `security/addendum/_pocs/n2_reach_blocked_test.go`, `TestN2ReachabilityBlockedByN4`): benign `GN[MyGame]` → 250 B frame delivered → converts normally; `game_name="x]TR["` → frame **truncated to 37 B** → unmarshal fails → `gamedataToSGF` **never called**; same for `x]LB[aa:PWNED]ZZ[`.
- **Why the PoCs don't establish reachability:** both `ogs_sgf_injection_test.go` (`TestZZOGSSGFInjection`) and `n_in_ogs_poc_test.go` (`TestNINSGFInjection`) call `o.gamedataToSGF(payload)` **directly** on a hand-built map, bypassing `readFrameFromChan`/`json.Unmarshal`. They validate only the isolated conversion + the C-2b/XSS sink, not the socket→frame→convert path.
- **Residual value (why it's still worth fixing):** it is a genuine latent injection that would become live if N-4's byte counter is replaced with a `json.Decoder` (the N-4 fix) **without** also escaping the OGS strings — so the two must be fixed together. The impact it would then borrow is C-2b (empty-`TR[]` nil-deref, unrecovered in the OGS goroutine) and XSS-1 (`LB` label). Note the crash variant would be in-memory only (`Hub.Save` runs only at graceful shutdown), and delivery needs live egress to `online-go.com` plus (for `game` type) an ongoing game.
- **Overlap with the prior catalog:** heavy — H-9 already flags these same functions (`ogs.go:358-437`) as an untrusted-input parser feeding the unrecovered goroutine, and its recommended `recover()` wrap contains this crash class too; the sinks are C-2b and XSS-1 verbatim. The genuinely new element is only the *interpolation root cause* (unescaped third-party metadata at SGF-construction time) and its blocked delivery.
- **PoC:** `security/addendum/_pocs/ogs_sgf_injection_test.go`, `security/addendum/_pocs/n_in_ogs_poc_test.go` (`go test [-tags poc] -run TestNINSGFInjection -v ./pkg/room/plugin/`) — **isolated conversion only** (do not establish end-to-end reachability; see above).
- **Fix:** SGF-escape all interpolated OGS strings (`[ ] ( ) ; \`) in `gameInfoToSGF`/`initStateToSGF` — do this **together with** the N-4 fix so replacing the frame parser doesn't unmask the injection; wrap `o.loop` in `recover()` (also downgrades C-1/H-9); validate marks in `FromSGF` per the C-2 fix.

### N-3 — `request_sgf` fetch path: M-2's uncapped download is directly weaponizable via allow-listed attacker-content hosts → unauthenticated fatal stack overflow / OOM

- **Severity:** High (escalation of M-2 from conditional Medium to reliable High) · **Status:** reproduced in Go test (fatal crash observed)
- **Location:** `internal/fetch/fetch.go:99-112` (`Fetch`: bare `io.ReadAll`), `:125-137` (`ApprovedFetch`); no compensating check in `pkg/room/handlers.go:248-254` (`handleRequestSGF` → `Room.UploadSGF`).
- **Root cause:** The 1 MiB cap exists only in `handleUploadSGF`'s string branch (`handlers.go:137`). The `request_sgf` path downloads server-side with **no `LimitReader`, no `MaxBytesReader`, no client timeout**, and hands the entire body to `state.FromSGF`. The hostname allow-list is not a content control: **`raw.githubusercontent.com` (any public repo file) and `cdn.discordapp.com` (any uploaded attachment) serve fully attacker-controlled bytes** — no redirect, open-redirect, or SSRF required.
- **Trigger (unauthenticated):** `{"event":"request_sgf","value":"https://raw.githubusercontent.com/<attacker>/<repo>/main/bomb.sgf"}` where `bomb.sgf` is ~12 MB of `(` → `parseBranch` recursion → **fatal stack overflow**; or a multi-GB body → OOM. Also via plain GET `/ext/upload?url=…` — an `<img src>` CSRF beacon on any web page crashes the server when viewed. The attacker's own request is a few hundred bytes, so reverse-proxy request-body caps are irrelevant — the volume is on the server-side **download**.
- **Reproduced:** real `ApprovedFetch` + real `handleRequestSGF` chain with a stub allow-listed host: `ApprovedFetch returned 12000000 bytes with NO size cap` → child process died `fatal error: stack overflow` inside `handleRequestSGF`.
- **Why not a duplicate (escalation, honestly framed):** M-2 *does* state the missing size cap ("`io.ReadAll`s the body (no size cap)", fix: "`io.LimitReader`") — the root cause is not new. What M-2 did **not** establish is reachability and impact: it rates the item **Medium / "Cond."** precisely because "reachability needs an open-redirect on an approved host (or the `OGSCheckEnded`/`FetchOGS` direct-`Fetch` paths)". This finding removes that precondition — two allow-listed hosts (`raw.githubusercontent.com`, `cdn.discordapp.com`) serve arbitrary attacker content **directly**, no redirect or SSRF involved — and demonstrates the outcome is a reliable unauthenticated **fatal** crash (stack overflow) or OOM, not a conditional SSRF. It is reported as a distinct High because the escalation changes the severity and the required fix priority (M-2's `io.LimitReader` fix closes it), and because neither C-3's nor C-7's fixes touch this delivery.
- **PoC:** `security/addendum/_pocs/n_in_requestsgf_poc_test.go` (`go test -tags poc -run TestNINRequestSGFNoCap -v ./pkg/room/`).
- **Fix:** `io.ReadAll(io.LimitReader(resp.Body, 1<<20))` + truncation error in `Fetch`; sane `http.Client{Timeout}`; mirror the 1 MiB check in `handleRequestSGF`; same cap in `FetchOGS`/`OGSCheckEnded`.

---

## 4. Medium findings

### N-4 — OGS frame parser counts `[`/`]` inside JSON strings → permanent connector stall + unbounded buffer growth

- **Severity:** Medium · **Status:** reproduced in Go tests (both failure modes, ×2 PoCs)
- **Location:** `pkg/room/plugin/ogs.go:141-172` (`readFrameFromChan`), called from `loop` (`ogs.go:244`).
- **Root cause:** a hand-rolled framing parser counts raw `[`/`]` bytes with no notion of JSON quoted strings. OGS frames carry attacker-influenced strings (game names, usernames, chat). Two modes: **`[` in a string** → depth never returns to 0 → the frame never ends → the goroutine stays inside `readFrameFromChan` forever, appending every subsequent byte (move/gamedata pushes keep arriving via the ping-kept-alive socket) — **unbounded memory growth** + silent integration death (the `winner` game-over frame is never seen, and `End()`/`DeregisterPlugin` can't unwind it because `o.Exit` is only checked between frames). **`]` in a string** → early termination → next call fails `invalid starting byte` → `loop()` breaks → connector dies.
- **Trigger:** OGS game name containing a bracket; any room attaches via unauthenticated `request_sgf`.
- **Reproduced:** with `game_name:"evil[["` in the stream, `readFrameFromChan` never returned (2 s timeout; buffer keeps growing); with `"]"` in a string, the frame was cut short and the remainder failed to parse.
- **Why not a duplicate:** H-9 = type-assertion panics; H-8/GL-2 = socket/channel blocking; C-1 = `Board.Set`. Distinct root cause (string-blind framing) and effects (mis-framing, stall, retention).
- **PoC:** `security/addendum/_pocs/ogs_frame_parser_stall_test.go`, `security/addendum/_pocs/n_in_ogs_poc_test.go` (`TestNINFrameParserBracketsInStrings`).
- **Fix:** replace the byte counter with `encoding/json` `json.Decoder` over the socket stream (or track in-string/escape state).

### N-5 — Off-board coordinates decode to nil `*Coord` **without error** → nil-deref panic in 9 command types

- **Severity:** Medium · **Status:** reproduced in Go test
- **Location:** `pkg/core/coord/coord.go:254` (`FromInterface` returns `NewCoord(x,y), nil` — `NewCoord` is nil for coords outside `[0,18]`); panic sites: `pkg/state/commands.go` `add_stone` (:37), `remove_stone` (:116), `triangle` (:147), `square` (:166), `letter` (:186), `number` (:208), `label` (:230), `goto_coord` (:404), `markdead` (:615).
- **Root cause:** two missing guards compose — `FromInterface` doesn't map a nil `NewCoord` result to an error (so every decoder check passes), and the command `Execute` methods deref `cmd.crd` with no nil check (`remove_mark` is accidentally safe via nil-tolerant `ToLetters`).
- **Trigger (unauthenticated):** `{"event":"triangle","value":[50,50]}`, `{"event":"goto_coord","value":[-1,-1]}`, `{"event":"markdead","value":[100,100]}`, `{"event":"add_stone","value":{"coords":[25,3],"color":1}}`, `{"event":"label","value":{"coords":[50,50],"label":"x"}}` — WS or `/api/v1`.
- **Reproduced:** `FromInterface([50,50]) = <nil>, err=<nil>`; `triangle [50,50]` → `runtime error: invalid memory address or nil pointer dereference` (connection dropped; server alive).
- **Why not a duplicate:** M-10's `coord.FromInterface` item is the `v.(float64)` **assertion** at coord.go:249 (non-numeric input). This is a different root cause and sink: *numeric, well-formed* input passes the assertion, yields nil-with-nil-error, and panics later inside `commands.go`. Comma-ok on line 249 (M-10's fix) does not fix this.
- **PoC:** `security/addendum/_pocs/core_top3_verify_test.go` (`TestNilCoord`), `security/addendum/_pocs/nilcoord2_test.go`, `security/addendum/_pocs/poc_test.go`.
- **Fix:** error from `FromInterface` when `NewCoord` returns nil; nil-check `cmd.crd` in each `Execute`.

### N-6 — NGF parser emits attacker-controlled SGF property KEYS → persisted SGFIX unparseable → room destroyed on restart ⚑

- **Severity:** Medium (persistent data destruction; M-11-class impact, different root cause) · **Status:** reproduced in Go test
- **Location:** `pkg/core/parser/ngfparser.go:60` (`key := fmt.Sprintf("%c", line[4])`) and `:219` (`node.AddField(move.key, move.coord)`); verbatim serialization at `pkg/state/state.go:142`; silent drop at `pkg/hub/hub.go:171-174`.
- **Root cause:** an NGF move line's byte 4 is copied **unchanged** into an SGF property key — no check that it is `B`/`W` or even a letter. `FromSGF` accepts the node, `UploadSGF` commits it, `ToSGFIX` writes the raw byte as a key, and the persisted file no longer parses; on restart `Hub.Load` logs and **skips the room — its entire history is destroyed**.
- **Trigger (unauthenticated):** upload a crafted NGF via `upload_sgf` (NGF is auto-detected), e.g. base64 `TXkgR2FtZQoxOQp3aGl0ZXBsYXllciAxZApibGFja3BsYXllciAyZAp3YmFkdWsKMAowCjYKMjAyNi0wMS0wMQpwCmJsYWNrIHJlc2lnbgoxClBNICBbYWEgIA==`.
- **Reproduced:** upload succeeds; persisted SGFIX = `(;BR[2d]DT[2026-01-01]GN[My Game]KM[6.5]PB[blackplayer]PC[wbaduk]PW[whiteplayer]RE[B+R]SZ[19]WR[1d]IX[0];[[tt]IX[1])` — note the `[[` key; reload fails `couldn't detect filetype` → room dropped. Works with key bytes `[`, `]`, `(`, `)`, `;`, `\`, digits (letter keys reload fine).
- **Why not a duplicate:** M-5 = value escaping (file still loads); C-2/C-2b = mark-value poison (panic on load); M-11 = size>19. This is a property-**name** injection with a reload-parse-failure sink. The exclusions' GIB/NGF note covers only the coordinate panic and text escaping.
- **PoC:** `security/addendum/_pocs/core_top3_verify_test.go` (`TestNGFKeyPoison`), `security/addendum/_pocs/ngf_test.go`, `security/addendum/_pocs/ngf_room_test.go`.
- **Fix:** accept only `B`/`W` move keys in `parseMove` (else skip); validate keys (uppercase letters) in `toSGF`/`ToSGFIX` and at `FromSGF`.

### N-7 — `IX` index collision + `cut` → tree/map inconsistency → nil-deref in `graft`

- **Severity:** Medium · **Status:** reproduced in Go test
- **Location:** `pkg/state/state.go:217-225` (uploaded `IX` trusted as node indices, no uniqueness check); `pkg/state/edit.go:383-385` (`cut` deletes `s.nodes[n.Index]` for every branch node); panic at `pkg/state/commands.go:554` (`col := s.nodes[parentIndex].Color`).
- **Root cause:** the SGFIX `IX` property is attacker-controlled; two nodes can share an index and `s.nodes` keeps only the last. `cut()` on one deletes the **shared** map key, leaving a tree node whose `Index` has no map entry; a later `graft <moveNumber> <coord>` resolves that node via `TrunkNum` (tree walk) and dereferences the missing map entry.
- **Trigger (unauthenticated, 3 requests):** upload `(;SZ[19]GM[1]IX[0](;C[a]IX[3])(;C[b]IX[3]))`; `right`, `cut`; then `{"event":"graft","value":"1 d4"}` → nil deref.
- **Why not a duplicate:** no exclusion covers the `IX` namespace, `cut`'s map deletion, or this deref (M-10 = other single-request sinks; L-13 = `Down[PreferredChild]`).
- **PoC:** `security/addendum/_pocs/ngf_room_test.go` (`TestIXCutGraft`).
- **Fix:** re-index nodes on load (ignore uploaded `IX`) or reject duplicate/out-of-range `IX`; tolerate missing map entries in `commands.go:554`/`smartGraft`.

### N-8 — `PX[NaN:…]` / `PX[+Inf:…]` passes the pen guard → `json.Marshal` fails on every frame → room silently frozen; persists across restart ⚑

- **Severity:** Medium (persistent room-wide silent DoS, no crash) · **Status:** reproduced in Go test
- **Location:** `pkg/state/frame.go:141-153` (`strconv.ParseFloat` accepts `NaN`/`±Inf`); marshal failure at `pkg/event/channel.go:49`; errors swallowed at `pkg/room/room.go:361-373,443` (`//nolint:errcheck`) and `pkg/hub/apiv1router.go:49` (the swallowed `json.Marshal(evt)`; `:46` is the error-branch `fmt.Sprintf`).
- **Root cause:** the PX validator checks field count and parse errors, but `ParseFloat("NaN")/("Inf")` **succeed**. A `Pen` with a non-JSON-representable float makes **every** frame marshaled while the current node carries it fail — and every send path discards the error, so broadcasts (and the join-time initial frame) silently vanish.
- **Trigger (unauthenticated):** upload `(;GM[1]FF[4]SZ[19]PB[B]PW[W]PX[NaN:0:0:0:red];B[pd])` → `/api/v1` returns the malformed `{"success": true, "output": }`; joins/moves/navigation then produce no frames for anyone.
- **Reproduced:** `json.Marshal(frame)` → `json: unsupported value: NaN`; after `ToSGFIX`→`FromSGF` round-trip the poison is live again (**survives restart**). No log line is emitted anywhere.
- **Why not a duplicate:** C-2 notes the PX branch as "correctly guards" — the NaN/Inf case was not considered. New sink (JSON serialization failure) with a new, silent availability impact.
- **PoC:** `security/addendum/_pocs/core_top3_verify_test.go` (`TestNaNPen`), `security/addendum/_pocs/nan_test.go`, `security/addendum/_pocs/nan_persist_test.go`.
- **Fix:** reject non-finite floats in the PX branch (`math.IsNaN`/`IsInf`) and at `FromSGF`; log (don't drop) `SendEvent`/marshal errors.

### N-9 — `graft` with an off-board letter on a 9×9/13×13 board → unguarded `Board.Set` index-OOB panic

- **Severity:** Medium · **Status:** reproduced in Go test
- **Location:** `pkg/core/coord/coord.go:273-299` (`FromAlphanumeric`: row number checked against `size`, letter capped at a fixed `'t'` — correct for 19×19 only); panic via `commands.go:577` → `edit.go:277` (`smartGraft` → `s.board.Move`) → `board.go:248` (`Legal` calls unguarded `Set` after the guarded `Get` returns `Empty`).
- **Trigger (unauthenticated):** upload `(;GM[1]FF[4]SZ[9]PB[B]PW[W])`, then `{"event":"graft","value":"t1"}` (per H-6 graft needs no authorization).
- **Reproduced:** `index out of range [18] with length 9` (and `length 13`); clean on 19×19.
- **Why not a duplicate:** the "command-path mark bounds" note covers mark commands, which *do* check `x >= s.size`; the graft path uses `FromAlphanumeric`, which nobody checks against board size. New request-path delivery of the C-1 unguarded-`Set` defect at a new site (`edit.go:277`).
- **PoC:** `security/addendum/_pocs/graft_test.go` (`TestGraftOffBoardLetter`).
- **Fix:** reject letters mapping to `x >= size` in `FromAlphanumeric`; guard `Board.Set`/`Legal` per C-1's fix.

### N-10 — `draw` command indexes `vals[0..4]` with no length check → index-OOB panic

- **Severity:** Medium (per the project rubric "request-path panic recovered by `net/http` = Medium"). Impact is **per-connection**: the panic runs synchronously in the request/WS goroutine and `net/http` recovers it — attacker self-teardown + a logged stack trace, no shared/prod impact (verified live, server stayed up). This is the **M-10 class**; a stricter triage would fold it into M-10 rather than count it as a separate Medium. · **Status:** reproduced **live** (`http: panic serving ... index out of range [2] with length 2` at `command_decoder.go:179`)
- **Location:** `pkg/state/command_decoder.go:153-194`.
- **Trigger (unauthenticated, open room):** `{"event":"draw","value":[]}` / `[1.0]` / `[1.0,2.0]` — WS or `/api/v1`.
- **Why not a duplicate:** an **additional instance of the already-catalogued M-10 class** (unchecked-input request-path panics, recovered per-connection) at an unlisted line — M-10 enumerates only `c1`/`c2`/`m7`, and its own fix ("bounds-check slice indices; treat `handlers.go`/`command_decoder.go` as untrusted-input parsers") already covers this line. Distinct code *location*, same class/severity/containment/fix; a stricter triage would fold it into M-10.
- **PoC:** `security/addendum/_pocs/decoder_panics.go` (live), `security/addendum/_pocs/poc_test.go` (`TestDrawShortArray/EmptyArray`).
- **Fix:** `if len(vals) != 5 { return error }` before indexing.

### N-11 — `upload_sgf` array branch: unchecked `ifc.(string)` assertion → panic

- **Severity:** Medium (project rubric: recovered request-path panic = Medium). Per-connection only — the finding's own live PoC asserts connection EOF, not a server crash. **M-10 class**; a stricter triage would fold it into M-10 rather than count a separate Medium. · **Status:** reproduced **live** (`interface conversion: interface {} is float64, not string`)
- **Location:** `pkg/room/handlers.go:161`.
- **Trigger (unauthenticated, open room):** `{"event":"upload_sgf","value":[123]}`.
- **Why not a duplicate:** C-7 covers the array branch's *size* cap (a distinct defect), not input-type validation — so N-11 is genuinely distinct from C-7. But its true nearest neighbour is **M-10**: this is another member of that class (per-connection recovered assertion panic), same file, same comma-ok fix. Distinct line, not a distinct root cause.
- **PoC:** `security/addendum/_pocs/decoder_panics.go` (live), `security/addendum/_pocs/graft_test.go` (`TestUploadArrayNonString`; `TestUploadValid` control).
- **Fix:** `str, ok := ifc.(string); if !ok { return error }`.

### N-13 — Loki log store: `auth_enabled: false` and port 3100 published on all interfaces

- **Severity:** Medium · **Status:** code/config inspection
- **Location:** `monitoring/loki/loki-config.yaml:1`; `docker-compose.yaml` (`loki` service `ports: - "3100:3100"`; the service is gated behind the `monitoring`/`prod` compose profiles, so the exposure applies when those profiles are deployed).
- **Impact:** unauthenticated Loki HTTP API — full log query, label enumeration, log injection (`POST /loki/api/v1/push`), stream deletion. If the operator pipes app logs through the provided Alloy pipeline, contents include the startup DSN-with-password (CS-1 chain, conditional on stdout redirection), room IDs, and nicknames.
- **Why not a duplicate:** L-5 = Grafana default admin; L-7 = CI scanning. The Loki service surface is not mentioned anywhere in the report.
- **Fix:** drop the `ports:` entry (Alloy/Grafana reach Loki over the compose network) or front it with an authenticating proxy; enable `auth_enabled: true` if it must be published.

### N-14 — docker-compose publishes Postgres `5432:5432` on all interfaces (with committed default creds)

- **Severity:** Medium · **Status:** config inspection
- **Location:** `docker-compose.yaml` (`postgres` service `ports: - "5432:5432"`, `POSTGRES_USER=postgres`, `POSTGRES_PASSWORD=postgres`).
- **Precondition (re-verification correction):** the `postgres` service is gated behind `profiles: ["monitoring"]` (docker-compose.yaml:88). It starts — and publishes 5432 — **only** under the `monitoring` compose profile (`--profile monitoring` / `COMPOSE_PROFILES`); a bare `docker compose up` and `--profile prod` do **not** start Postgres at all. (The sibling N-13 correctly notes profile gating; N-14 originally omitted it. The earlier "the compose file is the production deployment recipe" framing is inaccurate — under `--profile prod` neither the app nor Postgres runs.) Remote reach also needs the host firewall to permit inbound 5432.
- **Impact (when the monitoring profile is deployed):** the exposure vector that makes L-4 *remote*: the database is directly reachable with `postgres/postgres` — full read/write of the room store (bcrypt room hashes, all room content) and Postgres superuser primitives (`COPY ... FROM PROGRAM`, `LOAD`) for container-level code execution.
- **Why not a duplicate:** L-4 flags the credentials in the config file; this is the *network publication* of the database service — a different location and the precondition that makes L-4 remotely exploitable. Nothing in the report notes 5432 is host-published.
- **Fix:** remove the `ports:` mapping (or bind `127.0.0.1:5432:5432`); rotate the default credentials.

---

## 5. Low findings

### N-12 — Twitch `!branch` chat command missing the `broadcaster == chatter` check that `!setboard` has

- **Severity:** Low · **Status:** reproduced in Go test
- **Location:** `pkg/hub/twitchrouter.go:240-255` (`case "branch"`), contrast `:220-221` (`setboard` gates on `broadcaster == chatter`).
- **Root cause:** the `branch` case never verifies the chatter is the broadcaster — **any viewer in the streamer's chat** can `!branch <moves>` and graft onto the broadcaster's mapped room, without knowing the room ID.
- **Severity rationale (Low, honestly bounded):** because graft is already unauthenticated for everyone (H-6) and room names are enumerable (L-8), the practical delta over the baseline is narrow — mainly target discovery (the broadcaster↔room mapping removes the need to find the room ID) and a valid-signature delivery path. The finding's value is the authorization-model inconsistency itself.
- **Reproduced:** control OK (non-broadcaster `!setboard` refused); a random chatter's `!branch` grew the room's nodes 1 → 2.
- **Why not a duplicate:** L-12 rates the chat commands Low *assuming the broadcaster is the actor* ("a broadcaster's chat command … grants no new capability"); H-5 is signature forgery. This is an authorization omission in the handler itself — with valid Twitch delivery and a valid secret, a non-broadcaster is still authorized to mutate the room.
- **PoC:** `security/addendum/_pocs/n_in_twitch_poc_test.go` (`go test -tags poc -run TestNINTwitchBranchAuthz -v ./pkg/hub/`).
- **Fix:** apply the same `broadcaster == chatter` gate to `branch` (or a broadcaster-configured moderator list).

### N-15 — Pen (`draw`) color unvalidated → stored + broadcast CSS injection into SVG `stroke`
- **Location:** sink `pkg/frontend/js/boardgraphics/boardgraphics.js:494` (`path.style.stroke = pen_color`); source `pkg/state/command_decoder.go:153-194` (any string accepted); persisted via `PX` (`commands.go:431-444`, re-emitted `frame.go:138-156`).
- **Trigger (unauthenticated):** `{"event":"draw","value":[0.1,0.1,0.5,0.5,"url(//attacker.example/beacon.svg#p)"]}`.
- **Status:** server half reproduced **live** — the color string is rebroadcast verbatim and persisted (`PX[0.1000:0.1000:0.5000:0.5000:url(//attacker.example/beacon.svg#p)]` via `/b/{id}/sgfix`); PoC `security/addendum/_pocs/pencolor.go` is the Go WS client demonstrating that round trip. The browser half (Playwright, `svg#pen path.style.stroke` readback) was authored by the frontend audit but not executed in this environment; the sink assignment is a one-line DOM property set visible at `boardgraphics.js:494`.
- **Impact:** in Firefox, external SVG paint-server references are fetched cross-origin → a viewer-IP/viewer-count tracking beacon baked into the shared document (Chromium stores but does not fetch). Single CSS property, no script execution — honestly Low.
- **Why not a duplicate:** all four excluded client XSS findings are HTML-into-`innerHTML` sinks; this is a CSSOM property assignment on a field (pen color) the report never assesses.
- **Fix:** validate the color server-side (`^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$`); defense-in-depth regex in `draw_pen`.

### N-16 — WebSocket room identity derived from the raw request-target, not the route parameter
- **Location:** `pkg/hub/hub.go:293-303` (`HandlerWrapper` uses `ws.Request().URL.String()` + `ParseURL`, `hub.go:32-45`) instead of chi's `{boardID}`.
- **Root cause:** `URL.String()` includes the **query string**, and for proxy-style absolute-form request-targets the scheme+authority; `core.Sanitize` strips punctuation but keeps alphanumerics, folding query/authority text **into** the room id.
- **Status:** reproduced **live** — `/socket/b/alpha?x=1` vs `?x=2` created distinct rooms `alphax1`/`alphax2` (this review: room `alphax999` confirmed via `/b/alphax999/debug`); an absolute-form upgrade (`http://attacker.example/socket/b/absform`) created room **`attackerexample`**.
- **Impact:** room-space multiplication per board name (amplifies H-2 without new names); room-identity confusion (clients who believe they share a board are in different rooms); identity drivable by arbitrary authority text that proxies may forward/log differently.
- **Fix:** pass chi's `URLParam(r,"boardID")` through to `Handler` instead of re-parsing the raw target.

### N-17 — `POST /api/v1/room/{board}` skips `core.Sanitize` → room-ID divergence; orphaned, unjoinable rooms
- **Location:** `pkg/hub/apiv1router.go:23-25` vs `hub.go:308-312` (WS sanitizes) and `webrouter.go:124-132` (web 400s unsanitized).
- **Status:** reproduced **live** — API-created `MixedCase` ≠ WS/web `mixedcase` (`/api/stats` increments again); the API room is unreachable from web/WS/debug yet consumes memory and is persisted until the idle reaper. Also: raw percent-encoded ids (e.g. `..%2F..%2Fevil%0Ainjected`) are stored verbatim as room ids.
- **Impact:** shadow/orphan rooms (API automation writes rooms no web user can see); inconsistent security posture (a password set via API on `MixedCase` does not protect the room web users actually join).
- **Fix:** `board = core.Sanitize(chi.URLParam(r,"board"))`; reject when it differs from the input (as `/b/{boardID}` does).

### N-18 — `lastActive` refreshed only by the `"_"` command chain → API-/Twitch-driven rooms reaped + DB-deleted at 24 h despite activity
- **Location:** `pkg/hub/hub.go:190-221` (`Heartbeat` → `Close` + `DeleteRoom` + `db.DeleteRoom`); `pkg/room/handlers.go:368-377` (`setTimeAfter` wraps only the `"_"` chain, `:77-82`); `RegisterConnection` does not refresh it.
- **Root cause:** the registered handlers `upload_sgf`, `request_sgf`, `trash`, `update_nickname`, `update_settings`, `graft`, `checkpassword`, `ping` never update activity — and therefore `/ext/upload` (always `request_sgf`) and Twitch `!branch` (always `graft`) never do. **Correction (re-verification):** not *all* `/api/v1` traffic is affected — a generic board-move/command event whose type is **not** in the handler map routes to the `"_"` chain and **does** refresh `lastActive` via `setTimeAfter`; the defect is specific to the enumerated registered commands (and the `/ext/upload`+Twitch paths that always use them). A room driven exclusively via those is closed and **its persisted row deleted** at creation+24 h even if used minutes earlier. (The earlier "live connections keep working against an unmapped room / split-brain" claim is largely wrong: `Heartbeat` calls `Close()`, which closes **all** `r.conns`, before `DeleteRoom` — connections are actively terminated at reap, save for a narrow join-during-close race. The solid impact is DB deletion of persisted history + a fresh empty room on next access.)
- **Status:** code inspection (24 h timer; both the routes auditor and this review verified `setTimeAfter`'s sole placement).
- **Why not a duplicate:** M-6 is the opposite defect (abandoned rooms linger too long).
- **Fix:** update `lastActive` in `HandleAny`/`RegisterConnection` (or a middleware on every chain).

### N-19 — Phantom users: unauthenticated `/api/v1` nickname updates plant permanent entries in `r.nicks`, broadcast room-wide
- **Location:** `pkg/room/handlers.go:274-283` (`update_nickname` — no `authorized`/`outsideBuffer`) and `:311`; pruning exists only in WS teardown (`room.go:466-470`).
- **Status:** reproduced **live** — `curl -XPOST /api/v1/room/<room> -d '{"event":"update_nickname","value":"site-admin","userid":"ghost-1"}'` → every room client immediately received `connected_users` containing `"ghost-1":"site-admin"`, persisting for the room's lifetime.
- **Impact:** permanent spoofed occupants (social-engineering/display-integrity); unauthenticated unbounded `nicks` growth compounding M-3's N² rebroadcast; works even on password-protected rooms (no `authorized` middleware).
- **Why not a duplicate (weak distinction — re-verification):** substantial overlap with the prior catalog, honestly noted. **M-3** (Medium) already documents the same sink at the same line (`handlers.go:63`: `update_nickname` has no `authorized`/`outsideBuffer`, nick held in `r.nicks`, N-entry map rebroadcast); **DR-1** (Critical) already reproduced the identical unauthenticated `POST /api/v1 update_nickname` burst hitting `r.nicks` ("no auth on this handler"); **AZ-1**'s root cause ("never trust client `userid` on the HTTP path") already covers attacker-chosen ids, and its token fix is N-19's fix; **M-4** already covers the unbounded-map-never-pruned theme. N-19's only genuinely new element is the narrow observation that `nicks` (unlike `auth`/`notified`) *has* a prune path but only on **WS** teardown, so a connection-less API identity persists forever. Given the overlap, Low is appropriate.
- **Fix:** gate `update_nickname` (and the `SetNick` in `handleUpdateSettings`) on `authorized`; key API identity to server-issued expiring tokens; prune `nicks` entries with no live connection.

### N-20 — Dependency/toolchain advisories: chi open-redirect fix pending; Dockerfile pins unpatched Go toolchain
- **Details:** `github.com/go-chi/chi/v5 v5.2.2` → GO-2026-4316 (open redirect in `RedirectSlashes`) fixed in v5.2.4 — the app uses `StripSlashes` (no redirect), so **not exploitable**, bump anyway. `Dockerfile:1` pins `golang:1.24.0-alpine`; `govulncheck -mode=source ./...` reports **27 reachable stdlib advisories** fixed in 1.24.6+ (`net/http`, `crypto/tls`, `crypto/x509`, `net/url`, `archive/zip`, …) — cleared by rebuilding on the latest patch image. x/net@v0.47.0 / x/crypto@v0.45.0 module advisories are in packages the app does not call (govulncheck confirms no reachable vulnerable symbol).
- **Why not a duplicate:** L-6 flags the deprecated `x/net/websocket` package; L-7 flags missing CI scanning; neither records the chi fix or the pinned unpatched toolchain.
- **Fix:** bump chi ≥ v5.2.4; pin `golang:1.24-alpine` (latest patch); add `govulncheck` to CI (also satisfies L-7).

### N-21 — Self-referential fetch amplification: the board's own domain is on the fetch allow-list
- **Location:** `internal/fetch/fetch.go:30-31` (`"golab.gg"`, `"test.golab.gg"`); `pkg/hub/extrouter.go:23-44`.
- **Root cause:** with the board's own host fetch-approved, one unauthenticated GET `/ext/upload?url=https://golab.gg/ext/upload?url=https://golab.gg/ext/upload?url=...` (nested K deep; `?` is legal inside a query value; bounded only by header limits) makes each handler synchronously create a room **and** fire the next nested server-side fetch: 1 request → K rooms + K internal round-trips, multiplying H-2; each nested download is additionally subject to N-3's missing cap.
- **Status:** code inspection.
- **Fix:** remove the server's own hostnames from `okList` (or refuse URLs resolving to the server's own URL); enforce fan-out/depth limits.

---

## 6. Verification appendix

**Independently re-verified by the lead reviewer** (second environment, live server and/or Go tests): N-1 (live, two WS clients), N-2 (test), N-3 (auditor PoC re-run), N-4 (test ×2), N-5 (test), N-6 (test), N-7 (auditor PoC re-run), N-8 (test), N-9 (auditor PoC re-run), N-10 (live), N-11 (live), N-12 (auditor PoC re-run), N-15 server round-trip (live), N-16 (live), N-17 (live), N-19 (live). N-13/N-14/N-20/N-21 are config/dependency items verified by inspection + `govulncheck` output; N-18 is timer-bound (inspection; call-graph verified).

**Areas swept and found clean (no new findings):** static-file serving traversal (blocked by `serveFile` dot-dot check); open redirects/header injection (ids sanitized); chi method confusion (405s); template injection (all templates render with nil data); `show_toast` (operator-only DB messages); treegraphics/modal innerHTML sinks beyond the known four (numeric/static only); SQL injection (independently re-verified — all queries parameterized, `rebind` receives constants only); zip-slip (names never written to disk); tree cycles via cut/paste/graft (not creatable); scoring/markdead adversarial boards (bounds hold); GIB/NGF text-field escaping (rides M-5); negative/zero `SZ` (server-safe, client-rendering only); fetch scheme/userinfo/DNS-rebinding allow-list bypasses (fail closed); CI workflow script injection (no `pull_request_target`, no `github.event.*` interpolation); browser-extension content scripts (no exploitable sink); `loadtest/`/`integration/` (not in the prod binary); concurrent WS writes (`x/net/websocket` serializes per-connection writes). Two full fuzz passes (`parser.Parse` 152k execs; `FromSGF`→frame→`ToSGFIX`→reload 198k execs) plus a 26-command × 22-value sweep found nothing beyond the reported items.

**PoC index:** [`security/addendum/_pocs/`](security/addendum/_pocs/) — see [`security/addendum/_pocs/README.md`](security/addendum/_pocs/README.md) for per-finding run instructions. Several PoCs crash or exhaust the target — **authorized local testing only**.

*Caveats: line numbers reference PR #2 head (`12030bc`); dynamic validation ran against the default in-memory config; findings marked `insp.` are confirmed by code/config inspection. Per-area detail and rejected-candidate lists: `findings_frontend.md`, `findings_routes.md`, `findings_core.md`, `findings_integrations.md`.*

---

## 7. Independent re-verification (second-reviewer pass, 2026-07-21)

This addendum was independently re-reviewed: **every PoC was re-run from scratch** (live server on `:8091` for N-1/N-10/N-11/N-15/N-16/N-19; Go tests driving the real code for N-2/N-3/N-4/N-5/N-6/N-7/N-8/N-9/N-12) and **every cited code path and "why not a duplicate" claim was re-read against the source**, aided by a 24-agent parallel verification (one independent read-only verifier per finding, plus an adversarial refutation pass on the three original High findings). **All 21 root causes reproduced or were confirmed by inspection** — the technical substance is sound. Three severity corrections and several precision notes follow.

### Corrections applied to this document

- **N-2 → Low (was High/Critical).** The interpolation defect in `gameInfoToSGF` is real, but the end-to-end injection **is blocked by the addendum's own N-4**. The only production path to `gameInfoToSGF` is the `game/<id>/gamedata` socket frame, which passes through `readFrameFromChan` (the N-4 byte-counter). Every injection payload needs `]` to close `GN[`; that `]` drives the frame parser's depth to 0 and truncates the frame before `json.Unmarshal`, so the malicious name never reaches the converter. **Verified end-to-end this pass:** feeding a full `gamedata` frame through the *real* `readFrameFromChan` — benign `GN[MyGame]` → 250 B frame delivered → converts; `game_name="x]TR["` → frame truncated to 37 B → unmarshal fails → `gamedataToSGF` never called (same for the `LB` payload). Both N-2 PoCs sidestep this by calling `gamedataToSGF` directly, so they prove only the isolated conversion. N-2 is retained as a **latent / defense-in-depth** item because an N-4 fix that swaps the byte-counter for a `json.Decoder` *without* also escaping the OGS strings would unmask it — the two must be fixed together.
- **N-10, N-11 kept Medium, reframed.** Both are unchecked-input request-path panics that `net/http` **recovers per-connection** (confirmed live: the server stayed up; the connection dropped). By the project's rubric a recovered request-path panic is Medium (same tier as M-10, and as siblings N-5/N-7/N-9 which have identical impact), so I did **not** downgrade them — but flagged them clearly as additional instances of the already-catalogued **M-10** class (same file, same comma-ok fix) that a stricter triage would fold into M-10 rather than count separately.
- **Revised totals: 2 High, 10 Medium, 9 Low** (from 3 / 10 / 8) — the single severity change is N-2 High→Low.

### Precision notes (findings kept as-is, but worth stating)

- **Per-connection containment (not whole-server):** N-5, N-7, N-9, N-10, N-11 all panic on the *request/WS* goroutine, which `net/http` recovers — so they drop only the attacker's own connection, not the server. (Contrast the truly fatal, goroutine-/runtime-level items C-1/H-9/DR-1 in the base report.) N-5/N-7/N-9 keep Medium on parity with M-10's tier; N-9's genuinely novel bit is the `FromAlphanumeric` column-bound bug (`coord.go`), its sink being C-1's unguarded `Board.Set`.
- **"Unauthenticated" = open (password-less) room** for the command-path findings (N-5, N-8, N-9-via-graft-excepted, N-10, N-15): the `"_"`/command chains run behind the `authorized` middleware, a no-op only when `GetPassword()==""`. This is the default room and matches the base report's threat model, but the precondition is real. (`graft`, per H-6, bypasses `authorized` entirely, so N-9's graft delivery is genuinely un-gated.)
- **N-3** is an honest **escalation of M-2** (uncapped fetch) reaching the **C-3** stack-overflow sink; its novel contribution is the reachability observation that `raw.githubusercontent.com`/`cdn.discordapp.com` are allow-listed and serve attacker bytes directly (removing M-2's open-redirect precondition). Note C-3's own depth-cap fix would already close the stack-overflow variant from *any* delivery; only the multi-GB-OOM variant depends on M-2's `LimitReader`. High stands (reliable unauthenticated fatal crash), reproduced live (child process died `fatal error: stack overflow`).
- **N-12** is not internet-unauthenticated: `!branch` requires a valid Twitch-signed callback (collapses into H-5 only if the secret is empty) and a prior `!setboard` room mapping; it is a real authorization-omission refinement of **L-12** (which already names `!branch`). Correctly Low.
- **N-14** is gated behind the `monitoring` compose profile (corrected inline); **N-13** (Loki) and **N-21** (self-fetch, and only where `golab.gg` DNS resolves to the server) likewise carry deployment preconditions. **N-18** applies to the enumerated registered commands, not literally all `/api/v1` traffic (corrected inline). **N-8**'s `apiv1router.go` cite fixed `:46`→`:49`.
- **Solid as filed (no changes):** N-1 (password broadcast — reproduced live, dedup vs AZ-1/AZ-2/ID-1/CS-2 holds), N-4, N-6, N-8, N-13, N-15, N-16, N-17, N-20. N-1's only qualifier — a legitimate authorized settings change must occur to trigger the leak — is already stated in the finding.

### Repository hygiene fix

The PoC directory was committed as `security/addendum/pocs/` containing **six different Go packages in one directory** (`main`, `zz_verify`, `zzpoc`, `plugin`, `room`, `hub`), which broke `go build/vet/test ./...` (`[setup failed]`) — regressing the green suite established by PR #2. It has been renamed to **`security/addendum/_pocs/`** (the `_` prefix makes the Go toolchain skip it, so the files remain runnable-by-copy but no longer break the module build); references updated. `go build/vet/test ./...` is green again.

*This section records the independent re-verification only; the findings above are the original auditors' work with the corrections noted here folded into the master table, severities, and detail blocks.*
