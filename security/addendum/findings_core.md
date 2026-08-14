# NEW Findings — Parsers & Game-State Core (golab-board PR #2)

> **Re-verification note:** consolidated + independently re-verified in [`SECURITY_ADDENDUM.md`](../../SECURITY_ADDENDUM.md); see its **§7** for corrections (notably N-2 downgraded to Low, and per-finding precondition/dedup caveats). Severities/IDs here are the per-area working notes.


Audit scope: `pkg/core/parser/`, `pkg/core/tree|board|coord|fields|color`, `pkg/core/util.go`, `pkg/core/verify.go`, `pkg/state/`, `internal/zip`, `internal/sgfsamples`.
Method: full read of every file + dynamic confirmation. All PoCs were executed against:
(a) Go tests in `/tmp/golab/app/zz_poc/` (module-internal test package, run with `go test ./zz_poc/`), and
(b) a live server (`/tmp/golab/board -f config-core.yaml`, port 8094) via `POST /api/v1/room/{id}`.
Environment note: the prepared tree was absent, so the source was re-cloned from `github.com/RomanPszonka/golab-board` at PR #2 head (`12030bc`). Findings file mirrored to `/mnt/agents/output/findings_core.md`.

Every finding below is distinct from the exclusions (C-1..C-8, DR-*, DL-*, H-*, M-1..M-12, L-1..L-13, AZ-*, GL-*, CS-*, ID-*, XSS-*). Severity follows the project rubric: request-path panics recovered by `net/http` = **Medium**; persisted poison that survives restart is flagged ⚑.

---

## N-CR-1 — `draw` command: missing array-length check → index-out-of-range panic

- **Severity:** Medium (per-connection DoS; recovered by net/http)
- **Location:** `pkg/state/command_decoder.go:153-194` (`case "draw"` — `vals[0]`…`vals[4]` with no `len(vals)` check)
- **Root cause:** The decoder asserts `evt.Value().([]any)` and then indexes `vals[0]` through `vals[4]` unconditionally. Any array shorter than 5 elements panics. Length is never validated.
- **Attacker-reachable trigger (unauthenticated):**
  ```
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"draw","value":[]}'
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"draw","value":[1.0]}'
  ```
  (also over the WebSocket with the same JSON event)
- **Impact:** `runtime error: index out of range [0] with length 0` (or `[1] with length 1`, `[2] with length 2`, `[4] with length 4` depending on length). Kills the attacker's connection; the room mutex is released by the deferred unlock in `Room.Execute`, so impact is contained per `net/http` recovery. Verified: HTTP request → connection dropped (curl exits with empty reply), server stays up.
- **PoC:** `zz_poc/poc_test.go` — `TestDrawShortArray`, `TestDrawEmptyArray` (both panic as predicted). E2E: curl above → `HTTP 000` (connection reset), subsequent `/api/stats` → 200.
- **Why not a duplicate:** M-10 enumerates `handleUpdateSettings` assertions, GIB `alphabet[x]`, `coord.FromInterface`, and `remove_mark value[:2]`. The `draw` length check is a different sink (index-out-of-range, not type assertion) at a different location, and none of the M-10 PoCs (`c1`,`c2`,`m7`) touch it.
- **Fix:** `if len(vals) != 5 { return nil, fmt.Errorf("'value' should be [float,float,float,float,string]") }` before indexing.

## N-CR-2 — Out-of-range coordinates decode to nil `*Coord` **without error** → nil-deref panic in 9 commands

- **Severity:** Medium (per-connection DoS; recovered by net/http)
- **Location:** `pkg/core/coord/coord.go:254` (`FromInterface` returns `NewCoord(x, y), nil` — `NewCoord` returns `nil` for `x`/`y` outside `[0,18]`, and the `nil` error makes every decoder check pass); panic sites in `pkg/state/commands.go:37` (`add_stone`), `:116` (`remove_stone`), `:147` (`triangle`), `:166` (`square`), `:186` (`letter`), `:208` (`number`), `:230` (`label`), `:404` (`goto_coord`), `:615` (`markdead`) — all do `cmd.crd.X` / `cmd.crd.Y` on a nil pointer.
- **Root cause:** Two missing guards compose: (1) `FromInterface` doesn't treat an out-of-range (nil) result from `NewCoord` as an error; (2) the command `Execute` methods dereference `cmd.crd` without a nil check (`remove_mark` is accidentally safe because `ToLetters()` is nil-tolerant).
- **Attacker-reachable trigger (unauthenticated):**
  ```
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"triangle","value":[50,50]}'
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"goto_coord","value":[-1,-1]}'
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"markdead","value":[100,100]}'
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"add_stone","value":{"coords":[25,3],"color":1}}'
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"label","value":{"coords":[50,50],"label":"x"}}'
  ```
- **Impact:** `runtime error: invalid memory address or nil pointer dereference` on every one of the 9 command types. Contained per-connection (deferred `r.mu.Unlock` runs; net/http recovers). Verified live: connection reset, server unaffected.
- **PoC:** `zz_poc/poc_test.go` — `TestNilCoordTriangle/GotoCoord/Markdead/AddStone`; `zz_poc/nilcoord2_test.go` — `TestNilCoordLabelLetterNumber` (label/letter/number/remove_stone/square). All panic. `FromInterface([50,50]) = <nil>, err=<nil>` — proves the decoder cannot reject it.
- **Why not a duplicate:** M-10's `coord.FromInterface` item (PoC `m7`) is the **`v.(float64)` type-assertion panic at coord.go:249** (non-numeric elements like `["x","y"]`). This finding is a *different root cause and sink*: numeric, well-formed input (`[50,50]`) passes the assertion, produces a nil coord with a **nil error**, and panics later inside `commands.go`. Fixing line 249 with comma-ok (M-10's suggested fix) does **not** fix this.
- **Fix:** in `FromInterface`, return an error when `NewCoord` returns nil (or validate range there); additionally nil-check `cmd.crd` in each `Execute`.

## N-CR-3 — NGF parser emits attacker-controlled SGF property KEYS → persisted SGFIX is unparseable → room destroyed on restart ⚑

- **Severity:** Medium (persistent data destruction of any room; analogous impact to M-11)
- **Location:** `pkg/core/parser/ngfparser.go:60` (`key := fmt.Sprintf("%c", line[4])`) and `:219` (`node.AddField(move.key, move.coord)`); serialized verbatim at `pkg/state/state.go:142` (`sb.WriteString(key)` — only `]` is escaped in *values*, keys are written raw); reload dropped at `pkg/hub/hub.go:171-174` (`room.Load` error → `continue`).
- **Root cause:** An NGF move line (`PM........`, exactly 9 chars) has byte 4 copied *unchanged* into an SGF property key — no check that it is `B` or `W`, or even a letter. SGF's own parser only ever produces letter keys, so nothing downstream defends against this. `FromSGF` accepts the resulting node as a field node, `UploadSGF` commits it, `ToSGFIX` writes the raw byte as a key, and the persisted file no longer parses.
- **Attacker-reachable trigger (unauthenticated):**
  ```
  NGF='My Game\n19\nwhiteplayer 1d\nblackplayer 2d\nwbaduk\n0\n0\n6\n2026-01-01\n0\nblack resign\n1\nPM  [aa  '
  curl -X POST http://target:8080/api/v1/room/<room> \
       -d "{\"event\":\"upload_sgf\",\"value\":\"$(printf "$NGF" | base64 -w0)\"}"
  ```
  (base64 for the exact payload: `TXkgR2FtZQoxOQp3aGl0ZXBsYXllciAxZApibGFja3BsYXllciAyZAp3YmFkdWsKMAowCjYKMjAyNi0wMS0wMQpwCmJsYWNrIHJlc2lnbgoxClBNICBbYWEgIA==` — note line 7/10 must be non-blank, e.g. `0`, or the NGF fields misalign.)
- **Impact:** Upload succeeds (`{"success": true, ...}` — state committed). Persisted SGFIX contains the raw key, e.g. `(;BR[2d]...IX[0];[[tt]IX[1])`. On restart, `Hub.Load → room.Load → state.FromSGF` fails (`couldn't detect filetype` / `bad property`), the hub logs and **skips the room — its entire persisted history is destroyed**, permanently. Works with key bytes `[`, `]`, `(`, `)`, `;`, `\`, digits, etc. (keys that are letters, e.g. `C`, reload fine). Any anonymous user can do this to any room.
- **PoC:** `zz_poc/ngf_room_test.go — TestNGFPoisonEndToEnd`: upload → `Room.Save` → persisted SGFIX printed → `room.Load(saved)` → `err=couldn't detect filetype`. E2E upload returns `success: true` (see above). Also `zz_poc/ngf_test.go — TestNGFKeyRoundTrip` over 8 key bytes: all non-letter keys produce reload failures.
- **Why not a duplicate:** M-5 is about `\`-escaping of property *values* breaking round-trip fidelity (data corruption; the room still loads). C-2/C-2b are mark-value poison that *panics* on load. M-11 is `update_settings` size>19. This finding is a different root cause (NGF move-key byte used as a property *name*) and a different sink (reload **parse failure** → silent room drop). The exclusions' GIB/NGF note covers only the coordinate panic and text-field escaping.
- **Fix:** in `parseMove`, accept only `B`/`W` (else skip the move); defensively validate keys in `toSGF`/`ToSGFIX` (SGF spec: uppercase letters only) and reject others at `FromSGF`.

## N-CR-4 — `IX` index collision + `cut` → tree/map inconsistency → nil-deref panic in `graft`

- **Severity:** Medium (per-connection DoS; recovered by net/http)
- **Location:** `pkg/state/state.go:217-225` (uploaded `IX` values trusted as node indices with no uniqueness check); `pkg/state/edit.go:383-385` (`cut` deletes `s.nodes[n.Index]` for every branch node); panic at `pkg/state/commands.go:554` (`col := s.nodes[parentIndex].Color`).
- **Root cause:** The SGFIX `IX` property is attacker-controlled (upload path). Two nodes can share one index; `s.nodes` keeps only the last. `cut()` on one of them deletes the *shared* map key, leaving a remaining tree node whose `Index` has no map entry. A later `graft <moveNumber> <coord>` resolves that node via `TrunkNum` (tree walk) and dereferences the missing map entry.
- **Attacker-reachable trigger (unauthenticated, 3 requests):**
  ```
  # 1. upload SGFIX with duplicate IX[3] on two siblings
  {"event":"upload_sgf","value":base64("(;SZ[19]GM[1]IX[0](;C[a]IX[3])(;C[b]IX[3]))")}
  # 2. navigate into the first child and cut it
  {"event":"right"}  then  {"event":"cut"}
  # 3. graft at trunk move 1 -> TrunkNum returns 3 -> s.nodes[3] == nil
  {"event":"graft","value":"1 d4"}
  ```
- **Impact:** `runtime error: invalid memory address or nil pointer dereference` (contained per-connection). More broadly this shows the node-index namespace is forgeable by upload: indices are persisted (`ToSGFIX` emits `IX`), so collision-based confusion also survives restarts (wrong-node `setPreferred`/`gotoIndex` behavior).
- **PoC:** `zz_poc/ngf_room_test.go — TestIXCutGraft` — exact sequence above, panics as predicted.
- **Why not a duplicate:** M-10's items are all single-request assertion/index panics at other sites; L-13 is `Down[PreferredChild]` bounds. No exclusion covers the `IX` namespace, `cut`'s map deletion, or this `s.nodes[...]` deref.
- **Fix:** on load, re-index nodes sequentially (ignore uploaded `IX`) or reject duplicate/out-of-range `IX` values in `FromSGF`; make `commands.go:554` and `smartGraft` tolerate missing map entries.

## N-CR-5 — `PX[NaN:…]` / `PX[+Inf:…]` pass the pen guard → `json.Marshal` fails on every frame → all broadcasts silently dropped; persists across restart ⚑

- **Severity:** Medium (persistent room-wide silent DoS; no crash)
- **Location:** `pkg/state/frame.go:141-153` (`strconv.ParseFloat` accepts `NaN`/`+Inf`/`-Inf`; only *parse errors* are filtered); marshal failure at `pkg/event/channel.go:49`; errors swallowed at `pkg/room/room.go:361-373` (`Broadcast`: `conn.SendEvent(evt) //nolint:errcheck`), `:443` (join path), and `pkg/hub/apiv1router.go:46` (`data, _ = json.Marshal(evt)`).
- **Root cause:** The PX (pen) validator checks field count and `ParseFloat` errors, but `ParseFloat("NaN")`/`("Inf")` succeed. The resulting `Pen` struct contains a non-JSON-representable float, so *every* frame marshaled while the current node carries that field fails — and every send path explicitly discards the error.
- **Attacker-reachable trigger (unauthenticated):**
  ```
  SGF='(;GM[1]FF[4]SZ[19]PB[B]PW[W]PX[NaN:0:0:0:red];B[pd])'
  curl -X POST http://target:8080/api/v1/room/<room> \
       -d "{\"event\":\"upload_sgf\",\"value\":\"$(echo -n "$SGF" | base64 -w0)\"}"
  # -> {"success": true, "output": }      <- malformed JSON: frame marshal failed
  ```
- **Impact:** (1) The upload's full-frame broadcast is dropped — the API returns `{"success": true, "output": }` (invalid JSON). (2) While the room's current node has the field, **every** frame broadcast (joins, moves, navigation) silently fails to serialize → clients see a frozen room; new joiners receive no initial state (send error ignored at room.go:443). Putting `PX[NaN…]` on many nodes amplifies this. (3) The field is written back by `ToSGFIX`, reload parses fine, and the poison is live again — **survives restarts**. No log line is emitted anywhere (errors are `nolint`-discarded), so this is hard to detect operationally.
- **PoC:** `zz_poc/nan_test.go — TestNaNPen`: `json.Marshal(frame)` → `json: unsupported value: NaN` (and `+Inf`). `zz_poc/nan_persist_test.go — TestNaNPersist`: round-trip through `ToSGFIX`+`FromSGF` still fails to marshal. E2E above shows the malformed API response.
- **Why not a duplicate:** C-2 notes the PX branch as "correctly guards" (length/parse-error) — the NaN/Inf case was not considered. M-5 is escaping corruption; C-2/C-2b are load-time panics. This is a new sink (JSON serialization failure) with a new, silent availability impact.
- **Fix:** reject non-finite floats in the PX branch (`math.IsNaN`/`IsInf`); log (don't silently drop) `SendEvent`/`json.Marshal` errors; validate PX at `FromSGF`.

## N-CR-6 — `graft` with an off-board letter on a 9x9/13x13 board → `Board.Set` index-out-of-range panic

- **Severity:** Medium (per-connection DoS; recovered by net/http)
- **Location:** `pkg/core/coord/coord.go:273-299` (`FromAlphanumeric`: row number is checked against `size`, but the letter is only capped at a fixed `'t'` — correct for 19x19 only); panic via `pkg/state/commands.go:577` → `pkg/state/edit.go:277` (`smartGraft` → `s.board.Move`) → `pkg/core/board/board.go:248` (`Legal` calls unguarded `Set` after the *guarded* `Get` returns `Empty`).
- **Root cause:** For `size < 19`, letters `j`..`t` produce x-coordinates 9..18 that pass `FromAlphanumeric` (e.g. `t1` on a 9x9 → coord (18,8), no error). `Board.Legal`'s bounds-guarded `Get` returns `Empty` (move not rejected), then the unguarded `Set` indexes `Points[y][18]` on a 9-column row.
- **Attacker-reachable trigger (unauthenticated):**
  ```
  curl -X POST .../api/v1/room/<room> -d '{"event":"upload_sgf","value":base64("(;GM[1]FF[4]SZ[9]PB[B]PW[W])")}'
  curl -X POST .../api/v1/room/<room> -d '{"event":"graft","value":"t1"}'
  ```
  (Note: per H-6 the `graft` route doesn't even require authorization.)
- **Impact:** `runtime error: index out of range [18] with length 9` (or `length 13`). Contained per-connection. The same unguarded-`Set` defect is Critical in the OGS goroutine (C-1) — this is a second, previously unlisted request-path delivery of it.
- **PoC:** `zz_poc/graft_test.go — TestGraftOffBoardLetter`: panics on 9 and 13, clean on 19. E2E: connection reset, server alive.
- **Why not a duplicate:** M-10's list (update_settings, GIB `alphabet[x]`, `coord.FromInterface`, `remove_mark value[:2]`) and the "command-path mark bounds" non-exploitable note cover only the mark commands, which *do* bounds-check (`x >= s.size`). The `graft` path uses `FromAlphanumeric`, which nobody bounds-checks against board size; the exclusions' C-1 fix note even flags `Legal`/`Set` as the latent defect — this is a new reachable trigger for it at a new site (`edit.go:277`).
- **Fix:** in `FromAlphanumeric`, reject letters mapping to `x >= size` (use board-appropriate max letter); also guard `Board.Set`/`Legal` per C-1's fix.

## N-CR-7 — `upload_sgf` array branch: unchecked `ifc.(string)` assertion → panic

- **Severity:** Medium (per-connection DoS; recovered by net/http)
- **Location:** `pkg/room/handlers.go:161` (`str := ifc.(string)` inside the `[]any` branch of `handleUploadSGF`)
- **Root cause:** Array elements are asserted to `string` without comma-ok. Any non-string element panics.
- **Attacker-reachable trigger (unauthenticated):**
  ```
  curl -X POST http://target:8080/api/v1/room/<room> -d '{"event":"upload_sgf","value":[123]}'
  ```
- **Impact:** `interface conversion: interface {} is float64, not string` — contained per-connection. Verified live (connection reset; server stays up).
- **PoC:** `zz_poc/graft_test.go — TestUploadArrayNonString` (panics); `TestUploadValid` control passes.
- **Why not a duplicate:** C-7 covers the *uncapped size* of this array branch, not input-type validation; M-10 enumerates other assertion sites (update_settings etc.) but not this one — different location, and the M-10 PoCs don't exercise `upload_sgf` arrays. (Same hardening theme as M-10, new instance.)
- **Fix:** `str, ok := ifc.(string); if !ok { return error }`.

---

## Rejected candidates (investigated, found clean or out of scope)

- **Negative/zero board size via `SZ[-5]` / `SZ[0]` (SGF or NGF):** accepted by `FromSGF` (only `>19` rejected) and persisted. Verified **no server panic**: `crd.Valid(size)` is false for every coord so moves are skipped; command coords fail the `x >= s.size` checks; `Board.Get` returns `Empty`; frames/scoring iterate zero rows. Room is unplayable and `metadata.size` is negative/zero — a client-side rendering concern only (web auditor's territory).
- **Tree cycles (cut/paste/graft) → `Fmap`/`locate`/`gotoCoord` infinite loop:** no cycle is creatable — `cut` detaches the branch, `paste` inserts a fresh `Copy`, graft/graftCommand only append *new* nodes, and the parser cannot produce cycles from text.
- **`saveTree(PartialNodes)` `start.Up.Index` nil-deref (save.go:57):** only called after operations that guarantee `current.Up != nil` (post-add or goto-child); `root == nil` states are unreachable from rooms.
- **ZIP entry-count DoS (100k+ tiny entries):** real CPU cost, but same root cause/location as C-6 (no caps of any kind in `zip.Decompress`); marginal beyond C-6 and requires C-7's uncapped delivery.
- **Zip-slip / symlink entries:** `Decompress` never writes entry names to disk (already in report §7 positives).
- **`PushHead` with out-of-range x/y → `board.Move(nil)` panic (edit.go:63-127):** real, but only reachable from the OGS plugin goroutine with OGS-server data — same defect/sink as C-1.
- **Duplicate/huge/negative `IX` without `cut`:** causes wrong-node navigation confusion (`gotoIndex`/`setPreferred` walk the *other* node with the same index) but no panic found; the map never goes nil for an in-tree index until `cut` removes it.
- **GIB `STO` with negative coordinate (`alphabet[-1]`):** same line/sink as M-10's `gibparser.go:280`.
- **GIB/NGF free-text fields (nicks, GN, PC, ranks) containing `\`/`]`:** rides the M-5 escaping class; no new effect.
- **`graft()` (non-smart, edit.go:299) nil `RecomputeDepth` on empty moves:** dead code — no callers outside tests.
- **`smartGraft` with empty moves (`{"event":"graft","value":"5"}`):** guarded (`if graft != nil`) — no panic.
- **NGF empty-line field misalignment** (blank filler lines shift fields; komi `Atoi` fails): upload rejected, no security impact.
- **`remove_mark` with out-of-range coord:** nil-safe (`ToLetters` handles nil); only the known M-10 `value[:2]` issue remains.
- **Command sweep (26 event types × 22 adversarial values) + Go fuzzing** (`parser.Parse` 45s/152k execs; `FromSGF`→frame→`ToSGFIX`→reload round-trip 60s/198k execs): no crashes beyond the reported findings and the already-excluded M-10 items.
- **Scoring/markdead with adversarial boards:** bounds checks hold (matches exclusions' "scoring path robust").
- **`update_settings` size 20 / `computeDiffSetup` O(N²) / copy-paste amplification:** excluded (M-11, M-12, C-8) — re-verified present, not re-reported.

## Artifacts

- PoC tests: `/tmp/golab/app/zz_poc/*.go` (run: `go test ./zz_poc/ -v`; left in place — test-only package, excluded from `go build`; also copied to `/tmp/golab/_pocs/zz_poc/` and `/mnt/agents/output/pocs-core/`).
- Live server used for E2E: `/tmp/golab/board -f /tmp/golab/_pocs/config-core.yaml` (port 8094, memory DB). Left running.
- Fuzz corpus: `zz_poc/testdata` (Go fuzz cache under the test package).
