# Security Assessment — golab/board

**Target:** `golab-board` (multi-user Go board web application)
**Assessment date:** 2026-07-07
**Scope:** Full source review of the Go backend (~10k LOC): HTTP/WebSocket routing, event handling, file-format parsers (SGF/GIB/NGF/ZIP), room/state management, OGS and Twitch integrations, persistence layer, and deployment configuration.
**Method:** Manual source-code audit (white-box), **followed by dynamic proof-of-concept validation** against a locally-run instance. Runnable PoCs for every Critical and High finding are in [`security/poc/`](security/poc/); §0 records what validation confirmed and corrected.

---

## 0. PoC validation results (2026-07-07)

After the initial static review, every Critical and High finding was exercised with a proof-of-concept ([`security/poc/`](security/poc/)). Validation **corrected several severities** — most importantly, it disproved the original headline claim that panics crash the whole server. Read this section before acting on the ratings below.

**Key correction — Go's `net/http` recovers request-goroutine panics.** The board's WebSocket handler (`golang.org/x/net/websocket`) and the HTTP API both run their work *inside the HTTP request goroutine*, which `net/http` wraps in a `recover()`. Empirically, the unchecked-type-assertion panics (C-1, C-2, C-7's panic) fire but are caught (`http: panic serving …`): they drop the **single offending connection** and spam logs — they do **not** crash the process. They are reclassified from Critical to **Medium**. (They *would* be fatal if reached from a spawned goroutine — see M-6/OGS and the heartbeat.)

**The genuine unauthenticated whole-server crashes** are the ones that bypass `recover()`:

| Finding | What was proven end-to-end | Result |
|---------|----------------------------|--------|
| **C-6** stack overflow (SGF parse) | `POST /api/v1/room/{id}` with `{"event":"upload_sgf","value":["<b64 of '(' ×12,000,000>"]}` → `fatal error: stack overflow`, process dead | **Confirmed — whole-server crash, unauthenticated** |
| **H-7** stack overflow (`toSGF`) | same request with **two** list entries → trace shows `(*SGFNode).toSGF`, process dead | **Confirmed — elevated to Critical** |
| **C-3** board-size OOM | one unauthenticated request with `size:20000` grew server RSS 80 MB → 626 MB and retained it; `size:200000` (~320 GB) OOM-kills | **Confirmed** |
| **C-5** zip bomb | `internal/zip.Decompress` returned **536 MB from a 510 KB** archive | **Confirmed** |
| **C-2** GIB index panic | `alphabet[25]` panics (`index out of range [25] with length 19`) | **Confirmed, but recovered → Medium** |
| **C-1 / C-7 panic** | `interface conversion: string, not map` — but caught by `net/http` | **Recovered → Medium; C-7 stays Critical for unauth *control* + crash delivery** |
| **H-1** CSWSH | cross-origin socket accepted, initial board frame received | **Confirmed** |
| **H-2** room flood | rooms grew 1 → 501 from junk connections | **Confirmed** |
| **H-3** connection flood | 1000 concurrent connections, no cap/throttle | **Confirmed** |
| **H-5** Twitch bypass | forged webhook with an **invalid** signature returned `200 OK` (empty secret) | **Confirmed** |
| **H-6** NGF/SGF board OOM | `state.FromSGF` rejects `SZ[50000]` (“unsupported board size”); NGF parser never allocates on size | **False positive — mitigated; dropped** |
| **C-4** “instant 4 GB” | `readBytes` grows incrementally, not pre-allocated | **Mechanism corrected → High (no max message size + no read deadline)** |

**Two important delivery details validation surfaced:**

1. **The 1 MB upload cap is bypassable.** `handleUploadSGF` caps the decoded size at 1 MiB **only** on the string branch. The **array branch** (`value` as a JSON list) has **no cap** and feeds `parser.Merge` → the parser/serializer. This is what makes C-6/H-7 exploitable at crash-scale.
2. **`recover()` is still worth adding** — not for the request path (net/http already covers it) but for the **spawned goroutines** (OGS plugin loop, heartbeat, message loop), where an unchecked assertion *is* an unrecovered whole-process crash.

> A **second-pass, multi-agent crash hunt** (16 verified findings) followed up specifically on new attack surfaces, stacking low-severity issues into crashes, and *unrecoverable* session/board crashes. Its results are in **[§10](#10-second-pass-new-crash-surfaces-multi-agent-hunt)** and are the most important additions to this report — in particular a confirmed unauthenticated **whole-server crash via the OGS review plugin goroutine** (P2-A1) and a confirmed **persistent poison-pill that bricks a board on every load** (P2-B1).

---

## 1. Executive summary

The application is a no-login, no-signup collaborative Go board. Any anonymous client can open a WebSocket, create rooms, upload files, and drive board state. This is a large, fully **unauthenticated attack surface**, and the codebase currently trusts client input in many places where it should not.

The most serious *validated* problems are **unauthenticated whole-server crashes** that a single request triggers and that Go's `recover()` cannot stop: **unbounded recursion** in the SGF parser and tree serializer (C-6, H-7 — a `fatal error: stack overflow`) and **unbounded memory allocation** (C-3 board size, C-5 zip bomb — OOM). All are reachable through the uncapped `upload_sgf` array branch and the unauthenticated `POST /api/v1/room/{board}` endpoint. These were reproduced end-to-end (see §0).

A second class of bugs — unchecked type assertions that panic (C-1, C-2, C-7) — is real but **contained by `net/http`'s per-request `recover()`**: each drops one connection rather than the server. They matter for robustness and become fatal in spawned goroutines, but they are not the emergency the raw code smell suggests.

Alongside these, there are missing WebSocket **origin validation** (cross-site WebSocket hijacking, H-1), unbounded **room/connection creation** (H-2/H-3), no **timeouts** (slow-loris, H-4/C-4/M-1), and a **Twitch webhook authentication bypass** when the signing secret is unset (H-5) — all validated.

Before exposing this on a public website, the items in [§3 Critical](#3-critical-findings) and [§4 High](#4-high-findings) should be remediated, and the deployment hardening in [§7](#7-deployment--configuration-hardening) applied.

### Severity counts (post-validation)

| Severity | Count | IDs |
|----------|-------|-----|
| Critical | 5 | C-3, C-5, C-6, C-7, H-7 |
| High | 6 | C-4, H-1, H-2, H-3, H-4, H-5 |
| Medium | 10 | C-1, C-2, M-1 … M-8 |
| Low / Hardening | 9 | L-1 … L-9 |
| Mitigated / dropped | — | H-6 |

> IDs keep their original labels (C-#, H-#) for traceability even where validation changed the severity; the level is stated on each finding.

### Highest-priority fixes (do these first)

1. **Bound recursion depth** in the SGF parser (`parseBranch`) and the tree serializer (`toSGF`/`Copy`) — this closes the two confirmed whole-server crashes (C-6, H-7).
2. **Cap the `upload_sgf` array branch** to the same 1 MiB limit as the string branch (removes the crash-scale delivery path), and **cap all attacker-controlled allocation sizes**: board size (C-3), ZIP output + entry count (C-5), WebSocket message size (C-4).
3. **Authenticate/limit `POST /api/v1/room/{board}`** and wrap its body in `http.MaxBytesReader` (C-7) — it is the unauthenticated delivery vector for the above.
4. **Validate the WebSocket `Origin`** header (H-1) and add **connection/room caps + rate limiting** (H-2, H-3) and **read/HTTP timeouts** (H-4, C-4, M-1).
5. **Fail-closed on an empty Twitch secret** (H-5).
6. **Replace unchecked type assertions with comma-ok checks** and add `recover()` to spawned goroutines (C-1, C-2, M-6) — lower urgency (net/http already contains the request-path panics) but removes latent crashes and log spam.

---

## 2. Findings overview

| ID | Severity | Title | Location |
|----|----------|-------|----------|
| C-6 | **Critical** | Stack overflow via deeply nested SGF (unbounded recursion) — **validated whole-server crash** | `pkg/core/parser/sgfparser.go:214-255` |
| H-7 | **Critical** (was High) | Stack overflow in tree `toSGF`/`Copy` recursion — **validated whole-server crash** | `pkg/core/parser/parser.go:51-83`, `pkg/core/tree/tree.go:149-170` |
| C-3 | **Critical** | Board-size memory exhaustion via `update_settings` — **validated (RSS 80→626 MB)** | `pkg/room/handlers.go:243`, `pkg/core/board/board.go:61` |
| C-5 | **Critical** | ZIP bomb — unbounded in-memory decompression — **validated (536 MB from 510 KB)** | `internal/zip/zip.go:37-46` |
| C-7 | **Critical** | Unauthenticated state control + crash delivery via HTTP API | `pkg/hub/apiv1router.go` |
| C-4 | High (was Critical) | No max WebSocket message size + no read deadline (unbounded buffering / slow-loris) | `pkg/event/channel.go:88-126` |
| H-1 | High | No WebSocket Origin check → cross-site WebSocket hijacking (CSWSH) — **validated** | `pkg/hub/socketrouter.go:35-43` |
| H-2 | High | Unbounded room creation → resource exhaustion — **validated (1→501)** | `pkg/hub/hub.go:275-291` |
| H-3 | High | No connection limits / rate limiting — **validated (1000 conns)** | `pkg/hub/hub.go`, `socketrouter.go` |
| H-4 | High | No WebSocket read timeout → slow-loris | `pkg/event/channel.go` |
| H-5 | High | Twitch webhook HMAC bypass when secret is empty — **validated (200 to bad sig)** | `internal/twitch/twitch.go:72-82` |
| C-1 | Medium (was Critical) | `update_settings` type-assertion panic — **recovered by net/http** (per-connection DoS) | `pkg/room/handlers.go` |
| C-2 | Medium (was Critical) | GIB coordinate index panic — **recovered by net/http** via upload path | `pkg/core/parser/gibparser.go:280` |
| H-6 | ~~High~~ **Mitigated** | Board size from NGF/SGF — `state.FromSGF` clamps `size>19`; **not exploitable** (see C-3) | `pkg/core/parser/ngfparser.go:122` |
| **Uncapped array branch** | High | `upload_sgf` array branch skips the 1 MiB cap — the crash-scale delivery path for C-6/H-7 | `pkg/room/handlers.go:150-170` |
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

> The detailed write-ups below keep their original IDs. Where validation changed a rating (§0), the corrected severity is stamped at the top of the entry. C-1 and C-2 remain in this section for traceability but are **Medium** post-validation.

### C-1. Type-assertion panics in handlers  ·  **Corrected: Medium (recovered by net/http), not a whole-server crash**

> **Validation result:** the panic fires as described, **but** it occurs in the HTTP/WebSocket request goroutine, which Go's `net/http` server wraps in `recover()`. Observed: `http: panic serving 127.0.0.1:…: interface conversion: interface {} is string, not map[string]interface {}` — the connection is dropped, the **server keeps running**. Impact is therefore a per-connection DoS + log spam, not a process crash. The fix below still matters: the *same* unchecked assertions are an unrecovered whole-process crash when reached from a spawned goroutine (see M-6, OGS plugin loop; and the heartbeat / message-loop goroutines).

**Locations:** `pkg/room/room.go:454` (`Handle` loop → `HandleAny`), `pkg/room/handlers.go` (multiple). Note there is **no `recover()`** anywhere in the codebase, so the spawned-goroutine paths are unprotected.

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

### C-2. Index-out-of-range panic on malformed GIB coordinates  ·  **Corrected: Medium (recovered by net/http)**

> **Validation result:** the panic is confirmed (`index out of range [25] with length 19`), but via an upload it runs in the request goroutine and is recovered by `net/http`, exactly like C-1 — one connection dies, the server survives. Still fix it (it is a fatal crash if the GIB is ever parsed from a spawned goroutine, and it's plain incorrect).

**Location:** `pkg/core/parser/gibparser.go:280` — `value := string([]byte{alphabet[x], alphabet[y]})` (`alphabet` is 19 chars).

The GIB parser reads `STO` move coordinates and indexes a 19-character alphabet with `x`/`y` parsed straight from the file. The values are validated only for *parseability* as integers (lines 263-274), never for range. A GIB upload such as:

```
\HS\HE\GS
STO 0 0 1 25 0
\GE
```

makes `alphabet[25]` (or a negative index) panic. The file-type detector only needs the `\HS` prefix to route into this parser.

**Impact:** Per-connection DoS (recovered) on upload; a whole-process crash only if reached from a spawned goroutine. File uploads are accepted over both the WebSocket `upload_sgf` handler and the HTTP API.

**Remediation:** After parsing, bounds-check: `if x < 0 || x >= len(alphabet) || y < 0 || y >= len(alphabet) { continue }` before indexing.

---

### C-3. Board-size memory exhaustion via `update_settings`

**Locations:** `pkg/room/handlers.go:243` (`size := int(sMap["size"].(float64))`) → `pkg/room/handlers.go:271` (`state.NewState(settings.Size)`) → `pkg/core/board/board.go:61-71` (`NewBoard`).

`handleUpdateSettings` reads `size` directly from the client and passes it, unbounded, to `NewBoard`, which allocates a `size × size` slice-of-slices (`O(size²)` memory). There is **no** range check on this path (the `size > 19` guard in `pkg/state/state.go:196` is only in the SGF-parse path, not here).

A client sending `size = 100000` requests ~10 billion cells → immediate OOM / crash.

> **Validation result (confirmed):** one unauthenticated `POST /api/v1/room/{id}` with `size:20000` grew the server's resident memory from ~80 MB to ~626 MB and retained it. `size:200000` (~320 GB) exhausts RAM and the process is OOM-killed — an outcome `recover()` cannot catch.

**Impact:** Unauthenticated remote memory-exhaustion DoS. Reachable on any password-less room, and via the HTTP API (C-7) against any room.

**Remediation:** Validate `size ∈ {9, 13, 19}` (or `1 ≤ size ≤ maxBoardSize`) in `handleUpdateSettings` before use, and defensively clamp/reject in `NewBoard`.

---

### C-4. No maximum WebSocket message size + no read deadline  ·  **Corrected: High (mechanism was mis-stated)**

**Location:** `pkg/event/channel.go:88-126` (`readPacket` / `readBytes`).

> **Validation result:** the original "single 4-byte frame → instant ~4 GB allocation" is **incorrect**. `readBytes` does *not* pre-allocate the declared length; it grows the buffer 64 bytes at a time only as bytes actually arrive. So the real defects are: (a) **no upper bound on message size** — a client can make the server buffer as much as it is willing to send, per connection, with the 1 MB upload check applied only *after* full buffering; and (b) **no read deadline** — a client can send a large length prefix then stall, pinning a goroutine and partial buffer indefinitely (this is the H-4 slow-loris).

```go
length := binary.LittleEndian.Uint32(lengthArray)   // client-controlled, up to 4 GiB
if length > 1024 {
    data, err = ec.readBytes(int(length))   // grows as data arrives, no ceiling
} else {
    data = make([]byte, length)
}
```

(Additionally, the fixed-size read uses `ec.ws.Read(data)` and ignores the returned count — a short read silently trusts a partial/zeroed buffer; use `io.ReadFull`.)

**Impact:** Unbounded per-connection memory buffering and goroutine/connection pinning (slow-loris); memory-exhaustion DoS when combined across many connections.

**Remediation:** Reject `length > maxMessageBytes` (e.g. 1–2 MB) **before** entering `readBytes`, close the connection on violation, and set a read deadline for assembling each message. Use `io.ReadFull` for both the header and the body.

---

### C-5. ZIP bomb — unbounded in-memory decompression

**Location:** `internal/zip/zip.go:37-46` (`io.ReadAll(rc)` per entry, appended into a slice, no caps).

`Decompress` opens every entry and `io.ReadAll`s it with no per-entry limit, no total limit, and no entry-count limit, retaining every entry's bytes in the returned slice. A few-KB "zip bomb" that inflates to gigabytes (or an archive declaring millions of entries) exhausts memory. The 1 MB check upstream applies to the *compressed* upload only — decompression ratio is unbounded.

Note: there is no zip-slip (path-traversal) risk here because entry names are never used to write files — good — but the resource-exhaustion risk is real.

> **Validation result (confirmed):** a crafted 510 KB archive (one entry of zeros) decompressed to **536 MB** in memory via `internal/zip.Decompress` — a ~1000× amplification with no cap. Scaling the entry size or count OOM-kills the process.

**Impact:** Unauthenticated OOM DoS from a tiny upload.

**Remediation:** Enforce a per-entry cap via `io.LimitReader(rc, maxPerFile)`, a running total-bytes budget, and a maximum entry count (reject `len(zipReader.File) > N`). Consult `file.UncompressedSize64` and reject before reading when it exceeds the budget.

---

### C-6. Stack overflow via deeply nested SGF (unbounded recursion)  ·  **Validated whole-server crash**

**Location:** `pkg/core/parser/sgfparser.go:214-255` (`parseBranch` recurses per `(`); reachable from both the clean and dirty SGF paths.

`parseBranch` calls itself for every `(` with no depth cap. A Go **stack overflow is a `fatal error` that `recover()` cannot catch** — so unlike the panics in C-1/C-2, `net/http` does **not** contain this; the whole process dies.

> **Validation result (confirmed end-to-end):** the `upload_sgf` *string* branch caps decoded input at 1 MiB, which limits `(` depth below the overflow threshold — so that path is safe. **But the array branch has no cap** (see the "Uncapped array branch" finding). This unauthenticated request killed the server with `fatal error: stack overflow`:
> ```
> POST /api/v1/room/{id}
> {"event":"upload_sgf","value":["<base64 of '(' × 12,000,000>"]}
> ```
> Measured threshold in the server's goroutine: no crash at ~2 M frames, `fatal error: stack overflow` by ~8–12 M.

**Impact:** Unauthenticated single-request hard crash of the entire server (all rooms, all users).

**Remediation:** Thread a depth counter through `parseBranch` and error out past a hard cap (e.g. 1000), or rewrite iteratively with an explicit heap stack. **Also apply the 1 MiB cap to the array branch** (see below).

---

### C-7. Unauthenticated state manipulation + crash via HTTP API

**Location:** `pkg/hub/apiv1router.go` — `POST /api/v1/room/{board}`.

```go
room := h.GetOrCreateRoom(board)
data, err := io.ReadAll(r.Body)        // no size limit
evt, err := event.EventFromJSON(data)
evt = room.HandleAny(evt)              // arbitrary event type, no auth
```

This endpoint lets **any unauthenticated HTTP client** create a room and dispatch **any event** to it — `update_settings`, `upload_sgf`, `graft`, board commands — with no authentication and no request-body size limit. It is a clean, scriptable trigger for the exhaustion/crash bugs above without needing a WebSocket, and its `io.ReadAll(r.Body)` is itself an unbounded-memory vector (see M-2).

> **Validation result:** confirmed as the delivery vector for the whole-server crashes — the C-6 and H-7 array-upload bodies POSTed here killed the process. Note that a *panic*-based payload (e.g. `update_settings` with a wrong-typed value) is caught by `net/http`'s recover (server survives, one request 500s); the crashes come from the stack-overflow/OOM payloads, not the panics.

**Impact:** Full unauthenticated control over any room's state, plus a one-line `curl` that delivers a whole-server crash.

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

### H-6. Board size from NGF/SGF  ·  **Mitigated — not exploitable (false positive)**

**Location:** `pkg/core/parser/ngfparser.go:122` (`size, err := p.parseInt()`).

> **Validation result:** the original claim that a huge NGF/SGF size reaches `board.NewBoard` and OOMs is **wrong**. The NGF parser only stores `size` as the `SZ` *string* field and never allocates on it. The only path from parsed SGF/NGF to `NewBoard` is `state.FromSGF`, which **clamps `size > 19`** (`pkg/state/state.go:196`) and returns `"unsupported board size"` before allocating — confirmed with `state.FromSGF("(;SZ[50000])")`. The genuine unclamped board-size DoS is **C-3** (`update_settings`), which does *not* go through this clamp.

**Residual note (not a DoS):** `parseMove` uses `byte(size)` (`ngfparser.go:65`), which truncates for `size > 255` and yields garbage coordinates — a data-integrity nit worth a range check, not a security finding.

### H-7. Stack overflow in tree `toSGF`/`Copy` recursion  ·  **Validated whole-server crash (elevated to Critical)**

**Location:** `pkg/core/parser/parser.go:51-83` (`SGFNode.toSGF`), `pkg/core/tree/tree.go:149-170` (`TreeNode.Copy`).

A long linear game (`(;;;;…)` with millions of nodes) produces a deep chain. `toSGF` and `Copy` recurse once per level (unlike `Fmap`, which is iterative), overflowing the stack — an unrecoverable `fatal error` that `net/http` cannot catch.

> **Validation result (confirmed end-to-end):** `parser.Merge` calls `toSGF`, and `Merge` runs only when **≥2** SGFs are uploaded. This unauthenticated request killed the server, with the crash trace showing `(*SGFNode).toSGF`:
> ```
> POST /api/v1/room/{id}
> {"event":"upload_sgf","value":["<b64 of '(' + ';'×12,000,000 + ')'>","<same>"]}
> ```
> Delivered through the same **uncapped array branch** as C-6.

**Remediation:** Rewrite `toSGF` and `Copy` iteratively, or enforce a depth cap at parse time; and cap the array-branch input size.

---

### Uncapped `upload_sgf` array branch (crash-scale delivery path)  ·  High

**Location:** `pkg/room/handlers.go:150-170`.

`handleUploadSGF` enforces the `len(decoded) > 1<<20` ("file exceeds the 1MB maximum") check **only** on the string-value branch. When `value` is a JSON **array**, each element is base64-decoded and concatenated with **no size check**, then passed to `parser.Merge`. This is the delivery path that makes C-6 and H-7 exploitable at crash scale (a >8 MB payload that the string branch would reject). **Remediation:** apply the same 1 MiB (and element-count) cap to the array branch before parsing/merging.

---

## 5. Medium findings

> **All Medium findings are now PoC-verified.** Runnable: `m2` (unbounded body), `m3` ★ (`/debug` leak), `m4` ★ (SSRF redirect-follow), `m5` ★ (Twitch challenge echo), `m7` (coord/board OOB, recovered), and `c1`/`c2` (the two recovered panics downgraded from Critical); M-6 is `a1`. M-1 and M-8 are verified by code inspection (a config fact and a constant, not a runnable exploit). Each Medium is rated for the reverse-proxy/Kubernetes threat model in **[§11](#11-effectiveness-behind-a-reverse-proxy--in-kubernetes)**.

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

1. **Stop the confirmed whole-server crashes first:** bound recursion in `parseBranch` (C-6) and `toSGF`/`Copy` (H-7); cap the `upload_sgf` **array branch** (the delivery path); cap board size (C-3); cap zip output + entry count (C-5). These are the trivially-triggerable unauthenticated hard crashes proven in §0.
2. **Close the unauthenticated delivery surface:** authenticate/limit `POST /api/v1/room/{board}` and cap its body (C-7, M-2); cap WebSocket message size + add a read deadline (C-4).
3. **Lock down the socket surface:** validate `Origin` (H-1); connection/room caps + rate limiting (H-2, H-3, M-8); HTTP timeouts (M-1); gate `/debug` (M-3).
4. **Integration auth:** fail-closed on empty Twitch secret (H-5, M-5).
5. **Robustness (lower urgency — net/http already contains the request-path panics):** comma-ok type checks + `recover()` in spawned goroutines (C-1, C-2, M-6, M-7).
6. **Hardening:** all Low items + §7.

---

## 9. Scope, caveats & positives

**Reviewed as safe / done well:**
- Passwords are hashed with **bcrypt** (`pkg/core/verify.go`) and compared in constant time — correct.
- **SQL is fully parameterized** in `pkg/loader/dbloader.go` — no SQL injection found. (One non-security portability note: `dbloader.go:382` uses double-quoted string literals that would break on Postgres.)
- HTML templates use `html/template` auto-escaping.
- ZIP extraction does not write to disk from entry names — **no zip-slip**.
- No hardcoded secrets are committed in the app config (aside from the sample Postgres/Grafana defaults noted in L-4/L-5).
- No `InsecureSkipVerify` / disabled TLS verification anywhere in outbound clients.

**Caveats:** The findings began as a static/manual review; the Critical and High items were then **dynamically validated** with the PoCs in [`security/poc/`](security/poc/) against a locally-run instance (see §0), which corrected several severities. Items not exercised (most Medium/Low) remain static-only and are labelled by their code location. Line numbers reference the repository state at assessment time. Third-party dependency internals were not audited beyond version identification. Validation ran against the default in-memory configuration; behaviour behind a production reverse proxy (which may impose its own limits) was not tested.

---

## 10. Second-pass: new crash surfaces (multi-agent hunt)

A follow-up hunt targeted three questions the first pass did not fully answer: **new** attack surfaces, **stacking** low-severity issues into a crash, and **unrecoverable** session/board crashes. It produced 21 candidates; 16 survived adversarial verification against the `recover()` boundary. Every item below was checked for *which goroutine it runs in* — the decisive factor for whether a panic is contained (request goroutine) or fatal (spawned goroutine / runtime-fatal / persisted). Findings marked **★ empirically reproduced** were run locally.

### A) New confirmed whole-server crashes

#### P2-A1 — `Board.Set` nil / out-of-bounds via the OGS review goroutine · **Critical, new ★**
- **Location:** `pkg/core/board/board.go:127-129` (`b.Points[c.Y][c.X] = col`, no nil/bounds guard), reached from `pkg/room/plugin/ogs.go:327-349`.
- **Why it crashes the whole server:** the OGS plugin runs its receive/parse loop in `go o.loop(...)` (`ogs.go:198`) — a **spawned goroutine outside** net/http's per-request `recover()`. There is no `recover()` anywhere in `pkg/`. So a panic here aborts the whole process (unlike the request-path panics C-1/C-2).
- **The bug:** `Board.Set` is unguarded, but its siblings are not — `Get` (`board.go:131`) is nil-and-bounds-checked and `SetMany` (`board.go:141`) uses `c.Valid`. `Board.Legal` calls the guarded `Get` first (returns `Empty` for an off-board/nil coord, so the "already a stone" check *passes*) and then calls the **unguarded** `Set` → panic. Reproduced: `Board.Move` with `(1000,1000)` or `(-1,-1)` → `runtime error: invalid memory address or nil pointer dereference`.
- **Unauthenticated trigger:** create a review/demo on `online-go.com` (free account) containing an off-board move or a pass (`".."` → nil coord); open a WebSocket to any password-less room; send `{"event":"request_sgf","value":"https://online-go.com/review/<id>"}`. When OGS pushes the move, `loop` → `AddStonesToTrunk` → `smartGraft` → `board.Move` → `Set` panics in the spawned goroutine → server down. Even *non-malicious* reviews with unusual data can hit it.
- **Fix:** guard `Board.Set` (`c != nil && c.Valid(size)`); reject nil/off-board coords in `Legal` before `Set`; comma-ok the OGS move parsing; wrap `loop()` in `defer recover()`.

#### P2-A2 — OGS `loop()` unchecked type assertions (cluster) · **High/Critical, new**
- **Locations:** `ogs.go:264,306,310,318,362-364,390-401,411-421` — `arr[0].(string)`, `payload["m"].(string)`, `int(payload["f"].(float64))` (existence-checked but type-unchecked), `gamedata["moves"].([]any)` (no length guard), `players["black"].(map[string]any)`, `["rank"].(float64)`, etc.
- **Same non-recovered goroutine as P2-A1.** A malformed or merely *variant* OGS frame (a rengo/handicap game whose `players.black` isn't `{username,rank}`, a `moves` entry of length < 2, a wrong-typed `m`/`f`) panics the loop → whole-server crash.
- **Confirmed vs plausible:** the goroutine reachability and crash class are **confirmed**; what is *plausible* (depends on whether OGS relays attacker-chosen JSON *types* verbatim) is some specific wrong-type triggers. P2-A1 is the clean, self-contained crash and does not depend on that. (The verifier rejected an "empty top-level frame → `arr[0].(string)`" trigger: the OGS envelope is server-generated `["<event>", data]`, so that specific mechanism is not producible.)
- **Fix:** comma-ok every assertion in `loop`/`gamedataToSGF`/`gameInfoToSGF`/`initStateToSGF`; bounds-check slice indexes; the `defer recover()` in `loop()` alone converts this whole class from whole-server to contained.

### B) Unrecoverable / persistent poison pill

#### P2-B1 — Colon-less `LB` label bricks a board on every load · **High (Critical if OGS active), new ★**
- **Location:** `pkg/state/frame.go:131` — `generateMarks` does `spl := strings.SplitN(lb, ":", 2); text := spl[1]` with **no length guard** (the PX/Pen branch at `frame.go:142` correctly guards with `if len(spl) != 5 { continue }`).
- **Why it is unrecoverable:** `FromSGF` accepts `LB[z]` (a label with no colon) and stores it — parse succeeds. `UploadSGF` calls `SetState` (**commits** the poisoned state) *before* generating a frame, so the subsequent `GenerateFullFrame` panic never rolls it back. `ToSGFIX` writes `LB[z]` back verbatim, and `Hub.Save` persists it. On restart, `Hub.Load → room.Load → FromSGF` re-poisons the room; it loads clean and then **panics on the first `RegisterConnection → GenerateFullFrame`** (`room.go:441`). Reproduced: `(;GM[1]FF[4]SZ[19]LB[z])` → `FromSGF` OK, `GenerateFullFrame` → `index out of range [1] with length 1`.
- **Recover framing (important):** each individual join panic is in the request goroutine and *is* recovered → the server survives, but the **room is permanently unjoinable** and the poison **survives restart** — the "per-room session that crashes on every access" the task asked about. **Escalation:** if the poisoned room has the OGS plugin active, the same `generateMarks` runs inside the OGS spawned goroutine (`BroadcastFullFrame`) → **unrecovered → whole-server crash**.
- **Unauthenticated trigger:** `POST /api/v1/room/{id}` (or ws) with `{"event":"upload_sgf","value":"KDtHTVsxXUZGWzRdU1pbMTldTEJbel0p"}` (base64 of the SGF above) on any password-less room.
- **Fix:** `if len(spl) != 2 { continue }` at `frame.go:131`; validate `LB` values in `FromSGF` so malformed marks are never committed or persisted.
- **Rejected as poison pills (verifier):** `removeMarkCommand` `value[:2]` (`commands.go:256`) — durable but only evaluated on an explicit `remove_mark` command, and recovered per-connection (also, `&&` short-circuits, so only the `LB` branch slices — `SQ`/`TR` do not panic); and the GIB `alphabet[x]` panic — GIB is never persisted (rooms are stored as clean SGF), so it is recovered-per-connection only.

### C) Stacking chains → exhaustion / OOM (fatal, bypass `recover()`)

The terminal state of these is a Go-runtime **OOM**, which is fatal regardless of which goroutine allocates. Individually slow; the point is they **compose**, and `graft` removes the usual gates.

- **P2-C1 — `graft` bypasses `authorized` *and* `outsideBuffer` · High, new.** `pkg/room/handlers.go:74` — `"graft": chain(r.handleEvent, r.broadcastFullFrameAfter)` is the only mutating handler with **neither** the password gate nor the rate-limit buffer (every sibling has both). So `graft` mutates **password-protected** rooms without ever sending `checkpassword`, unthrottled. This is the multiplier under C2–C4. **Fix:** add `r.authorized` and `r.outsideBuffer` to the graft chain.
- **P2-C2 — Unbounded tree growth + quadratic full-frame rebroadcast · High, new.** `smartGraft` (`edit.go:271`) inserts every new move into `s.nodes` with no cap (`GetNextIndex` has no ceiling), and each `graft` re-serializes the *entire* tree (`saveTree` Fmap + `MaxDepth` a second Fmap, both O(n)) and broadcasts it to every connection → `O(k²·conns)` CPU and unbounded heap; the persisted SGF also inflates every future `Load`. Distinct from the recursion crashes (Fmap is iterative) and from the board-size OOM (which is auth-gated). **Fix:** per-room node cap; incremental frames for graft.
- **P2-C3 — OGS fd + goroutine leak on every `request_sgf` · High, new.** `End()`/`closeOGS` set `o.Exit=true` but **never** call `o.Socket.Close()` (`ogs.go:201`). After deregister, `readSocketToChan` stays parked in `Socket.Read` and `loop` on `<-socketchan`; setting `Exit` cannot wake either. Net leak per event: **2 goroutines + 1 TCP fd** to online-go.com, unreclaimed and unthrottled (attacker is `lastUser`, so `outsideBuffer` is bypassed). **Fix:** `o.Socket.Close()` in `End()`; read deadline; cap concurrent connectors per room.
- **P2-C4 — Uncapped frame length + uncapped persisted/broadcast fields · Medium/High.** Reconfirms C-4 (no max declared length, no read deadline; the 1 MB cap is inside `handleUploadSGF`, after the read) — and note the corrected mechanism (incremental growth, not an instant 4 GB). Stacks with **`update_nickname`** (`handlers.go:63`): no `authorized`, no `outsideBuffer`, no length cap — an oversized nick is held in `r.nicks` and the full N-entry map is re-marshalled to all N connections on every join/leave/nick-change (`N²·nick`); and with **uncapped comment text** appended into a persisted SGF field. **Fix:** length-cap frames/nicks/comments; gate `update_nickname`.
- **P2-C5 — Unbounded per-room `auth` map · Medium, new (accelerant).** `SetAuth`/`SetAuthAll` write `r.auth[uuid]=true` but there is **no `delete(r.auth,…)` anywhere** — `DeregisterConnection` prunes only `conns`, the `Handle` defer only `nicks`. Reconnect (fresh UUID) → re-auth grows the map for the room's ~24h life; same UUIDs also leak into `message.notified`. Slow alone; an OOM accelerant across thousands of flooded rooms. (`lastMessages` at `room.go:39` is dead code — never written — not a leak.) **Fix:** delete `auth`/`notified` entries on disconnect.

### D) New unguarded panic sites — contained (recovered), fix for defense-in-depth

Same *contained* class as C-1/C-2 (each kills only the issuing connection) but at new locations; each becomes fatal if ever reached from a spawned goroutine, so guarding them also closes escalation doors:
- **D1 — `commands.go:256`** `value[:2]` slice-bounds panic on a 1-char `LB` value via `remove_mark`.
- **D2 — `coord.FromInterface`** (`coord.go:249`, `int(v.(float64))`) and other decoder assertions in `command_decoder.go` on wrong-typed command args.
- **D3 — board/coord out-of-range** in `Score`/`Move` paths on crafted coords (companion to P2-A1 in the request path).

### Answering the three questions directly

1. **New attack surfaces:** yes — the **OGS review plugin** is the standout (A1/A2/C3): it parses attacker-influenceable data in an un-recovered goroutine and leaks resources. The **state/command layer** (graft, labels, nicknames) and the **persistence round-trip** were also largely un-audited before this pass.
2. **Stacking low-severity → crash:** yes — `graft` (C1) unlocks unbounded tree growth (C2); OGS re-connect leaks (C3) and the `auth`-map/nick leaks (C4/C5) each trend to OOM, which is fatal and bypasses `recover()`. Room-flooding (H-2) multiplies all of them. And crash-to-force-reload (C-6) **stacks with the poison pill**: crash the server, and poisoned rooms come back bricked.
3. **Unrecoverable session/board crash:** yes — **P2-B1** (colon-less `LB`) bricks a board on every load and survives restart; the earlier label-escaping bug (below) corrupts persisted labels on reload. Both are unauthenticated on the default password-less rooms.

### Also noted (lower severity, from direct review)

- **Label escaping is not round-trip safe.** The `label` command stores raw client text into `LB` (`commands.go:238`), and both serializers escape `]`→`\]` but **not** a literal `\` (`state.go:144`, `parser.go:64`). A label ending in `\` serializes to `[value\]`; on reload the parser (`sgfparser.go` `parseField`) consumes the `\]` as an escaped literal, so the field swallows the following `IX[n]`/field. Reproduced: standard `ToSGFIX` saves have a trailing `IX[n]` that supplies a terminator, so this **corrupts** labels/indices on reload rather than hard-failing — a persistent data-integrity bug, Medium, unauthenticated. (A field that is genuinely terminal reparses to `couldn't detect filetype` and the board is dropped.) **Fix:** also escape `\` in both serializers.

---

## 11. Effectiveness behind a reverse proxy / in Kubernetes

This section answers a specific deployment question: **which findings still bite when the attacker has no direct/shell access to the server, the app runs in Kubernetes, and all traffic is behind a reverse proxy / ingress?** Every Critical, High, and Medium finding now has a runnable PoC in [`security/poc/`](security/poc/) (Medium PoCs added: `m2 m3 m4 m5 m7`; `c1 c2` cover the two downgraded Criticals; `a1` covers M-6). The verdicts below were reasoned against — and where marked ★, empirically reproduced against — a locally-run instance.

### Threat model **D**

- Attacker is a **remote client only** — no shell on the pod/node, no `kubectl`, no cluster network foothold.
- **Kubernetes:** the pod has a **memory limit** (breach → `OOMKilled`) and a **liveness probe** that **auto-restarts** a crashed/hung pod in seconds. Because all room state is **in-memory**, the app is effectively **single-instance** (multiple replicas would split rooms across pods and break the app unless sticky-session + shared state, which it is not). Persistence is a **shared DB** (Postgres, or a PVC-backed SQLite) that **survives pod restarts**.
- **Reverse proxy / ingress:** assume typical hardening — an **HTTP request-body cap** (e.g. nginx `client_max_body_size`, commonly ~1 MB), **read/send timeouts** (e.g. 60 s), and it **tunnels WebSocket** frames after upgrade (no body-size cap applies to WS payloads; only an idle-timeout governs a silent WS).

### Two facts that decide most rows

1. **The proxy caps HTTP bodies but *tunnels* WebSocket.** Every crash reachable through `upload_sgf`/the WS framing is deliverable over the WebSocket regardless of `client_max_body_size`. **★ Confirmed:** the C-6 12 MB array-upload, blocked as a 12 MB HTTP POST by a 1 MB cap, crashed the server with `fatal error: stack overflow` when delivered over the WebSocket. **So the proxy body cap is not a mitigation for the crash bugs.**
2. **K8s auto-restart heals *transient* crashes but not *persisted* state.** OOM/stack-overflow crashes become a **repeatable transient DoS** (attacker re-sends, the pod flaps), but the **poison-pill P2-B1 and the persisted-corruption bugs survive the restart** — the pod reloads the poison and re-bricks. Under this model **P2-B1 is the single most dangerous finding**, precisely because self-healing does not touch it.
3. **SSRF (M-4) is an *egress* problem — the ingress proxy is irrelevant.** Only a Kubernetes **egress NetworkPolicy** (or a locked-down egress) limits it, and the blast radius is *larger* in K8s: cluster-internal ClusterIP services and the cloud metadata endpoint `169.254.169.254` (IAM credentials) become reachable from the pod.

### Effectiveness table

Legend — **Yes** = works as-is under D · **WS** = works via WebSocket (HTTP vector capped by proxy) · **Partly** = blunted, not prevented · **Cond.** = needs a precondition · **Mitigated** = proxy/K8s largely prevents · **Per-conn** = only the attacker's own connection, no shared impact · **↻transient** = crashes but pod auto-restarts (repeatable) · **⚑persistent** = survives restart.

| ID | Sev | PoC | Effective under D? | Why / K8s–proxy nuance |
|----|-----|-----|--------------------|------------------------|
| **P2-B1** | Crit | `b1` ★ | **Yes ⚑persistent** | `LB[z]` upload is tiny (passes any body cap); poison is stored in the shared DB → **auto-restart reloads it**; board bricked forever; whole-server crash-loop if OGS active. *The standout under D.* |
| **C-6** | Crit | `c6` ★ | **Yes (WS) ↻transient** | 12 MB HTTP POST capped by proxy, but delivered over the tunneled WebSocket → confirmed stack overflow. Pod restarts; attacker re-sends. |
| **H-7** | Crit | `h7` ★ | **Yes (WS) ↻transient** | Same WS channel, two-element array → `toSGF` overflow. |
| **C-3** | Crit | `c3` ★ | **Yes ↻transient** | `size:200000` is a *tiny* request — passes every body cap, HTTP or WS. OOMKilled → restart → repeatable. |
| **C-5** | Crit | `c5` ★ | **Yes (WS) ↻transient** | ~512 KB may pass the HTTP cap; larger bombs via WS. OOM → restart. |
| **C-7** | Crit | `c7` ★ | **Partly / Yes** | Endpoint reachable through the proxy. Unauth *state control* + small payloads: Yes. Large crash bodies capped on HTTP → deliver via WS instead. |
| **P2-A1 / M-6** | Crit | `a1` ★ | **Cond. → Yes ↻transient** | Trigger is a tiny `request_sgf`; needs the OGS feature + egress to online-go.com (default on) + an attacker-authored review. Non-recovered goroutine → whole-server crash. |
| **P2-A2** | High | `a1` | **Cond. → Yes** | Same OGS goroutine; malformed/variant upstream frame. |
| **H-1** | High | `h1` ★ | **Yes** | Origin unvalidated; the proxy forwards the browser-set `Origin`. Any website drives a visitor's boards — the most relevant risk for "board on my website." |
| **H-2** | High | `h2` ★ | **Yes** | Normal WS to arbitrary room IDs; single in-memory replica accumulates rooms (1 h lifetime — M-8). |
| **H-3** | High | `h3` ★ | **Partly** | Ingress/proxy per-IP connection limits may cap the flood; without them, Yes. |
| **H-4** | High | `h4` | **Partly** | WS tunneled; the proxy idle-timeout (~60 s) closes a silent socket, but a slow *drip* keeps it alive and buffering. |
| **C-4** | High | `c4` | **Partly** | Same as H-4 plus unbounded per-message buffering; proxy idle-timeout blunts the pure stall. |
| **H-5** | High | `h5` ★ | **Cond.** | Only if the Twitch integration is enabled **and** the secret is empty; the webhook is public via the proxy, so a forged event is accepted. |
| **P2-C1** | High | (graft) | **Yes** | Small `graft` commands pass the proxy; mutate even password-protected rooms (no `authorized`/`outsideBuffer`). Multiplier for C2–C4. |
| **P2-C2** | High | (graft loop) | **Yes ↻/⚑** | Tiny grafts grow the tree unbounded → OOM → restart (repeatable); the **persisted SGF also inflates**, slowing every reload (a creeping, semi-persistent escalation). |
| **P2-C3** | High | (req_sgf loop) | **Cond.** | Needs OGS egress; each `request_sgf` leaks 2 goroutines + 1 fd → OOM/fd-exhaustion → restart. |
| **M-4** | Med | `m4` ★ | **Cond., high impact** | **Egress problem — ingress proxy irrelevant.** Needs an open-redirect on an approved host (or the OGS direct-`Fetch` paths). Without an egress NetworkPolicy, reaches ClusterIP services + `169.254.169.254` IAM metadata. |
| **M-3** | Med | `m3` ★ | **Yes** | Normal unauthenticated `GET /b/{id}/debug` through the proxy leaks any room's full state, **including password-protected rooms**, unless ops explicitly blocks the path. |
| **M-8** | Med | (inspection) | **Yes (amplifier)** | 3600 s heartbeat keeps abandoned rooms (+ goroutine) alive ≥1 h; worsens H-2 on the single replica. |
| **M-5** | Med | `m5` ★ | **Yes (low impact)** | Public webhook reflects arbitrary `challenge` text unauthenticated; mainly a spec/integrity gap. |
| **P2-C4** | Med | (nick) | **Yes** | `update_nickname` (no auth/no cap) → oversized nick re-broadcast `N²` per room. |
| **P2-C5** | Med | (reconnect) | **Yes (slow)** | `auth`/`notified` maps never pruned; OOM accelerant across flooded rooms. |
| Label-escape | Med | (§10) ★ | **Yes ⚑persistent** | Label ending in `\` corrupts persisted labels/indices on reload (survives restart). |
| **M-2** | Med | `m2` ★ | **Mitigated (HTTP)** | `client_max_body_size` caps the HTTP body; the uncapped equivalent is the WS path (C-4). |
| **M-1** | Med | (inspection) | **Mitigated** | The front proxy has its own timeouts/buffering and shields the origin from HTTP slow-loris. *Deployment reduces this one.* |
| **C-1** | Med | `c1` ★ | **Per-conn** | `net/http` recovers the request-goroutine panic in every deployment; only the attacker's own connection drops. |
| **C-2** | Med | `c2` ★ | **Per-conn** | As C-1 (GIB panic on upload is recovered). |
| **M-7** | Med | `m7` ★ | **Per-conn** | `coord`/board OOB panic in the request path is recovered. (Same defect is fatal via the OGS goroutine — that's A1.) |

### Bottom line for deploying behind a proxy in K8s

- The reverse proxy **does not** protect against the crash/DoS findings that matter: the stack-overflow and OOM crashes are all deliverable over the **tunneled WebSocket**, and C-3 is a tiny request that passes any body cap. Treat the proxy body/timeout limits as protecting only the plain-HTTP `/api/v1` and `/ext` surfaces (which meaningfully mitigates M-1/M-2).
- K8s auto-restart turns most crashes into a **repeatable transient DoS** rather than a permanent outage — *except* **P2-B1** (and the label-escape corruption), which **persist in the DB and survive the restart**. Fix `frame.go:131` (and the `LB` validation) before anything else if you value uptime, because self-healing will not save you there.
- Two risks are **worse** in K8s than on a single box: **M-4 SSRF** (cluster-internal services + cloud IAM metadata — add an egress `NetworkPolicy`) and **M-3 /debug** (silent cross-room info disclosure — block the path at the ingress). Neither is addressed by the reverse proxy.
- Because room state is in-memory, run it as a single instance (or add sticky sessions + shared state); note that any one crash drops **all** live boards on that pod.
