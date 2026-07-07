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
