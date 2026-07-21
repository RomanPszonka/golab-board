// N-2 reachability check (second-reviewer pass). Copy into pkg/room/plugin/ and run:
//
//	go test -run TestN2ReachabilityBlockedByN4 -v ./pkg/room/plugin/
//
// Demonstrates that the N-2 SGF-injection payload does NOT reach gameInfoToSGF/
// gamedataToSGF end-to-end, because it must first pass through readFrameFromChan
// (the JSON-blind bracket counter that is N-4): any game_name containing ']'
// truncates the frame before json.Unmarshal, so the malicious name is dropped.
// The addendum's N-2 PoCs bypass this by calling gamedataToSGF directly.
package plugin

import (
	"encoding/json"
	"strings"
	"testing"
)

func n2feed(frame []byte) ([]byte, error) {
	ch := make(chan byte, len(frame)+8)
	for _, b := range frame {
		ch <- b
	}
	close(ch)
	return readFrameFromChan(ch)
}

func n2gamedataFrame(name string) []byte {
	gd := map[string]any{
		"width": 19.0, "komi": 6.5, "game_name": name, "rules": "japanese",
		"players": map[string]any{
			"black": map[string]any{"username": "b", "rank": 30.0},
			"white": map[string]any{"username": "w", "rank": 30.0},
		},
		"initial_player": "black",
		"initial_state":  map[string]any{"black": "", "white": ""},
		"moves":          []any{[]any{15.0, 15.0}},
	}
	b, _ := json.Marshal([]any{"game/999/gamedata", gd})
	return b
}

func TestN2ReachabilityBlockedByN4(t *testing.T) {
	cases := []struct {
		name   string
		gname  string
		inject bool
	}{
		{"benign control", "MyGame", false},
		{"injection x]TR[", "x]TR[", true},
		{"injection x]LB[aa:PWNED]ZZ[", "x]LB[aa:PWNED]ZZ[", true},
	}
	for _, tc := range cases {
		frame := n2gamedataFrame(tc.gname)
		out, err := n2feed(frame)
		reached := false
		var sgf string
		if err == nil && out != nil {
			arr := make([]any, 2)
			if json.Unmarshal(out, &arr) == nil {
				if topic, ok := arr[0].(string); ok && topic == "game/999/gamedata" {
					if payload, ok := arr[1].(map[string]any); ok {
						reached = true
						sgf = (&OGSConnector{}).gamedataToSGF(payload)
					}
				}
			}
		}
		t.Logf("[%s] gname=%q frame=%dB readFrameFromChan.out=%dB (truncated=%v) reachedConverter=%v",
			tc.name, tc.gname, len(frame), len(out), len(out) < len(frame), reached)
		if reached && (strings.Contains(sgf, "TR[]") || strings.Contains(sgf, "ZZ[")) {
			t.Errorf("N-2 REACHABLE for %q — injection survived the frame parser (unexpected)", tc.gname)
		}
		if tc.inject && !reached {
			t.Logf("  => BLOCKED: %q never reached gamedataToSGF (N-4 frame parser truncated it)", tc.gname)
		}
		if !tc.inject && !reached {
			t.Errorf("benign frame should have reached the converter but didn't")
		}
	}
}
