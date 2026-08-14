//go:build poc

package plugin

// Security PoC for SECURITY_ASSESSMENT.md finding 1c (High).
//
// The OGS connector's read loop runs in a goroutine spawned by the plugin
// (`go o.loop(...)`, ogs.go:198) and converts online-go.com-controlled JSON into
// SGF using dozens of UNCHECKED type assertions (ogs.go:264-437): board width,
// komi, player objects, ranks, initial state, and every move are asserted to a
// concrete type with no `, ok` guard. Any message whose shape the code does not
// expect — a rengo (team) game where `players.black` is null or an array instead
// of `{username, rank}`, a game missing `width`, a truncated socket frame — makes
// one of these assertions panic. Because the panic happens inside a goroutine the
// plugin spawned itself (not the net/http request goroutine), net/http's
// per-request recover() does NOT catch it, so the panic propagates to the top of
// that goroutine and aborts the whole process — a whole-server crash.
//
// The attacker controls which OGS game/review the connector attaches to (an
// unauthenticated `request_sgf`/connect to an open room with an online-go.com
// URL), and therefore controls the gamedata shape. A single crafted or simply
// unusual game (rengo is public and common) crashes the server for everyone.
//
// This test feeds representative attacker-reachable shapes straight to the
// unexported conversion path and asserts each one panics — reproducing the crash
// deterministically without a live OGS socket. A well-formed 1v1 game is included
// as a control (it must NOT panic).
//
// Because it asserts that the vulnerability *reproduces*, it is build-tagged
// `poc` so it is excluded from the default `go test ./...` — it only runs when
// explicitly requested, and the normal suite stays green after the bug is fixed.
// Run it with:
//
//	go test -tags poc -run TestOGSGamedataCrash_1c ./pkg/room/plugin/

import "testing"

// wellFormedGamedata is a minimal, valid 1v1 gamedata payload — the shape the
// conversion code assumes. It must convert without panicking.
func wellFormedGamedata() map[string]any {
	return map[string]any{
		"width":     19.0,
		"komi":      6.5,
		"game_name": "poc",
		"rules":     "japanese",
		"players": map[string]any{
			"black": map[string]any{"username": "b", "rank": 30.0},
			"white": map[string]any{"username": "w", "rank": 30.0},
		},
		"initial_player": "black",
		"initial_state":  map[string]any{"black": "", "white": ""},
		"moves":          []any{},
	}
}

func didPanic(f func()) (panicked bool, val any) {
	defer func() {
		if r := recover(); r != nil {
			panicked, val = true, r
		}
	}()
	f()
	return
}

func TestOGSGamedataCrash_1c(t *testing.T) {
	// Control: the well-formed shape must NOT panic.
	if p, v := didPanic(func() { _ = (&OGSConnector{}).gamedataToSGF(wellFormedGamedata()) }); p {
		t.Fatalf("control: well-formed 1v1 gamedata should not panic, got: %v", v)
	}

	// Attacker-reachable shapes — each MUST panic. In the real read loop this
	// panic is unrecovered (spawned goroutine) => whole-server crash.
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"rengo: players.black is null", func(m map[string]any) {
			m["players"].(map[string]any)["black"] = nil
		}},
		{"rengo: players.black is an array", func(m map[string]any) {
			m["players"].(map[string]any)["black"] = []any{}
		}},
		{"missing width", func(m map[string]any) { delete(m, "width") }},
		{"width is a string", func(m map[string]any) { m["width"] = "19" }},
		{"missing players", func(m map[string]any) { delete(m, "players") }},
		{"komi is null", func(m map[string]any) { m["komi"] = nil }},
		{"missing rules", func(m map[string]any) { delete(m, "rules") }},
		{"missing initial_state", func(m map[string]any) { delete(m, "initial_state") }},
		{"move entry too short", func(m map[string]any) { m["moves"] = []any{[]any{1.0}} }},
		{"move coord is a string", func(m map[string]any) { m["moves"] = []any{[]any{"a", "b"}} }},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			g := wellFormedGamedata()
			c.mutate(g)
			panicked, val := didPanic(func() { _ = (&OGSConnector{}).gamedataToSGF(g) })
			if !panicked {
				t.Errorf("expected a panic (unrecovered in `go o.loop()` -> whole-server crash); got none")
				return
			}
			t.Logf("CONFIRMED: %q -> panic %v (unrecovered in the OGS loop goroutine -> server crash)", c.name, val)
		})
	}
}
