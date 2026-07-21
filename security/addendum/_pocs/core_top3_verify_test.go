package zz_verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/state"
)

// N-CR-2: FromInterface returns nil coord + nil error for off-board coords -> nil deref in commands
func TestNilCoord(t *testing.T) {
	s := state.NewState(19)
	evt, err := event.EventFromJSON([]byte(`{"event":"triangle","value":[50,50]}`))
	if err != nil {
		t.Fatalf("bad json: %v", err)
	}
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decoder unexpectedly rejected: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("N-CR-2 CONFIRMED: triangle [50,50] panicked: %v\n", r)
		} else {
			t.Fatalf("no panic")
		}
	}()
	cmd.Execute(s)
}

// N-CR-3: NGF move-line byte becomes an SGF property KEY -> persisted SGFIX unparseable
func TestNGFKeyPoison(t *testing.T) {
	ngfB64 := "TXkgR2FtZQoxOQp3aGl0ZXBsYXllciAxZApibGFja3BsYXllciAyZAp3YmFkdWsKMAowCjYKMjAyNi0wMS0wMQpwCmJsYWNrIHJlc2lnbgoxClBNICBbYWEgIA=="
	raw, _ := base64.StdEncoding.DecodeString(ngfB64)
	s, err := state.FromSGF(string(raw))
	if err != nil {
		t.Fatalf("upload rejected (unexpected): %v", err)
	}
	persisted := s.ToSGFIX()
	fmt.Printf("persisted SGFIX: %s\n", persisted)
	_, err = state.FromSGF(persisted)
	if err != nil {
		fmt.Printf("N-CR-3 CONFIRMED: persisted SGFIX fails to reload: %v (room dropped on restart)\n", err)
		return
	}
	t.Fatalf("persisted file reloaded fine - not vulnerable?")
}

// N-CR-5: PX[NaN:...] -> json.Marshal fails on every frame; persists through ToSGFIX round trip
func TestNaNPen(t *testing.T) {
	sgf := "(;GM[1]FF[4]SZ[19]PB[B]PW[W]PX[NaN:0:0:0:red];B[pd])"
	s, err := state.FromSGF(sgf)
	if err != nil {
		t.Fatalf("upload rejected (unexpected): %v", err)
	}
	frame := s.GenerateFullFrame(state.Full)
	_, err = json.Marshal(frame)
	if err != nil {
		fmt.Printf("N-CR-5 CONFIRMED: full frame fails to marshal: %v\n", err)
	} else {
		t.Fatalf("frame marshaled fine - not vulnerable?")
	}
	// persistence: round trip
	s2, err := state.FromSGF(s.ToSGFIX())
	if err != nil {
		t.Fatalf("reload failed (different bug): %v", err)
	}
	_, err = json.Marshal(s2.GenerateFullFrame(state.Full))
	if err != nil {
		fmt.Printf("N-CR-5 CONFIRMED: poison survives ToSGFIX reload, still unmarshalable: %v\n", err)
		return
	}
	t.Fatalf("poison did not persist")
}
