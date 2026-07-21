package zzpoc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golab/board/pkg/state"
)

// N-CR-5 persistence: NaN PX survives ToSGFIX -> reload -> still breaks every frame marshal
func TestNaNPersist(t *testing.T) {
	s, err := state.FromSGF("(;GM[1]FF[4]SZ[19]PB[B]PW[W]PX[NaN:0:0:0:red];B[pd])")
	if err != nil {
		t.Fatal(err)
	}
	sgf := s.ToSGFIX()
	fmt.Printf("persisted: %s\n", sgf)
	s2, err := state.FromSGF(sgf)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	frame := s2.GenerateFullFrame(state.Full)
	_, err = json.Marshal(frame)
	fmt.Printf("after reload: frame marshal err=%v\n", err)
}
