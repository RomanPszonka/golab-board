package zzpoc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golab/board/pkg/state"
)

// N-CR-6: PX with NaN/Inf survives ParseFloat guard, breaks json.Marshal of every frame
func TestNaNPen(t *testing.T) {
	for _, px := range []string{"NaN:0:0:0:red", "+Inf:0:0:0:blue", "-Inf:1:2:3:4:x"} {
		sgf := fmt.Sprintf("(;GM[1]FF[4]SZ[19]PB[B]PW[W]PX[%s];B[pd])", px)
		s, err := state.FromSGF(sgf)
		if err != nil {
			t.Fatalf("FromSGF failed: %v", err)
		}
		frame := s.GenerateFullFrame(state.Full)
		fmt.Printf("PX[%s]: pens=%+v\n", px, frame.Marks.Pens)
		_, err = json.Marshal(frame)
		fmt.Printf("    json.Marshal(frame) err=%v\n", err)
	}
}

// also confirm normal PX marshals fine (control)
func TestNormalPen(t *testing.T) {
	s, _ := state.FromSGF("(;GM[1]FF[4]SZ[19]PX[1:2:3:4:red];B[pd])")
	frame := s.GenerateFullFrame(state.Full)
	_, err := json.Marshal(frame)
	fmt.Printf("control: err=%v pens=%+v\n", err, frame.Marks.Pens)
}
