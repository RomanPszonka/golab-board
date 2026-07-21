package zzpoc

import (
	"fmt"
	"testing"

	"github.com/golab/board/pkg/core/coord"
	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/state"
)

// N-CR-1: draw command with a short array -> index out of range
func TestDrawShortArray(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (draw short array): %v", r)
		}
	}()
	evt := event.NewEvent("draw", []any{1.0})
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decode error instead of panic: %v", err)
	}
	s := state.NewState(19)
	_, _ = cmd.Execute(s)
	t.Log("no panic")
}

func TestDrawEmptyArray(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (draw empty array): %v", r)
		}
	}()
	evt := event.NewEvent("draw", []any{})
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decode error instead of panic: %v", err)
	}
	s := state.NewState(19)
	_, _ = cmd.Execute(s)
	t.Log("no panic")
}

// N-CR-2: out-of-range coord -> FromInterface returns (nil, nil) -> nil deref in Execute
func TestNilCoordTriangle(t *testing.T) {
	c, err := coord.FromInterface([]any{50.0, 50.0})
	fmt.Printf("FromInterface([50,50]) = %v, err=%v\n", c, err)
	evt := event.NewEvent("triangle", []any{50.0, 50.0})
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	s := state.NewState(19)
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (triangle [50,50]): %v", r)
		}
	}()
	_, _ = cmd.Execute(s)
	t.Log("no panic")
}

func TestNilCoordGotoCoord(t *testing.T) {
	evt := event.NewEvent("goto_coord", []any{-1.0, -1.0})
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	s := state.NewState(19)
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (goto_coord [-1,-1]): %v", r)
		}
	}()
	_, _ = cmd.Execute(s)
	t.Log("no panic")
}

func TestNilCoordMarkdead(t *testing.T) {
	evt := event.NewEvent("markdead", []any{100.0, 100.0})
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	s := state.NewState(19)
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (markdead [100,100]): %v", r)
		}
	}()
	_, _ = cmd.Execute(s)
	t.Log("no panic")
}

func TestNilCoordAddStone(t *testing.T) {
	evt := event.NewEvent("add_stone", map[string]any{"coords": []any{25.0, 3.0}, "color": 1.0})
	cmd, err := state.DecodeToCommand(evt)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	s := state.NewState(19)
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (add_stone [25,3]): %v", r)
		}
	}()
	_, _ = cmd.Execute(s)
	t.Log("no panic")
}

// N-CR-5: negative and zero SZ
func TestNegativeSize(t *testing.T) {
	s, err := state.FromSGF("(;GM[1]FF[4]SZ[-5]PB[B]PW[W])")
	fmt.Printf("FromSGF SZ[-5]: state=%v err=%v\n", s != nil, err)
	if err == nil {
		f := s.GenerateFullFrame(state.Full)
		fmt.Printf("full frame ok, metadata size=%d\n", f.Metadata.Size)
		sgf := s.ToSGFIX()
		fmt.Printf("ToSGFIX: %s\n", sgf)
		s2, err2 := state.FromSGF(sgf)
		fmt.Printf("reload: state=%v err=%v\n", s2 != nil, err2)
	}
}

func TestZeroSize(t *testing.T) {
	s, err := state.FromSGF("(;GM[1]FF[4]SZ[0]PB[B]PW[W])")
	fmt.Printf("FromSGF SZ[0]: state=%v err=%v\n", s != nil, err)
	if err == nil {
		f := s.GenerateFullFrame(state.Full)
		fmt.Printf("full frame ok, metadata size=%d\n", f.Metadata.Size)
	}
}
