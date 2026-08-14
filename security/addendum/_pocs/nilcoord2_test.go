package zzpoc

import (
	"fmt"
	"testing"

	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/state"
)

func TestNilCoordLabelLetterNumber(t *testing.T) {
	cases := []struct {
		ty  string
		val any
	}{
		{"label", map[string]any{"coords": []any{50.0, 50.0}, "label": "x"}},
		{"letter", map[string]any{"coords": []any{50.0, 50.0}, "letter": "A"}},
		{"number", map[string]any{"coords": []any{50.0, 50.0}, "number": 3.0}},
		{"remove_stone", []any{-3.0, 2.0}},
		{"square", []any{19.0, 0.0}},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("PANIC %s %v -> %v\n", c.ty, c.val, r)
				}
			}()
			evt := event.NewEvent(c.ty, c.val)
			cmd, err := state.DecodeToCommand(evt)
			if err != nil {
				fmt.Printf("%s: decode err %v\n", c.ty, err)
				return
			}
			s := state.NewState(19)
			_, _ = cmd.Execute(s)
			fmt.Printf("%s: no panic\n", c.ty)
		}()
	}
}
