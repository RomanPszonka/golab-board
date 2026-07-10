//go:build race

// Package race reproduces the DR-2 / DR-3 data races (SECURITY_ASSESSMENT.md §6)
// under the race detector: run `go test -race ./security/poc/race/`.
//
// Build-tagged `race` (like memoryloader_race_test.go) so these intentionally
// concurrent tests compile and run ONLY under `-race`, never in a plain
// `go test ./...`.
//
// These are torn-read races on tree field slices that are read outside r.mu
// (marshaled / iterated) while another goroutine mutates them under r.mu.
package race

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/room"
)

func mkEvent(typ string, val any, user string) event.Event {
	e := event.NewEvent(typ, val)
	e.SetUser(user)
	return e
}

// DR-2: the frame returned by GenerateFullFrame aliases live node field slices;
// marshaling it outside r.mu races with a concurrent field mutation.
func TestDR2_FrameMarshaledOutsideLock(t *testing.T) {
	r := room.NewRoom("dr2")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() { // mutate the current node's fields under r.mu
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r.HandleAny(mkEvent("update_settings", map[string]any{
				"buffer": float64(250), "size": float64(19), "nickname": "x",
				"black": "PlayerNameThatChanges", "white": "w", "komi": "6.5", "password": "",
			}, "u"))
		}
	}()
	for i := 0; i < 2000; i++ { // read: marshal the full frame outside the lock (as RegisterConnection does)
		f := r.GenerateFullFrame(0)
		_, _ = json.Marshal(f)
	}
	close(stop)
	wg.Wait()
}

// DR-3: Current() returns a node whose Fields alias the live node; iterating them
// (as logAfter does) races with a concurrent mark/label command.
func TestDR3_CurrentFieldsOutsideLock(t *testing.T) {
	r := room.NewRoom("dr3")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r.HandleAny(mkEvent("label", map[string]any{"coords": []any{float64(0), float64(0)}, "label": "lbl"}, "u"))
		}
	}()
	for i := 0; i < 2000; i++ {
		n := r.Current()
		for _, f := range n.AllFields() {
			_ = f.Values
		}
	}
	close(stop)
	wg.Wait()
}
