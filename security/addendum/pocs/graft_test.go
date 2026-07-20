package zzpoc

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/room"
	"github.com/golab/board/pkg/state"
)

// N-CR-6: graft with off-board letter on a small board -> Board.Set OOB panic
func TestGraftOffBoardLetter(t *testing.T) {
	for _, size := range []int{9, 13, 19} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("size %d: PANIC (graft t1): %v", size, r)
				}
			}()
			s := state.NewState(size)
			cmd := state.NewGraftCommand("t1")
			_, err := cmd.Execute(s)
			fmt.Printf("size %d: graft t1 -> err=%v (no panic)\n", size, err)
		}()
	}
}

// N-CR-7: upload_sgf array with non-string element -> ifc.(string) panic
func TestUploadArrayNonString(t *testing.T) {
	r := room.NewRoom("poc-arr")
	r.DisableBuffers()
	evt := event.NewEvent("upload_sgf", []any{123.0})
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (upload_sgf [123]): %v", r)
		}
	}()
	out := r.HandleAny(evt)
	fmt.Printf("no panic, out=%v\n", out)
}

// control: valid upload still works
func TestUploadValid(t *testing.T) {
	r := room.NewRoom("poc-ok")
	r.DisableBuffers()
	sgf := base64.StdEncoding.EncodeToString([]byte("(;GM[1]FF[4]SZ[19])"))
	evt := event.NewEvent("upload_sgf", sgf)
	out := r.HandleAny(evt)
	fmt.Printf("valid upload: %T\n", out)
}
