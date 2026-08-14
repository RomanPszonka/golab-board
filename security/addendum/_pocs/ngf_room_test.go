package zzpoc

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/room"
	"github.com/golab/board/pkg/state"
)

// N-CR-3 end-to-end: upload NGF with key '[', Save, reload like Hub.Load does
func TestNGFPoisonEndToEnd(t *testing.T) {
	r := room.NewRoom("poc-ngf")
	r.DisableBuffers()
	ngf := "My Game\n19\nwhiteplayer 1d\nblackplayer 2d\nwbaduk\n0\n0\n6\n2026-01-01\n0\nblack resign\n1\nPM  [aa  "
	evt := event.NewEvent("upload_sgf", base64.StdEncoding.EncodeToString([]byte(ngf)))
	out := r.HandleAny(evt)
	fmt.Printf("upload response type: %T\n", out)

	// persist (Hub.Save path -> Room.Save -> State.Save)
	saved := r.Save()
	dec, _ := base64.StdEncoding.DecodeString(saved.SGF)
	fmt.Printf("persisted SGFIX: %s\n", string(dec))

	// reload (Hub.Load path -> room.Load)
	_, err := room.Load(saved)
	fmt.Printf("room.Load after restart: err=%v (room DROPPED by Hub.Load on error)\n", err)
}

// N-CR-4: duplicate IX -> cut -> graft nil deref
func TestIXCutGraft(t *testing.T) {
	sgf := "(;SZ[19]GM[1]IX[0](;C[a]IX[3])(;C[b]IX[3]))"
	s, err := state.FromSGF(sgf)
	if err != nil {
		t.Fatalf("FromSGF failed: %v", err)
	}
	// navigate right into child A (preferred child 0 after resetPrefs)
	right := state.NewRightCommand()
	if _, err := right.Execute(s); err != nil {
		t.Fatalf("right failed: %v", err)
	}
	// cut branch A (this deletes map key 3, which ALSO backs tree node B)
	cut := state.NewCutCommand()
	if _, err := cut.Execute(s); err != nil {
		t.Fatalf("cut failed: %v", err)
	}
	// graft at trunk move 1 -> TrunkNum returns 3 -> s.nodes[3] == nil
	graft := state.NewGraftCommand("1 d4")
	defer func() {
		if r := recover(); r != nil {
			t.Logf("PANIC (graft after IX-collision cut): %v", r)
		}
	}()
	if _, err := graft.Execute(s); err != nil {
		t.Fatalf("graft returned error instead of panic: %v", err)
	}
	t.Log("no panic")
}
