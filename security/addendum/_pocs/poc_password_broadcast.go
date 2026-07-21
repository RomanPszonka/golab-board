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
		fmt.Printf("[%s] got: %.400s\n", tag, buf[:n])
	}
}

func main() {
	// observer connects FIRST
	obs, err := websocket.Dial("ws://localhost:8091/socket/b/pwtest", "", "http://localhost:8091/")
	if err != nil { panic(err) }
	defer obs.Close()
	readFor(obs, 1*time.Second, "obs-init")

	// owner connects and sets a password via update_settings
	owner, err := websocket.Dial("ws://localhost:8091/socket/b/pwtest", "", "http://localhost:8091/")
	if err != nil { panic(err) }
	defer owner.Close()
	readFor(owner, 1*time.Second, "owner-init")

	fmt.Println("-- owner sends update_settings with plaintext password")
	settings := `{"event":"update_settings","value":{"buffer":300.0,"size":19.0,"nickname":"owner","black":"","white":"","komi":"","password":"Sup3rSecretPW!"}}`
	if err := send(owner, settings); err != nil { panic(err) }
	readFor(owner, 2*time.Second, "owner-after")

	fmt.Println("-- OBSERVER now reads: did it receive the plaintext password?")
	readFor(obs, 3*time.Second, "obs-after")
}
