package zzpoc

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/golab/board/pkg/core/parser"
	"github.com/golab/board/pkg/state"
)

func ngfDoc(moveLines string) string {
	return "My Game\n19\nwhiteplayer 1d\nblackplayer 2d\nwbaduk\n0\n0\n6\n2026-01-01\n0\nblack resign\n2\n" + moveLines
}

// N-CR-3: NGF move line byte 4 is used verbatim as an SGF property KEY
func TestNGFKeyInjection(t *testing.T) {
	for _, key := range []byte{'B', 'W', 'C', 'X', ';', '(', ')', '[', ']', '\\', '1', ' '} {
		moves := fmt.Sprintf("PM  %caa  \nPM  %cbb  ", key, key)
		doc := ngfDoc(moves)
		p := parser.New(doc)
		_, err := p.Parse()
		if err != nil {
			fmt.Printf("key %q: parse error %v\n", key, err)
			continue
		}
		sgf := parser.Merge([]string{doc})
		fmt.Printf("key %q -> SGF: %q\n", key, sgf)
	}
}

// end-to-end: FromSGF on NGF with weird keys, then persist (ToSGFIX) and reload
func TestNGFKeyRoundTrip(t *testing.T) {
	for _, key := range []byte{';', '(', '[', ']', '\\', '1', 'C', 'Z'} {
		moves := fmt.Sprintf("PM  %caa  ", key)
		doc := ngfDoc(moves)
		s, err := state.FromSGF(doc)
		if err != nil {
			fmt.Printf("key %q: FromSGF error %v\n", key, err)
			continue
		}
		out := s.ToSGFIX()
		fmt.Printf("key %q -> persisted: %q\n", key, out)
		s2, err2 := state.FromSGF(out)
		fmt.Printf("    reload: ok=%v err=%v\n", s2 != nil, err2)
	}
}

// base64 helper for report
func TestNGFBase64(t *testing.T) {
	doc := ngfDoc("PM  [aa  ")
	fmt.Println(base64.StdEncoding.EncodeToString([]byte(doc)))
}
