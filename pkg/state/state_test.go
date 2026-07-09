/*
Copyright (c) 2026 Jared Nishikawa

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package state_test

import (
	"testing"

	"github.com/golab/board/internal/assert"
	"github.com/golab/board/internal/require"
	"github.com/golab/board/internal/sgfsamples"
	"github.com/golab/board/pkg/core/color"
	"github.com/golab/board/pkg/core/coord"
	"github.com/golab/board/pkg/state"
)

func TestState(t *testing.T) {
	s, err := state.FromSGF(sgfsamples.SimpleFourMoves)

	assert.NoError(t, err)
	assert.Equal(t, s.Size(), 19)
}

func TestState2(t *testing.T) {
	input := sgfsamples.SimpleFourMoves
	s, err := state.FromSGF(input)
	assert.NoError(t, err)

	sgf := s.ToSGF()
	sgfix := s.ToSGFIX()

	assert.Equal(t, len(sgf), len(input))
	assert.Equal(t, len(sgfix), 132)
}

func TestState3(t *testing.T) {
	input := sgfsamples.SimpleTwoBranches
	s, err := state.FromSGF(input)
	assert.NoError(t, err)

	sgf := s.ToSGF()
	assert.Equal(t, len(sgf), len(input))
}

func TestMultifieldSZ(t *testing.T) {
	input := sgfsamples.MultifieldSZ
	_, err := state.FromSGF(input)
	assert.NotNil(t, err)
}

func TestSGFIX(t *testing.T) {
	input := sgfsamples.SGFIX
	s, err := state.FromSGF(input)
	assert.NoError(t, err)
	assert.Equal(t, s.Root().Index, 100)
}

func TestParseTTPAss(t *testing.T) {
	input := sgfsamples.PassWithTT
	s, err := state.FromSGF(input)
	assert.NoError(t, err)
	node := s.Nodes()[358]
	assert.Equal(t, node.XY, nil)
}

func TestNewState(t *testing.T) {
	s1 := state.NewState(19)
	s2 := state.NewEmptyState(19)
	assert.Equal(t, s1.GetNextIndex(), 1)
	assert.Equal(t, s2.GetNextIndex(), 0)
}

func TestHandicap(t *testing.T) {
	s, err := state.FromSGF(sgfsamples.Handicap1)
	assert.NoError(t, err)
	root := s.Root()
	assert.Equal(t, len(root.GetField("AB")), 4)
}

func TestMissingSZ(t *testing.T) {
	s, err := state.FromSGF(sgfsamples.MissingSZ)
	assert.NoError(t, err)
	sz := s.Size()
	require.Equal(t, sz, 19)
}

func TestSuicide(t *testing.T) {
	_, err := state.FromSGF(sgfsamples.Suicide1)
	assert.NotNil(t, err)
}

func TestHeadColor(t *testing.T) {
	s, err := state.FromSGF(sgfsamples.SimpleEightMoves)
	require.NoError(t, err)
	assert.Equal(t, s.HeadColor(), color.White)
}

func TestGetColorAt1(t *testing.T) {
	s, err := state.FromSGF(sgfsamples.SimpleEightMoves)
	require.NoError(t, err)
	assert.Equal(t, s.GetColorAt(3), color.Black)
}

func TestGetColorAt2(t *testing.T) {
	s, err := state.FromSGF(sgfsamples.SimpleEightMoves)
	require.NoError(t, err)
	assert.Equal(t, s.GetColorAt(-1), color.Empty)
}

func TestSetNextIndex(t *testing.T) {
	s := state.NewState(9)
	s.SetNextIndex(100)
	assert.Equal(t, s.GetNextIndex(), 100)
	assert.Equal(t, s.GetNextIndex(), 101)
}

func TestEditPlayerBlack(t *testing.T) {
	s := state.NewState(9)
	s.EditPlayerBlack("pblack")
	pb := s.Root().GetField("PB")
	require.Equal(t, len(pb), 1)
	assert.Equal(t, pb[0], "pblack")
}

func TestEditPlayerWhite(t *testing.T) {
	s := state.NewState(9)
	s.EditPlayerWhite("pwhite")
	pw := s.Root().GetField("PW")
	require.Equal(t, len(pw), 1)
	assert.Equal(t, pw[0], "pwhite")
}

func TestEditKomi(t *testing.T) {
	s := state.NewState(9)
	s.EditKomi("100.5")
	km := s.Root().GetField("KM")
	require.Equal(t, len(km), 1)
	assert.Equal(t, km[0], "100.5")
}

func TestAddNode(t *testing.T) {
	s := state.NewState(19)
	s.AddNode(coord.NewCoord(9, 9), color.Black)
	assert.Equal(t, s.Current().Index, 1)
	s.AddNode(coord.NewCoord(10, 10), color.White)
	assert.Equal(t, s.Current().Index, 2)
	s.AddNode(coord.NewCoord(11, 11), color.Black)
	assert.Equal(t, s.Current().Index, 3)
}

func TestAddStonesToTrunk(t *testing.T) {
	s := state.NewState(19)
	s.PushHead(10, 10, color.Black)
	s.PushHead(11, 11, color.White)
	s.PushHead(12, 12, color.Black)
	s.PushHead(13, 13, color.White)
	stones := []*coord.Stone{}
	stones = append(stones, coord.NewStone(2, 3, color.Black))
	stones = append(stones, coord.NewStone(14, 3, color.White))
	s.AddStonesToTrunk(2, stones)
	assert.Equal(t, s.GetNextIndex(), 7)
}

func TestAddStonesNoChange(t *testing.T) {
	s := state.NewState(19)
	s.PushHead(10, 10, color.Black)
	s.PushHead(11, 11, color.White)
	s.PushHead(12, 12, color.Black)
	s.PushHead(13, 13, color.White)
	stones := []*coord.Stone{}
	stones = append(stones, coord.NewStone(10, 10, color.Black))
	stones = append(stones, coord.NewStone(11, 11, color.White))
	s.AddStones(stones)
	assert.Equal(t, s.GetNextIndex(), 5)
}

func FuzzFromSGF(f *testing.F) {
	testcases := []string{"(;)", "(;GM[1];B[b,c])", "(;GM[1]SZ[9];B[ss])", "(;GM[1];B[aa];W[bb];B[];W[ss])", "(;GM[1];C[comment \"with\" quotes])", sgfsamples.Empty, sgfsamples.SimpleTwoBranches, sgfsamples.SimpleWithComment, sgfsamples.SimpleFourMoves, sgfsamples.SimpleEightMoves, sgfsamples.Scoring1, sgfsamples.PassWithTT, sgfsamples.ChineseNames}
	for _, tc := range testcases {
		// add to seed corpus
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, orig string) {
		// looking for crashes or panics
		_, _ = state.FromSGF(orig)
	})
}

// FuzzSGFPipeline exercises the FULL untrusted-SGF pipeline that a real upload
// travels — parse, RENDER, persist, and RELOAD — not just the parser. This
// matters because every SGF poison-pill in this codebase (a colon-less `LB`
// label, an empty/1-char/compressed `TR` or `SQ` mark, a text field left
// un-round-trip-safe by the `]`-only escaping) PARSES cleanly and only crashes
// *later*: in GenerateFullFrame (`frame.go` `generateMarks`) or after a
// serialize→reparse cycle (exactly what Hub.Save/Hub.Load do on every restart).
// The parser-only targets above (FuzzFromSGF / FuzzSGFParser) never reach those
// sinks, which is why they ran millions of execs clean while the bugs sat live.
//
// Search with:  go test -run x -fuzz FuzzSGFPipeline ./pkg/state/
// (a crasher is written under testdata/fuzz/). The seed corpus is deliberately
// benign so the normal, non-`-fuzz` `go test` stays green.
func FuzzSGFPipeline(f *testing.F) {
	seeds := []string{
		"(;)",
		"(;GM[1]FF[4]SZ[19])",
		"(;GM[1]SZ[9];B[aa];W[bb];B[];W[ss])",
		"(;GM[1]FF[4]SZ[19]C[a comment];B[aa]TR[bb][cc]SQ[dd]LB[ee:label])",
		"(;GM[1]FF[4]SZ[19]AB[aa][bb]AW[cc]AE[dd])",
		"(;GM[1]FF[4]SZ[19]PX[1.0:2.0:3.0:4.0:red])",
		sgfsamples.SimpleTwoBranches, sgfsamples.SimpleWithComment,
		sgfsamples.SimpleEightMoves, sgfsamples.Scoring1, sgfsamples.ChineseNames,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, orig string) {
		s, err := state.FromSGF(orig)
		if err != nil || s == nil {
			return
		}
		// (1) RENDER — the mark sinks (TR/SQ/LB) fire here, never in the parser.
		for _, ty := range []state.TreeJSONType{state.Full, state.CurrentOnly} {
			_ = s.GenerateFullFrame(ty)
		}
		// (2) PERSIST → RELOAD → render again. The `]`-only escaping means a
		// value that survived (1) can still corrupt or crash on reload — this is
		// the Hub.Save/Hub.Load restart path that turns a bug into a poison-pill.
		for _, sgf := range []string{s.ToSGF(), s.ToSGFIX()} {
			s2, err := state.FromSGF(sgf)
			if err != nil || s2 == nil {
				continue
			}
			_ = s2.GenerateFullFrame(state.Full)
		}
	})
}
