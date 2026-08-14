//go:build race

// L-10 (SECURITY_ASSESSMENT.md §8): MemoryLoader has no mutex, so its `rooms`
// map is read and written concurrently by different room goroutines and the
// persist loop. Under the in-memory config this is an unauthenticated
// `fatal error: concurrent map iteration and map write` — a whole-server crash
// the runtime does NOT recover. This file is `//go:build race` so it only
// compiles under `go test -race` (the race detector reports the unsynchronized
// map access); it is excluded from a plain `go test ./...` run, where the same
// access could non-deterministically fatal the whole process.
//
//	go test -race -run TestL10 ./security/poc/race/
//
// (Production sqlite/postgres loaders go through database/sql and are
// concurrency-safe; this is a memory-mode-only defect.)
package race

import (
	"fmt"
	"sync"
	"testing"

	"github.com/golab/board/pkg/loader"
)

func TestL10_MemoryLoaderConcurrentMap(t *testing.T) {
	ml := loader.NewMemoryLoader()
	// pre-populate so LoadAllRooms iterates a non-trivial map (widens the window)
	for i := 0; i < 32; i++ {
		_ = ml.SaveRoom(fmt.Sprintf("seed-%d", i), &loader.LoadJSON{ID: "seed"})
	}

	const iters = 200000
	var wg sync.WaitGroup
	wg.Add(2)

	// writer: a second unauthenticated client creating/removing rooms — plain
	// map writes with no lock (SaveRoom/DeleteRoom).
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = ml.SaveRoom("r", &loader.LoadJSON{ID: "r"})
			_ = ml.DeleteRoom("r")
		}
	}()

	// reader: the persist/load path iterates the same map (LoadAllRooms),
	// concurrently and unsynchronized — the race detector fires on the overlap
	// (in practice within the first few iterations, long before `iters`).
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_, _ = ml.LoadAllRooms()
		}
	}()

	wg.Wait()
}
