// Package race holds the data-race reproductions referenced by
// SECURITY_ASSESSMENT.md (DR-1/DR-2/DR-3 and the L-10 MemoryLoader map race).
//
// The reproductions are build-tagged `race` (see the `*_test.go` files), so they
// compile and run only under `go test -race ./security/poc/race/`. A plain
// `go test ./...` finds no tests in this package — this file just gives the
// package a buildable source file so that default build stays clean.
package race
