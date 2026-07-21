# PoCs for SECURITY_ADDENDUM.md (new findings beyond PR #2's SECURITY_ASSESSMENT.md)

Target: golab-board @ PR #2 head (12030bc). Build & run a disposable local target:

```
go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml   # :8080
```

## Live-server PoCs (Go clients; protocol = 4-byte LE length + JSON)
- `poc_password_broadcast.go` — N-1 plaintext password broadcast (run: `go run poc_password_broadcast.go`; edit target const if needed)
- `decoder_panics.go` — N-10/N-11 draw & upload_sgf panic sinks (run: `go run decoder_panics.go localhost:8080`)
- `pencolor.go` — N-15 pen-color round trip (broadcast + PX persistence)

## Go-test PoCs (copy into the module, run with go test)
- `core_top3_verify_test.go` — N-5/N-6/N-8 (nil-coord panic, NGF key poison, NaN-PX freeze) — place in a package `zz_verify` under the module root: `go test -v ./zz_verify/`
- `poc_test.go`, `nilcoord2_test.go` — N-10/N-5 decoder & nil-coord suite (core audit)
- `nan_test.go`, `nan_persist_test.go` — N-8 NaN/Inf PX marshal failure + persistence
- `ngf_test.go`, `ngf_room_test.go` — N-6 NGF key poison + N-7 IX-collision/cut/graft
- `graft_test.go` — N-9 graft off-board letter (9x9/13x13) + N-11 upload array assertion
- `ogs_sgf_injection_test.go`, `n_in_ogs_poc_test.go` — N-2 OGS SGF injection + N-4 frame parser (copy into `pkg/room/plugin/`, run `go test [-tags poc] -run ... -v ./pkg/room/plugin/`)
- `ogs_frame_parser_stall_test.go` — N-4 frame parser stall (same placement)
- `n_in_requestsgf_poc_test.go` — N-3 uncapped request_sgf fetch → fatal stack overflow (copy into `pkg/room/`, `go test -tags poc -run TestNINRequestSGFNoCap -v ./pkg/room/`)
- `n_in_twitch_poc_test.go` — N-12 Twitch !branch missing broadcaster check (copy into `pkg/hub/`, `go test -tags poc -run TestNINTwitchBranchAuthz -v ./pkg/hub/`)
- `n2_reach_blocked_test.go` — **second-reviewer correction** for N-2: feeds a full `gamedata` frame through the *real* `readFrameFromChan` and shows the injection payload is truncated (N-4) before it reaches `gamedataToSGF` (copy into `pkg/room/plugin/`, `go test -run TestN2ReachabilityBlockedByN4 -v ./pkg/room/plugin/`). Contrast the N-2 PoCs above, which call `gamedataToSGF` directly and so only exercise the isolated conversion.

Several PoCs crash or exhaust the target — authorized local testing only.

> **Note:** this directory is named `_pocs` (underscore prefix) so the Go toolchain skips it in `go build/test ./...` — the files are not a single valid package (they target several packages for copy-in), and building them in place broke the module suite. Run each by copying into its target package (above) or, for the `main` programs, via `go run <file>` from inside this directory.
