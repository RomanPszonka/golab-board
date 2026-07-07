# Deploying Board on Kubernetes

This guide covers running **Board** (the multi-user Go board in this repo) inside
a Kubernetes cluster and integrating it into an existing project. It is written
against the code as it exists today — every claim below maps to a specific place
in the source, noted inline.

Ready-to-apply manifests live in [`deploy/kubernetes/`](../deploy/kubernetes).
For the request/response contract see the [API reference](api.md) and
[`openapi.yaml`](openapi.yaml).

---

## 1. What you are deploying

Board is a single, self-contained Go binary (`cmd/main.go`) that serves:

| Surface | Path prefix | Purpose |
| --- | --- | --- |
| Web UI (HTML/JS/CSS, embedded) | `/`, `/b/{boardID}`, `/static/*`, `/js/*` | The browser app |
| WebSocket | `/socket/b/{boardID}` | Live, shared board play |
| REST API v1 | `/api/v1/room/{boardID}` | Stateless-style HTTP access to a board |
| Service API | `/api/ping`, `/api/version`, `/api/stats` | Health & introspection |
| SGF export | `/b/{boardID}/sgf`, `/b/{boardID}/sgfix`, `/b/{boardID}/debug` | Download board state |
| Twitch integration | `/apps/twitch/*` | Optional; OAuth + EventSub |

Everything is compiled into one image and listens on a **single port (8080)**.
The frontend assets are embedded in the binary (`pkg/frontend/embed.go`), so
there is no separate static-file server or CDN to run.

### Runtime model in one paragraph

A `Hub` (`pkg/hub/hub.go`) holds a map of live `Room`s in memory. Each browser
opens a WebSocket to `/socket/b/{boardID}`; the Hub finds-or-creates that room
and registers the connection. Moves arrive as JSON *events*, are applied to the
room's in-memory game `State`, and are **broadcast to the other WebSocket
connections in that same room, on that same process**. Rooms are periodically
snapshotted to a database and reloaded on startup. Idle rooms are evicted after
a timeout (default 24h, `Room.timeout = 86400`).

> **The single most important consequence for Kubernetes:** live room state and
> broadcast fan-out are *per-process and in-memory*. There is no Redis, no shared
> bus, no cross-pod coordination. This shapes every scaling decision below — see
> [§6](#6-scaling-horizontally).

---

## 2. Configuration

Board is configured by **one YAML file**, passed with `-f`:

```
/root/main -f /etc/board/config.yaml
```

The schema is defined in `pkg/config/config.go`:

```yaml
mode: prod              # "prod" or "test"
server:
  host: 0.0.0.0         # bind address; use 0.0.0.0 inside a container
  port: 8080
  url: https://board.example.com   # public URL; only used for Twitch OAuth/callback
db:
  type: postgres        # "postgres" | "sqlite" | "memory"
  path: "postgres://user:pass@host:5432/board?sslmode=disable"
twitch:                 # optional; omit/blank to disable
  client_id: ""
  secret: ""
  bot_id: ""
```

Notes that matter for k8s:

- **There is no environment-variable override.** `config.New()` reads the file
  and nothing else. Any secret (the DB DSN, Twitch secret) must live *inside*
  that file. That is why the provided manifests store the whole `config.yaml` in
  a **Secret** and mount it, rather than splitting a ConfigMap + Secret.
  (If you want to keep the DSN out of the manifest, see
  [§7 "Injecting the DSN from a separate Secret"](#7-optional-injecting-the-dsn-from-a-separate-secret).)
- If the file is missing or fails to parse, the binary logs the error and falls
  back to `config.Default()` — which uses a **local SQLite file in the
  container's home dir**. In k8s that means silent data loss on restart, so make
  sure the config actually mounts and parses.
- `server.url` only affects the Twitch OAuth redirect and EventSub callback URLs.
  Core board play does not need it. Set it to your Ingress hostname if you use
  Twitch; otherwise its value is harmless.

### Choosing a database (`db.type`)

| Type | Backing | k8s fit |
| --- | --- | --- |
| `postgres` | External/in-cluster Postgres | **Recommended.** Stateless pods, standard backups, works with `Recreate` rollouts. |
| `sqlite` | Single file on disk (pure-Go `modernc.org/sqlite`, no CGO) | Works, but needs a `ReadWriteOnce` PVC and **forces one replica** (single-writer). Fine for tiny/personal deployments. |
| `memory` | None | Ephemeral; everything is lost on restart. Only for tests/demos. |

Schema is **auto-created on startup** (`CREATE TABLE IF NOT EXISTS` in
`pkg/loader/dbloader.go`), so there is no separate migration Job to run. The
Postgres loader also retries the connection ~10× at 1s intervals on boot
(`pkg/loader/postgresloader.go`), which tolerates a database that is still coming
up alongside the pod.

---

## 3. Building and pushing the image

The repo ships a `Dockerfile`. It bakes a config file in at build time via the
`CONFIG_FILE` build arg — for Kubernetes we **ignore that** and mount config at
runtime instead, so any of the bundled configs is a fine default to bake.

```bash
# from the repo root
VERSION=$(git describe --tags 2>/dev/null || echo dev)
docker build --build-arg VERSION=$VERSION -t ghcr.io/YOURORG/board:$VERSION .
docker push ghcr.io/YOURORG/board:$VERSION
```

The image `EXPOSE`s 8080 and its entrypoint is `["/root/main", "-f", "/root/config.yaml"]`.
The Deployment overrides the args to point at the mounted config:
`args: ["-f", "/etc/board/config.yaml"]`.

> **Version endpoint:** `-ldflags "-X main.version=$VERSION"` makes
> `GET /api/version` return your build's git tag — handy for verifying rollouts
> (`kubectl exec ... -- wget -qO- localhost:8080/api/version`).

### Hardening the image (optional)

The stock `Dockerfile` builds and runs as **root** on the full `golang:alpine`
image. To run as non-root with `readOnlyRootFilesystem: true` (as the manifest
requests), use a multi-stage build on a distroless/scratch base and a numeric
`USER`. Nothing in the app needs root or writes outside the DB, so this is
straightforward. Until then, keep `runAsNonRoot: false` in the pod securityContext.

---

## 4. Deploy

The fastest path (self-contained, with in-cluster Postgres):

```bash
# 1. Edit deploy/kubernetes/10-config.yaml + 20-postgres.yaml:
#    set a real DB password (in BOTH files) and your image/host names.
# 2. Apply everything:
kubectl apply -k deploy/kubernetes/
# 3. Watch it come up:
kubectl -n board get pods -w
# 4. Smoke test from inside the cluster:
kubectl -n board exec deploy/board -- wget -qO- localhost:8080/api/ping
#    -> {"message": "pong"}
```

Manifests, in apply order:

| File | Contents |
| --- | --- |
| `00-namespace.yaml` | `board` namespace |
| `10-config.yaml` | Secret holding `config.yaml` (includes the DB DSN) |
| `20-postgres.yaml` | Convenience in-cluster Postgres (delete if you use a managed DB) |
| `30-board.yaml` | Board Deployment + Service (**read the scaling caveat at the top**) |
| `40-ingress.yaml` | ingress-nginx Ingress with WebSocket-friendly timeouts |

---

## 5. Health checks, probes, and graceful shutdown

**Probes.** `GET /api/ping` returns `{"message": "pong"}` unconditionally and is
cheap — use it for both readiness and liveness (as the manifest does). Avoid
pointing probes at `/api/stats`; it locks the Hub to count rooms/connections and
is unnecessary work on a hot path. `/api/version` and `/api/stats` remain useful
for humans and dashboards.

**Graceful shutdown.** `main()` installs a handler for `SIGTERM`/`SIGINT`; on
signal it returns from `main`, which runs `defer a.Hub.Save()` and snapshots
every live room to the DB. Give the pod room to finish that:
`terminationGracePeriodSeconds: 30` (already set). Two honest caveats:

- The HTTP server is **not drained** (`http.ListenAndServe`, no
  `Server.Shutdown`). In-flight WebSockets are cut when the process exits; the
  browser client auto-reconnects and reloads state from the room, so users see a
  brief blip, not data loss — provided `Save()` completed first.
- Because state is per-pod, a rollout that starts a new pod before the old one
  saves can momentarily split a board. The manifest uses `strategy: Recreate`
  to avoid two pods owning the same board at once. Only switch to
  `RollingUpdate` if you have board-affinity routing (next section).

---

## 6. Scaling horizontally

**Default and recommended: `replicas: 1`.** A single modern pod comfortably
handles many concurrent rooms — the work per move is small and the load tests in
`/loadtest` exercise exactly this shape. Scale the pod *vertically* (CPU/memory)
before reaching for more replicas.

**If you must run more than one replica**, you have to guarantee that *every*
connection for a given board reaches the *same* pod, because rooms and broadcasts
are in-memory (see [§1](#runtime-model-in-one-paragraph)). The board ID is in the
URL path for both surfaces:

```
/b/{boardID}            (web + REST)
/socket/b/{boardID}     (websocket)
```

So the way to scale is **consistent-hash routing on the URL path** at the
Ingress. With ingress-nginx:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/upstream-hashing-by: "$request_uri"
    # or a stricter hash on just the board segment via a snippet/regex
```

This pins each board to one backend deterministically. Then, and only then, is a
multi-replica Deployment (with `RollingUpdate`) safe. Note the trade-offs:

- Rebalancing when a pod is added/removed will move some boards to a different
  pod; those rooms reload from their **last DB snapshot**, losing any moves made
  since the last save. Snapshots happen on shutdown and via the heartbeat, not on
  every move.
- `Session affinity` by cookie/IP is a weaker substitute (a user with two tabs,
  or two users behind one NAT, can still split); prefer path hashing.

There is no built-in sharded/clustered mode. A true multi-writer setup would
require adding a shared pub/sub (e.g. Redis) and moving broadcast off the
in-process map — a code change, not a config change.

---

## 7. (Optional) Injecting the DSN from a separate Secret

The binary reads config only from a file, so if you want the DB password to live
in its *own* Secret (e.g. produced by an external-secrets operator) rather than
inside the big config Secret, template it at pod start with an init step:

```yaml
# In the pod spec: render /etc/board/config.yaml from a template + env at boot.
initContainers:
  - name: render-config
    # NOTE: use an image that actually ships `envsubst` (it comes from gettext).
    # Plain busybox does NOT include envsubst. Options: a gettext image, or swap
    # the command for a busybox-native `sed`.
    image: ghcr.io/a8m/envsubst:latest # or e.g. bhgedigital/envsubst, alpine + `apk add gettext`
    command: ["sh", "-c", "envsubst < /tmpl/config.yaml > /etc/board/config.yaml"]
    env:
      - name: BOARD_DB_PATH
        valueFrom: { secretKeyRef: { name: db-dsn, key: dsn } }
    volumeMounts:
      - { name: tmpl, mountPath: /tmpl }
      - { name: rendered, mountPath: /etc/board }
# Busybox-only alternative (no extra image), substituting one placeholder with sed:
#   image: busybox:1.36
#   command: ["sh", "-c", "sed \"s#__BOARD_DB_PATH__#$BOARD_DB_PATH#\" /tmpl/config.yaml > /etc/board/config.yaml"]
#
# ...then mount `rendered` (emptyDir) into the board container at /etc/board,
# and put a config.yaml template (with `path: "${BOARD_DB_PATH}"` for envsubst,
# or `path: "__BOARD_DB_PATH__"` for the sed variant) in a ConfigMap mounted at
# /tmpl. This keeps the DSN in a dedicated Secret while the app still just reads a file.
```

This is purely a secrets-hygiene convenience; functionally identical to putting
the DSN in the config Secret directly.

---

## 8. Integrating Board into an existing project

Common integration patterns:

- **Embed a board in your app's UI.** Point an `<iframe>` (or a link/popout) at
  `https://board.example.com/b/<your-room-id>`. **Choose room IDs that already
  match `[a-z0-9-]` (lowercase).** The web route `/b/{boardID}` rejects anything
  else with a 400 (it compares the ID against `core.Sanitize` and refuses rather
  than silently stripping), and the REST route keys rooms by the raw ID without
  sanitizing — so an unsanitized ID can create a room that the browser page can
  never open, or split traffic across two differently-spelled rooms. Derive the
  ID from your own domain objects (e.g. `match-<uuid>`) using only those
  characters. Rooms are created on first visit — no provisioning call needed.
- **Drive a board from your backend.** Use the REST API
  (`POST /api/v1/room/{boardID}`) to place stones, upload SGF, navigate, etc.,
  from server-side code without opening a WebSocket. See [api.md](api.md).
- **Preload a game.** `POST /api/v1/room/{boardID}` with
  `{"event":"request_sgf","value":"<url>"}` (server fetches an allow-listed URL)
  or `{"event":"upload_sgf","value":"<base64 sgf>"}`.
- **Restrict who can open a board.** See [§9](#9-restricting-boards-to-specific-users).

Because state is per-pod, if you call the REST API and expect a browser on a
*different* pod to see the change, the same board-affinity rule from
[§6](#6-scaling-horizontally) applies. With the default single replica this is a
non-issue.

---

## 9. Restricting boards to specific users

Board has **no user accounts and no per-user access control** by design ("No
sign-up or login" is a listed feature). The only built-in gate is a **per-room
password**:

- A client sends `{"event":"update_settings", ...,"password":"secret"}`; the
  server bcrypt-hashes it (`core.Hash`) and stores it on the room.
- New clients call `{"event":"isprotected"}` and, if protected,
  `{"event":"checkpassword","value":"secret"}`. On a correct password the
  server marks *that connection* authorized (`room.auth[connID] = true`).
- Authorization is keyed by **ephemeral WebSocket connection ID** (a fresh UUID
  per socket, `event.NewDefaultEventChannel`), not by any durable identity. It
  is a shared room secret, not a per-user allow-list.

So a password protects a room, but it can't express "only Alice and Bob from my
server may enter." To get that, restrict access **in front of Board**, at the
Kubernetes layer — no code change required:

### Recommended: gate the Ingress with your existing auth (oauth2-proxy / forward-auth)

Put an authenticating proxy in front of Board and let your own identity provider
decide who reaches it. With ingress-nginx external auth:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "https://auth.example.com/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://auth.example.com/oauth2/start?rd=$escaped_request_uri"
```

Now only users who pass *your* login (OIDC, SSO, whatever oauth2-proxy is wired
to) can reach `/b/...` **or** `/socket/b/...`, so both the page and the live
socket are protected. Combine with per-room passwords if you also want
board-level separation among already-authenticated users. This is the cleanest
way to make boards "open only for specific users of my server."

### Finer-grained: per-board allow-lists via the proxy

If different boards should be visible to different subsets of your users, keep
the proxy but authorize per path. Two workable shapes:

- Map board IDs to groups in the proxy/forward-auth service (e.g. only members of
  group `team-a` may load paths matching `/b/team-a-*` and `/socket/b/team-a-*`).
- Or front Board with a tiny gateway in your own app that mints signed,
  short-lived board URLs for authorized users and rejects everyone else before
  proxying through.

### If you want it *inside* Board (code change)

There is currently no hook for this, but the room already has the necessary
seam: `Room.auth` (a `map[string]bool`) and the `authorized` middleware in
`pkg/room/handlers.go` gate every state-changing event. A native allow-list
feature would mean (a) carrying a trusted user identity onto each connection —
e.g. reading a header/JWT that your auth proxy injects — instead of the random
connection UUID, and (b) checking it against a per-room allowed-users set
alongside the existing password check. That is a feature to build, not a config
to set; the proxy approaches above achieve the same outcome today with zero
changes to Board.

**Bottom line:** out of the box, password-protected rooms are the only in-app
gate, and they are a shared secret, not a user allow-list. To restrict boards to
specific users of your server, authenticate in front of Board at the Ingress
(oauth2-proxy / forward-auth). See the [API reference](api.md#authentication--room-passwords)
for the exact password event flow.

---

## 10. Observability

- **Logs.** Board logs structured key/value lines to stdout (`pkg/logx`).
  `kubectl logs` works out of the box; ship to Loki/ELK as usual. The repo's
  `docker-compose.yaml` shows an Alloy → Loki → Grafana stack for reference, but
  in k8s you'll use your cluster's logging pipeline instead.
- **Metrics.** There is **no Prometheus endpoint**. `GET /api/stats` returns
  `{"rooms":N,"connections":M}` as a lightweight, pollable gauge if you want a
  basic dashboard; wrap it in an exporter/sidecar if you need Prometheus scrape
  format.
- **Version.** `GET /api/version` returns the build's git tag (see §3).

---

## 11. Quick reference

```bash
# Apply / update
kubectl apply -k deploy/kubernetes/

# Health
kubectl -n board exec deploy/board -- wget -qO- localhost:8080/api/ping
kubectl -n board exec deploy/board -- wget -qO- localhost:8080/api/version
kubectl -n board exec deploy/board -- wget -qO- localhost:8080/api/stats

# Logs
kubectl -n board logs deploy/board -f

# Roll a new image
kubectl -n board set image deploy/board board=ghcr.io/YOURORG/board:NEWTAG
```

| Concern | Decision |
| --- | --- |
| Replicas | 1 (default). >1 requires board-affinity path hashing. |
| Rollout strategy | `Recreate` (or `RollingUpdate` **with** path hashing) |
| Database | Postgres (managed preferred); SQLite needs a PVC + 1 replica |
| Config | Single YAML file in a Secret, mounted at `/etc/board/config.yaml` |
| Probes | `/api/ping` for readiness + liveness |
| Graceful stop | SIGTERM → `Hub.Save()`; `terminationGracePeriodSeconds: 30` |
| Restrict users | Auth proxy at the Ingress (oauth2-proxy/forward-auth) |
