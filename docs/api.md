# Board API Reference

Complete reference for every network surface Board exposes. It supersedes and
expands the older [`apiv1.md`](apiv1.md) (which documents only the REST event
body). Routes are defined in `pkg/app/app.go` and the routers under `pkg/hub/`.

A machine-readable **OpenAPI 3.1** description of the HTTP surface is in
[`openapi.yaml`](openapi.yaml) — see [Generating / serving the
spec](#generating--serving-the-spec).

- [Concepts](#concepts)
- [Transports](#transports)
- [The event object](#the-event-object)
- [Event catalog](#event-catalog)
- [HTTP endpoints](#http-endpoints)
  - [REST API v1](#rest-api-v1)
  - [Service API](#service-api)
  - [SGF export & debug](#sgf-export--debug)
  - [Web & extension routes](#web--extension-routes)
  - [Twitch routes](#twitch-routes)
- [WebSocket protocol](#websocket-protocol)
- [Authentication / room passwords](#authentication--room-passwords)
- [Errors](#errors)
- [Generating / serving the spec](#generating--serving-the-spec)

---

## Concepts

- **Room / board.** A room is one shared Go board, addressed by a `boardID`
  string. **Use only `[a-z0-9-]` (lowercase).** Handling differs by route and is
  *not* uniform: the WebSocket route sanitizes the ID (`core.Sanitize`); the web
  page `/b/{boardID}` **rejects** IDs containing anything else with a 400 rather
  than stripping; and the REST route `/api/v1/room/{boardID}` uses the raw ID
  verbatim (no sanitizing). So an ID like `Foo_Bar` can create a REST/socket room
  that the browser page can never open, or resolve to a different room than you
  expect. Stick to lowercase alphanumerics and hyphens to keep all three routes
  pointing at the same board. Rooms are created on first access (visit, socket,
  or API call) — there is no "create room" call.
- **Event.** Every action — over WebSocket or REST — is a JSON *event* with a
  `event` type and an optional `value`. The same event vocabulary drives both
  transports (`Room.HandleAny`, `pkg/room/handlers.go`).
- **Frame.** When an event changes the board, the server produces a `frame`
  event describing the new state, and broadcasts it to the room.
- **No accounts.** There is no login or per-user identity. The only access
  control is an optional per-room password — see
  [Authentication](#authentication--room-passwords).

---

## Transports

| Transport | Endpoint | Use it for |
| --- | --- | --- |
| **WebSocket** | `/socket/b/{boardID}` | Interactive, real-time play. The browser client uses this. You receive live `frame` broadcasts from other users. |
| **REST** | `POST /api/v1/room/{boardID}` | One-shot, server-to-server actions. No live updates pushed back; you get the single resulting event. |

Both accept the **same event objects** and run them through the same room
handlers. Choose WebSocket when you need to *observe* a room live; choose REST
when you just need to *mutate* or *query* it.

---

## The event object

```json
{
  "event":  "add_stone",
  "value":  { "coords": [9, 9], "color": 1 },
  "userid": "",
  "eventid": ""
}
```

| Field | JSON key | Direction | Meaning |
| --- | --- | --- | --- |
| Type | `event` | both | The event type (see catalog). Required. |
| Value | `value` | both | Type-specific payload. Optional; shape depends on `event`. |
| User ID | `userid` | server-set | The originating connection's ID. Set by the server; you don't send it. |
| Event ID | `eventid` | both | Correlation ID. If omitted, the server assigns a UUID (`EventFromJSON`). |

Colors are integers: **1 = black, 2 = white** (`pkg/core/color`). Coordinates are
`[x, y]` integer pairs, 0-indexed from the top-left, valid for the board size
(9, 13, or 19).

---

## Event catalog

All types below are valid in a REST body and over the WebSocket. Source of truth:
`pkg/room/handlers.go` (`initHandlers`) and `pkg/state/command_decoder.go`
(`DecodeToCommand`).

### Session / room control

| `event` | `value` | Effect |
| --- | --- | --- |
| `isprotected` | — | Replies (to caller only) with `value: true/false` — does the room have a password. |
| `checkpassword` | `"<password>"` | If correct, authorizes the caller; reply `value` is `""` on failure. |
| `ping` | — | No-op; echoes back. Liveness. |
| `debug` | — | Echoes back; server-side debug hook. |
| `update_nickname` | `"<nick>"` | Sets the caller's display name; broadcasts the `connected_users` list. |
| `update_settings` | object (below) | Updates buffer, board size, player names, komi, nickname, **and password**. Requires auth. |
| `trash` | — | Resets the board to empty (same size). Requires auth. |

`update_settings` value shape (`handleUpdateSettings`):

```json
{
  "buffer": 250,          // input debounce in ms (see WebSocket protocol)
  "size": 19,             // 9 | 13 | 19; changing it resets the board
  "nickname": "alice",
  "black": "Black Player",// SGF PB; "" leaves unchanged
  "white": "White Player",// SGF PW; "" leaves unchanged
  "komi": "6.5",          // SGF KM; "" leaves unchanged
  "password": "secret"    // "" clears; non-empty sets & bcrypt-hashes it
}
```

### Loading games

| `event` | `value` | Effect |
| --- | --- | --- |
| `upload_sgf` | base64 string, **or** array of base64 strings | Loads SGF(s). Accepts SGF/GIB/NGF and ZIP archives; multiple files are merged. 1 MB max per decoded payload. Requires auth. |
| `request_sgf` | `"<url>"` | Server fetches an **allow-listed** URL and loads it. Recognizes OGS game/review/demo URLs and live-syncs them via the OGS plugin. Requires auth. |

### Placing & marking

| `event` | `value` | Effect |
| --- | --- | --- |
| `add_stone` | `{"coords":[x,y],"color":1\|2}` | Play a stone (captures resolved by game logic). |
| `pass` | `1` or `2` | Pass for that color. |
| `remove_stone` | `[x,y]` | Remove a stone (edit). |
| `triangle` | `[x,y]` | Toggle a triangle mark. |
| `square` | `[x,y]` | Toggle a square mark. |
| `letter` | `{"coords":[x,y],"letter":"A"}` | Place a letter label. |
| `number` | `{"coords":[x,y],"number":7}` | Place a number label. |
| `label` | `{"coords":[x,y],"label":"foo"}` | Place a free-text label. |
| `remove_mark` | `[x,y]` | Remove any mark at a point. |
| `markdead` | `[x,y]` | Toggle a stone/group as dead (scoring). |

### Navigation & tree

| `event` | `value` | Effect |
| --- | --- | --- |
| `left` / `right` | — | Previous / next sibling variation. |
| `up` / `down` | — | Up / down the move tree. |
| `rewind` / `fastforward` | — | Jump to start / end of the current line. |
| `goto_grid` | `<int>` | Jump to a node by its index. |
| `goto_coord` | `[x,y]` | Jump to the node that played at a point. |
| `cut` | — | Delete the current node/subtree. |
| `graft` | `"<string>"` | Graft a serialized branch into the tree (also used by Twitch `!branch`). |
| `copy` / `clipboard` | — | Copy the current subtree / paste it. |

### Annotation & scoring

| `event` | `value` | Effect |
| --- | --- | --- |
| `comment` | `"<text>"` | Set the comment on the current node. |
| `draw` | `[x0,y0,x1,y1,"#rrggbb"]` | Pen stroke overlay (`x0`/`y0` may be `null` → start of stroke). |
| `erase_pen` | — | Clear pen overlays. |
| `score` | — | Toggle scoring/territory estimation. |

---

## HTTP endpoints

### REST API v1

```
POST /api/v1/room/{boardID}
Content-Type: application/json

{ "event": "...", "value": ... }
```

Runs one event against the board and returns the resulting event. Router:
`pkg/hub/apiv1router.go`.

**Success (event caused a board update):**

```json
{ "success": true, "output": { "event": "frame", "value": { ... }, ... } }
```

**Success (event did not produce a frame):** `output` is the precipitating event
echoed back.

**Failure:** HTTP 400 with

```json
{ "success": false, "error": "<message>" }
```

Notes:
- "Success" means *the event was received and interpreted*, not that the board
  changed. E.g. `add_stone` on an occupied point returns `success: true` with no
  state change.
- The REST path shares the room map with WebSocket clients. A REST mutation is
  broadcast to any WebSocket clients connected to the **same room on the same
  process** (see the scaling note in [kubernetes.md](kubernetes.md#6-scaling-horizontally)).
- **Response `Content-Type`.** The response *body* is JSON, but the server does
  not currently set a `Content-Type` header on these responses, so Go serves them
  as `text/plain; charset=utf-8`. Parse the body as JSON regardless; don't rely on
  the header. (The same applies to the `/api/*` service endpoints below.)

Example:

```bash
curl -X POST https://board.example.com/api/v1/room/demo \
  -H 'Content-Type: application/json' \
  -d '{"event":"add_stone","value":{"coords":[3,3],"color":1}}'
```

### Service API

Router: `pkg/hub/apirouter.go`. All return JSON.

| Method & path | Response | Purpose |
| --- | --- | --- |
| `GET /api/ping` | `{"message":"pong"}` | Liveness / readiness probe. |
| `GET /api/version` | `{"message":"<git tag>"}` | Build version (from `-ldflags -X main.version`). |
| `GET /api/stats` | `{"rooms":N,"connections":M}` | Live room & connection counts. |

### SGF export & debug

Router: `pkg/hub/webrouter.go`. Return `text/plain` bodies (empty if the room
doesn't exist).

| Method & path | Returns |
| --- | --- |
| `GET /b/{boardID}/sgf` | Current board as an SGF document. |
| `GET /b/{boardID}/sgfix` | SGF including node indexes. |
| `GET /b/{boardID}/debug` | JSON dump of internal room state (debugging). |

### Web & extension routes

| Method & path | Purpose |
| --- | --- |
| `GET /` | Home page. |
| `GET /b/{boardID}` | The board UI for a room. |
| `POST /new` | Create-and-redirect: form field `board_id` (blank → random name) → `302` to `/b/{id}`. |
| `GET /about` | About page. |
| `GET /integrations` | Twitch integrations page (or a "disabled" variant if Twitch is off). |
| `GET /ext/upload` | Query `url=` (+ optional `board_id`) → loads an SGF URL into a room and redirects. |
| `GET /static/{file}`, `GET /js/*`, `GET /favicon.ico` | Embedded static assets. |

### Twitch routes

Router: `pkg/hub/twitchrouter.go`. Only meaningful when `twitch.*` config is set
(`Config.TwitchEnabled()`). These implement Twitch OAuth + EventSub, not a
general-purpose API:

| Method & path | Purpose |
| --- | --- |
| `GET /apps/twitch/subscribe` | Start OAuth to subscribe a channel's chat to Board. |
| `GET /apps/twitch/unsubscribe` | Start OAuth to unsubscribe. |
| `GET /apps/twitch/callback` | OAuth redirect handler. |
| `POST /apps/twitch/callback` | Twitch EventSub webhook (verifies signatures; handles `!setboard` and `!branch` chat commands). |

---

## WebSocket protocol

Connect to:

```
wss://board.example.com/socket/b/{boardID}
```

### Framing

Board uses a small **length-prefixed** framing on top of WebSocket
(`pkg/event/channel.go`, client `pkg/frontend/js/network_handler.js`):

- **Client → server:** send **two** WebSocket messages per event:
  1. a 4-byte **little-endian uint32** with the byte length of the JSON, then
  2. the UTF-8 JSON payload.
- **Server → client:** a single WebSocket message containing the JSON event (no
  length prefix on this direction).

If you write your own WebSocket client, you must send the 4-byte length prefix
before each JSON payload, or the server's `readPacket` will misframe your input.

### Lifecycle

1. On connect, the server registers the connection, assigns it a UUID, and
   immediately sends a full `frame` event with the current board state.
2. The server broadcasts the `connected_users` list (nick map) to the room.
3. You send events (framed as above). State-changing events are validated,
   applied, and the resulting `frame` is broadcast to everyone in the room.
4. Typical first messages from a client: `{"event":"isprotected"}`, then
   `{"event":"update_nickname","value":"..."}`, and if protected,
   `{"event":"checkpassword","value":"..."}`.

### Server-sent event types you'll receive

| `event` | Meaning |
| --- | --- |
| `frame` | Full or partial board state to render. |
| `connected_users` | Map of connection ID → nickname currently in the room. |
| `global` | A server-wide broadcast message (from the Hub message loop). |
| `error` | Something went wrong handling an event (`value` is the message). |
| `nop` / empty | Ignore (used for buffering/no-op). |

### Input buffer (rate limiting)

Each room has an **input buffer** (default 250 ms, configurable via
`update_settings.buffer`). If two *different* users submit `add_stone`/`goto_grid`
faster than the buffer window, the later one is dropped and an empty frame is
broadcast to keep clients in sync (`outsideBuffer` middleware). This prevents
users from clobbering each other; a single user is never throttled against
themselves.

---

## Authentication / room passwords

Board has **no user accounts**. The only in-app access control is an optional
per-room password. The flow (source: `pkg/room/handlers.go`, `pkg/core/verify.go`):

1. **Set a password:** send `update_settings` with a non-empty `password`. The
   server bcrypt-hashes it (`core.Hash`) and stores the hash on the room. Setting
   a password auto-authorizes everyone currently connected (`SetAuthAll`).
2. **Discover protection:** a client sends `{"event":"isprotected"}` and gets
   `value: true|false`.
3. **Authenticate:** send `{"event":"checkpassword","value":"<pw>"}`. On a match
   (`bcrypt.CompareHashAndPassword`), the server marks **that connection**
   authorized (`room.auth[connID] = true`). On failure the reply `value` is `""`.
4. **Enforcement:** the `authorized` middleware wraps every state-changing event
   (`upload_sgf`, `request_sgf`, `trash`, `update_settings`, moves, …). If the
   room has a password and the caller isn't authorized, the handler is skipped.
   Read-only/among-caller events (`isprotected`, `checkpassword`, `ping`,
   `update_nickname`) are not gated.

Important properties:

- Authorization is keyed by **ephemeral connection ID** (a fresh UUID per
  WebSocket, `event.NewDefaultEventChannel`), so it does not persist across
  reconnects and is **not** a durable per-user identity.
- A room password is therefore a **shared secret for that room**, not an
  allow-list of specific users.
- Over **REST**, the room-password gate is effectively bypassable, so treat the
  REST API as trusted/server-side only and never expose it directly to untrusted
  clients. Concretely: the `authorized` check keys off the event's `userid`, and
  the REST handler (`pkg/hub/apiv1router.go`) passes the client-supplied `userid`
  from the JSON body straight through — it does **not** override it the way the
  WebSocket path does (`Room.Handle` calls `evt.SetUser(connID)`). A REST client
  can therefore pick any stable `userid`, `POST` `checkpassword` once with that
  `userid` to mark itself authorized, and then perform every password-gated event
  under the same `userid`. The password protects the *browser* flow, not the REST
  surface.

**To restrict a board to specific users of your own server**, authenticate in
front of Board at the Ingress (oauth2-proxy / forward-auth). See
[kubernetes.md §9](kubernetes.md#9-restricting-boards-to-specific-users) for the
full rationale and configuration.

---

## Errors

- **REST:** HTTP `400` + `{"success": false, "error": "..."}` for malformed
  bodies, unknown event types, or handler errors.
- **WebSocket:** an `error` event (`{"event":"error","value":"..."}`) is
  broadcast/returned; the socket stays open. A read error (bad framing, client
  gone) ends the connection loop.
- Common messages: `"unhandled event type"`, `"file exceeds the 1MB maximum"`,
  `"url parsing error"`, `"Error fetching SGF. Is it a private OGS game?"`.

---

## Generating / serving the spec

The HTTP surface is described in [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1).

**Why a hand-maintained spec rather than generated-from-code?** Board's REST API
is a single endpoint (`POST /api/v1/room/{boardID}`) whose behavior is a
discriminated union over the `event` field — the "API" is really the *event
catalog*, which lives as data in `pkg/state/command_decoder.go` and
`pkg/room/handlers.go`. There are no per-route handler annotations to scrape, so
a swagger-comment generator (e.g. `swaggo/swag`) would add annotation noise for
little gain. `openapi.yaml` models the event union with `oneOf`, which is a truer
description than one generated stub per route.

**View it** with any OpenAPI renderer, e.g.:

```bash
# Redoc (no install; needs npx)
npx @redocly/cli preview-docs docs/openapi.yaml

# or Swagger UI via Docker
docker run --rm -p 8081:8080 -e SWAGGER_JSON=/spec/openapi.yaml \
  -v "$PWD/docs:/spec" swaggerapi/swagger-ui
# then open http://localhost:8081
```

**Keep it in sync.** When you add or change an event type, update the
`EventBody` `oneOf` in `openapi.yaml` and the [event catalog](#event-catalog)
above. Both are short and live next to the code they describe.

**If you prefer generation from code later**, the lowest-friction path given the
architecture is a tiny Go generator that reflects over the `switch evt.Type()`
cases in `DecodeToCommand`/`initHandlers` and emits the `oneOf` — i.e. generate
from the *event table*, not from HTTP routes. That is an enhancement, not a
requirement; the checked-in spec is complete as of this writing.
