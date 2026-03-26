# Fetch example

Demonstrates the host-provides-capabilities pattern: untrusted code can
request web pages through a `get(url)` function, but the actual HTTP
request happens in the host process — the sandbox never touches the
network.

## Architecture

```
┌──────────────────────────────────────────────────┐
│ host.js (Node)                                   │
│  • spawns hermit                                 │
│  • loads wrapper.js then untrusted.js            │
│  • reads JSON requests from hermit stdout        │
│  • fulfills get requests with fetch()            │
│  • sends responses back via stdin                │
└────────────────────┬─────────────────────────────┘
                     │ stdio (JSON)
┌────────────────────▼─────────────────────────────┐
│ hermit sandbox                                   │
│  ┌─────────────────────────────────────────────┐ │
│  │ wrapper.js                                  │ │
│  │  • get(url) → Promise<string>               │ │
│  │  • respond(id, body) — called by host       │ │
│  └─────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────┐ │
│  │ untrusted.js                                │ │
│  │  • calls get("http://example.com")          │ │
│  │  • reverses the response body               │ │
│  │  • outputs { type: "result", body: "..." }  │ │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

## Protocol

All messages are single-line JSON on stdout/stdin.

**Sandbox → Host (stdout):**
```json
{ "type": "get", "id": 0, "url": "http://example.com" }
```

**Host → Sandbox (stdin):**
```js
respond(0, "<html>...")
```

**Sandbox → Host (stdout):**
```json
{ "type": "result", "body": "...>lmth<" }
```

## Running

```bash
cargo build --release
HERMIT_BIN=./target/release/hermit node examples/fetch/host.js
```
