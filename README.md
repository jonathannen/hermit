# Hermit

Hermit runs JavaScript in a cave. You can pass notes in and get notes back. That's it.

More specifically, Hermit runs JavaScript inside V8 isolates, using stdio as the control protocol. Beyond stdio, the it's completely sandboxed.

Code is sent via stdin and eval'd in the isolate. Input is buffered line-by-line until a blank line is received, at which point the accumulated block is evaluated. At this point, the Hermit waits for all microtasks to complete. On EOF, any remaining buffered code is flushed and evaluated.

The code in the isolate can call `console.log` and that's it. No file system, no environment variables, no `require`, and extremely limited globals.

Hermit provides the primitive isolate. It's expected that you'd build a host and protocol on top for doing real work.

The typical pattern is to send JavaScript wrapped in a protocol handler, then invoke this handler with later evals. The handler can interact with the host via console.log output — the protocol on how they communicate is up to you. See `examples/fetch` as an example.

Async handlers and interactions can be supported. See `tests/fixtures/async_bridge.js` as a starting point.

## Example

The most trivial example executes JavaScript directly.

```bash
printf 'console.log(1 + 2);\n\n' | hermit
# 3
```

You can define functions in one block and call them in a later block. This is the basis of the handler pattern — send a protocol handler first (potentially wrapping untrusted code), then invoke it with subsequent evals.

```bash
# Define a handler, then call it in a separate block.
printf 'const greet = (name) => console.log("hello " + name);\n\ngreet("world");\n\n' | hermit
# hello world
```

See `examples` and `tests/fixtures` for other examples. You can also substitute `hermit` for `cargo run`.

## Security Layers

- **[V8 Isolate](https://v8.dev/docs/embed#isolates)** — each instance of Hermit runs its own V8 isolate, the same process-level sandbox that Chrome uses to separate tabs.
- **[Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)** (Linux only) — a syscall filter that restricts what the process can do at the kernel level, even if the V8 sandbox is escaped.
- **Frozen globals** — the JavaScript environment is stripped down to a minimal set of builtins (`Array`, `Object`, `Promise`, `JSON`, etc.) with no `Date`, `Math`, `Proxy`, `eval`, typed arrays, or access to `Deno`/`Node` APIs. All prototypes and `globalThis` are frozen.

Note: Seccomp is naturally Linux only. There is a Mac build for local development only.

## Security Considerations

No sandbox is perfect, but escaping the V8 sandbox alone is worth [tens to hundreds of thousands of dollars in bounties from Google](https://bughunters.google.com/about/rules/chrome-friends/chrome-vulnerability-reward-program-rules). The Seccomp rules greatly limit the envelope even if that escape occurs. The reduced and frozen globals are the cherry on top.

Whilst that's pretty good, it's the start. To use this I'd recommend a defence-in-depth approach including at least:

- **Keep deno_core and V8 up-to-date.** This means updating the crates and making sure they track the latest V8 version. Easily the most important thing you can do.
- **Design your protocol carefully.** Exposing something like the current time may create opportunities for timing attacks. Consider short-lived tokens and other mechanisms where callouts are required.
- **Limit resources.** Use `--memory-limit` for the heap and `--timeout` for per-eval CPU time. For session-level limits, the host should manage process lifetime (e.g. total execution time, open handles).
- **Consider containerization.** With Seccomp the need is debatable, but it doesn't hurt. [Bubblewrap](https://github.com/containers/bubblewrap) is worth considering.
- **Static analysis.** Analyse code before it goes in. It's not perfect, but you can catch a lot early. You can also put tripwires in the globals.
- **Nuke bad actors.** Halt and quarantine any code that behaves badly — large allocations, infinite loops, etc.
- **The usual.** Users, permissions, least privilege.

If you want to use this in production, [reach out](https://jonathannen.com/about/).

## Options

- `--memory-limit <size>` — Set the V8 heap limit (default: 128MB). Limits heap only, not stack. If the heap limit is reached, the process exits with code 137. Examples: `64mb`, `256m`, `1gb`.
- `--timeout <duration>` — Max wall-clock time per eval block (default: none). If an eval exceeds this, the process exits with code 142. Examples: `5s`, `500ms`, `30s`. The timeout spans both script execution and the microtask drain that follows, so it covers synchronous infinite loops, microtask floods, and unawaited async functions (e.g. `a()` without `await` where `a` loops forever). For session-level timeouts, the host should manage process lifetime.
- `--jit` — Enable V8 JIT compilation. By default, Hermit runs in jitless mode, which disables the JIT compiler entirely. Jitless is slower but reduces attack surface.

## Build & Test

```bash
cargo build
cargo build --release
cargo test
```

## Remaining Tasks

- **macOS**: Seccomp only applies on Linux. It would be great to find a similar set of entitlements for macOS.
- **Pooling**: Unclear whether pooling isolates should be Hermit's job or its host's.
- **Hardening**: Contributions are very welcome, especially on seccomp rules.

## Alternatives

There are several ways to sandbox JavaScript. Each makes different trade-offs between security, performance, API surface, and operational complexity.

**[isolated-vm](https://github.com/nickmccurdy/isolated-vm)** — Node.js library that exposes V8 isolates as an in-process API. Fast (no process spawn), supports transferring values and references across the isolate boundary. But it runs inside your Node process — a V8 escape compromises the host. No syscall-level sandboxing. Best for trusted-ish code where performance matters more than isolation depth.

**[Wasmer](https://wasmer.io/)** / **[Wasmtime](https://wasmtime.dev/)** — WebAssembly runtimes. Language-agnostic, strong sandboxing (capability-based, no ambient authority), and near-native performance. The trade-off is that JavaScript must first be compiled to Wasm (via QuickJS or similar), which adds complexity and limits JS features. No native Promises or event loop. Best when you need polyglot sandboxing or are already in a Wasm ecosystem.

**[gVisor](https://gvisor.dev/)** / **[Firecracker](https://firecracker-microvm.github.io/)** — kernel-level or microVM sandboxing. Run anything (not just JS) with strong isolation. Heavy operationally — container images, VM boot times, memory overhead. Best when you need to sandbox arbitrary processes, not just JavaScript.

**[QuickJS](https://bellard.org/quickjs/)** — small embeddable JS engine. Easy to sandbox (no JIT, tiny attack surface).

**[Cloudflare Workers](https://workers.cloudflare.com/)** / **[Deno Deploy](https://deno.com/deploy)** — managed V8 isolate platforms. These are specific to those vendors. Cloudflare have the Open Source [workerd](https://github.com/cloudflare/workerd) based off Workers.

**Hermit** sits in a specific niche: V8 performance and full JS semantics (including async/await), with the smallest possible API surface (just `console.log`), defence-in-depth sandboxing (V8 isolate + seccomp + frozen globals), and a dead-simple stdio protocol. It's a raw primitive — you build the protocol, the host, and the orchestration yourself.

## Giants

Hermit stands on the shoulders of giants — specifically [Deno](https://github.com/denoland/deno) and [Google V8](https://v8.dev/).
