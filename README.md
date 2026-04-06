# Hermit

Hermit runs JavaScript in a cave. You can pass notes in and get notes back. That's it.

More specifically, Hermit runs JavaScript inside V8 isolates, using stdio as the control protocol. Code is sent via stdin and eval'd in the isolate. Input is buffered line-by-line until a blank line is received, at which point the accumulated block is evaluated. At this point, the Hermit waits for all microtasks to complete. On EOF, any remaining buffered code is flushed and evaluated.

The code in the isolate can call `console.log` and that's it. No environment variables, no `require`, and extremely limited globals.

Hermit provides the primitive isolate. It's expected that you'd build a host and protocol on top for doing real work.

The typical pattern is to send JavaScript wrapped in a protocol handler, then invoke this handler with later evals. The handler can interact with the host via console.log output — the protocol on how they communicate is up to you. See `examples/fetch` as an example. Async handlers and interactions can be supported. See `tests/fixtures/async_bridge.js` as a starting point.

On Linux, Hermit layers multiple OS-level sandboxing mechanisms on top of V8's isolate. There is a Mac build for local development only.

## Why

As part of [alpyne.dev](http://alpyne.dev) I wanted to be able to run untrusted JavaScript code against a well-defined set of interfaces. A plugin is the best natural example of this in the wild.

There are already tools that help on the untrusted side, but they were either too heavy or required a bunch of plumbing to work. In my case I just want to run JavaScript.

Hermit gives you the primitives to do this. You've given a vary narrow window - stdio message passing. On top of this you can construct any protocol you like.

On Linux, Hermit layers mount namespaces, Landlock, two-stage seccomp, and rlimits on top of V8's process-level isolation. It's a single binary with no runtime dependencies.

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

This is the most basic primitive to build off. From here you can create much richer interfaces. See `examples` and `tests/fixtures` for other examples.

Note: You can also substitute `hermit` for `cargo run` as you like.

## Security Layers

- **[V8 Isolate](https://v8.dev/docs/embed#isolates)** — each instance of Hermit runs its own V8 isolate, the same process-level sandbox that Chrome uses to separate tabs. V8 is run with `--disallow-code-generation-from-strings` and by default no JIT.
- **Frozen globals** — the JavaScript environment is stripped down to a minimal set of builtins (`Array`, `Object`, `Promise`, `JSON`, etc.) with no `Date`, `Math`, `Proxy`, `eval`, typed arrays, or access to `Deno`/`Node` APIs. `globalThis` and all reachable prototypes are transitively deep-frozen, including prototypes only reachable via syntax literals (generators, async generators, `RegExp`, `BigInt`), V8-thrown exceptions (`ReferenceError`, `SyntaxError`, `URIError`), builtin operations (`AggregateError` via `Promise.any`, `%RegExpStringIteratorPrototype%` via `matchAll`), and all iterator prototypes. The `Function` constructor is poisoned on all function-kind prototypes.
- **[Mount namespace](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)** (Linux) — on startup, Hermit creates a new user and mount namespace and pivots to a unique-per-run tmpfs root (created via `mkdtemp`). The tmpfs is mounted with `MS_NOSUID|MS_NODEV|MS_NOEXEC` and remounted read-only after setup completes. During V8 initialization only `/proc/self/maps`, `/proc/self/status`, `/proc/self/fd`, `/sys/devices/system/cpu`, and `/dev/urandom` are visible. After warmup, `/proc/self/maps`, `/proc/self/status`, `/dev/urandom`, and `/sys` are unmounted — only `/proc/self/fd` remains. This prevents a post-escape attacker from reading `/proc/self/maps` (ASLR defeat) or `/proc/self/status` (host info leak). The host filesystem (source trees, secrets, `/etc`) is never reachable. In `--strict` mode (the Linux default), failure to create the namespace is fatal. In `--permissive` mode, Hermit warns and continues without filesystem isolation.
- **[Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)** (Linux) — a two-stage syscall filter that restricts what the process can do at the kernel level, even if the V8 sandbox is escaped. Stage 1 is installed after V8 initialization and blocks networking, exec, fork, timing, and most filesystem operations. A warmup eval then triggers V8's lazy initialization. Stage 2 is applied with `SECCOMP_FILTER_FLAG_TSYNC` to cover all threads (including V8 GC threads spawned during warmup), locks down further, and blocks the `seccomp` syscall itself — preventing a post-escape attacker from loosening the filter from any thread. Argument-level filtering restricts `clone` to require `CLONE_THREAD` (no fork/namespace escape), `mmap` to `MAP_PRIVATE` only (no shared memory), `mremap` to block `MREMAP_FIXED` (no remapping over arbitrary targets), `mprotect` to block `PROT_EXEC` in jitless mode (no executable pages), `madvise` to safe flags, and `openat` to read-only. `clone3` is forced to return `ENOSYS` via a stacked filter so glibc falls back to the filterable `clone` syscall.
- **[Landlock](https://docs.kernel.org/userspace-api/landlock.html)** (Linux 5.13+) — after the mount namespace is set up, Hermit applies Landlock LSM rules that restrict the entire filesystem to read-only. This provides an independent security layer: even if seccomp is bypassed via a kernel bug, Landlock still enforces path-level access control. Best-effort — silently skipped on older kernels.
- **FD hygiene** — all inherited file descriptors above stderr are closed before any runtime initialization, preventing interaction with FDs the parent may have left open.
- **Resource limits** — `RLIMIT_NOFILE` (capped at 64, tightened after init), `RLIMIT_FSIZE` (zero — no file writes), `RLIMIT_NPROC` (frozen at current thread count + headroom), `RLIMIT_CORE` (zero — no core dumps), `RLIMIT_AS` (current virtual memory + headroom — caps total address space), and `RLIMIT_CPU` (kernel-enforced hard timeout when `--timeout` is set — backstop that works even if the watchdog thread is dead) are set automatically. V8 heap limits and per-eval timeouts are configurable via `--memory-limit` and `--timeout`.
- **prctl hardening** — `PR_SET_DUMPABLE` is disabled (no core dumps or ptrace attachment) and `PR_SET_NO_NEW_PRIVS` is set (no privilege escalation via execve).
- **Architecture validation** — seccomp filters include an `AUDIT_ARCH` check that kills the process on architecture mismatch, blocking 32-bit compat syscall bypass attempts on 64-bit kernels.

Note: Seccomp, mount namespaces, and Landlock are Linux only. There is a Mac build for local development only.

## Security Considerations

No sandbox is perfect, but escaping the V8 sandbox alone is worth [tens to hundreds of thousands of dollars in bounties from Google](https://bughunters.google.com/about/rules/chrome-friends/chrome-vulnerability-reward-program-rules). The frozen globals eliminate the API surface most useful for heap exploitation (no TypedArrays, ArrayBuffer, Proxy, or eval). The seccomp rules greatly limit what a post-escape attacker can do even with arbitrary code execution.

Hermit is a security layer. There are three key ways to maintain this layer:

- **Keep deno_core and V8 up-to-date.** This means updating the crates and making sure they track the latest V8 version. Easily the most important thing you can do.
- **Design your protocol carefully.** Do this with care. Exposing something like the current time may create opportunities for timing attacks. Consider short-lived tokens and other mechanisms where callouts are required.
- **Linux Strict Jitless.** Is the intended deployment with the strongest checks. On Linux, no jit, and strict mode are already defaults.

From here it becomes defence-in-depth:

- **Limit resources.** Use `--memory-limit` for the heap and `--timeout` for per-eval CPU time. Hermit sets OS-level rlimits automatically, but the host should manage session-level process lifetime (e.g. total execution time, open handles).
- **Ensure namespace isolation is active.** Mount namespace isolation requires Linux user namespaces. In `--strict` mode (the Linux default), Hermit will refuse to start if namespaces are unavailable. If you run with `--permissive`, the host filesystem is still reachable read-only via seccomp. To enable namespaces in Docker, use `--privileged` or configure AppArmor/seccomp to allow `unshare`. On bare metal, ensure `/proc/sys/kernel/unprivileged_userns_clone` is `1`.
- **Static analysis.** Analyse code before it goes in. It's not perfect, but you can catch a lot early. You can also put tripwires in the globals.
- **Nuke bad actors.** Halt and quarantine any code that behaves badly — large allocations, infinite loops, etc.
- **The usual.** Users, permissions, least privilege.

If you want to use this in production, [reach out](https://jonathannen.com/about/).

## Options

- `--memory-limit <size>` — Set the V8 heap limit (default: 128MB). Limits heap only, not stack. If the heap limit is reached, the process exits with code 137. Examples: `64mb`, `256m`, `1gb`.
- `--timeout <duration>` — Max wall-clock time per eval block (default: none). If an eval exceeds this, the process exits with code 142. Examples: `5s`, `500ms`, `30s`. The timeout spans both script execution and the microtask drain that follows, so it covers synchronous infinite loops, microtask floods, and unawaited async functions (e.g. `a()` without `await` where `a` loops forever). For session-level timeouts, the host should manage process lifetime.
- `--strict` — Fail if mount namespace isolation cannot be established. This is the default on Linux, where user namespaces are expected to be available. If namespace creation fails (e.g. disabled kernel, restricted Docker), the process exits with code 1.
- `--permissive` — Warn and continue without mount namespace isolation if it cannot be established. This is the default on macOS, where mount namespaces are not available.
- `--jit` — Enable V8 JIT compilation (weaker security). By default, Hermit runs in jitless mode, which disables the JIT compiler entirely. JIT mode is faster but materially weakens the sandbox: `mprotect` must remain unrestricted so V8 can make pages executable at runtime, which is the key primitive an attacker needs for shellcode injection after a V8 escape. In jitless mode, `mprotect` with `PROT_EXEC` is blocked by seccomp. **Use jitless (the default) for untrusted code.** Only enable `--jit` when you trust the code or need the performance and accept the wider attack surface.

## Build & Test

```bash
cargo build
cargo build --release
cargo test
```

## Remaining Tasks

- **macOS sandbox**: Seccomp and mount namespaces only apply on Linux. A similar set of entitlements for macOS (e.g. `sandbox_init`, App Sandbox) would be valuable.
- **Pooling**: Unclear whether pooling isolates should be Hermit's job or its host's.
- **Hardening**: Contributions are welcome.

## Alternatives

There are several ways to sandbox JavaScript. Each makes different trade-offs between security, performance, API surface, and operational complexity.

**[isolated-vm](https://github.com/nickmccurdy/isolated-vm)** — Node.js library that exposes V8 isolates as an in-process API. Fast (no process spawn), supports transferring values and references across the isolate boundary. But it runs inside your Node process — a V8 escape compromises the host. No syscall-level sandboxing. Best for trusted-ish code where performance matters more than isolation depth.

**[Wasmer](https://wasmer.io/)** / **[Wasmtime](https://wasmtime.dev/)** — WebAssembly runtimes. Language-agnostic, strong sandboxing (capability-based, no ambient authority), and near-native performance. The trade-off is that JavaScript must first be compiled to Wasm (via QuickJS or similar), which adds complexity and limits JS features. No native Promises or event loop. Best when you need polyglot sandboxing or are already in a Wasm ecosystem.

**[gVisor](https://gvisor.dev/)** / **[Firecracker](https://firecracker-microvm.github.io/)** — kernel-level or microVM sandboxing. Run anything (not just JS) with strong isolation. Heavy operationally — container images, VM boot times, memory overhead. Best when you need to sandbox arbitrary processes, not just JavaScript.

**[QuickJS](https://bellard.org/quickjs/)** — small embeddable JS engine. Easy to sandbox (no JIT, tiny attack surface). Still in-process and not hardened generally (it's often used with WASM).

**[Cloudflare Workers](https://workers.cloudflare.com/)** / **[Deno Deploy](https://deno.com/deploy)** — managed V8 isolate platforms. These are specific to those vendors. Cloudflare have the Open Source [workerd](https://github.com/cloudflare/workerd) based off Workers.

**Hermit** sits in a specific niche: V8 performance and full JS semantics (including async/await), with the smallest possible API surface (just `console.log`), defence-in-depth sandboxing (V8 isolate + mount namespace + Landlock + two-stage seccomp + frozen globals + rlimits + FD hygiene), and a dead-simple stdio protocol. It's a raw primitive — you build the protocol, the host, and the orchestration yourself.

## Giants

Hermit stands on the shoulders of giants — specifically [Deno](https://github.com/denoland/deno) and [Google V8](https://v8.dev/).
