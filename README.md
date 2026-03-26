# Hermit

Hermit runs JavaScript in a cave. You can pass notes in and get notes back. That's it.

More specifically, Hermit runs JavaScript inside V8 isolates, using stdio as the control protocol. Code is sent via stdin and eval'd in the isolate. Input is buffered line-by-line until a blank line is received, at which point the accumulated block is evaluated. On EOF, any remaining buffered code is flushed and evaluated.

The code in the isolate can call `console.log` and that's it. No file system, no environment variables, no `require`, and extremely limited globals.

Hermit provides the primitive isolate. It's expected that you'd build a host and protocol on top for doing real work.

Async handlers and work is completely possible. See `tests/fixtures/async_bridge.js` as a starting point.

## Example

```bash
printf 'const add = (a, b) => a + b;\n\nconsole.log(add(1, 2));\n\n' | hermit
# 3
```

See `tests/fixtures` for other examples.

## Security Layers

- **[V8 Isolate](https://v8.dev/docs/embed#isolates)** — each execution runs in its own V8 isolate, the same process-level sandbox that Chrome uses to separate tabs.
- **[Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)** (Linux) — a syscall filter that restricts what the process can do at the kernel level, even if the V8 sandbox is escaped.
- **Frozen globals** — the JavaScript environment is stripped down to a minimal set of builtins (`Array`, `Object`, `Promise`, `JSON`, etc.) with no `Date`, `Math`, `Proxy`, `eval`, typed arrays, or access to `Deno`/`Node` APIs. All prototypes and `globalThis` are frozen.

## Security Considerations

No sandbox is perfect, but escaping the V8 sandbox alone is worth [tens to hundreds of thousands in bounties from Google](https://bughunters.google.com/about/rules/chrome-friends/chrome-vulnerability-reward-program-rules). The Seccomp rules greatly limit the envelope even if that escape occurs. The reduced and frozen globals are the cherry on top.

Whilst that's pretty damn good, it's the start. To use this I'd recommend a defence-in-depth approach. This includes at least:

- **Keep deno_core and V8 up-to-date.** This means updating the crates and making sure they track the latest V8 version. Easily the most important thing you can do.
- **Design your protocol carefully.** Exposing something like the current time may create opportunities for timing attacks. Consider short-lived tokens and other mechanisms where callouts are required.
- **Limit resources.** Use the `--memory-limit` flag for RAM. For CPU, your host needs to manage that (e.g. execution time, open handles).
- **Consider containerization.** With Seccomp the need is debatable, but it doesn't hurt. [Bubblewrap](https://github.com/containers/bubblewrap) is worth considering.
- **Static analysis.** Analyse code before it goes in. It's not perfect, but you can catch a lot early. You can also put tripwires in the globals.
- **Nuke bad actors.** Halt and quarantine any code that behaves badly — large allocations, infinite loops, etc.
- **The usual.** Users, permissions, least privilege.

If you want to use this in production, [reach out](https://jonathannen.com/about/).

## Build & Test

```bash
cargo build
cargo build --release
cargo test
```

## Remaining Tasks

- **x86**: The Seccomp rules are currently Linux/ARM only. Running in Docker on Mac/Rosetta is not sufficient — it needs an actual x86 CPU to be developed.
- **macOS**: Seccomp only applies on Linux. It would be great to find a similar set of entitlements for macOS.
- **Pooling**: Unclear whether pooling isolates should be Hermit's job or its host's.
- **Hardening**: If you'd like to further battle-test this, contributions are very welcome.

## Giants

Hermit stands on the shoulders of giants — specifically [Deno](https://github.com/denoland/deno) and [Google V8](https://v8.dev/).
# hermit
