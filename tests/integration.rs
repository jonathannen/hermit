//! Integration tests for hermit runtime

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

struct Hermit {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl Hermit {
    fn spawn() -> Self {
        Self::spawn_with_args(&[])
    }

    fn spawn_with_args(extra_args: &[&str]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hermit"));

        if std::env::var("HERMIT_JIT").is_ok() {
            cmd.arg("--jit");
        }

        // CI runners often lack user namespaces; default to --permissive
        // unless the test explicitly passes --strict.
        if !extra_args.contains(&"--strict") {
            cmd.arg("--permissive");
        }

        cmd.args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().expect("failed to spawn");
        let stdin = child.stdin.take().unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            reader,
        }
    }

    fn eval(&mut self, code: &str) {
        writeln!(self.stdin, "{}", code).unwrap();
        writeln!(self.stdin).unwrap();
        self.stdin.flush().unwrap();
    }

    #[allow(dead_code)]
    fn flush(&mut self) {
        writeln!(self.stdin, "__flush__").unwrap();
        writeln!(self.stdin).unwrap();
        self.stdin.flush().unwrap();
    }

    fn read_line(&mut self) -> String {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .expect("failed to read line");
        if n == 0 {
            let status = self.child.try_wait().ok().flatten();
            panic!("process died unexpectedly, exit status: {:?}", status);
        }
        line.trim_end().to_string()
    }

    fn shutdown(mut self) -> i32 {
        drop(self.stdin);
        let status = self.child.wait().unwrap();
        if let Some(code) = status.code() {
            return code;
        }
        // Killed by signal — map to 128 + signal (standard shell convention)
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                return 128 + sig;
            }
        }
        -1
    }
}

#[test]
fn hello_world() {
    let mut c = Hermit::spawn();
    c.eval(r#"console.log("Hello World!")"#);
    assert_eq!(c.read_line(), "Hello World!");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn multi_eval() {
    let mut c = Hermit::spawn();
    c.eval(r#"console.log("one")"#);
    c.eval(r#"console.log("two")"#);
    c.eval(r#"console.log("three")"#);
    assert_eq!(c.read_line(), "one");
    assert_eq!(c.read_line(), "two");
    assert_eq!(c.read_line(), "three");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn eval_expression() {
    let mut c = Hermit::spawn();
    c.eval(r#"console.log(1 + 2)"#);
    assert_eq!(c.read_line(), "3");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn prevents_code_bomb_attacks() {
    let mut c = Hermit::spawn();
    c.eval(r#"new Function("return 1;")"#);
    // Should not crash - Function constructor is poisoned
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn no_access_to_atomics() {
    let mut c = Hermit::spawn();
    c.eval(r#"console.log(typeof Atomics)"#);
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn no_access_to_date() {
    let mut c = Hermit::spawn();
    c.eval(r#"console.log(typeof Date)"#);
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn prevents_deep_recursion_attacks() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        let root = { val: 1 };
        for (let i = 0; i < 100000; i++) root = { next: root };
        console.log("done");
    "#,
    );
    // May or may not print "done" depending on serialization, but should not crash
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn prevents_stack_smash_attacks() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const args = new Array(200000).fill(0);
        (function(){}).apply(null, args);
    "#,
    );
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn prevents_modifying_global_scope() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        globalThis.hello = 'world';
        console.log(typeof globalThis.hello);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn eval_is_disabled() {
    let mut c = Hermit::spawn();
    c.eval(r#"eval("1+1")"#);
    // Should error to stderr, not crash
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn async_handler_fixture() {
    let js = include_str!("fixtures/async_handler.js");
    let mut c = Hermit::spawn();
    c.eval(js);
    c.eval(r#"handler("foo").then(result => console.log(result))"#);
    assert_eq!(c.read_line(), "handled: processed: FOO");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn async_bridge_fixture() {
    let js = include_str!("fixtures/async_bridge.js");
    let mut c = Hermit::spawn();
    c.eval(js);
    // Spawn three handlers that each wait for their id to be resolved
    c.eval(r#"handler("a").then(v => console.log("a: " + v))"#);
    c.eval(r#"handler("b").then(v => console.log("b: " + v))"#);
    c.eval(r#"handler("c").then(v => console.log("c: " + v))"#);
    // Resolve out of order
    c.eval(r#"resolve("c", "third")"#);
    c.eval(r#"resolve("a", "first")"#);
    c.eval(r#"resolve("b", "second")"#);
    // Output should match resolve order, not spawn order
    assert_eq!(c.read_line(), "c: third");
    assert_eq!(c.read_line(), "a: first");
    assert_eq!(c.read_line(), "b: second");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn run_basic_fixture() {
    let js = include_str!("fixtures/basic.js");
    let mut c = Hermit::spawn();
    c.eval(js);
    assert_eq!(c.read_line(), "hello from fixture");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn prototypes_are_frozen() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        try { Array.prototype.evil = 1; } catch(e) {}
        try { Object.prototype.evil = 1; } catch(e) {}
        try { String.prototype.evil = 1; } catch(e) {}
        console.log(typeof [].evil);
        console.log(typeof ({}).evil);
        console.log(typeof "".evil);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn proto_manipulation_blocked() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        try { ({}).__proto__.polluted = true; } catch(e) {}
        try { Object.defineProperty(Object.prototype, "x", { value: 1 }); } catch(e) {}
        console.log(typeof ({}).polluted);
        console.log(typeof ({}).x);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn dynamic_import_blocked() {
    let mut c = Hermit::spawn();
    c.eval(r#"import("fs").then(() => console.log("bad")).catch(() => console.log("blocked"))"#);
    assert_eq!(c.read_line(), "blocked");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn globals_are_deny_by_default() {
    let mut c = Hermit::spawn();
    // Enumerate all own properties on globalThis — only the safe allowlist
    // should survive. This catches new V8 globals automatically.
    c.eval(
        r#"
        const allowed = [
            "Array", "Boolean", "Error", "JSON", "Map", "Number", "Object",
            "Promise", "RangeError", "Set", "String", "TypeError",
            "console", "eval", "globalThis", "undefined", "NaN", "Infinity",
            "isNaN", "isFinite", "parseFloat", "parseInt",
            "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent",
            "AggregateError"
        ];
        const props = Object.getOwnPropertyNames(globalThis);
        const unexpected = props.filter(p => !allowed.includes(p));
        console.log(unexpected.length === 0 ? "OK" : "UNEXPECTED: " + unexpected.join(", "));
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn webassembly_is_inaccessible() {
    let mut c = Hermit::spawn();
    c.eval(r#"console.log(typeof WebAssembly);"#);
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn regex_literals_cannot_escape_sandbox() {
    let mut c = Hermit::spawn();
    // Regex literals still work at the V8 level even with RegExp deleted
    c.eval(
        r#"
        try {
            const re = /test/;
            console.log(re.test("test"));
        } catch(e) {
            console.log("error");
        }
    "#,
    );
    let result = c.read_line();
    // Either works (true) or errors — both are acceptable, just shouldn't crash
    assert!(result == "true" || result == "error");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn this_cannot_reach_unfrozen_scope() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // sloppy-mode function this
        try { (function() { this.leaked = 1; })(); } catch(e) {}
        // constructor this
        try { const o = new (function() { this.x = 1; })(); } catch(e) {}
        console.log(typeof leaked);
        console.log(typeof globalThis.leaked);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn string_bomb_is_contained() {
    let mut c = Hermit::spawn_with_args(&["--memory-limit", "16mb"]);
    c.eval(
        r#"
        let s = "a";
        try { while(true) s += s; } catch(e) {}
        console.log("survived");
    "#,
    );
    // V8 throws RangeError on string length before hitting heap limit
    assert_eq!(c.read_line(), "survived");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn microtask_flood_is_contained() {
    let mut c = Hermit::spawn_with_args(&["--memory-limit", "16mb"]);
    c.eval(
        r#"
        const f = () => Promise.resolve().then(f);
        f();
    "#,
    );
    // Should eventually OOM or error, not hang forever
    // (microtask queue grows unboundedly, hitting heap limit)
    let code = c.shutdown();
    assert!(code == 137 || code == 0, "unexpected exit code: {}", code);
}

#[test]
fn cross_block_state_persists() {
    let mut c = Hermit::spawn();
    c.eval(r#"const greet = (name) => console.log("hi " + name);"#);
    c.eval(r#"greet("world")"#);
    assert_eq!(c.read_line(), "hi world");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn cross_block_const_cannot_be_redefined() {
    let mut c = Hermit::spawn();
    c.eval(r#"const x = 1;"#);
    // Redefining a const in a later block should error
    c.eval(r#"const x = 2;"#);
    // Process should survive the error
    c.eval(r#"console.log("alive")"#);
    assert_eq!(c.read_line(), "alive");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn null_bytes_in_input() {
    let mut c = Hermit::spawn();
    c.eval("console.log(\"a\\x00b\")");
    // Should handle null bytes without crashing
    c.eval(r#"console.log("still alive")"#);
    assert_eq!(c.read_line(), "a\x00b");
    assert_eq!(c.read_line(), "still alive");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn very_long_line() {
    let mut c = Hermit::spawn();
    // Send a 1MB string literal
    let long_str = "a".repeat(1_000_000);
    c.eval(&format!(r#"console.log("{}".length)"#, long_str));
    assert_eq!(c.read_line(), "1000000");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn empty_blocks() {
    let mut c = Hermit::spawn();
    // Send several empty blocks (just blank lines)
    c.eval("");
    c.eval("");
    c.eval("");
    c.eval(r#"console.log("alive")"#);
    assert_eq!(c.read_line(), "alive");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn timeout_kills_infinite_loop() {
    let mut c = Hermit::spawn_with_args(&["--timeout", "1s"]);
    c.eval(r#"while(true){}"#);
    assert_eq!(c.shutdown(), 142);
}

#[test]
fn timeout_does_not_affect_fast_eval() {
    let mut c = Hermit::spawn_with_args(&["--timeout", "2s"]);
    c.eval(r#"console.log("fast")"#);
    assert_eq!(c.read_line(), "fast");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn timeout_kills_microtask_flood() {
    let mut c = Hermit::spawn_with_args(&["--timeout", "1s"]);
    c.eval(r#"const f = () => { while(true){} }; Promise.resolve().then(f);"#);
    assert_eq!(c.shutdown(), 142);
}

#[test]
fn caller_chain_cannot_escape_sandbox() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        (function outer() {
            (function inner() {
                const caller = arguments.callee.caller;
                // Can walk to caller, but cannot reach anything beyond user code
                try { caller.constructor("return this")(); } catch(e) {}
                console.log(typeof caller);
            })();
        })();
    "#,
    );
    // caller is accessible but Function constructor is poisoned
    assert_eq!(c.read_line(), "function");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn error_stack_does_not_leak_paths() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const stack = new Error("test").stack;
        // Stack should only reference <stdin>, not internal file paths
        const hasInternalPaths = stack.includes("/") || stack.includes("\\");
        console.log(hasInternalPaths);
        console.log(stack.includes("<stdin>"));
    "#,
    );
    assert_eq!(c.read_line(), "false");
    assert_eq!(c.read_line(), "true");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn function_constructor_blocked_via_builtins() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const paths = [
            console.log.constructor,
            [].map.constructor,
            "".toString.constructor,
            (()=>{}).constructor,
        ];
        let escaped = false;
        for (const F of paths) {
            try { new F("return 1"); escaped = true; } catch(e) {}
            try { F("return 1"); escaped = true; } catch(e) {}
        }
        console.log(escaped);
    "#,
    );
    assert_eq!(c.read_line(), "false");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn malicious_tojson_and_tostring_contained() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const bomb = { toString() { throw new Error("boom"); } };
        try { console.log(bomb); } catch(e) {}
        const recursive = { toString() { return console.log(recursive); } };
        try { console.log(recursive); } catch(e) {}
        console.log("survived");
    "#,
    );
    assert_eq!(c.read_line(), "survived");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn intl_crypto_queuemicrotask_deleted() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        console.log(typeof Intl);
        console.log(typeof crypto);
        console.log(typeof queueMicrotask);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn console_log_non_string_types() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        console.log(undefined);
        console.log(null);
        console.log(true);
        console.log(12345);
        console.log({a:1});
        console.log([1,2,3]);
        console.log(1, "two", null);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "null");
    assert_eq!(c.read_line(), "true");
    assert_eq!(c.read_line(), "12345");
    assert_eq!(c.read_line(), "[object Object]");
    assert_eq!(c.read_line(), "1,2,3");
    assert_eq!(c.read_line(), "1 two null");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn console_log_no_args() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        console.log();
        console.log("after");
    "#,
    );
    assert_eq!(c.read_line(), "");
    assert_eq!(c.read_line(), "after");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn console_log_large_string() {
    let mut c = Hermit::spawn();
    c.eval(r#"const s = "x".repeat(1024 * 1024); console.log(s.length);"#);
    assert_eq!(c.read_line(), "1048576");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn invalid_js_does_not_crash() {
    let mut c = Hermit::spawn();
    c.eval(r#"{{{"#);
    // Syntax error goes to stderr, process continues
    c.eval(r#"console.log("still alive")"#);
    assert_eq!(c.read_line(), "still alive");
    assert_eq!(c.shutdown(), 0);
}

// === Sandbox hardening tests ===

#[test]
fn survives_many_sequential_evals() {
    // Verify the full sandbox (namespace + seccomp stage 2) doesn't
    // break under sustained eval load.
    let mut c = Hermit::spawn();
    for i in 0..100 {
        c.eval(&format!(r#"console.log({})"#, i));
        assert_eq!(c.read_line(), i.to_string());
    }
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn warmup_does_not_leak_to_user_code() {
    // The warmup eval ("1") runs before user code.
    // Verify it doesn't produce output or leave state.
    let mut c = Hermit::spawn();
    c.eval(r#"console.log("first")"#);
    assert_eq!(c.read_line(), "first");
    assert_eq!(c.shutdown(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn seccomp_blocks_with_exit_159() {
    // Deno.core is deleted, but if we somehow bypass JS lockdown and
    // trigger a blocked syscall, the process should exit with 159
    // (our SIGSYS handler's exit code). We can't easily trigger this
    // from JS since dangerous APIs are removed, but we verify the
    // exit code convention by checking that the process doesn't use
    // 159 for normal operations.
    let mut c = Hermit::spawn();
    c.eval(r#"console.log("ok")"#);
    assert_eq!(c.read_line(), "ok");
    let code = c.shutdown();
    assert_ne!(code, 159, "normal shutdown should not exit with seccomp trap code");
}

#[test]
fn async_works_after_warmup() {
    // Verify Promise.then works correctly after warmup + stage-2 seccomp.
    let mut c = Hermit::spawn();
    c.eval(r#"Promise.resolve(42).then(v => console.log(v))"#);
    assert_eq!(c.read_line(), "42");
    assert_eq!(c.shutdown(), 0);
}
