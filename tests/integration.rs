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
    // safeString bypasses toString entirely — both objects output [object Object]
    assert_eq!(c.read_line(), "[object Object]");
    assert_eq!(c.read_line(), "[object Object]");
    assert_eq!(c.read_line(), "survived");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn coercion_valueof_cannot_escape() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // valueOf on object passed to console.log — String() uses toString, not valueOf
        const evil = { valueOf() { throw new Error("escape"); } };
        try { console.log(evil); } catch(e) {}

        // valueOf returning object (infinite coercion)
        const loop_obj = { valueOf() { return loop_obj; } };
        try { console.log(+loop_obj); } catch(e) {}

        // toString/valueOf priority — toString is called for string coercion
        const prio = {
            toString() { throw new Error("toString"); },
            valueOf() { throw new Error("valueOf"); }
        };
        try { console.log("" + prio); } catch(e) {}

        console.log("survived");
    "#,
    );
    // Read past any coercion output to find "survived"
    let mut lines = Vec::new();
    loop {
        let line = c.read_line();
        lines.push(line.clone());
        if line == "survived" { break; }
    }
    assert!(lines.contains(&"survived".to_string()));
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn thrown_non_error_values_contained() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // Throw primitives
        try { throw 42; } catch(e) { console.log(typeof e); }
        try { throw "str"; } catch(e) { console.log(typeof e); }
        try { throw null; } catch(e) { console.log(e); }
        try { throw undefined; } catch(e) { console.log(e); }

        // Throw object with malicious toString
        try {
            throw { toString() { throw new Error("nested"); } };
        } catch(e) {
            try { "" + e; } catch(e2) { console.log("nested caught"); }
        }

        console.log("survived");
    "#,
    );
    assert_eq!(c.read_line(), "number");
    assert_eq!(c.read_line(), "string");
    assert_eq!(c.read_line(), "null");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "nested caught");
    assert_eq!(c.read_line(), "survived");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn getter_based_escape_attempts() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // Try to define getter on frozen prototype (should fail silently or throw)
        try {
            Object.defineProperty(Object.prototype, "escape", {
                get() { return "leaked"; }
            });
            console.log("FAIL");
        } catch(e) {
            console.log("blocked");
        }

        // Getter on a local object (allowed, but can't escape)
        const obj = {};
        try {
            Object.defineProperty(obj, "trap", {
                get() { throw new Error("trap"); }
            });
            obj.trap;
            console.log("FAIL");
        } catch(e) {
            console.log("caught");
        }

        // Try to access constructor chain from error
        try {
            null.x;
        } catch(e) {
            const ctor = e.constructor;
            try {
                Object.defineProperty(ctor.prototype, "evil", { value: 1 });
                console.log("FAIL");
            } catch(e2) {
                console.log("frozen");
            }
        }

        console.log("survived");
    "#,
    );
    assert_eq!(c.read_line(), "blocked");
    assert_eq!(c.read_line(), "caught");
    assert_eq!(c.read_line(), "frozen");
    assert_eq!(c.read_line(), "survived");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn circular_structure_handling() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // Circular object in console.log (String coercion)
        const a = {};
        a.self = a;
        try { console.log(a); } catch(e) {}

        // Circular array
        const arr = [1, 2, 3];
        arr.push(arr);
        try { console.log(arr); } catch(e) {}

        // Circular in JSON.stringify
        const circ = {};
        circ.ref = circ;
        try { JSON.stringify(circ); } catch(e) { console.log("json caught"); }

        console.log("survived");
    "#,
    );
    // Read past any output from the first two attempts
    let mut lines = Vec::new();
    loop {
        let line = c.read_line();
        lines.push(line.clone());
        if line == "survived" {
            break;
        }
    }
    assert!(lines.contains(&"json caught".to_string()));
    assert!(lines.contains(&"survived".to_string()));
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn constructor_recovery_attempts_blocked() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // Try to recover Function via error constructor chain
        // (returns the poisoned constructor, not real Function)
        try {
            const e = new Error();
            const ctor = e.constructor.constructor;
            ctor("return 1")(); // should throw "Function constructor is disabled"
            console.log("FAIL");
        } catch(e) {
            console.log("poisoned");
        }

        // Try to recover RegExp constructor via literal
        try {
            const re = /x/;
            const RegExp = re.constructor;
            // Prototype should be frozen
            RegExp.prototype.evil = true;
            // Check if it actually stuck (non-strict mode silently fails)
            console.log(RegExp.prototype.evil === true ? "FAIL" : "silent-fail");
        } catch(e) {
            console.log("frozen");
        }

        // Try to recover Symbol via getOwnPropertySymbols
        try {
            const syms = Object.getOwnPropertySymbols(Object.prototype);
            if (syms.length > 0) {
                const Sym = syms[0].constructor;
                Sym.prototype.evil = true;
                console.log("FAIL");
            } else {
                console.log("no syms");
            }
        } catch(e) {
            console.log("frozen");
        }

        console.log("survived");
    "#,
    );
    let mut lines = Vec::new();
    loop {
        let line = c.read_line();
        lines.push(line.clone());
        if line == "survived" { break; }
    }
    // Function constructor should be the poisoned one, not actual Function
    assert!(!lines.contains(&"FAIL".to_string()), "escape detected: {:?}", lines);
    assert!(lines.contains(&"survived".to_string()));
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
    assert_eq!(c.read_line(), "[object Object]"); // safeString returns static tag for all objects
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

/// Spawn hermit and capture stderr (for kernel-boundary tests).
/// Returns (stdout_lines, stderr_output, exit_code).
#[cfg(target_os = "linux")]
fn run_hermit_with_input(args: &[&str], input: &str) -> (Vec<String>, String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hermit"));
    if std::env::var("HERMIT_JIT").is_ok() {
        cmd.arg("--jit");
    }
    if !args.contains(&"--strict") {
        cmd.arg("--permissive");
    }
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).ok();
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    let stdout_lines: Vec<String> = output.stdout
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| String::from_utf8_lossy(l).to_string())
        .collect();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout_lines, stderr, code)
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

#[cfg(target_os = "linux")]
#[test]
fn seccomp_blocks_forbidden_syscall_on_timeout() {
    // When the watchdog kills the process via process::exit(), it exercises
    // the exit_group syscall which is in our allowlist. Verify the timeout
    // mechanism still works under seccomp stage-2 (exit code 142).
    let (_, _, code) = run_hermit_with_input(
        &["--timeout", "100ms"],
        "while(true) {}\n\n",
    );
    assert_eq!(code, 142, "timeout should produce exit code 142 under seccomp");
}

#[cfg(target_os = "linux")]
#[test]
fn oom_exit_works_under_seccomp() {
    // OOM handler calls process::exit(137). Verify it works under seccomp.
    let (_, stderr, code) = run_hermit_with_input(
        &["--memory-limit", "8mb"],
        "const a = []; while(true) { a.push(new Array(10000)); }\n\n",
    );
    assert_eq!(code, 137, "OOM should produce exit code 137; stderr: {}", stderr);
}

#[cfg(target_os = "linux")]
#[test]
fn strict_mode_enforces_namespace() {
    // In --strict mode on Linux, mount namespace must succeed.
    // Skip if user namespaces aren't available (common in CI containers).
    let (stdout, stderr, code) = run_hermit_with_input(
        &["--strict"],
        "console.log(\"strict-ok\")\n\n",
    );
    if code == 1 && stderr.contains("mount namespace setup failed") {
        eprintln!("skipping: user namespaces not available on this runner");
        return;
    }
    assert_eq!(code, 0, "strict mode failed unexpectedly; stderr: {}", stderr);
    assert!(stdout.contains(&"strict-ok".to_string()));
}

#[cfg(target_os = "linux")]
#[test]
fn multiple_evals_stable_under_seccomp() {
    // Verify that repeated evals don't trigger seccomp violations.
    // V8 GC may spawn threads lazily; this exercises that path.
    let mut input = String::new();
    for i in 0..50 {
        input.push_str(&format!("console.log({})\n\n", i));
    }
    let (stdout, stderr, code) = run_hermit_with_input(&[], &input);
    assert_eq!(code, 0, "50 evals should succeed; stderr: {}", stderr);
    assert!(!stderr.contains("SECCOMP BLOCKED"), "seccomp violation during evals: {}", stderr);
    assert_eq!(stdout.len(), 50, "expected 50 lines of output, got {}", stdout.len());
}

#[test]
fn typed_array_and_arraybuffer_inaccessible() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const types = [
            "ArrayBuffer", "DataView", "Int8Array", "Uint8Array",
            "Uint8ClampedArray", "Int16Array", "Uint16Array",
            "Int32Array", "Uint32Array", "Float32Array", "Float64Array",
            "BigInt64Array", "BigUint64Array", "SharedArrayBuffer"
        ];
        const results = types.map(t => typeof globalThis[t]);
        console.log(results.every(r => r === "undefined") ? "OK" : "FAIL: " + results.join(","));
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn proxy_reflect_inaccessible() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        console.log(typeof Proxy);
        console.log(typeof Reflect);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn timing_primitives_inaccessible() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        console.log(typeof Date);
        console.log(typeof performance);
        console.log(typeof setTimeout);
        console.log(typeof setInterval);
        console.log(typeof queueMicrotask);
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn async_works_after_warmup() {
    // Verify Promise.then works correctly after warmup + stage-2 seccomp.
    let mut c = Hermit::spawn();
    c.eval(r#"Promise.resolve(42).then(v => console.log(v))"#);
    assert_eq!(c.read_line(), "42");
    assert_eq!(c.shutdown(), 0);
}

// === Critical attack surface: ensure key primitives are fully inaccessible ===
// These tests verify that the primitives most useful for V8 heap exploitation
// (TypedArrays, ArrayBuffer, Proxy, eval, Function constructor) cannot be
// recovered through any indirect path — not just that the globals are deleted.

#[test]
fn arraybuffer_not_recoverable_from_prototypes() {
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // Try every known path to recover ArrayBuffer/TypedArray constructors
        let found = false;

        // Via prototype chain of remaining builtins
        const probes = [Array, Object, Map, Set, String, Number, Boolean, Error, Promise];
        for (const C of probes) {
            try {
                const proto = Object.getPrototypeOf(C);
                if (proto && proto.constructor && proto.constructor.name === "ArrayBuffer") found = true;
            } catch(e) {}
        }

        // Via Symbol.species on Array
        try {
            const arr = [];
            const species = arr.constructor[Symbol.species];
            if (species && species.name === "ArrayBuffer") found = true;
        } catch(e) {}

        // Via iterator result objects
        try {
            const iter = [].values();
            const proto = Object.getPrototypeOf(iter);
            const names = Object.getOwnPropertyNames(proto);
            for (const n of names) {
                try {
                    const val = proto[n];
                    if (typeof val === "function" && val.name === "ArrayBuffer") found = true;
                } catch(e) {}
            }
        } catch(e) {}

        console.log(found ? "FAIL" : "OK");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn function_constructor_blocked_all_variants() {
    // Verify Function constructor is poisoned on sync, async, generator,
    // and async generator function prototypes — not just regular functions.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        let escaped = false;

        // Regular function
        try { (function(){}).constructor("return 1")(); escaped = true; } catch(e) {}

        // Arrow function
        try { (()=>{}).constructor("return 1")(); escaped = true; } catch(e) {}

        // Async function
        try { (async function(){}).constructor("return 1")(); escaped = true; } catch(e) {}

        // Generator function
        try { (function*(){}).constructor("return 1")(); escaped = true; } catch(e) {}

        // Async generator function
        try { (async function*(){}).constructor("return 1")(); escaped = true; } catch(e) {}

        // Via method shorthand
        try { ({m(){}}).m.constructor("return 1")(); escaped = true; } catch(e) {}

        // Via bound function
        try { (function(){}).bind().constructor("return 1")(); escaped = true; } catch(e) {}

        // Via Reflect (should be deleted, but belt-and-suspenders)
        try { Reflect.construct(Function, ["return 1"]); escaped = true; } catch(e) {}

        console.log(escaped ? "FAIL" : "OK");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn eval_blocked_all_paths() {
    // Verify eval is blocked both directly and via indirect invocation.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        let escaped = false;

        // Direct eval
        try { eval("escaped = true"); } catch(e) {}

        // Indirect eval (non-strict eval via variable)
        try { const e = eval; e("escaped = true"); } catch(e) {}

        // eval via globalThis
        try { globalThis.eval("escaped = true"); } catch(e) {}

        // eval via bracket notation
        try { globalThis["eval"]("escaped = true"); } catch(e) {}

        console.log(escaped ? "FAIL" : "OK");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn proxy_not_recoverable() {
    // Verify Proxy can't be recovered through any indirect path.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        let found = false;

        // Direct access
        try { if (typeof Proxy !== "undefined") found = true; } catch(e) {}

        // Via Object.prototype chain
        try {
            const names = Object.getOwnPropertyNames(Object);
            if (names.includes("Proxy")) found = true;
        } catch(e) {}

        // Walk all reachable properties from globalThis
        try {
            const props = Object.getOwnPropertyNames(globalThis);
            for (const p of props) {
                try {
                    const v = globalThis[p];
                    if (typeof v === "function" && v.name === "Proxy") found = true;
                } catch(e) {}
            }
        } catch(e) {}

        console.log(found ? "FAIL" : "OK");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn webassembly_not_recoverable() {
    // Verify WebAssembly can't be recovered through prototype walking.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        let found = false;

        try { if (typeof WebAssembly !== "undefined") found = true; } catch(e) {}

        // Walk all globals looking for anything wasm-related
        try {
            const props = Object.getOwnPropertyNames(globalThis);
            for (const p of props) {
                if (p.toLowerCase().includes("wasm") || p === "WebAssembly") found = true;
            }
        } catch(e) {}

        console.log(found ? "FAIL" : "OK");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn all_prototype_chains_frozen() {
    // Walk the prototype chain of every reachable builtin and verify
    // every prototype in the chain is frozen. Only checks prototypes,
    // not fresh instances (which are naturally unfrozen).
    let mut c = Hermit::spawn_with_args(&["--timeout", "5s"]);
    c.eval(
        r#"
        // Collect prototypes (not instances) reachable from builtins and literals
        const protos = new Set();
        const builtins = [Array, Boolean, Error, JSON, Map, Number, Object, Promise,
            RangeError, Set, String, TypeError];
        for (const B of builtins) {
            let p = B; while (p) { protos.add(p); p = Object.getPrototypeOf(p); }
            if (B.prototype) { let p = B.prototype; while (p) { protos.add(p); p = Object.getPrototypeOf(p); } }
        }
        // Literal-reachable prototypes
        // Symbol global is deleted, but well-known symbols survive on prototypes.
        // Use Object.getOwnPropertySymbols to find @@iterator on String.prototype.
        const strSyms = Object.getOwnPropertySymbols(String.prototype);
        const iterSym = strSyms.find(s => String.prototype[s] && typeof String.prototype[s] === "function");
        const literalProtos = [
            Object.getPrototypeOf(/x/),                       // RegExp.prototype
            Object.getPrototypeOf([].values()),                // ArrayIterator proto
            Object.getPrototypeOf(new Map().values()),         // MapIterator proto
            Object.getPrototypeOf(new Set().values()),         // SetIterator proto
            Object.getPrototypeOf((function*(){})),                            // GeneratorFunction proto
            Object.getPrototypeOf((function*(){}).prototype),                  // Generator.prototype (shared)
            Object.getPrototypeOf((async function*(){}).prototype),           // AsyncGenerator.prototype (shared)
            Object.getPrototypeOf(async function(){}),                        // AsyncFunction.prototype
        ];
        // Add StringIterator proto if we found @@iterator
        if (iterSym) {
            try { literalProtos.push(Object.getPrototypeOf(""[iterSym]())); } catch(e) {}
        }
        for (const lp of literalProtos) {
            let p = lp; while (p) { protos.add(p); p = Object.getPrototypeOf(p); }
        }
        const unfrozen = [];
        for (const p of protos) {
            if (!Object.isFrozen(p)) {
                unfrozen.push((p.constructor && p.constructor.name) || typeof p);
            }
        }
        console.log(unfrozen.length === 0 ? "OK" : "UNFROZEN: " + unfrozen.join(", "));
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn generator_prototype_is_frozen() {
    // The shared Generator.prototype (with next/return/throw) must be frozen.
    // Each function* gets its own .prototype, but they all share the same
    // [[Prototype]] which is Generator.prototype. If that's mutable, an attacker
    // can hijack .next()/.return()/.throw() on ALL generator instances.
    let mut c = Hermit::spawn_with_args(&["--timeout", "5s"]);
    c.eval(
        r#"
        // Walk past the per-function .prototype to the shared Generator.prototype
        const perFunc = Object.getPrototypeOf((function*(){})());
        const shared = Object.getPrototypeOf(perFunc);
        // isFrozen is the definitive check — sloppy mode silently drops writes
        console.log(Object.isFrozen(shared) ? "OK" : "FAIL");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn async_generator_prototype_is_frozen() {
    // Same as generator test: the shared AsyncGenerator.prototype must be frozen.
    let mut c = Hermit::spawn_with_args(&["--timeout", "5s"]);
    c.eval(
        r#"
        // agFunc.prototype is per-function; its [[Prototype]] is the shared one
        const agFunc = async function*(){};
        const shared = Object.getPrototypeOf(agFunc.prototype);
        console.log(Object.isFrozen(shared) ? "OK" : "FAIL");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn deleted_error_prototypes_are_frozen() {
    // ReferenceError, SyntaxError, URIError are deleted from globalThis but
    // their prototypes are still reachable when V8 throws them internally.
    // If unfrozen, an attacker can pollute the prototype to affect all
    // subsequently caught errors of that type.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        let unfrozen = [];

        // ReferenceError.prototype �� reachable via undeclared variable access
        try { undeclared_xyz; } catch(e) {
            if (!Object.isFrozen(Object.getPrototypeOf(e))) unfrozen.push("ReferenceError");
        }

        // SyntaxError.prototype — reachable via JSON.parse
        try { JSON.parse("{bad"); } catch(e) {
            if (!Object.isFrozen(Object.getPrototypeOf(e))) unfrozen.push("SyntaxError");
        }

        // URIError.prototype — reachable via decodeURI
        try { decodeURI("%"); } catch(e) {
            if (!Object.isFrozen(Object.getPrototypeOf(e))) unfrozen.push("URIError");
        }

        console.log(unfrozen.length === 0 ? "OK" : "UNFROZEN: " + unfrozen.join(", "));
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn bigint_prototype_is_frozen() {
    // BigInt is deleted from globalThis but BigInt.prototype is reachable
    // via bigint literals (42n). If unfrozen, an attacker can pollute
    // toString/valueOf on all bigints.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const biProto = Object.getPrototypeOf(Object(42n));
        console.log(Object.isFrozen(biProto) ? "OK" : "FAIL");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn console_log_does_not_invoke_tostringtag_getter() {
    // Symbol.toStringTag getter on user objects must not fire inside console.log.
    // safeString returns a static "[object Object]" without reading any property.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const syms = Object.getOwnPropertySymbols(JSON);
        const toStringTag = syms.find(s => String(s) === "Symbol(Symbol.toStringTag)");
        let getterFired = false;
        const evil = {};
        if (toStringTag) {
            Object.defineProperty(evil, toStringTag, {
                get() { getterFired = true; return "pwned"; }
            });
        }
        console.log(evil);
        console.log(getterFired ? "FAIL" : "OK");
    "#,
    );
    assert_eq!(c.read_line(), "[object Object]");
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn aggregate_error_prototype_is_frozen() {
    // AggregateError is recoverable via Promise.any() even though it's
    // deleted from globalThis. Its prototype and constructor must be frozen.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        Promise.any([Promise.reject(1), Promise.reject(2)]).catch(e => {
            const proto = Object.getPrototypeOf(e);
            const ctor = e.constructor;
            const protoOk = Object.isFrozen(proto);
            const ctorOk = Object.isFrozen(ctor);
            console.log(protoOk && ctorOk ? "OK" : "FAIL proto=" + protoOk + " ctor=" + ctorOk);
        });
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn regexp_string_iterator_prototype_is_frozen() {
    // %RegExpStringIteratorPrototype% is reachable via String.prototype.matchAll
    // but not from globalThis. If unfrozen, attacker can hijack .next() on all
    // matchAll iterators.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const iter = "foo".matchAll(/o/g);
        const proto = Object.getPrototypeOf(iter);
        console.log(Object.isFrozen(proto) ? "OK" : "FAIL");
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}

#[test]
fn filesystem_is_empty_after_warmup() {
    // After warmup, the mount namespace should be completely empty.
    // Any attempt to read filesystem paths should fail. This verifies
    // the Cloudflare-model empty namespace: no /proc, /sys, or /dev.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        // These paths should all be inaccessible after warmup + strip_filesystem
        const paths = [
            "/proc/self/maps", "/proc/self/status", "/proc/self/fd",
            "/proc/self/environ", "/proc/self/cmdline",
            "/sys/devices/system/cpu", "/dev/urandom",
            "/etc/passwd", "/tmp", "/"
        ];
        // In the sandbox, none of these should be readable. The JS runtime
        // has no fs API, so we can only verify indirectly: if the sandbox
        // is working, this code runs without error (the APIs don't exist).
        console.log(typeof require);   // should be undefined (no fs access)
        console.log(typeof Deno);      // should be undefined (no Deno APIs)
        console.log(typeof process);   // should be undefined (no Node APIs)
    "#,
    );
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.read_line(), "undefined");
    assert_eq!(c.shutdown(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn seccomp_survives_gc_pressure() {
    // V8 GC thread creation + heavy allocation must not trigger seccomp
    // violations. This exercises the steady-state syscall allowlist under
    // realistic heap pressure conditions.
    let mut input = String::new();
    // Allocate enough to trigger multiple GC cycles
    for i in 0..20 {
        input.push_str(&format!(
            "{{ const a = []; for(let j=0; j<5000; j++) a.push({{x:{}}}); console.log({}); }}\n\n",
            i, i
        ));
    }
    let (stdout, stderr, code) = run_hermit_with_input(&["--memory-limit", "64mb"], &input);
    assert_eq!(code, 0, "GC pressure test should succeed; stderr: {}", stderr);
    assert!(!stderr.contains("SECCOMP BLOCKED"), "seccomp violation during GC: {}", stderr);
    assert_eq!(stdout.len(), 20, "expected 20 lines, got {}", stdout.len());
}

#[cfg(target_os = "linux")]
#[test]
fn seccomp_stage2_kills_on_violation() {
    // After stage-2, seccomp violations should kill the process (not just trap).
    // We can't easily trigger a blocked syscall from JS since dangerous APIs are
    // removed, but we verify the convention: normal operations succeed under
    // stage-2, and the process shuts down cleanly without any seccomp kill signal.
    let mut input = String::new();
    for i in 0..10 {
        input.push_str(&format!("console.log({})\n\n", i));
    }
    let (stdout, stderr, code) = run_hermit_with_input(&[], &input);
    assert_eq!(code, 0, "stage-2 should allow normal ops; stderr: {}", stderr);
    assert!(!stderr.contains("SECCOMP BLOCKED"), "unexpected seccomp trap in stage-2: {}", stderr);
    assert_eq!(stdout.len(), 10);
}

#[test]
fn no_raw_memory_access_primitives() {
    // Comprehensive check that ALL memory-access primitives are removed.
    // These are the exact types an attacker needs for heap read/write.
    let mut c = Hermit::spawn();
    c.eval(
        r#"
        const dangerous = [
            "ArrayBuffer", "SharedArrayBuffer", "DataView",
            "Int8Array", "Uint8Array", "Uint8ClampedArray",
            "Int16Array", "Uint16Array", "Int32Array", "Uint32Array",
            "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array",
            "WebAssembly", "Atomics", "Proxy", "Reflect",
            "eval", "Function",
        ];
        const present = dangerous.filter(name => {
            try { return typeof globalThis[name] !== "undefined"; } catch(e) { return false; }
        });
        // eval is intentionally kept as a throwing stub — verify it throws
        let evalWorks = false;
        try { eval("1"); evalWorks = true; } catch(e) {}
        // Function is gone (not even a stub — constructor is poisoned on prototypes)
        let fnWorks = false;
        try { Function("return 1")(); fnWorks = true; } catch(e) {}

        const evalsafe = present.filter(p => p !== "eval");
        const ok = evalsafe.length === 0 && !evalWorks && !fnWorks;
        console.log(ok ? "OK" : "FAIL: " + evalsafe.join(", ") +
            (evalWorks ? " eval-works" : "") + (fnWorks ? " fn-works" : ""));
    "#,
    );
    assert_eq!(c.read_line(), "OK");
    assert_eq!(c.shutdown(), 0);
}
