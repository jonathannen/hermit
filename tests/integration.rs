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
        self.child.wait().unwrap().code().unwrap_or(-1)
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
fn invalid_js_does_not_crash() {
    let mut c = Hermit::spawn();
    c.eval(r#"{{{"#);
    // Syntax error goes to stderr, process continues
    c.eval(r#"console.log("still alive")"#);
    assert_eq!(c.read_line(), "still alive");
    assert_eq!(c.shutdown(), 0);
}
