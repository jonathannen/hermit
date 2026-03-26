use std::io::Write;

use deno_core::op2;

/// console.log implementation - writes to stdout
#[op2(fast)]
pub fn op_log(#[string] message: String) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", message);
    let _ = stdout.flush();
}
