use std::io::Write;

use deno_core::op2;

use crate::runtime::PIPE_EXIT_CODE;

/// console.log implementation - writes to stdout
#[op2(fast)]
pub fn op_log(#[string] message: String) {
    let mut stdout = std::io::stdout().lock();
    if writeln!(stdout, "{}", message).is_err() || stdout.flush().is_err() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "fatal: stdout write failed");
        let _ = stderr.flush();
        std::process::exit(PIPE_EXIT_CODE);
    }
}
