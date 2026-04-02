mod ops;
mod runtime;
mod seccomp;

use std::fmt;
use std::io::BufRead;
use std::time::Duration;

use deno_core::error::AnyError;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

const DEFAULT_MEMORY_LIMIT: usize = 128 * 1024 * 1024; // 128MB

/// Close all file descriptors above stderr (fd > 2).
/// Must be called before creating the tokio runtime or V8 isolate.
fn close_inherited_fds() {
    // Read /proc/self/fd to find open FDs (Linux).
    // On non-Linux, fall back to closing a reasonable range.
    let fds: Vec<i32> = if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
            .filter(|&fd| fd > 2)
            .collect()
    } else {
        // Fallback: close fds 3..1024 (covers typical inherited FDs)
        (3..1024).collect()
    };

    for fd in fds {
        // SAFETY: closing unknown FDs is safe — close on an invalid/already-closed FD
        // returns EBADF which we ignore. This runs before any Rust I/O beyond stdio.
        unsafe { libc::close(fd); }
    }
}

#[derive(Debug)]
struct InvalidDuration(String);

impl fmt::Display for InvalidDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid duration: {}", self.0)
    }
}

fn parse_timeout(s: &str) -> Result<Duration, InvalidDuration> {
    let s = s.trim().to_lowercase();
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix("s") {
        (n, 1000)
    } else {
        // bare number treated as milliseconds
        (s.as_str(), 1)
    };

    num_str
        .trim()
        .parse::<u64>()
        .map(|n| Duration::from_millis(n * multiplier))
        .map_err(|_| InvalidDuration(s))
}

/// Watchdog that kills the process if an eval exceeds the timeout.
/// Call `start()` before each eval and `stop()` after it completes.
struct Watchdog {
    tx: std::sync::mpsc::Sender<bool>,
}

impl Watchdog {
    fn spawn(timeout: Duration) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        std::thread::spawn(move || {
            loop {
                // Wait for a start signal
                match rx.recv() {
                    Ok(true) => {} // eval started, begin timing
                    _ => return,   // channel closed, exit
                }
                // Wait for stop signal or timeout
                match rx.recv_timeout(timeout) {
                    Ok(_) => continue, // eval completed in time
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        let mut stderr = std::io::stderr().lock();
                        use std::io::Write;
                        let _ = writeln!(stderr, "fatal: eval timed out");
                        let _ = stderr.flush();
                        std::process::exit(runtime::TIMEOUT_EXIT_CODE);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        });
        Watchdog { tx }
    }

    fn start(&self) {
        self.tx.send(true).expect("watchdog thread died");
    }

    fn stop(&self) {
        self.tx.send(false).expect("watchdog thread died");
    }
}

#[derive(Debug)]
struct InvalidMemoryLimit(String);

impl fmt::Display for InvalidMemoryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid memory limit: {}", self.0)
    }
}

fn parse_memory_limit(s: &str) -> Result<usize, InvalidMemoryLimit> {
    let s = s.trim().to_lowercase();
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix("gb") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("g") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("m") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("kb") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("k") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("b") {
        (n, 1)
    } else {
        (s.as_str(), 1)
    };

    num_str
        .trim()
        .parse::<usize>()
        .map(|n| n * multiplier)
        .map_err(|_| InvalidMemoryLimit(s))
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!("Usage: hermit [--memory-limit <size>] [--timeout <duration>] [--jit]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --jit                  Enable JIT compilation (default: jitless)");
    eprintln!("  --memory-limit <size>  Set V8 heap limit (default: 128MB)");
    eprintln!("                         Limits heap only, not stack (exit code 137).");
    eprintln!("                         Examples: 64mb, 256m, 1gb, 512kb");
    eprintln!("  --timeout <duration>   Max wall-clock time per eval block (default: none)");
    eprintln!("                         Kills process on timeout (exit code 142).");
    eprintln!("                         Examples: 5s, 500ms, 30s");
    eprintln!("  --version, -V          Print version");
}

fn main() {
    let mut memory_limit = DEFAULT_MEMORY_LIMIT;
    let mut allow_jit = false;
    let mut timeout: Option<Duration> = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--jit" => {
                allow_jit = true;
            }
            "--memory-limit" => {
                let Some(value) = args.next() else {
                    print_usage();
                    std::process::exit(1);
                };
                memory_limit = match parse_memory_limit(&value) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        print_usage();
                        std::process::exit(1);
                    }
                };
            }
            "--timeout" => {
                let Some(value) = args.next() else {
                    print_usage();
                    std::process::exit(1);
                };
                timeout = Some(match parse_timeout(&value) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        print_usage();
                        std::process::exit(1);
                    }
                });
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                eprintln!("hermit {}", VERSION);
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    // FD hygiene: close all inherited file descriptors except stdin/stdout/stderr.
    // This prevents a post-escape attacker from interacting with FDs the parent
    // may have accidentally left open (database connections, sockets, etc.).
    close_inherited_fds();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let local = tokio::task::LocalSet::new();
    if let Err(e) = local.block_on(&runtime, run(memory_limit, allow_jit, timeout)) {
        eprintln!("fatal: {}", e);
        std::process::exit(1);
    }
}

const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024; // 64MB

fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut buffer: Vec<String> = Vec::new();
        let mut buffer_size: usize = 0;
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.is_empty() {
                if !buffer.is_empty() {
                    let code = buffer.join("\n");
                    buffer.clear();
                    buffer_size = 0;
                    if tx.send(code).is_err() {
                        break;
                    }
                }
            } else {
                buffer_size += line.len() + 1; // +1 for newline
                if buffer_size > MAX_BLOCK_SIZE {
                    eprintln!("fatal: eval block exceeds {}MB limit", MAX_BLOCK_SIZE / (1024 * 1024));
                    std::process::exit(1);
                }
                buffer.push(line);
            }
        }
        // Flush any remaining buffered code on EOF
        if !buffer.is_empty() {
            let code = buffer.join("\n");
            let _ = tx.send(code);
        }
    });
    rx
}

async fn run(
    memory_limit: usize,
    allow_jit: bool,
    timeout: Option<Duration>,
) -> Result<(), AnyError> {
    let mut js_runtime = runtime::create_runtime(memory_limit, allow_jit)?;

    // Install seccomp filter (Linux only, no-op on macOS)
    seccomp::install(allow_jit).map_err(|e| {
        deno_error::JsErrorBox::new("Error", format!("failed to install seccomp filter: {}", e))
    })?;

    let watchdog = timeout.map(Watchdog::spawn);

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    let mut stdin_rx = spawn_stdin_reader();

    loop {
        tokio::select! {
            biased;

            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => break,
            msg = stdin_rx.recv() => {
                match msg {
                    Some(line) if line == "__flush__" => {
                        if let Some(w) = &watchdog { w.start(); }
                        if let Err(e) = js_runtime.run_event_loop(Default::default()).await {
                            eprintln!("{}", e);
                        }
                        if let Some(w) = &watchdog { w.stop(); }
                    }
                    Some(line) => {
                        if let Some(w) = &watchdog { w.start(); }
                        if let Err(e) = js_runtime.execute_script("<stdin>", line) {
                            eprintln!("{}", e);
                        }
                        // Drain microtasks (e.g. Promise .then() callbacks)
                        if let Err(e) = js_runtime.run_event_loop(Default::default()).await {
                            eprintln!("{}", e);
                        }
                        if let Some(w) = &watchdog { w.stop(); }
                    }
                    None => break, // stdin closed
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_limit_bytes() {
        assert_eq!(parse_memory_limit("1024").unwrap(), 1024);
        assert_eq!(parse_memory_limit("1024b").unwrap(), 1024);
    }

    #[test]
    fn parse_memory_limit_kilobytes() {
        assert_eq!(parse_memory_limit("64kb").unwrap(), 64 * 1024);
        assert_eq!(parse_memory_limit("64k").unwrap(), 64 * 1024);
    }

    #[test]
    fn parse_memory_limit_megabytes() {
        assert_eq!(parse_memory_limit("128mb").unwrap(), 128 * 1024 * 1024);
        assert_eq!(parse_memory_limit("128m").unwrap(), 128 * 1024 * 1024);
    }

    #[test]
    fn parse_memory_limit_gigabytes() {
        assert_eq!(parse_memory_limit("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_memory_limit("1g").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_memory_limit_case_insensitive() {
        assert_eq!(parse_memory_limit("128MB").unwrap(), 128 * 1024 * 1024);
        assert_eq!(parse_memory_limit("1GB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_memory_limit_whitespace() {
        assert_eq!(parse_memory_limit("  128mb  ").unwrap(), 128 * 1024 * 1024);
    }

    #[test]
    fn parse_memory_limit_invalid() {
        assert!(parse_memory_limit("abc").is_err());
        assert!(parse_memory_limit("").is_err());
        assert!(parse_memory_limit("mb").is_err());
    }

    #[test]
    fn parse_timeout_milliseconds() {
        assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_timeout("500").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn parse_timeout_seconds() {
        assert_eq!(parse_timeout("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_timeout_case_insensitive() {
        assert_eq!(parse_timeout("5S").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_timeout("500MS").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn parse_timeout_whitespace() {
        assert_eq!(parse_timeout("  5s  ").unwrap(), Duration::from_secs(5));
    }

    #[test]
    fn parse_timeout_invalid() {
        assert!(parse_timeout("abc").is_err());
        assert!(parse_timeout("").is_err());
        assert!(parse_timeout("s").is_err());
    }
}
