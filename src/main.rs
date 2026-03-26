mod ops;
mod runtime;
mod seccomp;

use std::fmt;
use std::io::BufRead;

use deno_core::error::AnyError;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

const DEFAULT_MEMORY_LIMIT: usize = 128 * 1024 * 1024; // 128MB

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
    eprintln!("Usage: hermit [--memory-limit <size>] [--jit]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --jit                  Enable JIT compilation (default: jitless)");
    eprintln!("  --memory-limit <size>  Set V8 heap limit (default: 128MB)");
    eprintln!("                         Limits heap only, not stack.");
    eprintln!("                         Examples: 64mb, 256m, 1gb, 512kb");
    eprintln!("  --version, -V          Print version");
}

fn main() {
    let mut memory_limit = DEFAULT_MEMORY_LIMIT;
    let mut allow_jit = false;
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

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let local = tokio::task::LocalSet::new();
    if let Err(e) = local.block_on(&runtime, run(memory_limit, allow_jit)) {
        eprintln!("fatal: {}", e);
        std::process::exit(1);
    }
}

fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut buffer: Vec<String> = Vec::new();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.is_empty() {
                if !buffer.is_empty() {
                    let code = buffer.join("\n");
                    buffer.clear();
                    if tx.send(code).is_err() {
                        break;
                    }
                }
            } else {
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

async fn run(memory_limit: usize, allow_jit: bool) -> Result<(), AnyError> {
    let mut js_runtime = runtime::create_runtime(memory_limit, allow_jit)?;

    // Install seccomp filter (Linux only, no-op on macOS)
    seccomp::install().map_err(|e| {
        deno_error::JsErrorBox::new("Error", format!("failed to install seccomp filter: {}", e))
    })?;

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
                        if let Err(e) = js_runtime.run_event_loop(Default::default()).await {
                            eprintln!("{}", e);
                        }
                    }
                    Some(line) => {
                        if let Err(e) = js_runtime.execute_script("<stdin>", line) {
                            eprintln!("{}", e);
                        }
                        // Drain microtasks (e.g. Promise .then() callbacks)
                        if let Err(e) = js_runtime.run_event_loop(Default::default()).await {
                            eprintln!("{}", e);
                        }
                    }
                    None => break, // stdin closed
                }
            }
        }
    }

    Ok(())
}
