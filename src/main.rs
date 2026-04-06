mod landlock;
mod ops;
mod runtime;
mod sandbox;
mod seccomp;

use std::fmt;
use std::time::Duration;

use deno_core::error::AnyError;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

const DEFAULT_MEMORY_LIMIT: usize = 128 * 1024 * 1024; // 128MB
const MIN_MEMORY_LIMIT: usize = 1024 * 1024; // 1MB — V8 needs headroom to initialize

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
        // Fallback: close fds 3..max. Use sysconf to find the real upper bound
        // so we don't miss high-numbered inherited FDs.
        let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        let max_fd = if max_fd > 0 { max_fd as i32 } else { 65536 };
        (3..max_fd).collect()
    };

    for fd in fds {
        // SAFETY: closing unknown FDs is safe — close on an invalid/already-closed FD
        // returns EBADF which we ignore. This runs before any Rust I/O beyond stdio.
        unsafe { libc::close(fd); }
    }
}

/// Clear all environment variables to prevent leaking host secrets.
/// Must be called before V8 init (V8 may read env vars during setup).
fn clear_env() {
    let keys: Vec<_> = std::env::vars_os().map(|(k, _)| k).collect();
    for key in keys {
        // SAFETY: called before any threads are created (single-threaded at this point).
        unsafe { std::env::remove_var(key); }
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
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .map(Duration::from_millis)
        .ok_or(InvalidDuration(s))
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
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or(InvalidMemoryLimit(s))
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn default_sandbox_mode() -> sandbox::SandboxMode {
    if cfg!(target_os = "linux") {
        sandbox::SandboxMode::Strict
    } else {
        sandbox::SandboxMode::Permissive
    }
}

fn print_usage() {
    let default_mode = if cfg!(target_os = "linux") { "strict" } else { "permissive" };
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
    eprintln!("  --strict               Fail if mount namespace cannot be created (default on Linux)");
    eprintln!("  --permissive           Warn and continue without namespace isolation (default on macOS)");
    eprintln!("                         Current default: --{}", default_mode);
    eprintln!("  --version, -V          Print version");
}

fn main() {
    let mut memory_limit = DEFAULT_MEMORY_LIMIT;
    let mut allow_jit = false;
    let mut timeout: Option<Duration> = None;
    let mut sandbox_mode = default_sandbox_mode();
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
                    Ok(v) if v < MIN_MEMORY_LIMIT => {
                        eprintln!("Error: memory limit must be at least {}MB", MIN_MEMORY_LIMIT / (1024 * 1024));
                        print_usage();
                        std::process::exit(1);
                    }
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
            "--strict" => {
                sandbox_mode = sandbox::SandboxMode::Strict;
            }
            "--permissive" => {
                sandbox_mode = sandbox::SandboxMode::Permissive;
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

    // Clear all environment variables. Even though JS can't access process.env,
    // a post-V8-escape attacker could read them from /proc/self/environ (if
    // mounted) or via libc getenv. Belt-and-suspenders with mount namespace
    // which doesn't mount /proc/self/environ.
    clear_env();

    // Mount namespace: pivot to a minimal filesystem with only /proc, /sys/cpu,
    // and /dev/urandom. Must happen before threads are created (unshare requirement).
    // In strict mode, failure is fatal. In permissive mode, warns and continues.
    sandbox::enter_mount_namespace(sandbox_mode);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let local = tokio::task::LocalSet::new();
    if let Err(e) = local.block_on(&runtime, run(memory_limit, allow_jit, timeout, sandbox_mode)) {
        eprintln!("fatal: {}", e);
        std::process::exit(1);
    }
}

/// Apply OS-level resource limits. Called after runtime init, before seccomp.
/// In strict mode, setrlimit failures are fatal.
fn apply_rlimits(mode: sandbox::SandboxMode, memory_limit: usize, timeout: Option<Duration>) {
    #[cfg(unix)]
    {
        use libc::{rlimit, setrlimit, RLIMIT_FSIZE, RLIMIT_NOFILE};

        let strict = mode == sandbox::SandboxMode::Strict;

        // RLIMIT_NOFILE: cap open file descriptors at 64 (or the current soft
        // limit if lower). V8/tokio have already opened their FDs; this prevents
        // FD exhaustion from a post-escape attacker.
        let mut current = rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit reads into a stack-allocated rlimit struct.
        if unsafe { libc::getrlimit(RLIMIT_NOFILE, &mut current) } == 0 {
            let cap = current.rlim_cur.min(64);
            let limit = rlimit { rlim_cur: cap, rlim_max: cap };
            // SAFETY: setrlimit with valid rlimit struct, lowering limits only.
            if unsafe { setrlimit(RLIMIT_NOFILE, &limit) } != 0 && strict {
                eprintln!("fatal: setrlimit(RLIMIT_NOFILE) failed");
                std::process::exit(1);
            }
        }

        // RLIMIT_FSIZE: prevent creating files (belt-and-suspenders with seccomp
        // openat read-only restriction). Set to 0 = no file writes allowed.
        let zero_limit = rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit with valid rlimit struct.
        if unsafe { setrlimit(RLIMIT_FSIZE, &zero_limit) } != 0 && strict {
            eprintln!("fatal: setrlimit(RLIMIT_FSIZE) failed");
            std::process::exit(1);
        }

        // RLIMIT_CORE: prevent core dumps from leaking heap contents.
        // Belt-and-suspenders with PR_SET_DUMPABLE(0).
        // SAFETY: setrlimit with valid rlimit struct.
        if unsafe { setrlimit(libc::RLIMIT_CORE, &zero_limit) } != 0 && strict {
            eprintln!("fatal: setrlimit(RLIMIT_CORE) failed");
            std::process::exit(1);
        }

        // RLIMIT_NPROC: cap number of processes/threads. V8 threads are already
        // created, so freeze at current count. This prevents thread explosion.
        #[cfg(target_os = "linux")]
        {
            use libc::RLIMIT_NPROC;
            // Count current threads from /proc/self/status
            let nproc = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Threads:"))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                })
                .unwrap_or(32); // fallback: generous cap
            let nproc_limit = rlimit { rlim_cur: nproc + 8, rlim_max: nproc + 8 };
            // SAFETY: setrlimit with valid rlimit struct.
            if unsafe { setrlimit(RLIMIT_NPROC, &nproc_limit) } != 0 && strict {
                eprintln!("fatal: setrlimit(RLIMIT_NPROC) failed");
                std::process::exit(1);
            }
        }

        // RLIMIT_AS: cap virtual address space to prevent mmap-based memory
        // exhaustion outside V8's heap limit. V8 heap limit only covers JS
        // allocations; this caps the entire process (stack, native heap, mmap).
        // Read current VmSize from /proc/self/status (V8 has already reserved
        // its cage + guard regions) and add the JS heap limit as headroom.
        #[cfg(target_os = "linux")]
        {
            let vm_size_kb = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("VmSize:"))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                });
            if let Some(vm_kb) = vm_size_kb {
                let current_bytes = vm_kb * 1024;
                // Allow current usage + 3x JS heap limit headroom for GC growth,
                // thread stacks, and V8 internal allocations beyond the JS heap.
                let as_cap = current_bytes.saturating_add((memory_limit as u64) * 3);
                let as_limit = rlimit { rlim_cur: as_cap, rlim_max: as_cap };
                // SAFETY: setrlimit with valid rlimit struct.
                if unsafe { setrlimit(libc::RLIMIT_AS, &as_limit) } != 0 && strict {
                    eprintln!("fatal: setrlimit(RLIMIT_AS) failed");
                    std::process::exit(1);
                }
            }
        }

        // RLIMIT_CPU: kernel-enforced hard timeout (SIGKILL on hard limit).
        // Works even if the watchdog thread is killed or the event loop is stuck.
        // Soft limit (SIGXCPU) is set to timeout + grace; hard limit (SIGKILL)
        // adds extra grace so the userspace watchdog fires first under normal
        // conditions, with RLIMIT_CPU as a backstop.
        if let Some(t) = timeout {
            let base_secs = t.as_secs().max(1);
            // Large grace period: the userspace watchdog handles normal timeouts;
            // RLIMIT_CPU is a last-resort backstop for cases where the watchdog
            // thread is dead. JIT mode burns CPU much faster than wall time.
            let soft = base_secs.saturating_mul(10).max(30);
            let hard = soft.saturating_add(5);
            let cpu_limit = rlimit { rlim_cur: soft, rlim_max: hard };
            // SAFETY: setrlimit with valid rlimit struct.
            if unsafe { setrlimit(libc::RLIMIT_CPU, &cpu_limit) } != 0 && strict {
                eprintln!("fatal: setrlimit(RLIMIT_CPU) failed");
                std::process::exit(1);
            }
        }
    }
}

/// Tighten RLIMIT_NOFILE after V8 init to just above current open FD count.
/// This limits the attack surface of internal V8/tokio FDs by preventing new
/// FDs from being opened beyond what's needed for GC thread creation.
fn tighten_nofile_limit() {
    #[cfg(unix)]
    {
        // Count open FDs by probing with fstat (avoids read_dir which needs
        // fchdir, blocked by seccomp). Check FDs 0..64 (our RLIMIT_NOFILE cap).
        let mut max_open: u64 = 0;
        for fd in 0..64i32 {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat on a valid or invalid FD just returns 0 or EBADF.
            if unsafe { libc::fstat(fd, &mut stat) } == 0 {
                max_open = fd as u64 + 1;
            }
        }
        // +8 headroom for V8 GC threads that open /proc files briefly
        let cap = max_open + 8;
        let limit = libc::rlimit { rlim_cur: cap, rlim_max: cap };
        // SAFETY: setrlimit with valid rlimit struct, lowering limits only.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit); }
    }
}

const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024; // 64MB

fn spawn_stdin_reader() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel(16);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = std::io::BufReader::new(stdin.lock());
        let mut buffer: Vec<String> = Vec::new();
        let mut buffer_size: usize = 0;
        let mut line_buf = Vec::with_capacity(4096);
        loop {
            line_buf.clear();
            // read_until appends to line_buf until \n or EOF. We check the
            // accumulated size after each internal fill_buf to bound memory.
            match read_line_bounded(&mut reader, &mut line_buf, MAX_BLOCK_SIZE) {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(ReadLineError::TooLong) => {
                    eprintln!("fatal: single line exceeds {}MB limit", MAX_BLOCK_SIZE / (1024 * 1024));
                    std::process::exit(1);
                }
                Err(ReadLineError::Io) => break,
            }
            // Strip trailing newline/carriage return
            if line_buf.last() == Some(&b'\n') { line_buf.pop(); }
            if line_buf.last() == Some(&b'\r') { line_buf.pop(); }
            let line = match String::from_utf8(std::mem::take(&mut line_buf)) {
                Ok(s) => s,
                Err(_) => break,
            };
            if line.is_empty() {
                if !buffer.is_empty() {
                    let code = buffer.join("\n");
                    buffer.clear();
                    buffer_size = 0;
                    if tx.blocking_send(code).is_err() {
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
            let _ = tx.blocking_send(code);
        }
    });
    rx
}

enum ReadLineError {
    TooLong,
    Io,
}

/// Read until \n or EOF, but bail if the line exceeds `limit` bytes.
fn read_line_bounded<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, ReadLineError> {
    let mut total = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ReadLineError::Io),
        };
        if available.is_empty() {
            return Ok(total); // EOF
        }
        // Find newline in the buffered data
        let (used, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if total + used > limit {
            return Err(ReadLineError::TooLong);
        }
        buf.extend_from_slice(&available[..used]);
        total += used;
        reader.consume(used);
        if done {
            return Ok(total);
        }
    }
}

async fn run(
    memory_limit: usize,
    allow_jit: bool,
    timeout: Option<Duration>,
    sandbox_mode: sandbox::SandboxMode,
) -> Result<(), AnyError> {
    let mut js_runtime = runtime::create_runtime(memory_limit, allow_jit)?;

    // Apply OS-level resource limits before entering the sandbox.
    // These act as a backstop for resource exhaustion attacks that bypass V8's
    // heap limit (which only covers the JS heap, not stack, threads, or FDs).
    apply_rlimits(sandbox_mode, memory_limit, timeout);

    // Tighten RLIMIT_NOFILE to just above current open FD count. V8 and tokio
    // have opened their internal FDs; this caps the total to prevent a post-escape
    // attacker from opening new ones. Must run before seccomp (fstat is blocked).
    tighten_nofile_limit();

    // Set NO_NEW_PRIVS early — required by both Landlock and seccomp.
    // Idempotent: seccomp::install() will set it again (harmless).
    #[cfg(target_os = "linux")]
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); }

    // Landlock: restrict filesystem to read-only at the LSM layer, independent
    // of seccomp. Even if seccomp is bypassed via a kernel bug, Landlock still
    // enforces. Best-effort: silently skipped on kernels < 5.13.
    match landlock::restrict_filesystem() {
        Ok(true) => {} // Landlock active
        Ok(false) => {
            if sandbox_mode == sandbox::SandboxMode::Strict {
                eprintln!("warning: Landlock not available, continuing without LSM filesystem restriction");
            }
        }
        Err(e) => {
            if sandbox_mode == sandbox::SandboxMode::Strict {
                eprintln!("fatal: Landlock setup failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Install stage-1 seccomp filter (Linux only, no-op on macOS)
    seccomp::install(allow_jit).map_err(|e| {
        deno_error::JsErrorBox::new("Error", format!("failed to install seccomp filter: {}", e))
    })?;

    // Warmup eval: trigger V8's lazy initialization (ICU data, JIT stubs, /proc reads)
    // so that stage-2 can lock down to the minimal steady-state syscall set.
    js_runtime.execute_script("<warmup>", "1".to_string())?;
    js_runtime.run_event_loop(Default::default()).await?;

    // Strip non-essential filesystem mounts (/dev/urandom, /sys) now that V8
    // initialization is complete. Only /proc remains for thread creation.
    sandbox::strip_filesystem();

    // Install stage-2 seccomp filter.
    seccomp::install_stage2(allow_jit).map_err(|e| {
        deno_error::JsErrorBox::new("Error", format!("failed to install stage-2 seccomp: {}", e))
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
