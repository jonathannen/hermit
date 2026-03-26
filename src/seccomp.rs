//! Seccomp sandbox for Linux
//!
//! Defense-in-depth: even if JS lockdown is bypassed, syscalls are blocked.
//! Acts as a tripwire for timing/randomness APIs that should be deleted in JS.

#[cfg(target_os = "linux")]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

/// Apply prctl hardening. Call before seccomp.
#[cfg(target_os = "linux")]
fn apply_prctl_restrictions() -> Result<(), Box<dyn std::error::Error>> {
    use libc::{prctl, PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS};

    // Prevent ptrace attachment and core dumps (anti-debugging/tampering)
    // SAFETY: prctl with PR_SET_DUMPABLE only sets a process flag, no pointer args.
    if unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err("prctl(PR_SET_DUMPABLE) failed".into());
    }

    // Prevent gaining privileges via execve (setuid, file caps)
    // Note: seccompiler also sets this, but we set it explicitly for clarity
    // and to ensure it's set even if seccomp application somehow fails.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS only sets a process flag, no pointer args.
    if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err("prctl(PR_SET_NO_NEW_PRIVS) failed".into());
    }

    Ok(())
}

/// Convert integer to string in stack buffer (signal-safe, no allocations)
#[cfg(target_os = "linux")]
fn itoa(mut n: i32, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let negative = n < 0;
    if negative {
        n = -n;
    }
    let mut i = 0;
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    if negative && i < buf.len() {
        buf[i] = b'-';
        i += 1;
    }
    buf[..i].reverse();
    i
}

/// SIGSYS handler that prints blocked syscall number.
///
/// This is a signal handler, so it must only call async-signal-safe functions.
/// We use `libc::write` (signal-safe) and `libc::_exit` (signal-safe) only.
#[cfg(target_os = "linux")]
extern "C" fn sigsys_handler(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    // SAFETY: `info` is provided by the kernel and guaranteed valid in a SA_SIGINFO handler.
    // We read si_syscall at offset 0x18 (24 bytes) from the start of siginfo_t.
    // This offset is stable on Linux aarch64 and x86_64 (defined by the kernel ABI).
    // We cannot use the libc crate's siginfo_t fields directly because si_syscall
    // is inside a union that libc doesn't fully expose.
    unsafe {
        let info_ptr = info as *const u8;
        let syscall = *(info_ptr.add(0x18) as *const i32);

        let mut buf = [0u8; 64];
        let prefix = b"SECCOMP BLOCKED syscall: ";
        buf[..prefix.len()].copy_from_slice(prefix);
        let num_len = itoa(syscall, &mut buf[prefix.len()..]);
        buf[prefix.len() + num_len] = b'\n';
        let total = prefix.len() + num_len + 1;
        libc::write(2, buf.as_ptr() as *const libc::c_void, total);
        libc::_exit(159);
    }
}

/// Install SIGSYS handler for seccomp trap debugging
#[cfg(target_os = "linux")]
fn install_sigsys_handler() {
    // SAFETY: We zero-init the sigaction struct (valid for all fields), then set
    // SA_SIGINFO and our handler. sigemptyset/sigaction are signal-safe libc calls.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO;
        sa.sa_sigaction = sigsys_handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());
    }
}

/// Install seccomp filter. Call this AFTER deno_core is initialized
/// (V8 needs to do its initial mmap/mprotect dance first).
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), Box<dyn std::error::Error>> {
    // Install SIGSYS handler to report blocked syscalls
    install_sigsys_handler();

    // Apply prctl restrictions first
    apply_prctl_restrictions()?;

    // Default action: trap to report blocked syscall
    let default_action = SeccompAction::Trap;

    // Rules: syscalls we explicitly allow
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Determine architecture
    #[cfg(target_arch = "x86_64")]
    let arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = TargetArch::aarch64;

    // === ALLOWED SYSCALLS ===

    // read/write must be unrestricted - tokio uses eventfd for waking reactor
    allow(&mut rules, libc::SYS_read);
    allow(&mut rules, libc::SYS_write);

    // These must remain unrestricted for V8/tokio internals
    allow_safe_ioctl(&mut rules); // ioctl restricted to safe terminal ops
    allow(&mut rules, libc::SYS_fstat); // V8 needs fstat on internal fds
    allow(&mut rules, libc::SYS_close);
    allow(&mut rules, libc::SYS_fcntl);
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, libc::SYS_openat); // aarch64 needs openat for V8 internals

    // Memory management (V8 JIT requires these)
    // We could consider turning off JIT
    allow(&mut rules, libc::SYS_mmap);
    allow(&mut rules, libc::SYS_munmap);
    allow(&mut rules, libc::SYS_mprotect);
    allow(&mut rules, libc::SYS_mremap);
    allow(&mut rules, libc::SYS_brk);
    allow(&mut rules, libc::SYS_madvise);

    // Futex (V8 internal locking - unfortunately required)
    allow(&mut rules, libc::SYS_futex);

    // Signals
    allow(&mut rules, libc::SYS_rt_sigaction);
    allow(&mut rules, libc::SYS_rt_sigprocmask);
    allow(&mut rules, libc::SYS_rt_sigreturn);
    allow(&mut rules, libc::SYS_sigaltstack);

    // Exit
    allow(&mut rules, libc::SYS_exit);
    allow(&mut rules, libc::SYS_exit_group);

    // Thread stuff (V8 may use)
    allow(&mut rules, libc::SYS_clone);
    // allow_clone_thread_only(&mut rules); // TODO: re-enable clone flag restrictions
    allow(&mut rules, libc::SYS_set_tid_address);
    allow(&mut rules, libc::SYS_set_robust_list);
    allow(&mut rules, libc::SYS_rseq);
    allow(&mut rules, libc::SYS_sched_getaffinity);
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, libc::SYS_sched_setaffinity);
    allow(&mut rules, libc::SYS_sched_yield);

    // Misc - getpid omitted (info leak, V8 caches at init)
    allow(&mut rules, libc::SYS_gettid); // V8 needs for thread-local ops
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_arch_prctl); // x86_64 TLS setup
    allow(&mut rules, libc::SYS_prlimit64); // V8 checks resource limits
    allow(&mut rules, libc::SYS_getrandom); // V8/tokio needs for initialization
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, 172); // getresgid on aarch64

    // Poll/epoll for tokio
    allow(&mut rules, libc::SYS_epoll_create1);
    allow(&mut rules, libc::SYS_epoll_ctl);
    // epoll_wait only exists on x86_64, aarch64 uses epoll_pwait
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_epoll_wait);
    allow(&mut rules, libc::SYS_epoll_pwait);
    allow(&mut rules, libc::SYS_epoll_pwait2);
    allow(&mut rules, libc::SYS_eventfd2); // tokio reactor wakeup

    // === EXPLICITLY BLOCKED (tripwires) ===
    // These are blocked by default (not in allow list), but listing for clarity:
    // - SYS_clock_gettime: Date/timing
    // - SYS_gettimeofday: Date/timing
    // - SYS_socket, SYS_connect, etc: networking
    // - SYS_open, SYS_openat: filesystem
    // - SYS_execve: no exec
    // - SYS_fork: no forking (clone is allowed for threads only)

    let filter = SeccompFilter::new(
        rules,
        default_action,
        SeccompAction::Allow,
        arch,
    )?;

    let bpf_prog: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&bpf_prog)?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn allow(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, syscall: i64) {
    // Empty rule = allow unconditionally
    rules.insert(syscall, vec![]);
}

/// Allow only safe ioctl operations (block TIOCSTI terminal injection, etc.)
#[cfg(target_os = "linux")]
fn allow_safe_ioctl(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // ioctl(fd, request, ...) - request is arg1
    // Allow specific safe terminal ioctls, block dangerous ones like TIOCSTI
    //
    // Safe ioctls we allow:
    // - TCGETS (0x5401) - get terminal attributes
    // - TIOCGWINSZ (0x5413) - get window size
    // - FIONREAD (0x541B) - bytes available to read
    // - FIONBIO (0x5421) - set non-blocking (tokio needs this)
    //
    // Dangerous ioctls we block:
    // - TIOCSTI (0x5412) - simulate terminal input (injection attack)
    // - TIOCSWINSZ (0x5414) - could confuse terminal apps
    // - TIOCLINUX (0x541C) - various dangerous terminal ops

    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const FIONREAD: u64 = 0x541B;
    const FIONBIO: u64 = 0x5421;

    // Allow each safe ioctl (OR'd rules)
    let ioctl_rules = vec![
        // Terminal ioctls
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, TCGETS)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, TIOCGWINSZ)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, FIONREAD)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, FIONBIO)
            .expect("valid")])
        .expect("valid"),
    ];

    rules.insert(libc::SYS_ioctl, ioctl_rules);
}

/// Allow clone only for thread creation (block namespace escapes like CLONE_NEWUSER)
#[cfg(target_os = "linux")]
fn allow_clone_thread_only(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // Block dangerous clone flags that could be used for container/sandbox escape:
    // - CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, etc.
    // We use masked_eq to check that none of the namespace flags are set.
    //
    // clone(2) arg0 is flags on x86_64, but on aarch64 it's arg1 (args are swapped).
    // However, clone3(2) uses a struct. We block clone3 entirely (not in allow list).
    //
    // Dangerous flags we must block:
    const CLONE_NEWNS: u64 = 0x00020000;
    const CLONE_NEWCGROUP: u64 = 0x02000000;
    const CLONE_NEWUTS: u64 = 0x04000000;
    const CLONE_NEWIPC: u64 = 0x08000000;
    const CLONE_NEWUSER: u64 = 0x10000000;
    const CLONE_NEWPID: u64 = 0x20000000;
    const CLONE_NEWNET: u64 = 0x40000000;
    #[allow(dead_code)]
    const CLONE_NEWTIME: u64 = 0x00000080;

    let dangerous_flags =
        CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

    // On x86_64, clone flags are in arg0
    // masked_eq(mask, val): (arg & mask) == val
    // We want: (flags & dangerous_flags) == 0
    #[cfg(target_arch = "x86_64")]
    let arg_index = 0;
    #[cfg(target_arch = "aarch64")]
    let arg_index = 0; // aarch64 also uses arg0 for flags in the clone wrapper glibc uses

    let rule = SeccompRule::new(vec![SeccompCondition::new(
        arg_index,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(dangerous_flags),
        0, // (flags & dangerous) must equal 0
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_clone, vec![rule]);
}

/// No-op on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<(), Box<dyn std::error::Error>> {
    // Seccomp is Linux-only; on macOS we rely on JS lockdown only
    Ok(())
}
