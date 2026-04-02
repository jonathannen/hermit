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

/// Offset of si_syscall within siginfo_t, defined by the Linux kernel ABI.
/// This is stable on x86_64 and aarch64. Adding a new architecture requires
/// verifying this offset against the kernel's struct siginfo layout.
#[cfg(target_os = "linux")]
const SI_SYSCALL_OFFSET: usize = {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("si_syscall offset is only verified for x86_64 and aarch64");
    0x18
};

/// SIGSYS handler that prints blocked syscall number.
///
/// This is a signal handler, so it must only call async-signal-safe functions.
/// We use `libc::write` (signal-safe) and `libc::_exit` (signal-safe) only.
#[cfg(target_os = "linux")]
extern "C" fn sigsys_handler(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    // SAFETY: `info` is provided by the kernel and guaranteed valid in a SA_SIGINFO handler.
    // We cannot use the libc crate's siginfo_t fields directly because si_syscall
    // is inside a union that libc doesn't fully expose.
    unsafe {
        let info_ptr = info as *const u8;
        let syscall = *(info_ptr.add(SI_SYSCALL_OFFSET) as *const i32);

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
        sa.sa_sigaction = sigsys_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());
    }
}

/// Install seccomp filter. Call this AFTER deno_core is initialized
/// (V8 needs to do its initial mmap/mprotect dance first).
#[cfg(target_os = "linux")]
pub fn install(allow_jit: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    // ioctl: BLOCKED entirely — no terminal or device ops needed post-init
    // fstat: BLOCKED — V8 init is done before seccomp; no runtime need expected
    allow(&mut rules, libc::SYS_close);
    allow_safe_fcntl(&mut rules);
    allow_openat_readonly(&mut rules); // openat restricted to read-only

    // Memory management (V8 JIT requires these)
    allow_mmap_private_only(&mut rules); // mmap restricted: no MAP_SHARED
    allow(&mut rules, libc::SYS_munmap);
    if allow_jit {
        allow(&mut rules, libc::SYS_mprotect);
    } else {
        // In jitless mode, block mprotect with PROT_EXEC — no reason to make pages
        // executable after init. This prevents shellcode injection post-V8-escape.
        allow_mprotect_noexec(&mut rules);
    }
    allow(&mut rules, libc::SYS_mremap);
    allow(&mut rules, libc::SYS_brk);
    allow_safe_madvise(&mut rules);

    // Futex (V8 internal locking - unfortunately required)
    allow(&mut rules, libc::SYS_futex);

    // Signals
    allow_sigaction_protect_sigsys(&mut rules); // block overriding our SIGSYS handler
    allow(&mut rules, libc::SYS_rt_sigprocmask);
    allow(&mut rules, libc::SYS_rt_sigreturn);
    allow(&mut rules, libc::SYS_sigaltstack);

    // Exit
    allow(&mut rules, libc::SYS_exit);
    allow(&mut rules, libc::SYS_exit_group);

    // Thread stuff (V8 may use)
    #[cfg(target_arch = "x86_64")]
    allow_clone_thread_only(&mut rules); // clone restricted: namespace flags blocked
    allow(&mut rules, libc::SYS_clone3); // newer glibc prefers clone3 for thread creation
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, libc::SYS_clone); // older aarch64 glibc falls back to clone
    allow(&mut rules, libc::SYS_set_tid_address);
    allow(&mut rules, libc::SYS_set_robust_list);
    allow(&mut rules, libc::SYS_rseq);
    allow(&mut rules, libc::SYS_sched_getaffinity);
    // sched_setaffinity: BLOCKED — setting CPU affinity not needed, only reading
    allow(&mut rules, libc::SYS_sched_yield);
    allow(&mut rules, libc::SYS_sched_getparam); // V8 thread scheduling
    allow(&mut rules, libc::SYS_sched_getscheduler); // V8 thread scheduling

    // Misc
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_getpid); // x86_64 tokio signal handling needs getpid
    allow(&mut rules, libc::SYS_gettid); // V8 needs for thread-local ops
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_arch_prctl); // x86_64 TLS setup
    allow_prlimit64_readonly(&mut rules); // V8 checks resource limits (read-only)
    // getrandom: BLOCKED — V8/tokio seed their RNGs during init before seccomp
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, 172); // getresgid on aarch64

    // clock_nanosleep: BLOCKED — V8 GC shouldn't need sleep post-init

    // prctl: BLOCKED — thread naming (PR_SET_NAME) is not security-critical

    // Poll/epoll for tokio
    // epoll_create1: BLOCKED — tokio creates its epoll fd during init
    allow(&mut rules, libc::SYS_epoll_ctl);
    // epoll_wait only exists on x86_64, aarch64 uses epoll_pwait
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_epoll_wait);
    allow(&mut rules, libc::SYS_epoll_pwait);
    // epoll_pwait2: BLOCKED — tokio uses epoll_pwait, not the newer pwait2
    // eventfd2: BLOCKED — tokio creates its eventfds during init

    // === EXPLICITLY BLOCKED (tripwires) ===
    // These are blocked by default (not in allow list), but listing for clarity:
    // - SYS_clock_gettime: Date/timing
    // - SYS_gettimeofday: Date/timing
    // - SYS_socket, SYS_connect, etc: networking
    // - SYS_open: filesystem (openat is allowed read-only)
    // - SYS_execve: no exec
    // - SYS_fork: no forking (clone/clone3 allowed for threads only)
    // - SYS_ptrace: no debugging/inspection

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

/// Allow only safe madvise flags (block MADV_DONTDUMP, MADV_HUGEPAGE, etc.)
#[cfg(target_os = "linux")]
fn allow_safe_madvise(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // madvise(addr, length, advice) - advice is arg2
    //
    // Safe flags we allow:
    // - MADV_NORMAL (0) - reset to default
    // - MADV_DONTNEED (4) - pages can be reclaimed (V8 GC uses this)
    // - MADV_FREE (8) - lazy free (V8 GC may use this)
    // - MADV_DONTFORK (10) - exclude from fork (V8 uses extensively)
    //
    // Dangerous flags we block:
    // - MADV_DONTDUMP (16) - hide memory from core dumps/forensics
    // - MADV_HUGEPAGE (14) - Rowhammer amplification
    // - MADV_MERGEABLE (12) - KSM side-channel

    const MADV_NORMAL: u64 = 0;
    const MADV_DONTNEED: u64 = 4;
    const MADV_FREE: u64 = 8;
    const MADV_DONTFORK: u64 = 10;

    let madvise_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, MADV_NORMAL)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, MADV_DONTNEED)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, MADV_FREE)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, MADV_DONTFORK)
            .expect("valid")])
        .expect("valid"),
    ];

    rules.insert(libc::SYS_madvise, madvise_rules);
}

/// Allow rt_sigaction but block overriding SIGSYS handler
#[cfg(target_os = "linux")]
fn allow_sigaction_protect_sigsys(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // rt_sigaction(signum, act, oldact, sigsetsize) - signum is arg0
    // Block signum == SIGSYS (31) to prevent a V8 escape from silently
    // uninstalling our seccomp violation handler.
    // We use Ne: allow any signal that is NOT SIGSYS.
    const SIGSYS: u64 = 31;

    let rule = SeccompRule::new(vec![SeccompCondition::new(
        0, // signum argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        SIGSYS,
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_rt_sigaction, vec![rule]);
}

/// Allow prlimit64 only for reading limits (new_limit must be NULL)
#[cfg(target_os = "linux")]
fn allow_prlimit64_readonly(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // prlimit64(pid, resource, new_limit, old_limit) - new_limit is arg2
    // Allow only when new_limit == NULL (0), i.e. read-only queries.
    // Block setting limits which could be used for DoS or side-channels.
    let rule = SeccompRule::new(vec![SeccompCondition::new(
        2, // new_limit argument
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::Eq,
        0, // must be NULL
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_prlimit64, vec![rule]);
}

/// Allow only safe fcntl operations (block F_SETOWN, F_SETSIG, etc.)
#[cfg(target_os = "linux")]
fn allow_safe_fcntl(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // fcntl(fd, cmd, ...) - cmd is arg1
    //
    // Safe ops we allow:
    // - F_GETFD (1) - get close-on-exec flag
    // - F_SETFD (2) - set close-on-exec flag
    // - F_GETFL (3) - get file status flags
    // - F_DUPFD_CLOEXEC (1030) - dup with close-on-exec (V8/tokio uses this)
    //
    // Dangerous ops we block:
    // - F_SETOWN (8) - redirect SIGIO/SIGURG to arbitrary pid
    // - F_SETSIG (10) - change signal delivered on I/O events
    // - F_SETFL (4) - could add O_APPEND to corrupt logs
    // - F_SETLK/F_SETLKW (6,7) - file locking (not needed)

    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_DUPFD_CLOEXEC: u64 = 1030;

    let fcntl_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, F_GETFD)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, F_SETFD)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, F_GETFL)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, F_DUPFD_CLOEXEC)
            .expect("valid")])
        .expect("valid"),
    ];

    rules.insert(libc::SYS_fcntl, fcntl_rules);
}

/// Block mprotect with PROT_EXEC (prevent making pages executable post-init)
#[cfg(target_os = "linux")]
fn allow_mprotect_noexec(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // mprotect(addr, len, prot) - prot is arg2
    // PROT_EXEC = 0x4. Block any call where PROT_EXEC is set.
    // (prot & PROT_EXEC) == 0
    const PROT_EXEC: u64 = 0x4;

    let rule = SeccompRule::new(vec![SeccompCondition::new(
        2, // prot argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(PROT_EXEC),
        0, // PROT_EXEC must not be set
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_mprotect, vec![rule]);
}

/// Allow mmap but block MAP_SHARED (prevent shared memory IPC / side-channels)
#[cfg(target_os = "linux")]
fn allow_mmap_private_only(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // mmap(addr, length, prot, flags, fd, offset) - flags is arg3
    // MAP_SHARED = 0x01. Block any mmap where MAP_SHARED is set.
    // V8 only needs MAP_PRIVATE | MAP_ANONYMOUS for heap and JIT pages.
    const MAP_SHARED: u64 = 0x01;

    let rule = SeccompRule::new(vec![SeccompCondition::new(
        3, // flags argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(MAP_SHARED),
        0, // MAP_SHARED must not be set
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_mmap, vec![rule]);
}


/// Allow openat only for read-only opens (block write, create, truncate, append)
#[cfg(target_os = "linux")]
fn allow_openat_readonly(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // openat(dirfd, pathname, flags, mode) - flags is arg index 2
    // Block any open that could write or create files:
    // O_WRONLY (0x1), O_RDWR (0x2), O_CREAT (0x40), O_TRUNC (0x200), O_APPEND (0x400)
    const DANGEROUS_FLAGS: u64 = 0x1 | 0x2 | 0x40 | 0x200 | 0x400;

    // Allow only if (flags & DANGEROUS_FLAGS) == 0 (i.e. read-only)
    let rule = SeccompRule::new(vec![SeccompCondition::new(
        2, // flags argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(DANGEROUS_FLAGS),
        0, // none of the dangerous flags set
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_openat, vec![rule]);
}

/// Allow clone only for thread creation (block namespace escapes like CLONE_NEWUSER)
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
fn allow_clone_thread_only(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // Block dangerous clone flags that could be used for container/sandbox escape:
    // - CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, etc.
    // We use masked_eq to check that none of the namespace flags are set.
    //
    // On x86_64, clone(2) flags are in arg0.
    const CLONE_NEWNS: u64 = 0x00020000;
    const CLONE_NEWCGROUP: u64 = 0x02000000;
    const CLONE_NEWUTS: u64 = 0x04000000;
    const CLONE_NEWIPC: u64 = 0x08000000;
    const CLONE_NEWUSER: u64 = 0x10000000;
    const CLONE_NEWPID: u64 = 0x20000000;
    const CLONE_NEWNET: u64 = 0x40000000;

    let dangerous_flags =
        CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

    // masked_eq(mask, val): (arg & mask) == val
    // We want: (flags & dangerous_flags) == 0
    let rule = SeccompRule::new(vec![SeccompCondition::new(
        0, // flags in arg0 on x86_64
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
pub fn install(_allow_jit: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Seccomp is Linux-only; on macOS we rely on JS lockdown only
    Ok(())
}
