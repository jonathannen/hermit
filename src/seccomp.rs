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
fn apply_prctl_restrictions(allow_jit: bool) -> Result<(), Box<dyn std::error::Error>> {
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

    // PR_SET_MDWE (Memory-Deny-Write-Execute): kernel-enforced W^X policy.
    // When set, all future mmap/mprotect calls that would create pages that
    // are both writable and executable are rejected by the kernel. This is
    // belt-and-suspenders with our seccomp mprotect(PROT_EXEC) filter.
    // Only in jitless mode — JIT needs to make pages executable.
    // Best-effort: returns EINVAL on kernels < 6.3 where MDWE is unavailable.
    if !allow_jit {
        const PR_SET_MDWE: libc::c_int = 65;
        const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
        // SAFETY: prctl with PR_SET_MDWE only sets a process flag.
        let ret = unsafe { prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) };
        if ret != 0 {
            // EINVAL = kernel too old, not an error. Other failures are unexpected.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(format!("prctl(PR_SET_MDWE) failed: {}", err).into());
            }
        }
    }

    Ok(())
}

/// Convert integer to string in stack buffer (signal-safe, no allocations)
#[cfg(target_os = "linux")]
fn itoa(n: i32, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    // Work with negative values to avoid overflow on i32::MIN.
    // -i32::MIN overflows, but i32::MIN itself is representable as negative.
    let negative = n < 0;
    let mut val = if negative { n } else { -n }; // val is always <= 0
    let mut i = 0;
    while val < 0 && i < buf.len() {
        buf[i] = b'0' + (-(val % 10)) as u8; // -(val % 10) is in 0..=9
        val /= 10;
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
    apply_prctl_restrictions(allow_jit)?;

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
    // fcntl: BLOCKED entirely — fd flags are set during init
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
    allow_mremap_no_fixed(&mut rules); // mremap restricted: no MREMAP_FIXED
    allow(&mut rules, libc::SYS_brk);
    allow_safe_madvise(&mut rules);

    // Futex (V8 internal locking - restricted to safe ops, blocking PI variants)
    allow_safe_futex(&mut rules);

    // Signals
    allow_sigaction_protect_sigsys(&mut rules); // block overriding our SIGSYS handler
    allow(&mut rules, libc::SYS_rt_sigprocmask);
    allow(&mut rules, libc::SYS_rt_sigreturn);
    allow(&mut rules, libc::SYS_sigaltstack);

    // Exit
    allow(&mut rules, libc::SYS_exit);
    allow(&mut rules, libc::SYS_exit_group);

    // Thread creation: clone(2) requires CLONE_THREAD and blocks namespace flags.
    // clone3 is allowed here but a stacked filter (below) returns ENOSYS for it.
    // clone3's flags are inside a userspace struct that seccomp BPF cannot inspect,
    // so we force glibc to fall back to the filterable clone(2) syscall.
    allow_clone_thread_only(&mut rules);
    allow(&mut rules, libc::SYS_clone3); // overridden to ENOSYS by second filter
    allow(&mut rules, libc::SYS_set_tid_address);
    allow(&mut rules, libc::SYS_set_robust_list);
    allow(&mut rules, libc::SYS_rseq);
    allow(&mut rules, libc::SYS_sched_getaffinity);
    // sched_setaffinity: BLOCKED — setting CPU affinity not needed, only reading
    allow(&mut rules, libc::SYS_sched_yield); // V8 GC thread uses under memory pressure
    allow(&mut rules, libc::SYS_sched_getparam); // V8 thread scheduling
    allow(&mut rules, libc::SYS_sched_getscheduler); // V8 thread scheduling

    // Misc
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_getpid); // x86_64 tokio signal handling needs getpid
    allow(&mut rules, libc::SYS_gettid); // V8 needs for thread-local ops
    #[cfg(target_arch = "x86_64")]
    allow_arch_prctl_fs_only(&mut rules); // x86_64 TLS setup (ARCH_SET_FS/GET_FS only)
    // prlimit64: BLOCKED — V8 checks resource limits at init only
    // getrandom: BLOCKED — V8/tokio seed their RNGs during init before seccomp
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, 172); // getresgid on aarch64

    // clock_nanosleep: V8 GC helper threads use this for backoff between cycles
    allow(&mut rules, libc::SYS_clock_nanosleep);

    // prctl restricted to safe operations (thread naming needed for clone(2) fallback)
    allow_safe_prctl(&mut rules);

    // umount2 needed for strip_filesystem() after warmup (before stage-2)
    allow(&mut rules, libc::SYS_umount2);

    // seccomp(2) must be allowed so stage-2 filter can be installed later.
    // Stage-2 does NOT include seccomp in its allowlist, so after stage-2
    // is installed, seccomp is blocked by the stacked filter combination.
    allow(&mut rules, libc::SYS_seccomp);

    // Poll/epoll for tokio
    // epoll_create1: BLOCKED — tokio creates its epoll fd during init
    // epoll_ctl: BLOCKED — tokio event registrations completed during init
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
    // - SYS_fork: no forking (clone allowed for threads only, clone3 returns ENOSYS)
    // - SYS_ptrace: no debugging/inspection

    // Install clone3 ENOSYS filter FIRST (before the restrictive main filter).
    // clone3's flags are inside a userspace struct that seccomp BPF cannot inspect,
    // so we return ENOSYS to force glibc to fall back to clone(2), which we CAN filter.
    // This must be installed before the main filter because the main filter blocks
    // the seccomp(2) syscall needed to install additional filters.
    let mut clone3_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    clone3_rules.insert(libc::SYS_clone3, vec![]);

    let clone3_filter = SeccompFilter::new(
        clone3_rules,
        SeccompAction::Allow,                       // mismatch (non-clone3): pass through
        SeccompAction::Errno(libc::ENOSYS as u32), // match (clone3): return ENOSYS
        arch,
    )?;

    let clone3_bpf: BpfProgram = clone3_filter.try_into()?;
    seccompiler::apply_filter(&clone3_bpf)?;

    // Main restrictive filter. With stacked filters the kernel picks the most
    // restrictive action per-syscall. clone3 is allowed here (overridden to ENOSYS
    // by the filter above since ENOSYS is more restrictive than Allow).
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

/// Install stage-2 seccomp filter after warmup eval.
/// Narrows the stage-1 allowlist by blocking seccomp(2) (preventing further
/// filter changes) and reinforcing all stage-1 restrictions. V8's lazy GC
/// thread creation means thread/signal syscalls must remain available.
///
/// Remaining attack surface: openat (V8 GC attempts /proc reads that fail
/// harmlessly in the empty namespace), thread creation (clone with namespace
/// flags blocked), and memory management.
///
/// Call this AFTER running a warmup eval to trigger V8's lazy init.
#[cfg(target_os = "linux")]
pub fn install_stage2(allow_jit: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    #[cfg(target_arch = "x86_64")]
    let arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = TargetArch::aarch64;

    // Steady-state syscalls only — verified via strace across 50+ evals
    // with heap pressure in both jitless and JIT modes.

    allow(&mut rules, libc::SYS_read);    // stdin input
    allow(&mut rules, libc::SYS_write);   // console.log output
    allow(&mut rules, libc::SYS_close);   // thread cleanup
    allow_openat_readonly(&mut rules);    // V8 GC threads attempt to open /proc files
                                           // during collection (fails harmlessly in empty
                                           // namespace, but the syscall must be allowed)
    allow_safe_futex(&mut rules);          // V8 thread synchronization (PI ops blocked)
    allow_safe_madvise(&mut rules);        // V8 GC page management (restricted flags)
    allow_mmap_private_only(&mut rules);   // V8 heap growth (private-only, no MAP_SHARED)
    allow(&mut rules, libc::SYS_munmap);   // V8 heap shrink
    allow_mremap_no_fixed(&mut rules);     // glibc realloc for large buffers (no MREMAP_FIXED)
    allow(&mut rules, libc::SYS_brk);     // glibc malloc for large allocations

    // epoll_pwait for tokio event loop
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_epoll_wait);
    allow(&mut rules, libc::SYS_epoll_pwait);

    if allow_jit {
        allow(&mut rules, libc::SYS_mprotect); // JIT: make pages executable
    } else {
        allow_mprotect_noexec(&mut rules);     // jitless: block PROT_EXEC
    }

    // Platform-specific
    #[cfg(target_arch = "x86_64")]
    allow(&mut rules, libc::SYS_getpid);   // tokio signal handling

    // exit/exit_group must remain available for clean shutdown and OOM handler
    allow(&mut rules, libc::SYS_exit);
    allow(&mut rules, libc::SYS_exit_group);

    // Thread creation: V8 lazily spawns GC helper threads after warmup.
    // clone(2) requires CLONE_THREAD and blocks namespace flags.
    // clone3 allowed so the stacked ENOSYS filter (not Trap) takes effect.
    allow_clone_thread_only(&mut rules);
    allow(&mut rules, libc::SYS_clone3);
    allow(&mut rules, libc::SYS_set_tid_address);
    allow(&mut rules, libc::SYS_set_robust_list);
    allow(&mut rules, libc::SYS_rseq);
    allow(&mut rules, libc::SYS_sched_getaffinity);
    allow(&mut rules, libc::SYS_sched_getparam);
    allow(&mut rules, libc::SYS_sched_getscheduler);
    allow(&mut rules, libc::SYS_sched_yield);
    allow(&mut rules, libc::SYS_clock_nanosleep); // V8 GC helper thread backoff
    allow(&mut rules, libc::SYS_gettid);
    allow(&mut rules, libc::SYS_sigaltstack); // V8 thread init sets up alt signal stacks
    // prctl restricted to safe operations (thread naming)
    allow_safe_prctl(&mut rules);
    #[cfg(target_arch = "aarch64")]
    allow(&mut rules, 172); // getresgid on aarch64

    // Signal handling (tokio signals, V8 stack guards, SIGSYS handler)
    allow_sigaction_protect_sigsys(&mut rules);
    allow(&mut rules, libc::SYS_rt_sigprocmask);
    allow(&mut rules, libc::SYS_rt_sigreturn);

    // Stacked filter: kill the process for anything not in stage-2 allowlist.
    // Stage-1 uses Trap (SIGSYS) for debugging visibility, but stage-2 uses
    // KillProcess to eliminate the signal handler race window — a post-escape
    // attacker cannot corrupt the SIGSYS handler to bypass the filter.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess, // mismatch: immediate kill (no signal handler race)
        SeccompAction::Allow,       // match: allow
        arch,
    )?;

    let bpf_prog: BpfProgram = filter.try_into()?;
    // Use TSYNC to apply stage-2 to ALL threads in the thread group.
    // V8 may have spawned GC helper threads during warmup; without TSYNC
    // those threads would keep the wider stage-1 allowlist (which includes
    // seccomp(2) and umount2). TSYNC ensures every thread gets stage-2.
    seccompiler::apply_filter_all_threads(&bpf_prog)?;

    Ok(())
}

/// No-op stage-2 on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn install_stage2(_allow_jit: bool) -> Result<(), Box<dyn std::error::Error>> {
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

/// Allow mremap but block MREMAP_FIXED (prevent remapping over arbitrary addresses).
/// MREMAP_FIXED allows an attacker with arbitrary-read to remap memory over
/// interesting targets (V8 heap metadata, stack, etc.). V8/glibc only need
/// MREMAP_MAYMOVE for realloc.
#[cfg(target_os = "linux")]
fn allow_mremap_no_fixed(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // mremap(old_addr, old_size, new_size, flags, [new_addr]) - flags is arg3
    // MREMAP_FIXED = 0x2. Block any call where MREMAP_FIXED is set.
    const MREMAP_FIXED: u64 = 0x2;

    let rule = SeccompRule::new(vec![SeccompCondition::new(
        3, // flags argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(MREMAP_FIXED),
        0, // MREMAP_FIXED must not be set
    )
    .expect("valid condition")])
    .expect("valid rule");

    rules.insert(libc::SYS_mremap, vec![rule]);
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


/// Allow only safe prctl operations (thread naming, VMA naming, seccomp setup)
#[cfg(target_os = "linux")]
fn allow_safe_prctl(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // prctl(option, arg2, ...) - option is arg0
    //
    // Safe ops we allow:
    // - PR_SET_NAME (15) - set thread name (glibc uses during thread creation)
    // - PR_SET_VMA (0x53564d41) - name anonymous VMAs (V8 uses, may return EINVAL)
    // - PR_SET_NO_NEW_PRIVS (38) - already set, re-setting is idempotent and harmless
    //   (needed because seccompiler calls this when installing additional filters)
    //
    // Dangerous ops we block:
    // - PR_SET_SECCOMP (22) - could modify seccomp filter
    // - PR_SET_DUMPABLE (4) - already set to 0, re-enabling would allow core dumps
    // - PR_SET_PDEATHSIG (1) - could be used for process signaling
    const PR_SET_NAME: u64 = 15;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_SET_VMA: u64 = 0x53564d41;

    let prctl_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, PR_SET_NAME)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, PR_SET_NO_NEW_PRIVS)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, PR_SET_VMA)
            .expect("valid")])
        .expect("valid"),
    ];

    rules.insert(libc::SYS_prctl, prctl_rules);
}

/// Allow futex but block dangerous operations (FUTEX_CMP_REQUEUE_PI, etc.)
/// FUTEX_CMP_REQUEUE_PI has been a repeated source of kernel vulnerabilities.
/// Chrome's RestrictFutex() blocks it. V8 only needs basic wait/wake ops.
#[cfg(target_os = "linux")]
fn allow_safe_futex(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // futex(uaddr, op, val, ...) - op is arg1
    // The futex command is in the low 7 bits (FUTEX_CMD_MASK = 0x7f).
    // FUTEX_LOCK_PI (6), FUTEX_UNLOCK_PI (7), FUTEX_TRYLOCK_PI (8),
    // FUTEX_CMP_REQUEUE_PI (12), FUTEX_WAIT_REQUEUE_PI (11) are PI ops
    // we don't need. Block all PI-related ops by allowing only the safe set.
    const FUTEX_CMD_MASK: u64 = 0x7f;
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    const FUTEX_WAKE_OP: u64 = 5;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_WAKE_BITSET: u64 = 10;

    // FUTEX_REQUEUE (3) and FUTEX_CMP_REQUEUE (4) removed — historically
    // tied to kernel CVEs (e.g. CVE-2014-3153) and not needed by V8/tokio.
    let futex_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(FUTEX_CMD_MASK), FUTEX_WAIT)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(FUTEX_CMD_MASK), FUTEX_WAKE)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(FUTEX_CMD_MASK), FUTEX_WAKE_OP)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(FUTEX_CMD_MASK), FUTEX_WAIT_BITSET)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(FUTEX_CMD_MASK), FUTEX_WAKE_BITSET)
            .expect("valid")])
        .expect("valid"),
    ];

    rules.insert(libc::SYS_futex, futex_rules);
}

/// Allow openat only for read-only opens (block write, create, truncate, append, path-only)
#[cfg(target_os = "linux")]
fn allow_openat_readonly(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // openat(dirfd, pathname, flags, mode) - flags is arg index 2
    // Block any open that could write, create files, or obtain path-only FDs:
    // O_WRONLY (0x1), O_RDWR (0x2), O_CREAT (0x40), O_TRUNC (0x200),
    // O_APPEND (0x400), O_PATH (0x200000)
    // O_PATH FDs bypass permission checks and can be used with openat for
    // relative path traversal, fstat, etc. — not needed for V8/tokio.
    const DANGEROUS_FLAGS: u64 = 0x1 | 0x2 | 0x40 | 0x200 | 0x400 | 0x200000;

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

/// Allow arch_prctl only for FS register operations (TLS setup).
/// Blocks ARCH_SET_GS, ARCH_GET_GS, ARCH_SET_CPUID, etc. which could be
/// used to redirect TLS-based data structures (stack canary, errno).
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
fn allow_arch_prctl_fs_only(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // arch_prctl(code, addr) - code is arg0
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    let arch_prctl_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, ARCH_SET_FS)
            .expect("valid")])
        .expect("valid"),
        SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, ARCH_GET_FS)
            .expect("valid")])
        .expect("valid"),
    ];

    rules.insert(libc::SYS_arch_prctl, arch_prctl_rules);
}

/// Allow clone only for thread creation.
///
/// Two conditions enforced (AND'd):
/// 1. CLONE_THREAD must be set — this is a thread, not a new process/fork.
/// 2. No namespace flags (CLONE_NEWUSER, CLONE_NEWPID, etc.) — prevents
///    container/sandbox escape.
///
/// clone(2) flags are in arg0 on both x86_64 and aarch64.
#[cfg(target_os = "linux")]
fn allow_clone_thread_only(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    const CLONE_THREAD: u64 = 0x00010000;
    const CLONE_NEWNS: u64 = 0x00020000;
    const CLONE_NEWCGROUP: u64 = 0x02000000;
    const CLONE_NEWUTS: u64 = 0x04000000;
    const CLONE_NEWIPC: u64 = 0x08000000;
    const CLONE_NEWUSER: u64 = 0x10000000;
    const CLONE_NEWPID: u64 = 0x20000000;
    const CLONE_NEWNET: u64 = 0x40000000;

    let dangerous_flags =
        CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

    // SeccompRule with multiple conditions = AND. Both must pass.
    let rule = SeccompRule::new(vec![
        // Condition 1: CLONE_THREAD must be set
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_THREAD),
            CLONE_THREAD, // (flags & CLONE_THREAD) == CLONE_THREAD
        )
        .expect("valid condition"),
        // Condition 2: no namespace flags
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(dangerous_flags),
            0, // (flags & dangerous) == 0
        )
        .expect("valid condition"),
    ])
    .expect("valid rule");

    rules.insert(libc::SYS_clone, vec![rule]);
}

/// No-op on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn install(_allow_jit: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Seccomp is Linux-only; on macOS we rely on JS lockdown only
    Ok(())
}
