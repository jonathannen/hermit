//! Landlock filesystem restriction for Linux
//!
//! Provides an independent LSM-layer filesystem restriction on top of the
//! mount namespace and seccomp filters. Even if seccomp is bypassed via a
//! kernel bug, Landlock still enforces path-level access control.
//!
//! Uses raw syscalls to avoid adding a dependency. Landlock ABI v1 (Linux 5.13+)
//! is sufficient for our needs — we only restrict filesystem access.

/// Apply Landlock restrictions. Best-effort: returns Ok(false) if Landlock
/// is not supported by the kernel (< 5.13 or disabled).
#[cfg(target_os = "linux")]
pub fn restrict_filesystem() -> Result<bool, Box<dyn std::error::Error>> {
    // Landlock syscall numbers (stable ABI)
    #[cfg(target_arch = "x86_64")]
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    #[cfg(target_arch = "x86_64")]
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    #[cfg(target_arch = "x86_64")]
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

    #[cfg(target_arch = "aarch64")]
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    #[cfg(target_arch = "aarch64")]
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    #[cfg(target_arch = "aarch64")]
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

    // Landlock ABI v1 access rights
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    // All ABI v1 filesystem access rights
    const ALL_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    // Only allow reading files and directories — no writes, no execution,
    // no creation of any filesystem objects.
    const READ_ONLY: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

    // Structs matching kernel ABI
    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    // 1. Create ruleset — handles all filesystem access types
    let attr = LandlockRulesetAttr {
        handled_access_fs: ALL_ACCESS,
    };
    // SAFETY: syscall with valid struct pointer and size.
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32, // flags
        )
    };
    if ruleset_fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) || err.raw_os_error() == Some(libc::EOPNOTSUPP) {
            // Landlock not supported — not an error, just unavailable
            return Ok(false);
        }
        return Err(format!("landlock_create_ruleset: {}", err).into());
    }
    let ruleset_fd = ruleset_fd as i32;

    // 2. Add rule: allow read-only access to "/" (the entire mount namespace root).
    // Since we're inside a minimal mount namespace with only a few bind-mounts,
    // this effectively limits access to only those paths — but read-only.
    let root_fd = unsafe {
        libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_CLOEXEC)
    };
    if root_fd < 0 {
        unsafe { libc::close(ruleset_fd); }
        return Err(format!("open /: {}", std::io::Error::last_os_error()).into());
    }

    let path_attr = LandlockPathBeneathAttr {
        allowed_access: READ_ONLY,
        parent_fd: root_fd,
    };
    // SAFETY: syscall with valid ruleset_fd and struct pointer.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &path_attr as *const LandlockPathBeneathAttr,
            0u32, // flags
        )
    };
    unsafe { libc::close(root_fd); }
    if ret < 0 {
        unsafe { libc::close(ruleset_fd); }
        return Err(format!("landlock_add_rule: {}", std::io::Error::last_os_error()).into());
    }

    // 3. Enforce the ruleset on this thread (and all future children)
    // Requires NO_NEW_PRIVS to be set (which we do before seccomp).
    // SAFETY: syscall with valid ruleset_fd.
    let ret = unsafe {
        libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32)
    };
    unsafe { libc::close(ruleset_fd); }
    if ret < 0 {
        return Err(format!("landlock_restrict_self: {}", std::io::Error::last_os_error()).into());
    }

    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn restrict_filesystem() -> Result<bool, Box<dyn std::error::Error>> {
    Ok(false)
}
