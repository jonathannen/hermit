//! Mount namespace sandbox for Linux
//!
//! Creates a new user+mount namespace and pivots to a minimal filesystem
//! containing only the paths V8 needs during initialization. After warmup,
//! these paths can be unmounted to leave an empty root.
//!
//! This is the same mechanism bubblewrap uses: unshare(CLONE_NEWUSER |
//! CLONE_NEWNS), build a new mount tree, pivot_root into it.
//!
//! Requires: single-threaded process (no tokio/V8 yet), Linux with user
//! namespaces enabled (most modern kernels).

/// Controls whether mount namespace failure is fatal or best-effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Namespace failure is fatal — the process exits.
    Strict,
    /// Namespace failure prints a warning and continues.
    Permissive,
}

/// Set up mount namespace isolation. Must be called before any threads are created.
///
/// In `Strict` mode, failure is fatal (exit code 1).
/// In `Permissive` mode, failure prints a warning and continues — seccomp
/// still provides defense.
#[cfg(target_os = "linux")]
pub fn enter_mount_namespace(mode: SandboxMode) {
    if let Err(e) = try_enter_mount_namespace() {
        match mode {
            SandboxMode::Strict => {
                eprintln!("fatal: mount namespace setup failed ({})", e);
                eprintln!("hint: use --permissive to continue without filesystem isolation");
                std::process::exit(1);
            }
            SandboxMode::Permissive => {
                eprintln!("warning: mount namespace setup failed ({}), continuing without filesystem isolation", e);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn try_enter_mount_namespace() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::io::Write;

    // Get uid/gid BEFORE unshare (after unshare they show as unmapped 65534)
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // 1. Create new user + mount namespace (unprivileged)
    // SAFETY: unshare only affects the calling thread's namespace membership.
    let ret = unsafe {
        libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS)
    };
    if ret != 0 {
        return Err(format!("unshare: {}", std::io::Error::last_os_error()).into());
    }

    // 2. Set up uid/gid mapping (map outer uid to 0 in the namespace)
    // This is required for mount operations in the new namespace.
    // Must use OpenOptions without O_CREAT since /proc files reject it.
    let mut f = fs::OpenOptions::new().write(true).open("/proc/self/setgroups")?;
    f.write_all(b"deny")?;
    drop(f);
    // uid_map/gid_map require a single atomic write — write! may split into chunks.
    let mut f = fs::OpenOptions::new().write(true).open("/proc/self/uid_map")?;
    f.write_all(format!("0 {} 1", uid).as_bytes())?;
    drop(f);
    let mut f = fs::OpenOptions::new().write(true).open("/proc/self/gid_map")?;
    f.write_all(format!("0 {} 1", gid).as_bytes())?;
    drop(f);

    // 3. Make all existing mounts private (prevent propagation)
    // SAFETY: mount with MS_REC|MS_PRIVATE on "/" affects mount propagation only.
    let none = std::ptr::null();
    let root = c"/".as_ptr();
    let ret = unsafe {
        libc::mount(none, root, none, libc::MS_REC | libc::MS_PRIVATE, none as *const libc::c_void)
    };
    if ret != 0 {
        return Err(format!("mount MS_PRIVATE: {}", std::io::Error::last_os_error()).into());
    }

    // 4. Create a tmpfs for the new root (unique per-run to avoid races)
    let mut template = b"/tmp/hermit-XXXXXX\0".to_vec();
    // SAFETY: mkdtemp modifies the template in-place, replacing XXXXXX with
    // a unique suffix. The buffer is properly null-terminated.
    let result = unsafe { libc::mkdtemp(template.as_mut_ptr() as *mut libc::c_char) };
    if result.is_null() {
        return Err(format!("mkdtemp: {}", std::io::Error::last_os_error()).into());
    }
    // Strip the null terminator for Rust string usage
    let new_root_str = std::str::from_utf8(&template[..template.len() - 1])
        .map_err(|_| "mkdtemp returned non-UTF8 path")?
        .to_string();

    let tmpfs = c"tmpfs".as_ptr();
    let new_root_cstr = format!("{}\0", new_root_str);
    let new_root_ptr = new_root_cstr.as_ptr() as *const libc::c_char;
    // SAFETY: mount creates a tmpfs at the target path.
    let ret = unsafe {
        libc::mount(tmpfs, new_root_ptr, tmpfs, libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, none as *const libc::c_void)
    };
    if ret != 0 {
        return Err(format!("mount tmpfs: {}", std::io::Error::last_os_error()).into());
    }

    // 5. Bind-mount only the paths V8 needs during initialization:
    //    - /proc/self/maps (V8 reads memory layout)
    //    - /proc/self/status (V8 reads process info, rlimit reads thread count)
    //    - /proc/self/fd (FD hygiene close_inherited_fds)
    //    - /sys/devices/system/cpu (for CPU topology)
    //    - /dev/urandom (for entropy)
    //
    //    Sensitive /proc files (environ, cmdline, mountinfo) are NOT mounted,
    //    preventing a post-V8-escape attacker from reading host secrets.
    let bind_srcs = [
        "/proc/self/maps",
        "/proc/self/status",
        "/proc/self/fd",
        "/sys/devices/system/cpu",
        "/dev/urandom",
    ];
    let bind_dsts: Vec<String> = bind_srcs.iter()
        .map(|src| format!("{}{}", new_root_str, src))
        .collect();

    for (src, dst) in bind_srcs.iter().zip(bind_dsts.iter()) {
        let dst_path = std::path::Path::new(dst);
        if std::path::Path::new(src).is_dir() {
            fs::create_dir_all(dst_path)?;
        } else {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }
            // Create empty file as mount point
            fs::File::create(dst_path)?;
        }

        let src_cstr = format!("{}\0", src);
        let dst_cstr = format!("{}\0", dst);
        // SAFETY: bind mount from existing path to our new root tree.
        let ret = unsafe {
            libc::mount(
                src_cstr.as_ptr() as *const libc::c_char,
                dst_cstr.as_ptr() as *const libc::c_char,
                none,
                libc::MS_BIND | libc::MS_REC,
                none as *const libc::c_void,
            )
        };
        if ret != 0 {
            return Err(format!("bind mount {} -> {}: {}", src, dst, std::io::Error::last_os_error()).into());
        }
    }

    // 6. pivot_root: swap root to our minimal tree
    // We need an old_root directory inside the new root for pivot_root
    let old_root = format!("{}/old_root", new_root_str);
    fs::create_dir_all(&old_root)?;

    let old_root_cstr = format!("{}\0", old_root);
    // SAFETY: pivot_root swaps the filesystem root. Process must have CAP_SYS_ADMIN
    // in the user namespace (which we do after unshare(CLONE_NEWUSER)).
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            new_root_ptr,
            old_root_cstr.as_ptr() as *const libc::c_char,
        )
    };
    if ret != 0 {
        return Err(format!("pivot_root: {}", std::io::Error::last_os_error()).into());
    }

    // 7. Unmount old root and remove the mount point
    let old_root_inside = "/old_root\0";
    // SAFETY: umount2 detaches the old root filesystem.
    let ret = unsafe {
        libc::umount2(old_root_inside.as_ptr() as *const libc::c_char, libc::MNT_DETACH)
    };
    if ret != 0 {
        return Err(format!("umount old_root: {}", std::io::Error::last_os_error()).into());
    }
    let _ = fs::remove_dir("/old_root");

    // 8. Remount root tmpfs read-only. Setup is complete — no more files or
    // directories need to be created. This prevents any writes to the tmpfs
    // even if an attacker bypasses the seccomp openat read-only filter.
    // SAFETY: remount on "/" with MS_RDONLY only changes mount flags.
    let ret = unsafe {
        libc::mount(
            none, root, none,
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            none as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!("remount / read-only: {}", std::io::Error::last_os_error()).into());
    }

    // 9. chdir to / in the new root
    // SAFETY: chdir to a valid path.
    unsafe { libc::chdir(c"/".as_ptr()); }

    Ok(())
}

/// Unmount bind-mounts after V8 warmup, leaving a minimal filesystem.
/// Only /proc/self/fd remains (needed for V8 GC thread creation).
/// /proc/self/maps and /proc/self/status are unmounted to prevent
/// a post-V8-escape attacker from defeating ASLR or reading host info.
/// Sensitive files like environ and cmdline were never mounted.
#[cfg(target_os = "linux")]
pub fn strip_filesystem() {
    // Unmount everything except /proc/self/fd — no longer needed after V8 init.
    // /proc/self/maps: V8 reads during init only; leaving it exposes full
    //   memory layout (ASLR defeat) to a post-escape attacker.
    // /proc/self/status: leaks outer UID/GID, capability sets, CPU affinity.
    // /dev/urandom: entropy source, not needed after V8 seeds its RNG.
    // /sys/devices/system/cpu: CPU topology, not needed after init.
    let paths = [
        "/proc/self/maps\0",
        "/proc/self/status\0",
        "/dev/urandom\0",
        "/sys/devices/system/cpu\0",
    ];
    for path in &paths {
        // SAFETY: umount2 with MNT_DETACH on paths we bind-mounted.
        unsafe {
            libc::umount2(path.as_ptr() as *const libc::c_char, libc::MNT_DETACH);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn enter_mount_namespace(_mode: SandboxMode) {
    // Mount namespaces are Linux-only; permissive is the only sensible default.
}

#[cfg(not(target_os = "linux"))]
pub fn strip_filesystem() {
    // Mount namespaces are Linux-only
}
