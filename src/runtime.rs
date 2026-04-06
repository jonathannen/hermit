use deno_core::{JsRuntime, RuntimeOptions, extension};

use crate::ops::op_log;

/// Exit code for OOM (128 + SIGKILL)
pub const OOM_EXIT_CODE: i32 = 137;

/// Exit code for timeout (128 + SIGALRM)
pub const TIMEOUT_EXIT_CODE: i32 = 142;

/// Exit code for stdout write failure (128 + SIGPIPE)
pub const PIPE_EXIT_CODE: i32 = 141;

extension!(
    hermit,
    ops = [op_log],
    esm_entry_point = "ext:hermit/runtime.js",
    esm = [dir "src", "runtime.js"],
);

extern "C" fn near_heap_limit_callback(
    _data: *mut std::ffi::c_void,
    _current_heap_limit: usize,
    _initial_heap_limit: usize,
) -> usize {
    // Use signal-safe write + _exit instead of std::process::exit to avoid
    // running atexit handlers and flushing stdio in a potentially corrupted
    // heap context. This callback fires during GC with the heap in an
    // unknown state.
    unsafe {
        let msg = b"fatal: out of memory - heap limit reached\n";
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(OOM_EXIT_CODE);
    }

    #[allow(unreachable_code)]
    _current_heap_limit
}

pub fn create_runtime(
    memory_limit: usize,
    allow_jit: bool,
) -> Result<JsRuntime, deno_core::error::AnyError> {
    let v8_flags = if allow_jit {
        "--disallow-code-generation-from-strings"
    } else {
        "--disallow-code-generation-from-strings --jitless"
    };
    deno_core::v8::V8::set_flags_from_string(v8_flags);

    let create_params = deno_core::v8::CreateParams::default()
        .heap_limits(0, memory_limit)
        .allow_atomics_wait(false);

    let mut runtime = JsRuntime::new(RuntimeOptions {
        extensions: vec![hermit::init()],
        create_params: Some(create_params),
        ..Default::default()
    });

    {
        let isolate = runtime.v8_isolate();
        isolate.add_near_heap_limit_callback(near_heap_limit_callback, std::ptr::null_mut());
    }

    Ok(runtime)
}
