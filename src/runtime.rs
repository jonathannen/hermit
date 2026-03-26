use std::io::Write;

use deno_core::{JsRuntime, RuntimeOptions, extension};

use crate::ops::op_log;

/// Exit code for OOM (128 + SIGKILL)
pub const OOM_EXIT_CODE: i32 = 137;

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
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "fatal: out of memory - heap limit reached");
    let _ = stderr.flush();

    std::process::exit(OOM_EXIT_CODE);

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
