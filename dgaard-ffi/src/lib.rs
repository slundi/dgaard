//! C ABI for the dgaard domain filtering engine.
//!
//! Builds as a `cdylib` and a `staticlib` so C, C++, cgo, ctypes and anything
//! else that speaks the C ABI can run the same classification pipeline the
//! `dgaard` daemon uses. The generated header lives at `include/dgaard.h`.
//!
//! # Shape of the API
//!
//! Two opaque handles. [`dgaard_engine`] is built once from a configuration
//! and shared — immutable and `Sync`, so every worker thread can hold the same
//! pointer. [`dgaard_verdict`] is one classification result, owned by the
//! caller and released with `dgaard_verdict_free`.
//!
//! Strings come back through caller-supplied buffers under the `snprintf`
//! convention: the return value is the length the text *needs*, so a NULL
//! buffer asks for a size and a return `>= capacity` means truncation. No
//! pointer this library returns ever has to be freed by the caller except the
//! two handles.
//!
//! # Failure is never a verdict
//!
//! Constructors and `dgaard_classify` return NULL on failure; the integer
//! predicates return `-1`; the tagged accessors return the dedicated
//! `DGAARD_ACTION_ERROR` / `DGAARD_REASON_ERROR` discriminants. None of those
//! values can be produced by a successful call, so a C caller cannot mistake a
//! broken configuration or a bad pointer for "this domain is fine".
//! `dgaard_last_error` explains the most recent failure on the calling thread.
//!
//! # Example
//!
//! ```c
//! dgaard_engine *engine = dgaard_engine_new_from_file("/etc/dgaard/config.toml");
//! if (!engine) {
//!     char message[256];
//!     dgaard_last_error(message, sizeof message);
//!     fprintf(stderr, "dgaard: %s\n", message);
//!     return 1;
//! }
//!
//! dgaard_verdict *verdict = dgaard_classify(engine, "kq3v9z7x1j4m2p8w.biz");
//! if (verdict && dgaard_verdict_action(verdict) == DGAARD_ACTION_BLOCK) {
//!     printf("blocked, reason %d, score %u\n",
//!            dgaard_verdict_block_reason(verdict),
//!            dgaard_verdict_score(verdict));
//! }
//!
//! dgaard_verdict_free(verdict);
//! dgaard_engine_free(engine);
//! ```

// Every public type and function here is named the way its C counterpart is
// spelled, because cbindgen copies these identifiers verbatim into
// `include/dgaard.h`. Rust casing would make the header unidiomatic for the
// only audience that reads it.
#![allow(non_camel_case_types)]

use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;

mod buffer;
mod engine;
mod error;
mod tags;
mod verdict;

pub use engine::{
    dgaard_check_qclass, dgaard_check_qtype, dgaard_classify, dgaard_engine, dgaard_engine_free,
    dgaard_engine_new_from_file, dgaard_engine_new_from_toml, dgaard_engine_new_heuristics,
    dgaard_is_dga, dgaard_is_illegal_idn, dgaard_is_structure_invalid, dgaard_score,
};
pub use error::{dgaard_clear_error, dgaard_last_error};
pub use tags::{dgaard_action, dgaard_reason};
pub use verdict::{
    dgaard_verdict, dgaard_verdict_action, dgaard_verdict_address, dgaard_verdict_block_number,
    dgaard_verdict_block_reason, dgaard_verdict_block_text, dgaard_verdict_free,
    dgaard_verdict_reason_at, dgaard_verdict_reason_count, dgaard_verdict_reason_number_at,
    dgaard_verdict_reason_text_at, dgaard_verdict_score,
};

use crate::buffer::write_c_string;

/// Version of the C ABI, bumped whenever an enum variant is appended or a
/// signature changes. Compare against `dgaard_abi_version` at startup to
/// catch a header that no longer matches the shared library.
pub const DGAARD_ABI_VERSION: u32 = 1;

/// The ABI version this library was built with. See [`DGAARD_ABI_VERSION`].
#[unsafe(no_mangle)]
pub extern "C" fn dgaard_abi_version() -> u32 {
    DGAARD_ABI_VERSION
}

/// Copy the `dgaard-ffi` crate version (e.g. `"0.2.0"`) into `buffer`.
///
/// Returns the byte length excluding the terminator, under the convention
/// described on `dgaard_verdict_block_text`.
///
/// # Safety
///
/// When `buffer` is non-NULL it must point to at least `capacity` writable
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_version(buffer: *mut c_char, capacity: usize) -> usize {
    // SAFETY: forwarded buffer contract.
    unsafe { write_c_string(env!("CARGO_PKG_VERSION"), buffer, capacity) }
}

/// Stop a Rust panic from unwinding across the C boundary.
///
/// A panic is turned into this call's documented failure value plus an error
/// message, so a C caller sees an error rather than a process abort. Note that
/// the workspace release profile sets `panic = "abort"`, under which nothing
/// unwinds and this is inert — it earns its keep in debug and test builds, and
/// for consumers who link a library built with unwinding enabled.
pub(crate) fn guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            error::set_error("internal error: panic in dgaard-engine");
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_passes_through_a_successful_call() {
        assert_eq!(guard(-1, || 7), 7);
    }

    #[test]
    fn guard_converts_a_panic_into_the_fallback() {
        error::clear_error();

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let value = guard(-1, || panic!("boom"));
        std::panic::set_hook(previous);

        assert_eq!(value, -1);
        assert_ne!(
            unsafe { dgaard_last_error(std::ptr::null_mut(), 0) },
            0,
            "a caught panic must leave an explanation behind"
        );
        error::clear_error();
    }

    #[test]
    fn abi_version_is_reported() {
        assert_eq!(dgaard_abi_version(), DGAARD_ABI_VERSION);
    }

    #[test]
    fn version_matches_the_crate_manifest() {
        let mut storage: [c_char; 32] = [0x7f; 32];
        let length = unsafe { dgaard_version(storage.as_mut_ptr(), storage.len()) };
        assert_eq!(
            buffer::tests::read_back(&storage),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(length, env!("CARGO_PKG_VERSION").len());
    }
}
