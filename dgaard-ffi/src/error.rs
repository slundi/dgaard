//! Thread-local error channel.
//!
//! Every fallible entry point signals failure through its return value — NULL
//! for handles, `-1` for the integer predicates — and leaves a human-readable
//! description here. Nothing in this API ever reports a failure as a benign
//! verdict, so a C caller can never mistake "the config did not parse" for
//! "this domain is fine".

use std::cell::RefCell;
use std::os::raw::c_char;

use crate::buffer::write_c_string;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Record a failure for the current thread, replacing any previous one.
pub(crate) fn set_error(message: impl Into<String>) {
    let message = message.into();
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(message));
}

/// Forget the current thread's failure. Called on entry to every operation
/// that can succeed, so a stale message is never attributed to a fresh call.
pub(crate) fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Copy the calling thread's last error message into `buffer`.
///
/// Returns the message length in bytes excluding the terminator, or `0` when
/// the thread has no pending error. Pass a NULL `buffer` to query the length
/// first; see `dgaard_version` for the same convention.
///
/// The message describes the most recent *failed* call on this thread only.
/// Errors are never shared between threads.
///
/// # Safety
///
/// When `buffer` is non-NULL it must point to at least `capacity` writable
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_last_error(buffer: *mut c_char, capacity: usize) -> usize {
    LAST_ERROR.with(|slot| match slot.borrow().as_deref() {
        // SAFETY: the buffer contract is forwarded from this function's own.
        Some(message) => unsafe { write_c_string(message, buffer, capacity) },
        None => {
            if !buffer.is_null() && capacity > 0 {
                // SAFETY: at least one writable byte, per the contract.
                unsafe { *buffer = 0 };
            }
            0
        }
    })
}

/// Discard the calling thread's pending error message.
#[unsafe(no_mangle)]
pub extern "C" fn dgaard_clear_error() {
    clear_error();
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::buffer::tests::read_back;

    /// Read the pending error back the way a C caller would.
    fn read_error() -> Option<String> {
        let mut storage: [c_char; 256] = [0x7f; 256];
        let length = unsafe { dgaard_last_error(storage.as_mut_ptr(), storage.len()) };
        if length == 0 {
            return None;
        }
        Some(read_back(&storage))
    }

    #[test]
    fn round_trips_a_message() {
        clear_error();
        set_error("TOML syntax error: expected `=`");
        assert_eq!(
            read_error().as_deref(),
            Some("TOML syntax error: expected `=`")
        );
        clear_error();
    }

    #[test]
    fn reports_zero_and_terminates_when_unset() {
        clear_error();
        let mut storage: [c_char; 8] = [0x7f; 8];
        let length = unsafe { dgaard_last_error(storage.as_mut_ptr(), storage.len()) };
        assert_eq!(length, 0);
        assert_eq!(
            storage[0], 0,
            "buffer must be an empty C string, not left dirty"
        );
    }

    #[test]
    fn reports_length_for_a_null_buffer() {
        clear_error();
        set_error("boom");
        assert_eq!(unsafe { dgaard_last_error(std::ptr::null_mut(), 0) }, 4);
        clear_error();
    }

    #[test]
    fn clear_error_entry_point_resets_the_slot() {
        set_error("boom");
        dgaard_clear_error();
        assert!(read_error().is_none());
    }

    #[test]
    fn a_new_error_replaces_the_previous_one() {
        set_error("first");
        set_error("second");
        assert_eq!(read_error().as_deref(), Some("second"));
        clear_error();
    }

    #[test]
    fn errors_do_not_leak_across_threads() {
        set_error("main thread only");
        let seen = std::thread::spawn(|| {
            let mut storage: [c_char; 64] = [0x7f; 64];
            unsafe { dgaard_last_error(storage.as_mut_ptr(), storage.len()) }
        })
        .join()
        .unwrap();
        assert_eq!(seen, 0);
        clear_error();
    }
}
