//! Caller-supplied buffer conventions shared by every string accessor.

use std::ffi::CStr;
use std::os::raw::c_char;

/// Copy `source` into the caller's buffer as a NUL-terminated C string.
///
/// Follows the `snprintf` convention: the return value is the length of
/// `source` in bytes *excluding* the terminator, whether or not it fit. A
/// caller that gets back a value `>= capacity` knows the text was truncated
/// and can retry with a larger buffer.
///
/// Passing a NULL `buffer` (or a `capacity` of zero) writes nothing and only
/// reports the required length — that is the supported way to size a buffer
/// before allocating it.
///
/// Truncation always lands on a UTF-8 character boundary, so the bytes handed
/// back are never an invalid fragment of a multi-byte character.
///
/// # Safety
///
/// When `buffer` is non-NULL it must point to at least `capacity` writable
/// bytes.
pub(crate) unsafe fn write_c_string(source: &str, buffer: *mut c_char, capacity: usize) -> usize {
    let needed = source.len();

    if buffer.is_null() || capacity == 0 {
        return needed;
    }

    let mut copied = needed.min(capacity - 1);
    while copied > 0 && !source.is_char_boundary(copied) {
        copied -= 1;
    }

    // SAFETY: the caller guarantees `capacity` writable bytes and
    // `copied < capacity`, so the copy and the terminator both stay in range.
    unsafe {
        std::ptr::copy_nonoverlapping(source.as_ptr().cast::<c_char>(), buffer, copied);
        *buffer.add(copied) = 0;
    }

    needed
}

/// Borrow a NUL-terminated C string as UTF-8.
///
/// Returns `None` for a NULL pointer or for bytes that are not valid UTF-8 —
/// both of which callers report as an error rather than silently passing a
/// mangled domain to the engine.
///
/// # Safety
///
/// When non-NULL, `pointer` must point to a NUL-terminated byte string that
/// stays valid for the duration of the call.
pub(crate) unsafe fn borrow_str<'a>(pointer: *const c_char) -> Option<&'a str> {
    if pointer.is_null() {
        return None;
    }

    // SAFETY: delegated to the caller's contract above.
    unsafe { CStr::from_ptr(pointer) }.to_str().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Read a NUL-terminated C string back out of a buffer, the way a C
    /// caller would.
    ///
    /// Reinterprets the whole slice rather than casting byte by byte:
    /// `c_char` is `i8` on x86_64 but `u8` on aarch64, so a per-element
    /// `as u8` is a no-op cast on the targets this project actually ships to,
    /// which `clippy::unnecessary_cast` rejects there.
    pub(crate) fn read_back(storage: &[c_char]) -> String {
        // SAFETY: `c_char` is a one-byte integer on every supported target, so
        // `*const c_char` and `*const u8` describe the same bytes. `.cast()`
        // rather than `as`: on aarch64 the two types are literally the same
        // and an `as` cast would be flagged as redundant.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), storage.len()) };
        // Bounded, so a buffer the library failed to terminate is a clean test
        // failure rather than a read off the end.
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .expect("accessor must NUL-terminate");
        String::from_utf8(bytes[..end].to_vec()).expect("accessor emitted invalid UTF-8")
    }

    /// Run `write_c_string` against a stack buffer and return what a C caller
    /// would observe: the reported length and the NUL-terminated contents.
    fn write(source: &str, capacity: usize) -> (usize, String) {
        // 0x7f is neither NUL nor part of any expected output, so a missing
        // terminator shows up as garbage instead of passing silently.
        let mut storage: Vec<c_char> = vec![0x7f; capacity.max(1) + 8];
        let needed = unsafe { write_c_string(source, storage.as_mut_ptr(), capacity) };

        if capacity == 0 {
            return (needed, String::new());
        }

        (needed, read_back(&storage))
    }

    #[test]
    fn writes_the_whole_string_when_it_fits() {
        let (needed, written) = write("oisd.nl", 64);
        assert_eq!(needed, 7);
        assert_eq!(written, "oisd.nl");
    }

    #[test]
    fn exact_fit_needs_room_for_the_terminator() {
        // 7 bytes of text in an 8-byte buffer: fits exactly.
        let (needed, written) = write("oisd.nl", 8);
        assert_eq!(needed, 7);
        assert_eq!(written, "oisd.nl");

        // One byte short: truncated, but `needed` still reports the full size.
        let (needed, written) = write("oisd.nl", 7);
        assert_eq!(needed, 7);
        assert_eq!(written, "oisd.n");
    }

    #[test]
    fn reports_required_length_for_a_null_buffer() {
        let needed = unsafe { write_c_string("stevenblack.txt", std::ptr::null_mut(), 0) };
        assert_eq!(needed, 15);
    }

    #[test]
    fn zero_capacity_writes_nothing() {
        let (needed, written) = write("stevenblack.txt", 0);
        assert_eq!(needed, 15);
        assert!(written.is_empty());
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // "é" is two bytes; a 2-byte payload budget must drop it entirely
        // rather than emit a lone continuation byte.
        let (needed, written) = write("aé", 3);
        assert_eq!(needed, 3);
        assert_eq!(written, "a");
    }

    #[test]
    fn empty_source_still_terminates() {
        let (needed, written) = write("", 4);
        assert_eq!(needed, 0);
        assert!(written.is_empty());
    }

    #[test]
    fn borrow_str_rejects_null() {
        assert!(unsafe { borrow_str(std::ptr::null()) }.is_none());
    }

    #[test]
    fn borrow_str_rejects_invalid_utf8() {
        let bytes = [0xff_u8, 0xfe, 0x00];
        assert!(unsafe { borrow_str(bytes.as_ptr().cast()) }.is_none());
    }

    #[test]
    fn borrow_str_reads_a_valid_string() {
        let text = std::ffi::CString::new("example.com").unwrap();
        assert_eq!(unsafe { borrow_str(text.as_ptr()) }, Some("example.com"));
    }
}
