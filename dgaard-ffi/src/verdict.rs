//! Opaque classification result and its accessors.
//!
//! The result is a heap handle rather than a by-value struct on purpose: a
//! flat C struct big enough to inline every reason would be several kilobytes
//! copied on every query, and one sized to a fixed cap would silently drop
//! reasons past the cap. Here the reason list is exact and the caller pays
//! one allocation per classification, freed with `dgaard_verdict_free`.

use std::net::IpAddr;
use std::os::raw::c_char;

use ::dgaard_engine::ResolveResult;

use crate::buffer::write_c_string;
use crate::error::set_error;
use crate::tags::{FlatReason, dgaard_action, dgaard_reason, flatten_action};

/// Opaque handle to the outcome of a classification.
///
/// Owned by the caller and freed with `dgaard_verdict_free`. Unlike the engine
/// handle it is *not* shared between threads: treat it as owned by whichever
/// thread called `dgaard_classify`.
pub struct dgaard_verdict {
    action: dgaard_action,
    block: Option<FlatReason>,
    address: Option<String>,
    score_total: u8,
    reasons: Vec<FlatReason>,
}

impl dgaard_verdict {
    pub(crate) fn from_result(result: &ResolveResult) -> Self {
        let (action, block, address) = flatten_action(&result.action);

        Self {
            action,
            block,
            address: address.as_ref().map(IpAddr::to_string),
            score_total: result.score.total,
            reasons: result
                .score
                .reasons
                .iter()
                .map(FlatReason::from_reason)
                .collect(),
        }
    }

    pub(crate) fn into_handle(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }
}

/// Borrow a verdict handle, recording an error for a NULL pointer.
///
/// # Safety
///
/// `handle`, when non-NULL, must come from `dgaard_classify` and must not
/// have been freed.
unsafe fn borrow<'a>(handle: *const dgaard_verdict) -> Option<&'a dgaard_verdict> {
    if handle.is_null() {
        set_error("null verdict handle");
        return None;
    }
    // SAFETY: delegated to the caller's contract above.
    Some(unsafe { &*handle })
}

/// Release a verdict returned by `dgaard_classify`. Passing NULL is a no-op.
///
/// # Safety
///
/// `handle` must come from `dgaard_classify` and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_free(handle: *mut dgaard_verdict) {
    if !handle.is_null() {
        // SAFETY: the caller guarantees sole ownership of a handle this
        // library allocated with `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// The action the caller should take.
///
/// Returns `DGAARD_ACTION_ERROR` for a NULL handle — a value no successful
/// classification can produce.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_action(handle: *const dgaard_verdict) -> dgaard_action {
    // SAFETY: forwarded contract.
    match unsafe { borrow(handle) } {
        Some(verdict) => verdict.action,
        None => dgaard_action::DGAARD_ACTION_ERROR,
    }
}

/// The reason the domain was blocked.
///
/// `DGAARD_REASON_NONE` when the action is not `DGAARD_ACTION_BLOCK`,
/// `DGAARD_REASON_ERROR` for a NULL handle.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_block_reason(
    handle: *const dgaard_verdict,
) -> dgaard_reason {
    // SAFETY: forwarded contract.
    match unsafe { borrow(handle) } {
        Some(verdict) => match &verdict.block {
            Some(reason) => reason.tag,
            None => dgaard_reason::DGAARD_REASON_NONE,
        },
        None => dgaard_reason::DGAARD_REASON_ERROR,
    }
}

/// Numeric payload of the block reason — entropy, TTL, query type, label
/// length or custom-flag bit, depending on the tag.
///
/// Returns NaN when the reason carries no number, when the domain was not
/// blocked, or for a NULL handle. Test with `isnan()`.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_block_number(handle: *const dgaard_verdict) -> f64 {
    // SAFETY: forwarded contract.
    unsafe { borrow(handle) }
        .and_then(|verdict| verdict.block.as_ref())
        .map_or(f64::NAN, |reason| reason.number)
}

/// Text payload of the block reason — the blocklist name, matched pattern,
/// keyword or country code, depending on the tag.
///
/// Returns the byte length excluding the terminator, or `0` when the reason
/// carries no text. Pass a NULL `buffer` to ask for the required size; a
/// return value `>= capacity` means the text was truncated.
///
/// # Safety
///
/// See `dgaard_verdict_free`. When non-NULL, `buffer` must point to at least
/// `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_block_text(
    handle: *const dgaard_verdict,
    buffer: *mut c_char,
    capacity: usize,
) -> usize {
    // SAFETY: forwarded contract.
    let text = unsafe { borrow(handle) }
        .and_then(|verdict| verdict.block.as_ref())
        .and_then(|reason| reason.text.as_deref());

    // SAFETY: forwarded buffer contract.
    unsafe { write_c_string(text.unwrap_or(""), buffer, capacity) }
}

/// Cumulative suspicion score, 0–255. Returns `0` for a NULL handle; use
/// `dgaard_verdict_action` to distinguish that from a genuinely clean domain.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_score(handle: *const dgaard_verdict) -> u8 {
    // SAFETY: forwarded contract.
    unsafe { borrow(handle) }.map_or(0, |verdict| verdict.score_total)
}

/// How many heuristics contributed to the score.
///
/// This is the exact count — the reason list is never capped or truncated, so
/// indices `0 .. count` are always in range.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_reason_count(handle: *const dgaard_verdict) -> usize {
    // SAFETY: forwarded contract.
    unsafe { borrow(handle) }.map_or(0, |verdict| verdict.reasons.len())
}

/// Tag of the score reason at `index`.
///
/// `DGAARD_REASON_NONE` when `index` is out of range,
/// `DGAARD_REASON_ERROR` for a NULL handle.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_reason_at(
    handle: *const dgaard_verdict,
    index: usize,
) -> dgaard_reason {
    // SAFETY: forwarded contract.
    match unsafe { borrow(handle) } {
        Some(verdict) => verdict
            .reasons
            .get(index)
            .map_or(dgaard_reason::DGAARD_REASON_NONE, |reason| reason.tag),
        None => dgaard_reason::DGAARD_REASON_ERROR,
    }
}

/// Numeric payload of the score reason at `index`, or NaN when it has none.
///
/// # Safety
///
/// See `dgaard_verdict_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_reason_number_at(
    handle: *const dgaard_verdict,
    index: usize,
) -> f64 {
    // SAFETY: forwarded contract.
    unsafe { borrow(handle) }
        .and_then(|verdict| verdict.reasons.get(index))
        .map_or(f64::NAN, |reason| reason.number)
}

/// Text payload of the score reason at `index`, under the buffer convention
/// described on `dgaard_verdict_block_text`.
///
/// # Safety
///
/// See `dgaard_verdict_free`. When non-NULL, `buffer` must point to at least
/// `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_reason_text_at(
    handle: *const dgaard_verdict,
    index: usize,
    buffer: *mut c_char,
    capacity: usize,
) -> usize {
    // SAFETY: forwarded contract.
    let text = unsafe { borrow(handle) }
        .and_then(|verdict| verdict.reasons.get(index))
        .and_then(|reason| reason.text.as_deref());

    // SAFETY: forwarded buffer contract.
    unsafe { write_c_string(text.unwrap_or(""), buffer, capacity) }
}

/// The address carried by `LOCAL_RESOLVE`, `INTERNAL_REDIRECT`, `RESPOND`,
/// `REDIRECT` and `OVERRIDE`, formatted as text.
///
/// Returns `0` for every other action, under the buffer convention described
/// on `dgaard_verdict_block_text`. IPv6 is written unbracketed, so a 46-byte
/// buffer always suffices.
///
/// # Safety
///
/// See `dgaard_verdict_free`. When non-NULL, `buffer` must point to at least
/// `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_verdict_address(
    handle: *const dgaard_verdict,
    buffer: *mut c_char,
    capacity: usize,
) -> usize {
    // SAFETY: forwarded contract.
    let address = unsafe { borrow(handle) }
        .and_then(|verdict| verdict.address.as_deref())
        .unwrap_or("");

    // SAFETY: forwarded buffer contract.
    unsafe { write_c_string(address, buffer, capacity) }
}
