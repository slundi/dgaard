//! Engine handle: construction, classification and the cheap predicates.

use std::os::raw::c_char;
use std::path::Path;

// Absolute paths throughout: the opaque handle below is deliberately named
// `dgaard_engine` for the C header, which shadows the crate of the same name.
use ::dgaard_engine::config::Config;
use ::dgaard_engine::resolve::{
    check_dga_heuristics, check_qclass, check_qtype, compute_score, is_illegal_idn,
    is_structure_invalid,
};
use ::dgaard_engine::{FilterEngine, resolve_with_score};

use crate::buffer::borrow_str;
use crate::error::{clear_error, set_error};
use crate::guard;
use crate::tags::{FlatReason, dgaard_reason};
use crate::verdict::dgaard_verdict;

/// Seed for the blocklist hash tables.
///
/// Deliberately not part of the ABI: it only has to be stable for the life of
/// one engine, and no hash ever crosses the boundary.
const HASH_SEED: u64 = 0;

/// Opaque handle to a configured filtering engine.
///
/// Immutable once built, and safe to share between threads: a single handle
/// can serve every worker in a thread pool. Free it with
/// `dgaard_engine_free` once no thread can still reach it.
pub struct dgaard_engine {
    config: Config,
    filter: FilterEngine,
}

// The documentation above promises the handle is shareable. Make the compiler
// prove it instead of taking the claim on trust.
const _: () = {
    const fn assert_shareable<T: Sync + Send>() {}
    assert_shareable::<dgaard_engine>();
};

impl dgaard_engine {
    fn into_handle(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }
}

/// Borrow an engine handle, recording an error for a NULL pointer.
///
/// # Safety
///
/// `handle`, when non-NULL, must come from a `dgaard_engine_new_*` call and
/// must not have been freed.
unsafe fn borrow<'a>(handle: *const dgaard_engine) -> Option<&'a dgaard_engine> {
    if handle.is_null() {
        set_error("null engine handle");
        return None;
    }
    // SAFETY: delegated to the caller's contract above.
    Some(unsafe { &*handle })
}

/// Borrow an engine and a domain together — the preamble every query-taking
/// entry point shares.
///
/// # Safety
///
/// See `borrow`; `domain` must be NUL-terminated or NULL.
unsafe fn borrow_query<'a>(
    handle: *const dgaard_engine,
    domain: *const c_char,
) -> Option<(&'a dgaard_engine, &'a str)> {
    // SAFETY: forwarded contract.
    let engine = unsafe { borrow(handle) }?;

    // SAFETY: forwarded contract.
    match unsafe { borrow_str(domain) } {
        Some(domain) => Some((engine, domain)),
        None => {
            set_error("domain must be a non-NULL, NUL-terminated UTF-8 string");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Build an engine that runs the heuristics only.
///
/// Uses the default configuration with **no lists loaded**: no blacklists, no
/// whitelists, no NRD list, no ASN or GeoIP data. It touches the filesystem
/// not at all, which makes it the right choice for embedding DGA, structure,
/// IDN and query-type checks without deploying list files.
///
/// Returns NULL on failure; see `dgaard_last_error`.
#[unsafe(no_mangle)]
pub extern "C" fn dgaard_engine_new_heuristics() -> *mut dgaard_engine {
    guard(std::ptr::null_mut(), || {
        clear_error();
        dgaard_engine {
            config: Config::default(),
            filter: FilterEngine::empty(),
        }
        .into_handle()
    })
}

/// Build a fully configured engine from a TOML file.
///
/// Every list the configuration names is read from disk, exactly as the
/// `dgaard` daemon does at startup. Returns NULL if the path is unreadable or
/// the TOML is invalid; see `dgaard_last_error` for which.
///
/// # Safety
///
/// `config_path` must be a NUL-terminated UTF-8 string, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_engine_new_from_file(
    config_path: *const c_char,
) -> *mut dgaard_engine {
    guard(std::ptr::null_mut(), || {
        clear_error();

        // SAFETY: forwarded contract.
        let Some(path) = (unsafe { borrow_str(config_path) }) else {
            set_error("config_path must be a non-NULL, NUL-terminated UTF-8 string");
            return std::ptr::null_mut();
        };

        match Config::load(Path::new(path)) {
            Ok(config) => build(config),
            Err(error) => {
                set_error(format!("{path}: {error}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// Build a fully configured engine from TOML held in memory.
///
/// Identical to `dgaard_engine_new_from_file` except that the configuration
/// text is supplied directly — useful when it comes from a database, an
/// embedded resource or a control plane rather than a file. Any list paths it
/// names are still read from disk.
///
/// Returns NULL on a parse error; see `dgaard_last_error`.
///
/// # Safety
///
/// `config_toml` must be a NUL-terminated UTF-8 string, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_engine_new_from_toml(
    config_toml: *const c_char,
) -> *mut dgaard_engine {
    guard(std::ptr::null_mut(), || {
        clear_error();

        // SAFETY: forwarded contract.
        let Some(text) = (unsafe { borrow_str(config_toml) }) else {
            set_error("config_toml must be a non-NULL, NUL-terminated UTF-8 string");
            return std::ptr::null_mut();
        };

        match Config::parse(text) {
            Ok(config) => build(config),
            Err(error) => {
                set_error(error.to_string());
                std::ptr::null_mut()
            }
        }
    })
}

fn build(config: Config) -> *mut dgaard_engine {
    let filter = FilterEngine::build_from_files(&config, HASH_SEED);
    dgaard_engine { config, filter }.into_handle()
}

/// Release an engine handle. Passing NULL is a no-op.
///
/// Verdicts outlive the engine that produced them — they own their payloads —
/// so the two can be freed in either order.
///
/// # Safety
///
/// `handle` must come from a `dgaard_engine_new_*` call, must not be freed
/// twice, and must not be in use by another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_engine_free(handle: *mut dgaard_engine) {
    if !handle.is_null() {
        // SAFETY: the caller guarantees sole ownership of a handle this
        // library allocated with `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Run `domain` through the full filter pipeline.
///
/// Returns a verdict handle the caller must release with
/// `dgaard_verdict_free`, or NULL on failure — a NULL handle is the *only*
/// error signal, so a bad pointer can never be mistaken for a clean verdict.
///
/// # Safety
///
/// `handle` must be a live engine handle and `domain` a NUL-terminated UTF-8
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_classify(
    handle: *const dgaard_engine,
    domain: *const c_char,
) -> *mut dgaard_verdict {
    guard(std::ptr::null_mut(), || {
        clear_error();

        // SAFETY: forwarded contract.
        let Some((engine, domain)) = (unsafe { borrow_query(handle, domain) }) else {
            return std::ptr::null_mut();
        };

        let result = resolve_with_score(domain, &engine.filter, &engine.config);
        dgaard_verdict::from_result(&result).into_handle()
    })
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// Shared shape for the boolean predicates: `1` true, `0` false, `-1` error.
///
/// # Safety
///
/// See `dgaard_classify`.
unsafe fn predicate(
    handle: *const dgaard_engine,
    domain: *const c_char,
    test: impl FnOnce(&dgaard_engine, &str) -> bool,
) -> i32 {
    guard(-1, || {
        clear_error();

        // SAFETY: forwarded contract.
        match unsafe { borrow_query(handle, domain) } {
            Some((engine, domain)) => i32::from(test(engine, domain)),
            None => -1,
        }
    })
}

/// Does the domain trip any DGA heuristic — entropy, repetition, consonant
/// ratio or n-gram?
///
/// Returns `1`, `0`, or `-1` on error. This is the DGA stage alone; it
/// consults no blocklist.
///
/// # Safety
///
/// See `dgaard_classify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_is_dga(handle: *const dgaard_engine, domain: *const c_char) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        predicate(handle, domain, |engine, domain| {
            check_dga_heuristics(domain, &engine.config).is_some()
        })
    }
}

/// Does the domain contain Punycode or non-ASCII labels, with
/// `server.block_idn` enabled?
///
/// Returns `1`, `0`, or `-1` on error.
///
/// # Safety
///
/// See `dgaard_classify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_is_illegal_idn(
    handle: *const dgaard_engine,
    domain: *const c_char,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        predicate(handle, domain, |engine, domain| {
            is_illegal_idn(domain, &engine.config)
        })
    }
}

/// Does the domain exceed the configured structural limits — subdomain depth
/// or total length?
///
/// Returns `1`, `0`, or `-1` on error.
///
/// # Safety
///
/// See `dgaard_classify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_is_structure_invalid(
    handle: *const dgaard_engine,
    domain: *const c_char,
) -> i32 {
    // SAFETY: forwarded contract.
    unsafe {
        predicate(handle, domain, |engine, domain| {
            is_structure_invalid(domain, &engine.config)
        })
    }
}

/// Suspicion score for a domain, `0`–`255`, without building a verdict.
///
/// Returns `-1` on error. Use `dgaard_classify` when the contributing reasons
/// matter; this is the cheap path for callers that only need the number.
///
/// # Safety
///
/// See `dgaard_classify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_score(handle: *const dgaard_engine, domain: *const c_char) -> i32 {
    guard(-1, || {
        clear_error();

        // SAFETY: forwarded contract.
        match unsafe { borrow_query(handle, domain) } {
            Some((engine, domain)) => {
                i32::from(compute_score(domain, &engine.filter, &engine.config).total)
            }
            None => -1,
        }
    })
}

/// Is this DNS record type forbidden by the QType Warden policy?
///
/// Returns `DGAARD_REASON_FORBIDDEN_QTYPE` when blocked,
/// `DGAARD_REASON_NONE` when allowed, `DGAARD_REASON_ERROR` on a NULL handle.
///
/// # Safety
///
/// `handle` must be a live engine handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_check_qtype(
    handle: *const dgaard_engine,
    qtype: u16,
) -> dgaard_reason {
    guard(dgaard_reason::DGAARD_REASON_ERROR, || {
        clear_error();

        // SAFETY: forwarded contract.
        match unsafe { borrow(handle) } {
            Some(engine) => check_qtype(qtype, &engine.config)
                .map_or(dgaard_reason::DGAARD_REASON_NONE, |reason| {
                    FlatReason::from_reason(&reason).tag
                }),
            None => dgaard_reason::DGAARD_REASON_ERROR,
        }
    })
}

/// Is this DNS query class forbidden by policy?
///
/// Returns `DGAARD_REASON_CHAOS_CLASS` when blocked, `DGAARD_REASON_NONE`
/// when allowed, `DGAARD_REASON_ERROR` on a NULL handle.
///
/// # Safety
///
/// `handle` must be a live engine handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dgaard_check_qclass(
    handle: *const dgaard_engine,
    qclass: u16,
) -> dgaard_reason {
    guard(dgaard_reason::DGAARD_REASON_ERROR, || {
        clear_error();

        // SAFETY: forwarded contract.
        match unsafe { borrow(handle) } {
            Some(engine) => check_qclass(qclass, &engine.config)
                .map_or(dgaard_reason::DGAARD_REASON_NONE, |reason| {
                    FlatReason::from_reason(&reason).tag
                }),
            None => dgaard_reason::DGAARD_REASON_ERROR,
        }
    })
}
