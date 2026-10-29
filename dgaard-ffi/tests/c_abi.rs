//! Exercises the C ABI the way a C caller does: opaque handles, raw pointers,
//! caller-supplied buffers and the documented error signals.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use dgaard::*;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Minimal configuration with every on-disk source removed, so a test never
/// reads `/etc/dgaard/lists` from the developer's machine.
const HERMETIC_TOML: &str = r#"
[sources]
blacklists = []
whitelists = []
nrd_list_path = ""
host_index_path = ""
browser_rules_path = ""
"#;

/// Read back a value written through the caller-buffer convention.
///
/// Mirrors what C does: call once to size, allocate, call again to fill.
fn read_text(mut accessor: impl FnMut(*mut c_char, usize) -> usize) -> String {
    let needed = accessor(ptr::null_mut(), 0);
    // 0x7f is neither NUL nor part of any expected output, so a missing
    // terminator shows up as garbage instead of passing silently.
    let mut storage: Vec<c_char> = vec![0x7f; needed + 1];
    let again = accessor(storage.as_mut_ptr(), storage.len());
    assert_eq!(
        again, needed,
        "the reported length must be stable across calls"
    );

    read_back(&storage)
}

/// Read a NUL-terminated C string back out of a buffer.
///
/// Reinterprets the slice rather than casting element by element: `c_char` is
/// `i8` on x86_64 but `u8` on aarch64, where a per-byte `as u8` is a no-op
/// cast that `clippy::unnecessary_cast` rejects.
fn read_back(storage: &[c_char]) -> String {
    // SAFETY: `c_char` is a one-byte integer on every supported target, so
    // `*const c_char` and `*const u8` describe the same bytes. `.cast()`
    // rather than `as`: on aarch64 the two types are literally the same and
    // an `as` cast would be flagged as redundant.
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

fn last_error() -> String {
    read_text(|buffer, capacity| unsafe { dgaard_last_error(buffer, capacity) })
}

fn block_text(verdict: *const dgaard_verdict) -> String {
    read_text(|buffer, capacity| unsafe { dgaard_verdict_block_text(verdict, buffer, capacity) })
}

fn address(verdict: *const dgaard_verdict) -> String {
    read_text(|buffer, capacity| unsafe { dgaard_verdict_address(verdict, buffer, capacity) })
}

/// RAII wrapper so a failing assertion cannot leak a handle.
struct Engine(*mut dgaard_engine);

impl Engine {
    fn heuristics() -> Self {
        let handle = dgaard_engine_new_heuristics();
        assert!(!handle.is_null(), "{}", last_error());
        Self(handle)
    }

    fn from_toml(toml: &str) -> Self {
        let text = CString::new(toml).unwrap();
        let handle = unsafe { dgaard_engine_new_from_toml(text.as_ptr()) };
        assert!(!handle.is_null(), "{}", last_error());
        Self(handle)
    }

    fn classify(&self, domain: &str) -> Verdict {
        let domain = CString::new(domain).unwrap();
        let handle = unsafe { dgaard_classify(self.0, domain.as_ptr()) };
        assert!(!handle.is_null(), "{}", last_error());
        Verdict(handle)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { dgaard_engine_free(self.0) };
    }
}

struct Verdict(*mut dgaard_verdict);

impl Verdict {
    fn action(&self) -> dgaard_action {
        unsafe { dgaard_verdict_action(self.0) }
    }

    fn reason(&self) -> dgaard_reason {
        unsafe { dgaard_verdict_block_reason(self.0) }
    }

    fn score(&self) -> u8 {
        unsafe { dgaard_verdict_score(self.0) }
    }

    fn reason_tags(&self) -> Vec<dgaard_reason> {
        let count = unsafe { dgaard_verdict_reason_count(self.0) };
        (0..count)
            .map(|index| unsafe { dgaard_verdict_reason_at(self.0, index) })
            .collect()
    }
}

impl Drop for Verdict {
    fn drop(&mut self) {
        unsafe { dgaard_verdict_free(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn heuristics_engine_needs_no_files() {
    let engine = Engine::heuristics();
    let verdict = engine.classify("example.com");
    assert_eq!(
        verdict.action(),
        dgaard_action::DGAARD_ACTION_PROXY_UPSTREAM
    );
}

#[test]
fn engine_builds_from_inline_toml() {
    let engine = Engine::from_toml(HERMETIC_TOML);
    let verdict = engine.classify("example.com");
    assert_eq!(
        verdict.action(),
        dgaard_action::DGAARD_ACTION_PROXY_UPSTREAM
    );
}

#[test]
fn engine_builds_from_a_config_file() {
    let directory = std::env::temp_dir().join("dgaard-ffi-config-test");
    std::fs::create_dir_all(&directory).unwrap();
    let config = directory.join("config.toml");
    std::fs::write(&config, HERMETIC_TOML).unwrap();

    let path = CString::new(config.to_str().unwrap()).unwrap();
    let handle = unsafe { dgaard_engine_new_from_file(path.as_ptr()) };
    assert!(!handle.is_null(), "{}", last_error());

    let domain = CString::new("0000000000000000001.com").unwrap();
    let verdict = unsafe { dgaard_classify(handle, domain.as_ptr()) };
    assert!(!verdict.is_null());
    assert_eq!(
        unsafe { dgaard_verdict_action(verdict) },
        dgaard_action::DGAARD_ACTION_BLOCK
    );

    unsafe { dgaard_verdict_free(verdict) };
    unsafe { dgaard_engine_free(handle) };
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn invalid_toml_is_an_error_not_a_default_engine() {
    let broken = CString::new("[server\nthis is not toml").unwrap();
    let handle = unsafe { dgaard_engine_new_from_toml(broken.as_ptr()) };
    assert!(
        handle.is_null(),
        "a broken config must never yield a usable engine"
    );
    assert!(!last_error().is_empty(), "the failure must be explained");
}

#[test]
fn missing_config_file_names_the_path_it_tried() {
    let path = CString::new("/nonexistent/dgaard/config.toml").unwrap();
    let handle = unsafe { dgaard_engine_new_from_file(path.as_ptr()) };
    assert!(handle.is_null());
    assert!(
        last_error().contains("/nonexistent/dgaard/config.toml"),
        "error should name the path: {}",
        last_error()
    );
}

#[test]
fn null_config_pointers_are_rejected() {
    assert!(unsafe { dgaard_engine_new_from_file(ptr::null()) }.is_null());
    assert!(!last_error().is_empty());
    assert!(unsafe { dgaard_engine_new_from_toml(ptr::null()) }.is_null());
    assert!(!last_error().is_empty());
}

#[test]
fn freeing_null_handles_is_a_no_op() {
    unsafe { dgaard_engine_free(ptr::null_mut()) };
    unsafe { dgaard_verdict_free(ptr::null_mut()) };
}

#[test]
fn a_verdict_outlives_the_engine_that_made_it() {
    let verdict = {
        let engine = Engine::heuristics();
        engine.classify("0000000000000000001.com")
    };
    // The engine is gone; the verdict still owns everything it reports.
    assert_eq!(verdict.action(), dgaard_action::DGAARD_ACTION_BLOCK);
    assert_ne!(verdict.reason(), dgaard_reason::DGAARD_REASON_NONE);
}

#[test]
fn one_engine_serves_many_threads() {
    let engine = Engine::heuristics();
    let shared = engine.0 as usize;

    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                let handle = shared as *const dgaard_engine;
                let domain = CString::new("0000000000000000001.com").unwrap();
                let verdict = unsafe { dgaard_classify(handle, domain.as_ptr()) };
                assert!(!verdict.is_null());
                let action = unsafe { dgaard_verdict_action(verdict) };
                unsafe { dgaard_verdict_free(verdict) };
                action
            })
        })
        .collect();

    for worker in workers {
        assert_eq!(worker.join().unwrap(), dgaard_action::DGAARD_ACTION_BLOCK);
    }
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

#[test]
fn a_counter_padded_label_is_blocked_with_its_length() {
    let engine = Engine::heuristics();
    let verdict = engine.classify("0000000000000000001.com");

    assert_eq!(verdict.action(), dgaard_action::DGAARD_ACTION_BLOCK);
    assert_eq!(verdict.reason(), dgaard_reason::DGAARD_REASON_LOW_ENTROPY);
    assert_eq!(
        unsafe { dgaard_verdict_block_number(verdict.0) },
        19.0,
        "the numeric payload is the offending label length"
    );
    assert!(
        block_text(verdict.0).is_empty(),
        "this reason carries no text"
    );
}

#[test]
fn a_blocklist_hit_carries_the_source_name_as_text() {
    let directory = std::env::temp_dir().join("dgaard-ffi-blocklist-test");
    std::fs::create_dir_all(&directory).unwrap();
    let list = directory.join("tracker-list.txt");
    std::fs::write(&list, "ads.example.com\n").unwrap();

    let engine = Engine::from_toml(&format!(
        r#"
[sources]
blacklists = ["{}"]
whitelists = []
nrd_list_path = ""
host_index_path = ""
browser_rules_path = ""
"#,
        list.display()
    ));

    let verdict = engine.classify("ads.example.com");
    assert_eq!(verdict.action(), dgaard_action::DGAARD_ACTION_BLOCK);
    assert_eq!(
        verdict.reason(),
        dgaard_reason::DGAARD_REASON_STATIC_BLACKLIST
    );
    // The engine labels the stage, not the file: `BlockReason::StaticBlacklist`
    // is built with a literal in `resolve_with_score`, so the list name never
    // reaches the verdict. Pinned here so the day the engine starts carrying
    // the real filename, this test says so instead of silently passing.
    assert_eq!(block_text(verdict.0), "blocklist");
    assert!(unsafe { dgaard_verdict_block_number(verdict.0) }.is_nan());

    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn an_override_reports_its_address() {
    let engine = Engine::from_toml(&format!(
        "{HERMETIC_TOML}\n[[overrides]]\ndomain = \"nas.lan\"\nto = \"10.0.0.7\"\n"
    ));

    let verdict = engine.classify("nas.lan");
    assert_eq!(verdict.action(), dgaard_action::DGAARD_ACTION_OVERRIDE);
    assert_eq!(address(verdict.0), "10.0.0.7");
    assert_eq!(verdict.reason(), dgaard_reason::DGAARD_REASON_NONE);
}

#[test]
fn actions_without_an_address_report_an_empty_one() {
    let engine = Engine::heuristics();
    let verdict = engine.classify("example.com");
    assert!(address(verdict.0).is_empty());
}

#[test]
fn score_reasons_are_exactly_indexable() {
    let engine = Engine::heuristics();
    let verdict = engine.classify("0000000000000000001.com");

    let count = unsafe { dgaard_verdict_reason_count(verdict.0) };
    assert!(count > 0, "a blocked domain should carry score reasons");
    assert!(verdict.score() > 0);

    // Every index below the reported count is populated — the list is the
    // exact set of contributing heuristics, never a truncated window.
    for tag in verdict.reason_tags() {
        assert_ne!(tag, dgaard_reason::DGAARD_REASON_NONE);
        assert_ne!(tag, dgaard_reason::DGAARD_REASON_ERROR);
    }

    // One past the end is NONE, not a read off the end of a fixed array.
    assert_eq!(
        unsafe { dgaard_verdict_reason_at(verdict.0, count) },
        dgaard_reason::DGAARD_REASON_NONE
    );
    assert!(unsafe { dgaard_verdict_reason_number_at(verdict.0, count) }.is_nan());
    assert_eq!(
        read_text(|buffer, capacity| unsafe {
            dgaard_verdict_reason_text_at(verdict.0, count, buffer, capacity)
        }),
        ""
    );
}

#[test]
fn a_clean_domain_scores_zero_with_no_reasons() {
    let engine = Engine::heuristics();
    let verdict = engine.classify("example.com");

    assert_eq!(verdict.score(), 0);
    assert_eq!(unsafe { dgaard_verdict_reason_count(verdict.0) }, 0);
    assert_eq!(verdict.reason(), dgaard_reason::DGAARD_REASON_NONE);
    assert!(unsafe { dgaard_verdict_block_number(verdict.0) }.is_nan());
}

#[test]
fn a_truncating_buffer_still_reports_the_full_length() {
    let engine = Engine::from_toml(&format!(
        "{HERMETIC_TOML}\n[[overrides]]\ndomain = \"nas.lan\"\nto = \"10.0.0.7\"\n"
    ));
    let verdict = engine.classify("nas.lan");

    let mut storage: [c_char; 4] = [0x7f; 4];
    let needed = unsafe { dgaard_verdict_address(verdict.0, storage.as_mut_ptr(), storage.len()) };
    assert_eq!(needed, 8, "snprintf convention: report what the text needs");
    assert_eq!(read_back(&storage), "10.");
}

// ---------------------------------------------------------------------------
// Failure is never a verdict
// ---------------------------------------------------------------------------

#[test]
fn a_null_engine_yields_no_verdict() {
    let domain = CString::new("example.com").unwrap();
    assert!(unsafe { dgaard_classify(ptr::null(), domain.as_ptr()) }.is_null());
    assert_eq!(last_error(), "null engine handle");
}

#[test]
fn a_null_domain_yields_no_verdict() {
    let engine = Engine::heuristics();
    assert!(unsafe { dgaard_classify(engine.0, ptr::null()) }.is_null());
    assert!(last_error().contains("domain"));
}

#[test]
fn a_non_utf8_domain_is_rejected_rather_than_mangled() {
    let engine = Engine::heuristics();
    let bytes = [b'e', b'v', 0xff, 0xfe, b'.', b'c', b'o', b'm', 0];
    assert!(unsafe { dgaard_classify(engine.0, bytes.as_ptr().cast()) }.is_null());
    assert!(!last_error().is_empty());
}

#[test]
fn accessors_on_a_null_verdict_return_the_error_discriminants() {
    assert_eq!(
        unsafe { dgaard_verdict_action(ptr::null()) },
        dgaard_action::DGAARD_ACTION_ERROR
    );
    assert_eq!(
        unsafe { dgaard_verdict_block_reason(ptr::null()) },
        dgaard_reason::DGAARD_REASON_ERROR
    );
    assert_eq!(
        unsafe { dgaard_verdict_reason_at(ptr::null(), 0) },
        dgaard_reason::DGAARD_REASON_ERROR
    );
    assert!(unsafe { dgaard_verdict_block_number(ptr::null()) }.is_nan());
    assert_eq!(unsafe { dgaard_verdict_score(ptr::null()) }, 0);
    assert_eq!(unsafe { dgaard_verdict_reason_count(ptr::null()) }, 0);
}

#[test]
fn the_error_discriminants_are_unreachable_from_a_real_verdict() {
    let engine = Engine::heuristics();
    for domain in [
        "example.com",
        "0000000000000000001.com",
        "a.b.c.d.e.f.g.h.i.j.k.example.com",
    ] {
        let verdict = engine.classify(domain);
        assert_ne!(verdict.action(), dgaard_action::DGAARD_ACTION_ERROR);
        assert_ne!(verdict.reason(), dgaard_reason::DGAARD_REASON_ERROR);
    }
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

#[test]
fn predicates_answer_one_zero_or_minus_one() {
    let engine = Engine::heuristics();
    let dga = CString::new("0000000000000000001.com").unwrap();
    let clean = CString::new("example.com").unwrap();
    let deep = CString::new("a.b.c.d.e.f.g.h.i.j.k.example.com").unwrap();
    let punycode = CString::new("xn--pple-43d.com").unwrap();

    assert_eq!(unsafe { dgaard_is_dga(engine.0, dga.as_ptr()) }, 1);
    assert_eq!(unsafe { dgaard_is_dga(engine.0, clean.as_ptr()) }, 0);
    assert_eq!(unsafe { dgaard_is_dga(ptr::null(), dga.as_ptr()) }, -1);
    assert_eq!(unsafe { dgaard_is_dga(engine.0, ptr::null()) }, -1);

    assert_eq!(
        unsafe { dgaard_is_structure_invalid(engine.0, deep.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { dgaard_is_structure_invalid(engine.0, clean.as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { dgaard_is_structure_invalid(ptr::null(), clean.as_ptr()) },
        -1
    );

    assert_eq!(
        unsafe { dgaard_is_illegal_idn(engine.0, punycode.as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { dgaard_is_illegal_idn(engine.0, clean.as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { dgaard_is_illegal_idn(ptr::null(), clean.as_ptr()) },
        -1
    );
}

#[test]
fn score_matches_the_verdict_it_would_have_produced() {
    let engine = Engine::heuristics();
    let domain = CString::new("0000000000000000001.com").unwrap();

    let direct = unsafe { dgaard_score(engine.0, domain.as_ptr()) };
    let verdict = engine.classify("0000000000000000001.com");

    assert!(direct > 0);
    assert_eq!(direct, i32::from(verdict.score()));
    assert_eq!(unsafe { dgaard_score(ptr::null(), domain.as_ptr()) }, -1);
    assert_eq!(unsafe { dgaard_score(engine.0, ptr::null()) }, -1);
}

#[test]
fn qtype_and_qclass_policy_is_queryable() {
    let engine = Engine::heuristics();

    // ANY (255) is blocked by the default warden policy; A (1) is not.
    assert_eq!(
        unsafe { dgaard_check_qtype(engine.0, 255) },
        dgaard_reason::DGAARD_REASON_FORBIDDEN_QTYPE
    );
    assert_eq!(
        unsafe { dgaard_check_qtype(engine.0, 1) },
        dgaard_reason::DGAARD_REASON_NONE
    );
    assert_eq!(
        unsafe { dgaard_check_qtype(ptr::null(), 255) },
        dgaard_reason::DGAARD_REASON_ERROR
    );

    // CHAOS (3) is blocked; IN (1) is not.
    assert_eq!(
        unsafe { dgaard_check_qclass(engine.0, 3) },
        dgaard_reason::DGAARD_REASON_CHAOS_CLASS
    );
    assert_eq!(
        unsafe { dgaard_check_qclass(engine.0, 1) },
        dgaard_reason::DGAARD_REASON_NONE
    );
    assert_eq!(
        unsafe { dgaard_check_qclass(ptr::null(), 3) },
        dgaard_reason::DGAARD_REASON_ERROR
    );
}

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

#[test]
fn version_and_abi_are_reported() {
    assert_eq!(dgaard_abi_version(), DGAARD_ABI_VERSION);
    let version = read_text(|buffer, capacity| unsafe { dgaard_version(buffer, capacity) });
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn a_successful_call_clears_a_stale_error() {
    let engine = Engine::heuristics();

    assert!(unsafe { dgaard_classify(engine.0, ptr::null()) }.is_null());
    assert!(!last_error().is_empty());

    let _verdict = engine.classify("example.com");
    assert!(
        last_error().is_empty(),
        "a success must not leave the previous failure behind"
    );
}

#[test]
fn clear_error_is_callable_from_c() {
    let engine = Engine::heuristics();
    assert!(unsafe { dgaard_classify(engine.0, ptr::null()) }.is_null());
    dgaard_clear_error();
    assert!(last_error().is_empty());
}
