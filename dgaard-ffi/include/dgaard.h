/*
 * dgaard — C ABI for the dgaard domain filtering engine.
 *
 * GENERATED FILE — do not edit by hand.
 * Regenerate with `just ffi-header` after changing dgaard-ffi/src.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DGAARD_H
#define DGAARD_H

#include <stdint.h>
#include <stddef.h>

/**
 * Version of the C ABI, bumped whenever an enum variant is appended or a
 * signature changes. Compare against `dgaard_abi_version` at startup to
 * catch a header that no longer matches the shared library.
 */
#define DGAARD_ABI_VERSION 1

/**
 * Which heuristic produced a block or a score contribution.
 */
enum dgaard_reason
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
    /**
     * The call failed. Inspect `dgaard_last_error`.
     */
    DGAARD_REASON_ERROR = -1,
    /**
     * No reason — the verdict was not a block, or the index was out of range.
     */
    DGAARD_REASON_NONE = 0,
    /**
     * Hit a static blacklist.
     *
     * Text payload: a label for the stage that matched. The engine does not
     * currently thread the source filename through to the verdict, so this
     * is the literal `"blocklist"` rather than, say, `"oisd.txt"`. Treat it
     * as a coarse origin tag, not as a list identifier.
     */
    DGAARD_REASON_STATIC_BLACKLIST = 1,
    /**
     * Hit an ABP-style or wildcard rule.
     *
     * Text payload: a stage label, with the same caveat as
     * `DGAARD_REASON_STATIC_BLACKLIST` — the matched pattern itself is not
     * carried out of the engine.
     */
    DGAARD_REASON_ABP_RULE = 2,
    /**
     * High Shannon entropy. Number payload: the entropy, in bits per character.
     */
    DGAARD_REASON_HIGH_ENTROPY = 3,
    /**
     * Repetitive or counter-padded label. Number payload: the label length.
     */
    DGAARD_REASON_LOW_ENTROPY = 4,
    /**
     * Failed consonant-ratio or n-gram analysis.
     */
    DGAARD_REASON_LEXICAL_ANALYSIS = 5,
    /**
     * Parental-control keyword hit. Text payload: the keyword.
     */
    DGAARD_REASON_BANNED_KEYWORD = 6,
    /**
     * Failed a structural check (depth, length, …).
     */
    DGAARD_REASON_INVALID_STRUCTURE = 7,
    /**
     * Suspicious IDN or Punycode homograph.
     */
    DGAARD_REASON_SUSPICIOUS_IDN = 8,
    /**
     * Listed as a newly registered domain.
     */
    DGAARD_REASON_NRD_LIST = 9,
    /**
     * Cumulative suspicion score crossed the blocking threshold.
     */
    DGAARD_REASON_SUSPICIOUS = 10,
    /**
     * The TLD is excluded by configuration.
     */
    DGAARD_REASON_TLD_EXCLUDED = 11,
    /**
     * A CNAME in the chain is blacklisted (cloaking).
     */
    DGAARD_REASON_CNAME_CLOAKING = 12,
    /**
     * Query type forbidden by policy. Number payload: the RFC 1035 type code.
     */
    DGAARD_REASON_FORBIDDEN_QTYPE = 13,
    /**
     * Upstream answer maps a public name to a private address.
     */
    DGAARD_REASON_DNS_REBINDING = 14,
    /**
     * Abnormally low response TTL. Number payload: the TTL, in seconds.
     */
    DGAARD_REASON_LOW_TTL = 15,
    /**
     * Resolves into a blocked ASN range.
     */
    DGAARD_REASON_ASN_BLOCKED = 16,
    /**
     * Resolves into a suspicious country. Text payload: the ISO 3166-1
     * alpha-2 code.
     */
    DGAARD_REASON_GEOIP_SUSPICIOUS = 17,
    /**
     * Special-use or internal TLD that must not be forwarded (RFC 6761/6762).
     */
    DGAARD_REASON_SPECIAL_USE_DOMAIN = 18,
    /**
     * Reverse lookup for a private address range.
     */
    DGAARD_REASON_PTR_LEAK = 19,
    /**
     * DNS CHAOS-class query.
     */
    DGAARD_REASON_CHAOS_CLASS = 20,
    /**
     * Hit a user-defined custom flag list. Number payload: the bit index (16–31).
     */
    DGAARD_REASON_CUSTOM_FLAG = 21,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum dgaard_reason dgaard_reason;
#else
typedef int32_t dgaard_reason;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Action the caller should take for a domain.
 */
enum dgaard_action
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
    /**
     * The call failed. Inspect `dgaard_last_error`. Never produced by a
     * successful classification, so it can never be confused with a verdict.
     */
    DGAARD_ACTION_ERROR = -1,
    /**
     * Forward the query to the configured upstream resolver.
     */
    DGAARD_ACTION_PROXY_UPSTREAM = 0,
    /**
     * Explicitly allowed (whitelist hit); forward it.
     */
    DGAARD_ACTION_ALLOW = 1,
    /**
     * Blocked. `dgaard_verdict_block_reason` says why.
     */
    DGAARD_ACTION_BLOCK = 2,
    /**
     * Discard the query without answering.
     */
    DGAARD_ACTION_DROP = 3,
    /**
     * Answer from the local cache. `dgaard_verdict_address` holds the IP.
     */
    DGAARD_ACTION_LOCAL_RESOLVE = 4,
    /**
     * Answer with an internal landing page. `dgaard_verdict_address` holds the IP.
     */
    DGAARD_ACTION_INTERNAL_REDIRECT = 5,
    /**
     * Answer immediately from the hot cache. `dgaard_verdict_address` holds the IP.
     */
    DGAARD_ACTION_RESPOND = 6,
    /**
     * Redirect to a local landing page. `dgaard_verdict_address` holds the IP.
     */
    DGAARD_ACTION_REDIRECT = 7,
    /**
     * Matched an inline config override; all filters were bypassed.
     * `dgaard_verdict_address` holds the IP.
     */
    DGAARD_ACTION_OVERRIDE = 8,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum dgaard_action dgaard_action;
#else
typedef int32_t dgaard_action;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Opaque handle to a configured filtering engine.
 *
 * Immutable once built, and safe to share between threads: a single handle
 * can serve every worker in a thread pool. Free it with
 * `dgaard_engine_free` once no thread can still reach it.
 */
typedef struct dgaard_engine dgaard_engine;

/**
 * Opaque handle to the outcome of a classification.
 *
 * Owned by the caller and freed with `dgaard_verdict_free`. Unlike the engine
 * handle it is *not* shared between threads: treat it as owned by whichever
 * thread called `dgaard_classify`.
 */
typedef struct dgaard_verdict dgaard_verdict;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * The ABI version this library was built with. See [`DGAARD_ABI_VERSION`].
 */
uint32_t dgaard_abi_version(void);

/**
 * Copy the `dgaard-ffi` crate version (e.g. `"0.2.0"`) into `buffer`.
 *
 * Returns the byte length excluding the terminator, under the convention
 * described on `dgaard_verdict_block_text`.
 *
 * # Safety
 *
 * When `buffer` is non-NULL it must point to at least `capacity` writable
 * bytes.
 */
size_t dgaard_version(char *buffer, size_t capacity);

/**
 * Build an engine that runs the heuristics only.
 *
 * Uses the default configuration with **no lists loaded**: no blacklists, no
 * whitelists, no NRD list, no ASN or GeoIP data. It touches the filesystem
 * not at all, which makes it the right choice for embedding DGA, structure,
 * IDN and query-type checks without deploying list files.
 *
 * Returns NULL on failure; see `dgaard_last_error`.
 */
dgaard_engine *dgaard_engine_new_heuristics(void);

/**
 * Build a fully configured engine from a TOML file.
 *
 * Every list the configuration names is read from disk, exactly as the
 * `dgaard` daemon does at startup. Returns NULL if the path is unreadable or
 * the TOML is invalid; see `dgaard_last_error` for which.
 *
 * # Safety
 *
 * `config_path` must be a NUL-terminated UTF-8 string, or NULL.
 */
dgaard_engine *dgaard_engine_new_from_file(const char *config_path);

/**
 * Build a fully configured engine from TOML held in memory.
 *
 * Identical to `dgaard_engine_new_from_file` except that the configuration
 * text is supplied directly — useful when it comes from a database, an
 * embedded resource or a control plane rather than a file. Any list paths it
 * names are still read from disk.
 *
 * Returns NULL on a parse error; see `dgaard_last_error`.
 *
 * # Safety
 *
 * `config_toml` must be a NUL-terminated UTF-8 string, or NULL.
 */
dgaard_engine *dgaard_engine_new_from_toml(const char *config_toml);

/**
 * Release an engine handle. Passing NULL is a no-op.
 *
 * Verdicts outlive the engine that produced them — they own their payloads —
 * so the two can be freed in either order.
 *
 * # Safety
 *
 * `handle` must come from a `dgaard_engine_new_*` call, must not be freed
 * twice, and must not be in use by another thread.
 */
void dgaard_engine_free(dgaard_engine *handle);

/**
 * Run `domain` through the full filter pipeline.
 *
 * Returns a verdict handle the caller must release with
 * `dgaard_verdict_free`, or NULL on failure — a NULL handle is the *only*
 * error signal, so a bad pointer can never be mistaken for a clean verdict.
 *
 * # Safety
 *
 * `handle` must be a live engine handle and `domain` a NUL-terminated UTF-8
 * string.
 */
dgaard_verdict *dgaard_classify(const dgaard_engine *handle, const char *domain);

/**
 * Does the domain trip any DGA heuristic — entropy, repetition, consonant
 * ratio or n-gram?
 *
 * Returns `1`, `0`, or `-1` on error. This is the DGA stage alone; it
 * consults no blocklist.
 *
 * # Safety
 *
 * See `dgaard_classify`.
 */
int32_t dgaard_is_dga(const dgaard_engine *handle, const char *domain);

/**
 * Does the domain contain Punycode or non-ASCII labels, with
 * `server.block_idn` enabled?
 *
 * Returns `1`, `0`, or `-1` on error.
 *
 * # Safety
 *
 * See `dgaard_classify`.
 */
int32_t dgaard_is_illegal_idn(const dgaard_engine *handle, const char *domain);

/**
 * Does the domain exceed the configured structural limits — subdomain depth
 * or total length?
 *
 * Returns `1`, `0`, or `-1` on error.
 *
 * # Safety
 *
 * See `dgaard_classify`.
 */
int32_t dgaard_is_structure_invalid(const dgaard_engine *handle, const char *domain);

/**
 * Suspicion score for a domain, `0`–`255`, without building a verdict.
 *
 * Returns `-1` on error. Use `dgaard_classify` when the contributing reasons
 * matter; this is the cheap path for callers that only need the number.
 *
 * # Safety
 *
 * See `dgaard_classify`.
 */
int32_t dgaard_score(const dgaard_engine *handle, const char *domain);

/**
 * Is this DNS record type forbidden by the QType Warden policy?
 *
 * Returns `DGAARD_REASON_FORBIDDEN_QTYPE` when blocked,
 * `DGAARD_REASON_NONE` when allowed, `DGAARD_REASON_ERROR` on a NULL handle.
 *
 * # Safety
 *
 * `handle` must be a live engine handle.
 */
dgaard_reason dgaard_check_qtype(const dgaard_engine *handle, uint16_t qtype);

/**
 * Is this DNS query class forbidden by policy?
 *
 * Returns `DGAARD_REASON_CHAOS_CLASS` when blocked, `DGAARD_REASON_NONE`
 * when allowed, `DGAARD_REASON_ERROR` on a NULL handle.
 *
 * # Safety
 *
 * `handle` must be a live engine handle.
 */
dgaard_reason dgaard_check_qclass(const dgaard_engine *handle, uint16_t qclass);

/**
 * Copy the calling thread's last error message into `buffer`.
 *
 * Returns the message length in bytes excluding the terminator, or `0` when
 * the thread has no pending error. Pass a NULL `buffer` to query the length
 * first; see `dgaard_version` for the same convention.
 *
 * The message describes the most recent *failed* call on this thread only.
 * Errors are never shared between threads.
 *
 * # Safety
 *
 * When `buffer` is non-NULL it must point to at least `capacity` writable
 * bytes.
 */
size_t dgaard_last_error(char *buffer, size_t capacity);

/**
 * Discard the calling thread's pending error message.
 */
void dgaard_clear_error(void);

/**
 * Release a verdict returned by `dgaard_classify`. Passing NULL is a no-op.
 *
 * # Safety
 *
 * `handle` must come from `dgaard_classify` and must not be freed twice.
 */
void dgaard_verdict_free(dgaard_verdict *handle);

/**
 * The action the caller should take.
 *
 * Returns `DGAARD_ACTION_ERROR` for a NULL handle — a value no successful
 * classification can produce.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
dgaard_action dgaard_verdict_action(const dgaard_verdict *handle);

/**
 * The reason the domain was blocked.
 *
 * `DGAARD_REASON_NONE` when the action is not `DGAARD_ACTION_BLOCK`,
 * `DGAARD_REASON_ERROR` for a NULL handle.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
dgaard_reason dgaard_verdict_block_reason(const dgaard_verdict *handle);

/**
 * Numeric payload of the block reason — entropy, TTL, query type, label
 * length or custom-flag bit, depending on the tag.
 *
 * Returns NaN when the reason carries no number, when the domain was not
 * blocked, or for a NULL handle. Test with `isnan()`.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
double dgaard_verdict_block_number(const dgaard_verdict *handle);

/**
 * Text payload of the block reason — the blocklist name, matched pattern,
 * keyword or country code, depending on the tag.
 *
 * Returns the byte length excluding the terminator, or `0` when the reason
 * carries no text. Pass a NULL `buffer` to ask for the required size; a
 * return value `>= capacity` means the text was truncated.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`. When non-NULL, `buffer` must point to at least
 * `capacity` writable bytes.
 */
size_t dgaard_verdict_block_text(const dgaard_verdict *handle, char *buffer, size_t capacity);

/**
 * Cumulative suspicion score, 0–255. Returns `0` for a NULL handle; use
 * `dgaard_verdict_action` to distinguish that from a genuinely clean domain.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
uint8_t dgaard_verdict_score(const dgaard_verdict *handle);

/**
 * How many heuristics contributed to the score.
 *
 * This is the exact count — the reason list is never capped or truncated, so
 * indices `0 .. count` are always in range.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
size_t dgaard_verdict_reason_count(const dgaard_verdict *handle);

/**
 * Tag of the score reason at `index`.
 *
 * `DGAARD_REASON_NONE` when `index` is out of range,
 * `DGAARD_REASON_ERROR` for a NULL handle.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
dgaard_reason dgaard_verdict_reason_at(const dgaard_verdict *handle, size_t index);

/**
 * Numeric payload of the score reason at `index`, or NaN when it has none.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`.
 */
double dgaard_verdict_reason_number_at(const dgaard_verdict *handle, size_t index);

/**
 * Text payload of the score reason at `index`, under the buffer convention
 * described on `dgaard_verdict_block_text`.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`. When non-NULL, `buffer` must point to at least
 * `capacity` writable bytes.
 */
size_t dgaard_verdict_reason_text_at(const dgaard_verdict *handle,
                                     size_t index,
                                     char *buffer,
                                     size_t capacity);

/**
 * The address carried by `LOCAL_RESOLVE`, `INTERNAL_REDIRECT`, `RESPOND`,
 * `REDIRECT` and `OVERRIDE`, formatted as text.
 *
 * Returns `0` for every other action, under the buffer convention described
 * on `dgaard_verdict_block_text`. IPv6 is written unbracketed, so a 46-byte
 * buffer always suffices.
 *
 * # Safety
 *
 * See `dgaard_verdict_free`. When non-NULL, `buffer` must point to at least
 * `capacity` writable bytes.
 */
size_t dgaard_verdict_address(const dgaard_verdict *handle, char *buffer, size_t capacity);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* DGAARD_H */
