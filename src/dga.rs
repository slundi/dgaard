//! DGA (Domain Generation Algorithm) detection module.
//!
//! This module provides heuristics for detecting algorithmically generated
//! domain names used by malware for C2 communication.
//!
//! Features:
//! - Shannon entropy calculation
//! - Consonant ratio and clustering detection
//! - N-gram language model analysis (embedded and external)

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

// Vowels for consonant ratio analysis (lowercase ASCII only)
const VOWELS: [u8; 5] = [b'a', b'e', b'i', b'o', b'u'];

// =============================================================================
// N-Gram Language Models (Approach B: Embedded Markov Matrices)
// =============================================================================
//
// These are 26x26 log-probability matrices for character bigram transitions.
// Each value represents log2(P(next_char | current_char)).
// Generated from large text corpora for each language.
//
// To interpret: matrix[from][to] where from/to are 0-25 (a-z)
// Higher values (closer to 0) = more likely transition
// Lower values (more negative) = less likely transition
// -10.0 = effectively impossible transition

/// Converts a lowercase ASCII letter to matrix index (0-25)
#[inline]
fn char_to_index(c: u8) -> Option<usize> {
    if c.is_ascii_lowercase() {
        Some((c - b'a') as usize)
    } else {
        None
    }
}

// English bigram log-probabilities (26x26 matrix)
// Based on analysis of English text corpora
// Format: ENGLISH_BIGRAMS[from_char][to_char] = log2(P(to|from))
#[rustfmt::skip]
const ENGLISH_BIGRAMS: [[f32; 26]; 26] = [
    // a: common transitions - at, an, al, ar, as, ay
    [-3.2, -2.8, -2.5, -2.9, -4.5, -4.2, -3.5, -5.0, -3.8, -6.0, -4.5, -2.2, -3.0, -1.8, -5.5, -3.5, -6.5, -2.0, -2.5, -1.5, -4.2, -3.8, -4.0, -5.5, -3.0, -5.5],
    // b: common - be, bl, br, bu
    [-3.5, -5.5, -6.0, -6.5, -1.8, -6.5, -6.5, -6.5, -3.2, -5.5, -6.5, -2.5, -6.5, -6.5, -2.8, -6.5, -6.5, -2.8, -4.5, -6.5, -2.5, -6.5, -6.5, -6.5, -3.5, -6.5],
    // c: common - ch, ck, co, ce, ca
    [-2.2, -6.5, -4.5, -6.5, -2.5, -6.5, -6.5, -1.5, -3.5, -6.5, -2.0, -3.8, -6.5, -6.5, -2.0, -6.5, -5.5, -4.5, -4.5, -3.0, -3.5, -6.5, -6.5, -6.5, -4.0, -6.5],
    // d: common - de, di, do, da
    [-3.0, -5.5, -5.5, -4.5, -2.0, -5.5, -4.5, -5.0, -2.5, -5.5, -6.5, -4.5, -5.0, -4.5, -2.8, -5.5, -6.5, -4.0, -3.5, -6.5, -3.5, -5.0, -4.5, -6.5, -4.0, -6.5],
    // e: common - er, es, en, ed, ea, et
    [-2.0, -4.5, -3.0, -2.2, -3.5, -3.5, -4.0, -5.5, -3.8, -5.5, -5.5, -2.8, -3.2, -1.8, -4.5, -3.5, -4.5, -1.5, -2.0, -2.5, -5.5, -3.5, -3.5, -3.5, -3.2, -6.5],
    // f: common - fo, fi, fr, fe, fu
    [-3.5, -6.5, -6.5, -6.5, -3.0, -3.5, -6.5, -6.5, -2.8, -6.5, -6.5, -3.5, -6.5, -6.5, -2.0, -6.5, -6.5, -2.5, -5.5, -4.0, -3.0, -6.5, -6.5, -6.5, -4.0, -6.5],
    // g: common - ge, go, gi, gr
    [-3.5, -6.5, -6.5, -6.5, -2.2, -6.5, -4.5, -3.5, -3.0, -6.5, -6.5, -4.0, -5.5, -4.5, -2.8, -6.5, -6.5, -2.8, -4.5, -5.5, -3.5, -6.5, -6.5, -6.5, -4.5, -6.5],
    // h: common - he, ha, hi, ho
    [-2.0, -6.5, -6.5, -6.5, -1.5, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -6.5, -6.5, -2.8, -6.5, -6.5, -5.5, -6.5, -5.5, -4.0, -6.5, -6.5, -6.5, -4.5, -6.5],
    // i: common - in, it, is, io, ic, ie
    [-3.5, -4.5, -2.5, -3.5, -3.0, -3.5, -3.5, -6.5, -6.5, -6.5, -4.0, -3.0, -3.2, -1.5, -2.8, -4.5, -5.5, -3.8, -2.5, -2.0, -6.5, -3.5, -6.5, -5.5, -6.5, -4.0],
    // j: rare letter - just, ja
    [-4.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -6.5, -6.5, -6.5],
    // k: common - ke, ki, kn
    [-4.5, -6.5, -6.5, -6.5, -2.0, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -5.5, -6.5, -3.5, -4.5, -6.5, -6.5, -6.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5],
    // l: common - le, li, ly, la, lo
    [-2.5, -6.5, -5.5, -3.5, -1.8, -4.5, -6.5, -6.5, -2.5, -6.5, -5.5, -3.0, -5.5, -6.5, -2.5, -5.5, -6.5, -6.5, -4.0, -4.5, -4.0, -5.5, -5.5, -6.5, -2.0, -6.5],
    // m: common - me, ma, mo, mi
    [-2.5, -4.5, -6.5, -6.5, -2.0, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -6.5, -4.0, -6.5, -2.8, -3.5, -6.5, -6.5, -4.5, -6.5, -3.5, -6.5, -6.5, -6.5, -4.0, -6.5],
    // n: common - ng, ne, nd, nt, no
    [-3.5, -6.5, -3.0, -2.5, -2.2, -4.5, -2.0, -5.5, -3.5, -5.5, -4.5, -5.5, -6.5, -4.0, -3.0, -6.5, -5.5, -6.5, -3.0, -2.5, -4.5, -5.5, -5.5, -6.5, -4.0, -6.5],
    // o: common - on, or, ou, oo, of
    [-4.5, -4.0, -3.5, -3.5, -4.5, -2.5, -4.0, -5.5, -4.5, -6.5, -4.0, -3.5, -2.8, -2.0, -3.0, -3.5, -6.5, -2.0, -3.5, -3.5, -2.0, -3.8, -3.0, -5.5, -5.5, -5.5],
    // p: common - pr, pe, pl, po, pa
    [-3.0, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -4.5, -3.5, -6.5, -6.5, -2.8, -6.5, -6.5, -2.8, -4.0, -6.5, -2.0, -4.0, -4.0, -3.5, -6.5, -6.5, -6.5, -4.5, -6.5],
    // q: almost always followed by u
    [-6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -0.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // r: common - re, ri, ra, ro
    [-2.5, -5.5, -4.5, -4.0, -1.8, -5.5, -4.5, -6.5, -2.5, -6.5, -4.5, -4.5, -4.5, -4.5, -2.5, -5.5, -6.5, -4.5, -3.0, -3.5, -4.0, -5.5, -5.5, -6.5, -3.5, -6.5],
    // s: common - st, se, si, so, ss
    [-3.5, -5.5, -4.0, -6.5, -2.2, -5.5, -6.5, -3.5, -2.8, -6.5, -4.5, -5.5, -4.5, -6.5, -3.0, -3.5, -5.5, -6.5, -3.0, -1.8, -3.5, -6.5, -4.5, -6.5, -4.5, -6.5],
    // t: common - th, ti, te, to, tr
    [-3.5, -5.5, -4.5, -6.5, -2.5, -5.5, -6.5, -1.2, -2.2, -6.5, -6.5, -4.5, -5.5, -6.5, -2.5, -6.5, -6.5, -3.5, -3.5, -4.0, -4.0, -6.5, -4.5, -6.5, -3.5, -6.5],
    // u: common - un, ur, us, ut
    [-4.0, -4.5, -3.5, -4.0, -4.0, -5.5, -4.0, -6.5, -4.5, -6.5, -6.5, -3.0, -4.0, -2.5, -6.5, -3.5, -6.5, -2.5, -2.5, -2.8, -6.5, -6.5, -6.5, -5.5, -6.5, -6.5],
    // v: common - ve, vi
    [-4.0, -6.5, -6.5, -6.5, -1.5, -6.5, -6.5, -6.5, -2.8, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -5.5, -6.5],
    // w: common - wa, we, wi, wh
    [-2.0, -6.5, -6.5, -6.5, -2.8, -6.5, -6.5, -3.0, -2.5, -6.5, -6.5, -6.5, -6.5, -4.5, -3.0, -6.5, -6.5, -5.5, -5.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // x: rare - usually word-ending
    [-4.5, -6.5, -4.5, -6.5, -4.5, -6.5, -6.5, -5.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -5.5, -6.5],
    // y: common - yo, ya
    [-3.5, -5.5, -5.5, -5.5, -3.5, -5.5, -6.5, -6.5, -4.5, -6.5, -6.5, -5.5, -5.5, -6.5, -3.0, -5.5, -6.5, -6.5, -4.0, -5.5, -6.5, -6.5, -5.5, -6.5, -6.5, -6.5],
    // z: rare
    [-4.5, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -5.0, -5.5],
];

// French bigram log-probabilities
// French has different patterns: more vowel clusters, silent letters, etc.
#[rustfmt::skip]
const FRENCH_BIGRAMS: [[f32; 26]; 26] = [
    // a: common - ai, au, an, ar, as
    [-3.5, -3.0, -3.0, -3.2, -5.0, -4.5, -3.8, -5.5, -2.0, -5.5, -5.0, -2.5, -3.2, -2.0, -5.5, -3.8, -4.5, -2.5, -2.8, -2.5, -2.5, -3.5, -5.5, -4.5, -3.5, -5.5],
    // b: common - be, bl, br
    [-4.0, -5.5, -6.0, -6.5, -2.0, -6.5, -6.5, -6.5, -3.5, -5.5, -6.5, -2.8, -6.5, -6.5, -3.0, -6.5, -6.5, -2.5, -5.0, -6.5, -4.0, -6.5, -6.5, -6.5, -4.5, -6.5],
    // c: common - ce, ch, co, ca, ci
    [-2.5, -6.5, -4.5, -6.5, -2.0, -6.5, -6.5, -1.8, -3.0, -6.5, -4.5, -4.0, -6.5, -6.5, -2.2, -6.5, -4.5, -4.0, -5.0, -3.5, -4.0, -6.5, -6.5, -6.5, -4.5, -6.5],
    // d: common - de, di, da
    [-3.5, -6.0, -5.5, -5.0, -1.5, -6.0, -5.5, -5.5, -2.8, -5.5, -6.5, -5.0, -5.5, -5.0, -3.0, -6.0, -6.5, -4.5, -4.0, -6.5, -3.8, -5.5, -6.5, -6.5, -4.5, -6.5],
    // e: very common in French - es, en, et, er, eu
    [-3.5, -5.0, -3.0, -2.5, -3.8, -4.0, -4.5, -6.0, -4.5, -5.5, -6.0, -2.8, -2.8, -1.5, -5.0, -3.8, -4.0, -2.0, -1.8, -2.2, -2.5, -4.0, -5.5, -3.0, -5.0, -5.5],
    // f: common - fa, fe, fi, fo, fr
    [-3.0, -6.5, -6.5, -6.5, -3.5, -3.5, -6.5, -6.5, -2.5, -6.5, -6.5, -4.0, -6.5, -6.5, -2.5, -6.5, -6.5, -3.0, -6.0, -6.5, -4.5, -6.5, -6.5, -6.5, -5.0, -6.5],
    // g: common - ge, gr, gu
    [-4.0, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -4.5, -6.5, -4.5, -4.0, -6.5, -6.5, -2.5, -6.0, -6.5, -2.5, -6.5, -6.5, -6.5, -5.0, -6.5],
    // h: less common in French (often silent)
    [-3.5, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -5.0, -6.5],
    // i: common - il, in, is, it, ie
    [-4.0, -4.5, -3.0, -4.0, -2.5, -4.0, -4.0, -6.5, -5.5, -5.5, -5.5, -2.5, -3.5, -2.0, -3.0, -5.0, -4.5, -3.5, -2.8, -2.5, -5.5, -4.0, -6.5, -4.5, -6.5, -4.5],
    // j: more common in French - je, jo
    [-4.0, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // k: rare in French
    [-5.5, -6.5, -6.5, -6.5, -5.0, -6.5, -6.5, -6.5, -5.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // l: common - le, la, li, lo, ll
    [-2.0, -6.0, -5.5, -4.5, -1.5, -5.5, -6.5, -6.5, -2.5, -6.5, -6.5, -3.0, -5.5, -6.5, -3.0, -5.5, -5.5, -6.5, -4.5, -5.0, -3.5, -5.5, -6.5, -6.5, -4.0, -6.5],
    // m: common - me, ma, mo, mi
    [-2.5, -4.5, -6.5, -6.5, -1.8, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -6.5, -3.5, -6.5, -2.8, -4.5, -6.5, -6.5, -5.0, -6.5, -4.0, -6.5, -6.5, -6.5, -4.5, -6.5],
    // n: common - ne, ni, no, nt
    [-4.0, -5.5, -3.5, -3.0, -2.0, -5.0, -4.0, -6.0, -3.5, -5.5, -6.0, -5.5, -6.5, -4.5, -3.0, -6.0, -5.0, -6.5, -3.5, -2.0, -4.0, -5.5, -6.5, -6.5, -5.0, -6.5],
    // o: common - ou, on, or, oi
    [-5.5, -4.5, -4.0, -4.0, -5.0, -4.5, -4.5, -6.0, -2.5, -5.5, -5.5, -3.5, -3.0, -2.0, -5.5, -4.0, -5.0, -2.5, -3.5, -4.0, -2.0, -4.0, -5.5, -4.5, -5.5, -6.0],
    // p: common - pr, pa, pe, po
    [-2.8, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -5.5, -3.5, -6.5, -6.5, -3.0, -6.5, -6.5, -2.8, -5.0, -6.5, -2.0, -5.0, -5.5, -3.5, -6.5, -6.5, -6.5, -5.0, -6.5],
    // q: always followed by u in French
    [-6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -0.2, -6.5, -6.5, -6.5, -6.5, -6.5],
    // r: common - re, ri, ra, ro
    [-2.5, -5.5, -4.5, -4.5, -1.5, -5.5, -5.0, -6.5, -2.8, -6.5, -6.0, -4.5, -4.5, -4.5, -2.8, -5.0, -5.5, -4.5, -3.5, -3.5, -4.0, -5.0, -6.5, -6.5, -4.5, -6.5],
    // s: common - se, si, so, ss, st
    [-3.5, -6.0, -4.5, -6.5, -2.0, -6.0, -6.5, -5.5, -2.5, -6.5, -6.5, -5.5, -5.0, -6.5, -3.0, -3.5, -4.5, -6.5, -3.0, -2.5, -3.5, -6.5, -6.5, -6.5, -5.0, -6.5],
    // t: common - te, ti, to, tr
    [-3.5, -5.5, -5.0, -6.5, -2.0, -5.5, -6.5, -5.5, -2.5, -6.5, -6.5, -5.0, -5.5, -6.5, -3.0, -6.5, -5.5, -2.8, -4.0, -5.5, -3.5, -6.5, -6.5, -6.5, -5.0, -6.5],
    // u: common - un, ur, us, ui
    [-4.5, -4.5, -4.0, -4.0, -3.0, -5.0, -4.0, -6.5, -3.0, -5.5, -6.5, -3.5, -4.0, -2.5, -6.0, -4.0, -6.5, -2.5, -3.0, -3.5, -6.5, -5.5, -6.5, -3.5, -6.5, -6.5],
    // v: common - ve, vi, vo
    [-3.5, -6.5, -6.5, -6.5, -2.0, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -5.5, -6.5],
    // w: very rare in French
    [-6.0, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // x: relatively common - ex
    [-4.5, -6.5, -4.5, -6.5, -3.5, -6.5, -6.5, -6.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -5.0, -6.5, -6.5, -6.5, -6.5, -6.0, -6.5],
    // y: relatively rare
    [-4.5, -6.0, -5.5, -6.0, -4.5, -6.0, -6.5, -6.5, -6.0, -6.5, -6.5, -6.0, -5.5, -6.5, -4.5, -5.5, -6.5, -6.0, -4.5, -6.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // z: rare in French
    [-4.5, -6.5, -6.5, -6.5, -4.0, -6.5, -6.5, -6.5, -5.0, -6.5, -6.5, -6.5, -6.5, -6.5, -5.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.0, -6.0],
];

// German bigram log-probabilities
#[rustfmt::skip]
const GERMAN_BIGRAMS: [[f32; 26]; 26] = [
    // a: common - an, au, ar, as, ab
    [-3.8, -2.8, -3.5, -3.5, -5.0, -4.0, -3.5, -4.5, -4.5, -5.5, -4.0, -2.8, -3.5, -2.0, -5.5, -4.0, -6.5, -2.5, -2.8, -2.8, -2.5, -5.0, -5.0, -6.5, -5.0, -5.0],
    // b: common - be, br
    [-4.0, -5.0, -6.5, -6.5, -1.5, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -4.0, -6.5, -6.5, -4.0, -6.5, -6.5, -3.0, -5.5, -6.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5],
    // c: common - ch (very common in German)
    [-6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -0.8, -6.5, -6.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // d: common - de, di, da
    [-3.5, -5.5, -6.0, -5.5, -1.8, -5.5, -6.0, -6.5, -2.8, -6.5, -6.5, -5.5, -5.5, -6.5, -4.0, -6.5, -6.5, -4.5, -5.0, -6.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // e: very common - en, er, ei, es
    [-4.0, -4.5, -4.0, -3.5, -4.5, -4.0, -3.5, -4.5, -2.0, -5.5, -4.5, -3.0, -3.5, -1.5, -5.5, -5.0, -6.5, -2.0, -2.5, -3.0, -4.5, -5.0, -5.0, -5.5, -6.5, -5.5],
    // f: common - fa, fe, fr, fu
    [-3.5, -6.5, -6.5, -6.5, -3.0, -4.0, -6.5, -6.5, -3.5, -6.5, -6.5, -4.5, -6.5, -6.5, -3.5, -6.5, -6.5, -3.0, -6.5, -4.5, -3.0, -6.5, -6.5, -6.5, -6.5, -6.5],
    // g: common - ge, gr, gu
    [-4.0, -5.5, -6.5, -6.5, -1.8, -6.5, -5.0, -5.5, -4.0, -6.5, -6.5, -4.5, -6.5, -5.5, -5.0, -6.5, -6.5, -3.0, -5.0, -4.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5],
    // h: common - he, ha
    [-2.5, -6.5, -6.5, -6.5, -2.0, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -4.5, -5.5, -5.5, -4.0, -6.5, -6.5, -5.0, -6.5, -4.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // i: common - in, ie, is, it
    [-4.5, -5.0, -3.0, -4.0, -2.5, -4.5, -3.5, -5.5, -6.0, -6.5, -4.0, -3.5, -3.5, -2.0, -4.5, -6.0, -6.5, -4.5, -3.0, -2.8, -6.0, -5.0, -6.5, -6.5, -6.5, -4.5],
    // j: relatively rare
    [-4.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -5.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // k: common - ke, ko, kr
    [-4.0, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -4.5, -6.5, -6.5, -4.5, -6.5, -6.5, -3.5, -6.5, -6.5, -4.0, -6.0, -5.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // l: common - le, li, la, ll
    [-3.0, -5.5, -6.0, -4.5, -2.0, -5.5, -5.5, -6.5, -2.8, -6.5, -5.5, -3.5, -5.5, -6.5, -3.5, -6.5, -6.5, -6.5, -4.5, -4.5, -4.0, -5.5, -6.5, -6.5, -6.5, -6.5],
    // m: common - me, ma, mi
    [-2.8, -5.0, -6.5, -6.5, -2.0, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -6.5, -4.0, -6.5, -4.0, -5.5, -6.5, -6.5, -5.5, -6.5, -4.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // n: very common - nd, ne, ng, nt
    [-4.5, -5.5, -4.0, -2.5, -2.5, -4.5, -2.5, -5.0, -3.5, -6.5, -4.0, -5.5, -6.0, -4.5, -4.5, -6.5, -6.5, -6.5, -3.5, -2.5, -4.5, -6.0, -5.5, -6.5, -6.5, -4.5],
    // o: common - or, on, ob
    [-5.5, -4.0, -4.5, -4.0, -5.0, -4.5, -4.5, -4.5, -5.5, -6.5, -5.0, -3.5, -3.5, -2.5, -5.5, -4.0, -6.5, -2.8, -4.0, -4.5, -4.5, -5.0, -5.5, -6.5, -6.5, -6.0],
    // p: common - pr, pf
    [-4.0, -6.5, -6.5, -6.5, -4.0, -3.5, -6.5, -5.5, -4.5, -6.5, -6.5, -4.5, -6.5, -6.5, -4.5, -5.5, -6.5, -3.0, -5.5, -5.0, -5.0, -6.5, -6.5, -6.5, -6.5, -6.5],
    // q: rare
    [-6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // r: common - re, ra, ri
    [-3.0, -5.0, -5.0, -4.0, -2.0, -5.0, -4.5, -5.5, -2.8, -6.5, -4.5, -5.0, -5.0, -4.5, -3.5, -5.5, -6.5, -5.5, -3.5, -4.0, -3.5, -5.5, -5.5, -6.5, -6.5, -5.5],
    // s: common - sch, st, se
    [-4.0, -5.5, -2.5, -5.5, -2.5, -5.5, -6.0, -4.0, -3.0, -6.5, -5.0, -5.5, -5.5, -6.5, -3.5, -4.0, -6.5, -6.5, -3.5, -2.0, -4.5, -6.5, -5.5, -6.5, -6.5, -6.0],
    // t: common - te, ti, tr
    [-3.5, -5.5, -5.5, -6.5, -2.0, -5.5, -5.5, -4.5, -2.8, -6.5, -6.5, -5.0, -5.5, -6.5, -4.0, -6.5, -6.5, -3.5, -4.5, -4.5, -4.5, -6.5, -5.5, -6.5, -6.5, -4.5],
    // u: common - un, ur, us
    [-5.0, -4.5, -4.0, -4.0, -4.5, -4.5, -4.0, -5.5, -5.0, -6.5, -6.5, -4.0, -4.0, -2.0, -6.0, -4.5, -6.5, -3.0, -3.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5, -5.5],
    // v: common - ve, vo
    [-4.5, -6.5, -6.5, -6.5, -2.0, -6.5, -6.5, -6.5, -3.5, -6.5, -6.5, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // w: common - we, wi, wa
    [-3.0, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -2.5, -6.5, -6.5, -6.5, -6.5, -6.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5, -5.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // x: rare
    [-6.0, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // y: rare in German
    [-6.0, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.0, -6.5, -6.5, -6.0, -6.5, -6.5, -5.0, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5, -6.5],
    // z: relatively common - zu, ze
    [-4.0, -6.5, -6.5, -6.5, -3.0, -6.5, -6.5, -6.5, -4.0, -6.5, -6.5, -6.5, -6.5, -6.5, -5.5, -6.5, -6.5, -6.5, -6.5, -5.5, -3.0, -6.5, -4.5, -6.5, -6.5, -6.5],
];

/// Supported languages for embedded N-gram models
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgramLanguage {
    English,
    French,
    German,
}

impl NgramLanguage {
    /// Parse a language name string into a NgramLanguage
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "english" | "en" => Some(Self::English),
            "french" | "fr" => Some(Self::French),
            "german" | "de" => Some(Self::German),
            _ => None,
        }
    }

    /// Get the bigram matrix for this language
    fn bigram_matrix(&self) -> &'static [[f32; 26]; 26] {
        match self {
            Self::English => &ENGLISH_BIGRAMS,
            Self::French => &FRENCH_BIGRAMS,
            Self::German => &GERMAN_BIGRAMS,
        }
    }
}

/// Calculate the N-gram score for a domain using embedded Markov matrices.
///
/// Returns the average log-probability of character transitions.
/// Higher scores (closer to 0) indicate more natural language patterns.
/// Lower scores (more negative) indicate random/DGA-like patterns.
///
/// # Arguments
/// * `domain` - The domain string to analyze (should be lowercase ASCII)
/// * `language` - The language model to use
///
/// # Returns
/// Average log2 probability of bigram transitions, or `f32::NEG_INFINITY` if
/// the domain has fewer than 2 analyzable characters.
pub fn ngram_score_embedded(domain: &str, language: NgramLanguage) -> f32 {
    let matrix = language.bigram_matrix();
    let bytes = domain.as_bytes();

    let mut total_log_prob = 0.0f32;
    let mut transition_count = 0u32;

    let mut prev_idx: Option<usize> = None;

    for &b in bytes {
        if let Some(curr_idx) = char_to_index(b) {
            if let Some(from_idx) = prev_idx {
                total_log_prob += matrix[from_idx][curr_idx];
                transition_count += 1;
            }
            prev_idx = Some(curr_idx);
        } else {
            // Non-letter breaks the chain (digit, hyphen, etc.)
            prev_idx = None;
        }
    }

    if transition_count == 0 {
        return f32::NEG_INFINITY;
    }

    total_log_prob / transition_count as f32
}

/// Check if a domain passes N-gram analysis using embedded models (OR logic).
///
/// The domain is considered legitimate if it scores above the threshold
/// in **at least one** of the specified languages.
///
/// # Arguments
/// * `domain` - The domain string to analyze
/// * `languages` - List of languages to check against
/// * `threshold` - Minimum acceptable average log-probability (e.g., -4.0)
///
/// # Returns
/// `true` if the domain passes (scores above threshold in at least one language)
pub fn ngram_check_embedded(domain: &str, languages: &[NgramLanguage], threshold: f32) -> bool {
    if languages.is_empty() {
        return true; // No models = pass by default
    }

    // OR logic: pass if ANY language model accepts the domain
    for &lang in languages {
        let score = ngram_score_embedded(domain, lang);
        if score >= threshold {
            return true;
        }
    }

    false
}

// =============================================================================
// N-Gram External File Loading (Approach A)
// =============================================================================

/// External N-gram model loaded from a binary file.
///
/// File format (little-endian):
/// - Header: 4 bytes magic "NGRM"
/// - Version: 1 byte (currently 1)
/// - N-gram size: 1 byte (2 for bigrams, 3 for trigrams)
/// - Entry count: 4 bytes u32
/// - Entries: [ngram_bytes..., log_prob as f32] repeated
#[derive(Debug)]
#[allow(dead_code)] // External model loading not yet integrated
pub struct ExternalNgramModel {
    /// N-gram size (2 for bigrams, 3 for trigrams)
    pub ngram_size: u8,
    /// Map from n-gram bytes to log-probability
    entries: HashMap<Vec<u8>, f32>,
    /// Default log-probability for unknown n-grams
    default_prob: f32,
}

#[allow(dead_code)] // External model loading not yet integrated
impl ExternalNgramModel {
    /// Load an N-gram model from a binary file.
    ///
    /// Returns `None` if the file cannot be read or has invalid format.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Option<Self> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);

        // Read and verify magic header
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).ok()?;
        if &magic != b"NGRM" {
            return None;
        }

        // Read version
        let mut version = [0u8; 1];
        reader.read_exact(&mut version).ok()?;
        if version[0] != 1 {
            return None; // Unsupported version
        }

        // Read n-gram size
        let mut ngram_size_buf = [0u8; 1];
        reader.read_exact(&mut ngram_size_buf).ok()?;
        let ngram_size = ngram_size_buf[0];
        if !(2..=4).contains(&ngram_size) {
            return None;
        }

        // Read entry count
        let mut count_buf = [0u8; 4];
        reader.read_exact(&mut count_buf).ok()?;
        let entry_count = u32::from_le_bytes(count_buf) as usize;

        // Read entries
        let mut entries = HashMap::with_capacity(entry_count);
        let entry_size = ngram_size as usize + 4; // ngram bytes + f32
        let mut entry_buf = vec![0u8; entry_size];

        for _ in 0..entry_count {
            if reader.read_exact(&mut entry_buf).is_err() {
                break;
            }
            let ngram = entry_buf[..ngram_size as usize].to_vec();
            let prob_bytes: [u8; 4] = entry_buf[ngram_size as usize..].try_into().ok()?;
            let prob = f32::from_le_bytes(prob_bytes);
            entries.insert(ngram, prob);
        }

        Some(Self {
            ngram_size,
            entries,
            default_prob: -10.0, // Very unlikely for unknown n-grams
        })
    }

    /// Calculate the N-gram score for a domain.
    pub fn score(&self, domain: &str) -> f32 {
        let bytes: Vec<u8> = domain
            .as_bytes()
            .iter()
            .filter(|b| b.is_ascii_lowercase())
            .copied()
            .collect();

        if bytes.len() < self.ngram_size as usize {
            return f32::NEG_INFINITY;
        }

        let mut total = 0.0f32;
        let mut count = 0u32;

        for window in bytes.windows(self.ngram_size as usize) {
            let prob = self
                .entries
                .get(window)
                .copied()
                .unwrap_or(self.default_prob);
            total += prob;
            count += 1;
        }

        if count == 0 {
            f32::NEG_INFINITY
        } else {
            total / count as f32
        }
    }
}

/// Check if a domain passes N-gram analysis using external models (OR logic).
#[allow(dead_code)] // External model loading not yet integrated
pub fn ngram_check_external(domain: &str, models: &[ExternalNgramModel], threshold: f32) -> bool {
    if models.is_empty() {
        return true;
    }

    for model in models {
        let score = model.score(domain);
        if score >= threshold {
            return true;
        }
    }

    false
}

/// Checks if a byte is a lowercase ASCII letter
#[inline]
fn is_lowercase_letter(b: u8) -> bool {
    b.is_ascii_lowercase()
}

/// Checks if a byte is a vowel (lowercase ASCII)
#[inline]
fn is_vowel(b: u8) -> bool {
    VOWELS.contains(&b)
}

/// Checks if a byte is a consonant (lowercase ASCII letter that is not a vowel)
#[inline]
fn is_consonant(b: u8) -> bool {
    is_lowercase_letter(b) && !is_vowel(b)
}

/// Calculates the consonant ratio of a string.
///
/// Returns the ratio of consonants to total letters (0.0 to 1.0).
/// Non-letter characters (digits, hyphens, etc.) are ignored.
///
/// Normal English words have a consonant ratio around 0.6-0.7.
/// DGA domains often have ratios > 0.8 due to random character generation.
///
/// # Examples
/// ```
/// use dgaard::dga::calculate_consonant_ratio;
/// let ratio = calculate_consonant_ratio("google"); // ~0.67 (4 consonants / 6 letters)
/// let ratio = calculate_consonant_ratio("xvbrtz"); // 1.0 (all consonants)
/// ```
pub fn calculate_consonant_ratio(s: &str) -> f32 {
    let bytes = s.as_bytes();
    let mut consonants = 0u32;
    let mut letters = 0u32;

    for &b in bytes {
        if is_lowercase_letter(b) {
            letters += 1;
            if is_consonant(b) {
                consonants += 1;
            }
        }
    }

    if letters == 0 {
        return 0.0;
    }

    consonants as f32 / letters as f32
}

/// Finds the longest sequence of consecutive consonants in a string.
///
/// Normal English words rarely have more than 3-4 consecutive consonants.
/// DGA domains often have sequences of 5+ consonants due to random generation.
///
/// # Examples
/// ```
/// use dgaard::dga::max_consonant_sequence;
/// let seq = max_consonant_sequence("strength"); // 3 ("str")
/// let seq = max_consonant_sequence("xvbrtzkm"); // 8 (all consonants)
/// ```
pub fn max_consonant_sequence(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut max_seq = 0usize;
    let mut current_seq = 0usize;

    for &b in bytes {
        if is_consonant(b) {
            current_seq += 1;
            if current_seq > max_seq {
                max_seq = current_seq;
            }
        } else {
            current_seq = 0;
        }
    }

    max_seq
}

/// Checks if a domain has suspicious consonant patterns.
///
/// This function combines both the consonant ratio and max sequence checks
/// to identify "unnatural" letter clustering typical of DGA domains.
///
/// # Arguments
/// * `s` - The domain string to analyze (should be lowercase)
/// * `ratio_threshold` - Maximum allowed consonant ratio (e.g., 0.8)
/// * `max_sequence_threshold` - Maximum allowed consecutive consonants (e.g., 4)
///
/// # Returns
/// `true` if the domain exceeds either threshold (suspicious)
pub fn is_consonant_suspicious(
    s: &str,
    ratio_threshold: f32,
    max_sequence_threshold: usize,
) -> bool {
    // Skip very short strings (not enough data to analyze)
    if s.len() < 4 {
        return false;
    }

    let ratio = calculate_consonant_ratio(s);
    if ratio > ratio_threshold {
        return true;
    }

    let max_seq = max_consonant_sequence(s);
    max_seq > max_sequence_threshold
}

/// Calculates the Shannon Entropy of a string with full unicode support.
/// Higher values (typically > 3.5 to 4.5) indicate potential DGA.
pub fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::with_capacity(36); // a-z + 0-9
    let len = s.len() as f32;

    // Count occurrences of each character
    for c in s.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
    }

    // Shannon Formula: H = -sum(p_i * log2(p_i))
    let mut entropy = 0.0;
    for &count in frequencies.values() {
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Optimized version for OpenWrt (no HashMap allocation)
pub fn calculate_entropy_fast(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    // Using a fixed-size array for ASCII chars to avoid Heap allocation
    let mut counts = [0u32; 256];
    let mut len = 0;

    for &byte in s.as_bytes() {
        counts[byte as usize] += 1;
        len += 1;
    }

    let mut entropy = 0.0;
    let len_f = len as f32;

    for &count in counts.iter() {
        if count > 0 {
            let p = count as f32 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // calculate_entropy (full Unicode, HashMap-based)
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_empty_string_returns_zero() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char_returns_zero() {
        // Single character has no randomness
        assert_eq!(calculate_entropy("a"), 0.0);
    }

    #[test]
    fn entropy_repeated_char_returns_zero() {
        // "aaaa" has zero entropy (completely predictable)
        assert_eq!(calculate_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_two_chars_equal_distribution() {
        // "ab" with equal distribution should have entropy of 1.0
        let e = calculate_entropy("ab");
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn entropy_increases_with_randomness() {
        // More unique characters = higher entropy
        let e1 = calculate_entropy("aabb");
        let e2 = calculate_entropy("abcd");
        assert!(e2 > e1);
    }

    #[test]
    fn entropy_normal_domain_below_threshold() {
        // Normal readable domains should have low entropy (< 4.0)
        let e = calculate_entropy("google");
        assert!(e < 3.0, "google entropy: {}", e);

        let e = calculate_entropy("facebook");
        assert!(e < 3.5, "facebook entropy: {}", e);

        let e = calculate_entropy("example");
        assert!(e < 3.0, "example entropy: {}", e);
    }

    #[test]
    fn entropy_dga_domain_above_threshold() {
        // Random-looking domains should have high entropy (>= 4.0)
        // 16 unique chars = log2(16) = 4.0, so we use >= for the boundary case
        let e = calculate_entropy("a1b2c3d4e5f6g7h8");
        assert!(e >= 4.0, "DGA-like entropy: {}", e);

        // More random chars for entropy clearly above 4.0
        let e = calculate_entropy("a1b2c3d4e5f6g7h8i9j0k");
        assert!(e > 4.0, "random chars entropy: {}", e);
    }

    #[test]
    fn entropy_unicode_support() {
        // Full entropy should handle Unicode correctly
        let e = calculate_entropy("héllo");
        assert!(e > 0.0);

        let e = calculate_entropy("日本語");
        assert!(e > 0.0);
    }

    // -----------------------------------------------------------------------
    // calculate_entropy_fast (ASCII-only, zero-allocation)
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_fast_empty_string_returns_zero() {
        assert_eq!(calculate_entropy_fast(""), 0.0);
    }

    #[test]
    fn entropy_fast_single_char_returns_zero() {
        assert_eq!(calculate_entropy_fast("a"), 0.0);
    }

    #[test]
    fn entropy_fast_repeated_char_returns_zero() {
        assert_eq!(calculate_entropy_fast("aaaa"), 0.0);
    }

    #[test]
    fn entropy_fast_two_chars_equal_distribution() {
        let e = calculate_entropy_fast("ab");
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn entropy_fast_increases_with_randomness() {
        let e1 = calculate_entropy_fast("aabb");
        let e2 = calculate_entropy_fast("abcd");
        assert!(e2 > e1);
    }

    #[test]
    fn entropy_fast_normal_domain_below_threshold() {
        let e = calculate_entropy_fast("google");
        assert!(e < 3.0, "google entropy: {}", e);

        let e = calculate_entropy_fast("facebook");
        assert!(e < 3.5, "facebook entropy: {}", e);
    }

    #[test]
    fn entropy_fast_dga_domain_above_threshold() {
        // 16 unique chars = log2(16) = 4.0, so we use >= for the boundary case
        let e = calculate_entropy_fast("a1b2c3d4e5f6g7h8");
        assert!(e >= 4.0, "DGA-like entropy: {}", e);

        // More random chars for entropy clearly above 4.0
        let e = calculate_entropy_fast("a1b2c3d4e5f6g7h8i9j0k");
        assert!(e > 4.0, "random chars entropy: {}", e);
    }

    // -----------------------------------------------------------------------
    // Comparison between fast and full entropy for ASCII input
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_fast_matches_full_for_ascii() {
        // For ASCII-only input, both functions should produce identical results
        let test_cases = [
            "google",
            "facebook",
            "example",
            "a1b2c3d4",
            "qwertasdfzxcv",
            "dgaard",
            "aaaabbbb",
        ];

        for s in test_cases {
            let full = calculate_entropy(s);
            let fast = calculate_entropy_fast(s);
            assert!(
                (full - fast).abs() < 0.001,
                "Mismatch for '{}': full={}, fast={}",
                s,
                full,
                fast
            );
        }
    }

    #[test]
    fn entropy_fast_handles_multibyte_as_bytes() {
        // Fast version treats input as bytes, so multi-byte UTF-8 is counted per byte
        // This is expected behavior for the fast path
        let fast = calculate_entropy_fast("héllo");
        let full = calculate_entropy("héllo");
        // They won't match because 'é' is 2 bytes in UTF-8
        // Fast version counts byte frequencies, full version counts char frequencies
        assert!(fast > 0.0);
        assert!(full > 0.0);
        // The values will differ, which is acceptable for the fast path
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_all_unique_chars() {
        // Maximum entropy for a given length: log2(n) where n is the number of unique chars
        let e = calculate_entropy("abcdefgh");
        // 8 unique chars -> max entropy = log2(8) = 3.0
        assert!((e - 3.0).abs() < 0.01);
    }

    #[test]
    fn entropy_fast_all_unique_chars() {
        let e = calculate_entropy_fast("abcdefgh");
        assert!((e - 3.0).abs() < 0.01);
    }

    #[test]
    fn entropy_numeric_string() {
        let e = calculate_entropy("1234567890");
        // 10 unique digits -> max entropy = log2(10) ≈ 3.32
        assert!((e - 3.32).abs() < 0.1);
    }

    #[test]
    fn entropy_fast_numeric_string() {
        let e = calculate_entropy_fast("1234567890");
        assert!((e - 3.32).abs() < 0.1);
    }

    // -----------------------------------------------------------------------
    // Consonant Ratio Tests (#4.3 from Roadmap)
    // -----------------------------------------------------------------------

    #[test]
    fn consonant_ratio_empty_string() {
        assert_eq!(calculate_consonant_ratio(""), 0.0);
    }

    #[test]
    fn consonant_ratio_only_vowels() {
        assert_eq!(calculate_consonant_ratio("aeiou"), 0.0);
    }

    #[test]
    fn consonant_ratio_only_consonants() {
        assert_eq!(calculate_consonant_ratio("bcdfg"), 1.0);
    }

    #[test]
    fn consonant_ratio_mixed() {
        // "google" = g, o, o, g, l, e -> 3 consonants (g, g, l) / 6 letters = 0.5
        let ratio = calculate_consonant_ratio("google");
        assert!((ratio - 0.5).abs() < 0.01, "google ratio: {}", ratio);
    }

    #[test]
    fn consonant_ratio_normal_domains() {
        // Normal domains should have ratios around 0.5-0.7
        // facebook = f-a-c-e-b-o-o-k = 8 letters, 4 consonants (f,c,b,k) = 0.5
        // example = e-x-a-m-p-l-e = 7 letters, 4 consonants (x,m,p,l) = ~0.57
        // amazon = a-m-a-z-o-n = 6 letters, 3 consonants (m,z,n) = 0.5
        let examples = [("facebook", 0.5), ("example", 0.571), ("amazon", 0.5)];

        for (domain, expected) in examples {
            let ratio = calculate_consonant_ratio(domain);
            assert!(
                (ratio - expected).abs() < 0.1,
                "{} ratio: {}, expected: {}",
                domain,
                ratio,
                expected
            );
        }
    }

    #[test]
    fn consonant_ratio_dga_like_domains() {
        // DGA domains often have very high consonant ratios
        let dga_examples = ["xvbrtz", "qwrtplk", "bcdfghjk"];

        for domain in dga_examples {
            let ratio = calculate_consonant_ratio(domain);
            assert!(ratio > 0.85, "{} should have high ratio: {}", domain, ratio);
        }
    }

    #[test]
    fn consonant_ratio_ignores_digits_and_hyphens() {
        // "abc123" has 2 consonants (b, c) / 3 letters = 0.67
        let ratio = calculate_consonant_ratio("abc123");
        assert!((ratio - 0.67).abs() < 0.1, "abc123 ratio: {}", ratio);

        // "a-b-c" has 2 consonants / 3 letters = 0.67
        let ratio = calculate_consonant_ratio("a-b-c");
        assert!((ratio - 0.67).abs() < 0.1, "a-b-c ratio: {}", ratio);
    }

    // -----------------------------------------------------------------------
    // Max Consonant Sequence Tests
    // -----------------------------------------------------------------------

    #[test]
    fn max_consonant_sequence_empty_string() {
        assert_eq!(max_consonant_sequence(""), 0);
    }

    #[test]
    fn max_consonant_sequence_only_vowels() {
        assert_eq!(max_consonant_sequence("aeiou"), 0);
    }

    #[test]
    fn max_consonant_sequence_single_consonant() {
        assert_eq!(max_consonant_sequence("aba"), 1);
    }

    #[test]
    fn max_consonant_sequence_normal_words() {
        // "strength" = s-t-r-e-n-g-t-h
        // "str" = 3, then "e" breaks, "ngth" = 4
        assert_eq!(max_consonant_sequence("strength"), 4);

        // "google" = g-o-o-g-l-e, "gl" = 2 consecutive
        assert_eq!(max_consonant_sequence("google"), 2);

        // "rhythm" = r-h-y-t-h-m (y is treated as consonant)
        // All 6 are consonants
        assert_eq!(max_consonant_sequence("rhythm"), 6);
    }

    #[test]
    fn max_consonant_sequence_dga_patterns() {
        // DGA patterns often have long consonant runs
        assert_eq!(max_consonant_sequence("xvbrtz"), 6);
        // "axvbrtzb" = a(vowel), then xvbrtzb = 7 consonants
        assert_eq!(max_consonant_sequence("axvbrtzb"), 7);
        assert_eq!(max_consonant_sequence("qwrtplk"), 7);
    }

    #[test]
    fn max_consonant_sequence_digits_break_sequence() {
        // Digits should break consonant sequences
        assert_eq!(max_consonant_sequence("bc1df"), 2);
    }

    // -----------------------------------------------------------------------
    // Combined Suspicious Check Tests
    // -----------------------------------------------------------------------

    #[test]
    fn is_consonant_suspicious_short_strings_not_flagged() {
        // Strings < 4 chars should not be flagged (not enough data)
        assert!(!is_consonant_suspicious("xyz", 0.8, 4));
        assert!(!is_consonant_suspicious("bc", 0.8, 4));
    }

    #[test]
    fn is_consonant_suspicious_normal_domains_pass() {
        // Normal domains should not be flagged
        let normal_domains = ["google", "facebook", "amazon", "example", "cloudflare"];

        for domain in normal_domains {
            assert!(
                !is_consonant_suspicious(domain, 0.8, 4),
                "{} should not be suspicious",
                domain
            );
        }
    }

    #[test]
    fn is_consonant_suspicious_dga_domains_flagged() {
        // DGA-like domains should be flagged
        let dga_domains = [
            "xvbrtzk",  // All consonants, long sequence
            "bcdfghjk", // All consonants
            "qwrtplkm", // All consonants, long sequence
        ];

        for domain in dga_domains {
            assert!(
                is_consonant_suspicious(domain, 0.8, 4),
                "{} should be suspicious",
                domain
            );
        }
    }

    #[test]
    fn is_consonant_suspicious_by_ratio() {
        // High ratio but no long sequence
        // "bcbcbc" has ratio 1.0 but max sequence of 1
        assert!(is_consonant_suspicious("bcbcbc", 0.8, 10));
    }

    #[test]
    fn is_consonant_suspicious_by_sequence() {
        // Long sequence but acceptable ratio
        // "astrength" has 4 consecutive consonants "ngth" and ratio ~0.78
        assert!(is_consonant_suspicious("xyzth", 0.95, 3));
    }

    #[test]
    fn is_consonant_suspicious_edge_case_y() {
        // "y" is treated as a consonant in our implementation
        // This is a simplification; linguistically y can be a vowel
        assert!(is_consonant(b'y'));
        // "syzygy" = s-y-z-y-g-y, all 6 are consonants
        assert_eq!(max_consonant_sequence("syzygy"), 6);
    }

    // -----------------------------------------------------------------------
    // N-Gram Embedded Model Tests (#4.4 and #4.5 from Roadmap)
    // -----------------------------------------------------------------------

    #[test]
    fn ngram_char_to_index_lowercase() {
        assert_eq!(char_to_index(b'a'), Some(0));
        assert_eq!(char_to_index(b'z'), Some(25));
        assert_eq!(char_to_index(b'm'), Some(12));
    }

    #[test]
    fn ngram_char_to_index_non_letter() {
        assert_eq!(char_to_index(b'0'), None);
        assert_eq!(char_to_index(b'-'), None);
        assert_eq!(char_to_index(b'A'), None); // uppercase
    }

    #[test]
    fn ngram_language_from_str() {
        assert_eq!(
            NgramLanguage::from_str("english"),
            Some(NgramLanguage::English)
        );
        assert_eq!(
            NgramLanguage::from_str("ENGLISH"),
            Some(NgramLanguage::English)
        );
        assert_eq!(NgramLanguage::from_str("en"), Some(NgramLanguage::English));
        assert_eq!(
            NgramLanguage::from_str("french"),
            Some(NgramLanguage::French)
        );
        assert_eq!(NgramLanguage::from_str("fr"), Some(NgramLanguage::French));
        assert_eq!(
            NgramLanguage::from_str("german"),
            Some(NgramLanguage::German)
        );
        assert_eq!(NgramLanguage::from_str("de"), Some(NgramLanguage::German));
        assert_eq!(NgramLanguage::from_str("unknown"), None);
    }

    #[test]
    fn ngram_score_empty_string() {
        let score = ngram_score_embedded("", NgramLanguage::English);
        assert!(score.is_infinite() && score < 0.0);
    }

    #[test]
    fn ngram_score_single_char() {
        let score = ngram_score_embedded("a", NgramLanguage::English);
        assert!(score.is_infinite() && score < 0.0);
    }

    #[test]
    fn ngram_score_normal_english_words() {
        // Common English words should have high scores (close to 0)
        let words = ["the", "and", "that", "have", "with", "this", "from"];

        for word in words {
            let score = ngram_score_embedded(word, NgramLanguage::English);
            assert!(
                score > -5.0,
                "{} should have score > -5.0, got {}",
                word,
                score
            );
        }
    }

    #[test]
    fn ngram_score_normal_domains() {
        // Normal domain names should pass
        let domains = ["google", "facebook", "amazon", "microsoft", "cloudflare"];

        for domain in domains {
            let score = ngram_score_embedded(domain, NgramLanguage::English);
            assert!(
                score > -5.0,
                "{} should have score > -5.0, got {}",
                domain,
                score
            );
        }
    }

    #[test]
    fn ngram_score_dga_domains() {
        // DGA-like random domains should have low scores
        let dga_domains = ["xvbrtzq", "qwrtplkm", "zxcvbnm", "jkqxzw"];

        for domain in dga_domains {
            let score = ngram_score_embedded(domain, NgramLanguage::English);
            assert!(
                score < -5.0,
                "{} should have score < -5.0, got {}",
                domain,
                score
            );
        }
    }

    #[test]
    fn ngram_score_french_words() {
        // French words should score well with French model
        let french_words = ["bonjour", "merci", "comment", "france"];

        for word in french_words {
            let score = ngram_score_embedded(word, NgramLanguage::French);
            assert!(
                score > -5.0,
                "French '{}' should have score > -5.0, got {}",
                word,
                score
            );
        }
    }

    #[test]
    fn ngram_score_german_words() {
        // German words should score well with German model
        let german_words = ["danke", "guten", "morgen", "deutsch"];

        for word in german_words {
            let score = ngram_score_embedded(word, NgramLanguage::German);
            assert!(
                score > -5.0,
                "German '{}' should have score > -5.0, got {}",
                word,
                score
            );
        }
    }

    #[test]
    fn ngram_score_handles_digits() {
        // Digits should break the chain but not crash
        let score = ngram_score_embedded("test123domain", NgramLanguage::English);
        assert!(!score.is_nan());
        // "test" and "domain" are both scored separately
    }

    #[test]
    fn ngram_score_handles_hyphens() {
        // Hyphens should break the chain
        let score = ngram_score_embedded("my-domain-name", NgramLanguage::English);
        assert!(!score.is_nan());
    }

    // -----------------------------------------------------------------------
    // N-Gram OR Logic Tests (#4.5)
    // -----------------------------------------------------------------------

    #[test]
    fn ngram_check_empty_languages_passes() {
        // No models = always pass
        assert!(ngram_check_embedded("xyzqwrt", &[], -4.0));
    }

    #[test]
    fn ngram_check_or_logic_english_only() {
        let languages = [NgramLanguage::English];

        // English word should pass
        assert!(ngram_check_embedded("google", &languages, -4.0));

        // Random DGA should fail
        assert!(!ngram_check_embedded("xvbrtzq", &languages, -4.0));
    }

    #[test]
    fn ngram_check_or_logic_multilingual() {
        let languages = [NgramLanguage::English, NgramLanguage::French];

        // English domain passes via English model
        assert!(ngram_check_embedded("google", &languages, -4.0));

        // French domain passes via French model
        assert!(ngram_check_embedded("bonjour", &languages, -4.0));

        // Random DGA fails both models
        assert!(!ngram_check_embedded("xvbrtzq", &languages, -4.0));
    }

    #[test]
    fn ngram_check_threshold_sensitivity() {
        let languages = [NgramLanguage::English];

        // With lenient threshold, more domains pass
        let lenient_threshold = -6.0;

        // "google" should definitely pass lenient
        assert!(ngram_check_embedded(
            "google",
            &languages,
            lenient_threshold
        ));

        // Random DGA should fail even lenient
        assert!(!ngram_check_embedded(
            "qxzjkw",
            &languages,
            lenient_threshold
        ));
    }

    #[test]
    fn ngram_check_real_world_domains() {
        let languages = [
            NgramLanguage::English,
            NgramLanguage::French,
            NgramLanguage::German,
        ];
        let threshold = -4.5;

        // Real-world domains that should pass
        let legitimate = [
            "google",
            "facebook",
            "amazon",
            "microsoft",
            "cloudflare",
            "netflix",
            "youtube",
        ];

        for domain in legitimate {
            assert!(
                ngram_check_embedded(domain, &languages, threshold),
                "{} should pass N-gram check",
                domain
            );
        }
    }

    #[test]
    fn ngram_check_known_dga_patterns() {
        let languages = [NgramLanguage::English, NgramLanguage::French];
        let threshold = -5.0;

        // Known DGA patterns (random consonant clusters)
        let dga_patterns = ["xvbrtzqk", "qwrtplkm", "bcdfghjk", "zxcvbnmq"];

        for domain in dga_patterns {
            assert!(
                !ngram_check_embedded(domain, &languages, threshold),
                "{} should fail N-gram check",
                domain
            );
        }
    }

    // -----------------------------------------------------------------------
    // External N-Gram Model Tests
    // -----------------------------------------------------------------------

    #[test]
    fn external_ngram_model_load_nonexistent_file() {
        let model = ExternalNgramModel::load_from_file("/nonexistent/path/model.bin");
        assert!(model.is_none());
    }

    #[test]
    fn external_ngram_check_empty_models_passes() {
        let models: Vec<ExternalNgramModel> = vec![];
        assert!(ngram_check_external("xyzqwrt", &models, -4.0));
    }
}
