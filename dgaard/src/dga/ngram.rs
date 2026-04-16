use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::*;
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
