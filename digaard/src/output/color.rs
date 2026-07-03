//! Minimal ANSI color palette + TTY detection for pretty-print output.
//!
//! Kept dependency-free: we speak SGR codes directly. `ColorMode::Auto` calls
//! `is_terminal_stdout()` at construction time and freezes into `Always`/`Never`.

use std::io::IsTerminal;

/// User-selectable color mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    /// Resolve `Auto` against the current stdout TTY state.
    pub fn resolved(self) -> Palette {
        match self {
            Self::Always => Palette::ANSI,
            Self::Never => Palette::PLAIN,
            Self::Auto => {
                if std::io::stdout().is_terminal() {
                    Palette::ANSI
                } else {
                    Palette::PLAIN
                }
            }
        }
    }
}

/// Small collection of styles used by the pretty renderer.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub header: &'static str,  // section titles: `;; ANSWER SECTION:`
    pub comment: &'static str, // `;` prefixed metadata
    pub name: &'static str,    // owner name in RR line
    pub ttl: &'static str,     // TTL
    pub class: &'static str,   // IN / CH / HS
    pub rtype: &'static str,   // A / AAAA / MX / …
    pub data: &'static str,    // RDATA
    pub error: &'static str,   // NXDOMAIN, SERVFAIL, etc.
    pub reset: &'static str,
}

impl Palette {
    /// No-op palette used when color is disabled.
    pub const PLAIN: Self = Self {
        header: "",
        comment: "",
        name: "",
        ttl: "",
        class: "",
        rtype: "",
        data: "",
        error: "",
        reset: "",
    };

    /// Full ANSI palette; conservative — no bold-on-bright, terminal-safe.
    pub const ANSI: Self = Self {
        header: "\x1b[1;36m",  // bold cyan
        comment: "\x1b[2;37m", // dim white
        name: "\x1b[32m",      // green
        ttl: "\x1b[33m",       // yellow
        class: "\x1b[35m",     // magenta
        rtype: "\x1b[1;34m",   // bold blue
        data: "\x1b[0m",       // default
        error: "\x1b[1;31m",   // bold red
        reset: "\x1b[0m",
    };

    pub fn is_enabled(&self) -> bool {
        !self.reset.is_empty()
    }
}
