pub mod color;
pub mod edge;
pub mod hex;
pub mod json;
pub mod text;

pub use color::ColorMode;

use hickory_proto::op::Message;

use crate::dnssec::Verdict;

/// All output formats digaard can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Dig-style human-readable text.
    Text,
    /// Newline-delimited JSON (one object per response).
    Json,
}

/// A single query result to render.
#[derive(Debug)]
pub struct Rendered<'a> {
    pub query: &'a str,
    pub response: &'a Message,
    /// Raw wire bytes of the response (for `--hex`).
    pub wire: &'a [u8],
    pub elapsed_ms: Option<u64>,
    /// DNSSEC verdict when `--validate` is enabled.
    pub verdict: Option<&'a Verdict>,
}

/// Rendering options shared across formats.
#[derive(Debug, Clone, Copy)]
pub struct RenderOpts {
    pub format: OutputFormat,
    pub short: bool,
    pub color: ColorMode,
    /// When true, `render_batch` inserts a header/separator between entries.
    pub batch: bool,
    /// Decode EDGE options (RFC 8914) into the ADDITIONAL section (pretty output).
    pub edge: bool,
    /// Print raw wire bytes as hex dump instead of parsed records.
    pub hex: bool,
}

/// Render a single DNS response.
pub fn render(opts: RenderOpts, item: &Rendered<'_>) -> String {
    if opts.hex {
        return hex::render(item);
    }

    match opts.format {
        OutputFormat::Text => text::render(item, opts.short, opts.color, opts.edge),
        OutputFormat::Json => {
            let mut out = json::render(
                item.response,
                item.elapsed_ms,
                item.query,
                opts.edge,
                item.verdict,
            );
            out.push('\n');
            out
        }
    }
}

/// Render a batch of responses in order.
pub fn render_batch(opts: RenderOpts, items: &[Rendered<'_>]) -> String {
    let mut out = String::new();
    for (idx, item) in items.iter().enumerate() {
        if !opts.hex && opts.format == OutputFormat::Text && opts.batch {
            if idx > 0 {
                out.push('\n');
            }
            out.push_str(&format!(";; ==> {} <==\n", item.query));
        }
        out.push_str(&render(opts, item));
    }
    out
}
