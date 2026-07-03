pub mod color;
pub mod json;
pub mod text;

pub use color::ColorMode;

use hickory_proto::op::Message;

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
    pub elapsed_ms: Option<u64>,
}

/// Rendering options shared across formats.
#[derive(Debug, Clone, Copy)]
pub struct RenderOpts {
    pub format: OutputFormat,
    pub short: bool,
    pub color: ColorMode,
    /// When true, `render_batch` inserts a header/separator between entries
    /// (dig-style). Ignored for JSON, which always emits one object per line.
    pub batch: bool,
}

/// Render a single DNS response.
pub fn render(opts: RenderOpts, item: &Rendered<'_>) -> String {
    match opts.format {
        OutputFormat::Text => text::render(item, opts.short, opts.color),
        OutputFormat::Json => {
            let mut out = json::render(item.response, item.elapsed_ms, item.query);
            out.push('\n');
            out
        }
    }
}

/// Render a batch of responses in order.
///
/// - Text: each response is prefixed with `; <-- query <name> -->` when
///   `opts.batch` is true, so users can tell them apart.
/// - JSON: line-delimited (one object per line), no separator.
pub fn render_batch(opts: RenderOpts, items: &[Rendered<'_>]) -> String {
    let mut out = String::new();
    for (idx, item) in items.iter().enumerate() {
        if opts.format == OutputFormat::Text && opts.batch {
            if idx > 0 {
                out.push('\n');
            }
            out.push_str(&format!(";; ==> {} <==\n", item.query));
        }
        out.push_str(&render(opts, item));
    }
    out
}
