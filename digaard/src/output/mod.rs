pub mod json;
pub mod text;

use hickory_proto::op::Message;

/// All output formats digaard can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Dig-style human-readable text.
    Text,
    /// Newline-delimited JSON (one object per response).
    Json,
}

/// Render a DNS response for display.
pub fn render(fmt: OutputFormat, short: bool, msg: &Message, elapsed_ms: Option<u64>) -> String {
    match fmt {
        OutputFormat::Text => text::render(msg, short, elapsed_ms),
        OutputFormat::Json => json::render(msg, elapsed_ms),
    }
}
