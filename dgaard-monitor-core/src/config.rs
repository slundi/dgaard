/// Wire format for forwarded events (file and HTTP POST).
#[derive(Debug, Default, PartialEq, Clone)]
pub enum ForwardFormat {
    /// Template string with `{timestamp}`, `{client_ip}`, `{action}`, `{domain}` placeholders.
    #[default]
    Template,
    /// Compact JSON object.
    Json,
    /// RFC 5424 syslog line with structured-data block (SD-ID `dgaard@32473`).
    Syslog,
    /// ArcSight Common Event Format v0 (`CEF:0|…`).
    Cef,
    /// Elasticsearch Bulk API NDJSON: `{"index":{}}\n{document}`.
    Elasticsearch,
}

impl ForwardFormat {
    /// HTTP `Content-Type` to use when POSTing events in this format.
    pub fn content_type(&self) -> &'static str {
        match self {
            ForwardFormat::Template | ForwardFormat::Syslog | ForwardFormat::Cef => {
                "text/plain; charset=utf-8"
            }
            ForwardFormat::Json => "application/json",
            ForwardFormat::Elasticsearch => "application/x-ndjson",
        }
    }
}

/// Controls where enriched events are forwarded.
///
/// When `file` is set events are appended to that path; forwarding never
/// writes to stdout, and runs only with a `file` or a `forward_url`. `template` is a
/// [strftime-like] format string where the following placeholders are
/// replaced: `{timestamp}`, `{client_ip}`, `{action}`, `{domain}`.
/// `forward_url` sends each matching event as an HTTP POST.
/// `filter` lists the action variants to forward; an empty list means *all*.
#[derive(Debug, PartialEq)]
pub struct ForwardingConfig {
    /// Append formatted lines to this file. Forwarding never writes to
    /// stdout: it belongs to the TUI or to the headless JSON stream.
    pub file: Option<String>,
    /// Template string used when `format = "template"`.
    pub template: String,
    /// HTTP(S) endpoint to POST events to (SOAR, Slack incoming webhook, …).
    pub forward_url: Option<String>,
    /// Action variants to forward. Empty list = forward everything.
    /// Valid values: "Allowed", "Proxied", "Blocked", "Suspicious", "HighlySuspicious".
    pub filter: Vec<String>,
    /// Wire format for both file and HTTP POST output.
    /// Valid values: "template" (default), "json", "syslog", "cef", "elasticsearch".
    pub format: ForwardFormat,
}

fn default_template() -> String {
    "{timestamp} {client_ip} {action} {domain}".to_string()
}

impl ForwardingConfig {
    /// `true` when at least one sink (`file` or `forward_url`) is configured.
    /// Without one, the forwarding task has nothing to do and is not started.
    pub fn has_sink(&self) -> bool {
        self.file.is_some() || self.forward_url.is_some()
    }
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            file: None,
            template: default_template(),
            forward_url: None,
            filter: Vec::new(),
            format: ForwardFormat::default(),
        }
    }
}
