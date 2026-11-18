use bpaf::{OptionParser, Parser, construct, short};

#[allow(dead_code)]
pub const DEFAULT_SOCKET: &str = "/tmp/dns.sock";
#[allow(dead_code)]
pub const DEFAULT_INDEX: &str = "/var/lib/dns/hosts.bin";
#[allow(dead_code)]
pub const DEFAULT_DB: &str = "/var/dgaard/stats.sqlite";

#[derive(Debug, Clone)]
pub struct Opts {
    pub config: Option<String>,
    pub socket: Option<String>,
    pub index: Option<String>,
    pub db: Option<String>,
    pub headless: bool,
}

impl Opts {
    #[allow(dead_code)]
    pub fn socket_path(&self) -> &str {
        self.socket.as_deref().unwrap_or(DEFAULT_SOCKET)
    }

    #[allow(dead_code)]
    pub fn index_path(&self) -> &str {
        self.index.as_deref().unwrap_or(DEFAULT_INDEX)
    }

    #[allow(dead_code)]
    pub fn db_path(&self) -> &str {
        self.db.as_deref().unwrap_or(DEFAULT_DB)
    }
}

/// `-h`/`--help` come from bpaf; the other short flags match the ones the
/// previous parser assigned.
fn options() -> OptionParser<Opts> {
    let path = |flag: char, name: &'static str, help: &'static str| {
        short(flag)
            .long(name)
            .help(help)
            .argument::<String>("PATH")
            .optional()
    };
    let config = path('c', "config", "path to TOML configuration file");
    let socket = path(
        's',
        "socket",
        "path to Unix Domain Socket (overrides config)",
    );
    let index = path('i', "index", "path to host index file (overrides config)");
    let db = path('d', "db", "path to SQLite database (overrides config)");
    let headless = short('H')
        .long("headless")
        .help("disable the TUI and run as a headless service")
        .switch();
    construct!(Opts {
        config,
        socket,
        index,
        db,
        headless
    })
    .to_options()
    .descr("Telemetry agent for the dgaard DNS proxy")
}

pub fn parse() -> Opts {
    options().run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpaf::ParseFailure;

    fn parse_args(args: &[&str]) -> Result<Opts, ParseFailure> {
        options().run_inner(args)
    }

    #[test]
    fn test_defaults() {
        let opts = parse_args(&[]).unwrap();
        assert!(opts.config.is_none());
        assert_eq!(opts.socket_path(), DEFAULT_SOCKET);
        assert_eq!(opts.index_path(), DEFAULT_INDEX);
        assert_eq!(opts.db_path(), DEFAULT_DB);
    }

    #[test]
    fn test_long_socket_flag() {
        let opts = parse_args(&["--socket", "/custom/dns.sock"]).unwrap();
        assert_eq!(opts.socket_path(), "/custom/dns.sock");
        assert_eq!(opts.index_path(), DEFAULT_INDEX);
        assert_eq!(opts.db_path(), DEFAULT_DB);
    }

    #[test]
    fn test_long_index_flag() {
        let opts = parse_args(&["--index", "/custom/hosts.bin"]).unwrap();
        assert_eq!(opts.socket_path(), DEFAULT_SOCKET);
        assert_eq!(opts.index_path(), "/custom/hosts.bin");
        assert_eq!(opts.db_path(), DEFAULT_DB);
    }

    #[test]
    fn test_long_db_flag() {
        let opts = parse_args(&["--db", "/custom/stats.sqlite"]).unwrap();
        assert_eq!(opts.socket_path(), DEFAULT_SOCKET);
        assert_eq!(opts.index_path(), DEFAULT_INDEX);
        assert_eq!(opts.db_path(), "/custom/stats.sqlite");
    }

    #[test]
    fn test_all_combined() {
        let opts = parse_args(&[
            "--socket",
            "/run/dns.sock",
            "--index",
            "/data/hosts.bin",
            "--db",
            "/data/stats.db",
        ])
        .unwrap();
        assert_eq!(opts.socket_path(), "/run/dns.sock");
        assert_eq!(opts.index_path(), "/data/hosts.bin");
        assert_eq!(opts.db_path(), "/data/stats.db");
    }

    #[test]
    fn test_short_flags_match_previous_parser() {
        let opts = parse_args(&[
            "-c",
            "/etc/m.toml",
            "-s",
            "/s.sock",
            "-i",
            "/h.bin",
            "-d",
            "/s.db",
            "-H",
        ])
        .unwrap();
        assert_eq!(opts.config.as_deref(), Some("/etc/m.toml"));
        assert_eq!(opts.socket_path(), "/s.sock");
        assert_eq!(opts.index_path(), "/h.bin");
        assert_eq!(opts.db_path(), "/s.db");
        assert!(opts.headless);
    }

    #[test]
    fn test_config_long_flag() {
        let opts = parse_args(&["--config=/etc/monitor.toml"]).unwrap();
        assert_eq!(opts.config.as_deref(), Some("/etc/monitor.toml"));
    }

    #[test]
    fn test_headless_default_is_false() {
        let opts = parse_args(&[]).unwrap();
        assert!(!opts.headless);
    }

    #[test]
    fn test_headless_flag() {
        let opts = parse_args(&["--headless"]).unwrap();
        assert!(opts.headless);
    }

    #[test]
    fn test_help_lists_every_option() {
        let Err(ParseFailure::Stdout(doc, _)) = parse_args(&["--help"]) else {
            panic!("--help must print usage");
        };
        let help = doc.to_string();
        for flag in ["--config", "--socket", "--index", "--db", "--headless"] {
            assert!(help.contains(flag), "{flag} missing from:\n{help}");
        }
    }

    #[test]
    fn test_unknown_flag_returns_error() {
        let result = parse_args(&["--unknown-flag"]);
        assert!(matches!(result, Err(ParseFailure::Stderr(_))));
    }
}
