use bpaf::{OptionParser, Parser, construct, short};

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct Opts {
    pub config: Option<String>,
    pub socket: Option<String>,
    pub index: Option<String>,
    pub db: Option<String>,
    pub headless: bool,
}

impl Opts {
    /// Apply the path flags on top of the loaded config: a flag, when given,
    /// wins over the config file and the built-in default.
    pub fn apply_overrides(&self, cfg: &mut Config) {
        if let Some(socket) = &self.socket {
            cfg.input.socket.clone_from(socket);
        }
        if let Some(index) = &self.index {
            cfg.input.index.clone_from(index);
        }
        if let Some(db) = &self.db {
            cfg.persistence.db.clone_from(db);
        }
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
        .help("disable the TUI and run as a headless service (automatic when stdout is not a terminal)")
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

    /// Parse `args` and apply them to the built-in default config.
    fn resolved(args: &[&str]) -> Config {
        let mut cfg = Config::default();
        parse_args(args).unwrap().apply_overrides(&mut cfg);
        cfg
    }

    #[test]
    fn test_no_flag_keeps_config_paths() {
        let defaults = Config::default();
        let cfg = resolved(&[]);
        assert_eq!(cfg.input.socket, defaults.input.socket);
        assert_eq!(cfg.input.index, defaults.input.index);
        assert_eq!(cfg.persistence.db, defaults.persistence.db);
    }

    #[test]
    fn test_long_socket_flag() {
        let defaults = Config::default();
        let cfg = resolved(&["--socket", "/custom/dns.sock"]);
        assert_eq!(cfg.input.socket, "/custom/dns.sock");
        assert_eq!(cfg.input.index, defaults.input.index);
        assert_eq!(cfg.persistence.db, defaults.persistence.db);
    }

    #[test]
    fn test_long_index_flag() {
        let defaults = Config::default();
        let cfg = resolved(&["--index", "/custom/hosts.bin"]);
        assert_eq!(cfg.input.socket, defaults.input.socket);
        assert_eq!(cfg.input.index, "/custom/hosts.bin");
        assert_eq!(cfg.persistence.db, defaults.persistence.db);
    }

    /// Regression: `--db` was parsed but never applied.
    #[test]
    fn test_long_db_flag() {
        let defaults = Config::default();
        let cfg = resolved(&["--db", "/custom/stats.sqlite"]);
        assert_eq!(cfg.input.socket, defaults.input.socket);
        assert_eq!(cfg.input.index, defaults.input.index);
        assert_eq!(cfg.persistence.db, "/custom/stats.sqlite");
    }

    #[test]
    fn test_flags_override_config_file_values() {
        let mut cfg = Config::default();
        cfg.input.socket = "/from/config.sock".to_string();
        cfg.input.index = "/from/config.bin".to_string();
        cfg.persistence.db = "/from/config.sqlite".to_string();
        parse_args(&[
            "--socket",
            "/run/dns.sock",
            "--index",
            "/data/hosts.bin",
            "--db",
            "/data/stats.db",
        ])
        .unwrap()
        .apply_overrides(&mut cfg);
        assert_eq!(cfg.input.socket, "/run/dns.sock");
        assert_eq!(cfg.input.index, "/data/hosts.bin");
        assert_eq!(cfg.persistence.db, "/data/stats.db");
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
        assert_eq!(opts.socket.as_deref(), Some("/s.sock"));
        assert_eq!(opts.index.as_deref(), Some("/h.bin"));
        assert_eq!(opts.db.as_deref(), Some("/s.db"));
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
