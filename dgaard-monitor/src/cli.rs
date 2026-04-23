use gumdrop::Options;

pub const DEFAULT_SOCKET: &str = "/tmp/dns.sock";
pub const DEFAULT_INDEX: &str = "/var/lib/dns/hosts.bin";
#[allow(dead_code)]
pub const DEFAULT_DB: &str = "/var/dgaard/stats.sqlite";

#[derive(Debug, Options)]
pub struct Opts {
    #[options(help = "print help message")]
    pub help: bool,

    #[options(short = "c", help = "path to TOML configuration file", meta = "PATH")]
    pub config: Option<String>,

    #[options(help = "path to Unix Domain Socket (overrides config)", meta = "PATH")]
    pub socket: Option<String>,

    #[options(help = "path to host index file (overrides config)", meta = "PATH")]
    pub index: Option<String>,

    #[options(help = "path to SQLite database (overrides config)", meta = "PATH")]
    pub db: Option<String>,

    #[options(help = "disable the TUI and run as a headless service")]
    pub headless: bool,
}

impl Opts {
    pub fn socket_path(&self) -> &str {
        self.socket.as_deref().unwrap_or(DEFAULT_SOCKET)
    }

    pub fn index_path(&self) -> &str {
        self.index.as_deref().unwrap_or(DEFAULT_INDEX)
    }

    #[allow(dead_code)]
    pub fn db_path(&self) -> &str {
        self.db.as_deref().unwrap_or(DEFAULT_DB)
    }
}

pub fn parse() -> Opts {
    let args: Vec<String> = std::env::args().collect();
    match Opts::parse_args_default(&args[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Usage: dgaard-monitor [OPTIONS]");
            eprintln!("{}", Opts::usage());
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gumdrop::Options;

    fn parse_args(args: &[&str]) -> Result<Opts, gumdrop::Error> {
        Opts::parse_args_default(args)
    }

    #[test]
    fn test_defaults() {
        let opts = parse_args(&[]).unwrap();
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
    fn test_unknown_flag_returns_error() {
        let result = parse_args(&["--unknown-flag"]);
        assert!(result.is_err());
    }
}
