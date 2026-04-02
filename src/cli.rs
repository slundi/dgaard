use gumdrop::Options;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Options)]
pub struct CliOptions {
    #[options(help = "Print help information")]
    pub help: bool,

    #[options(help = "Print version information")]
    pub version: bool,

    #[options(help = "Path to the configuration file", meta = "FILE")]
    pub config: Option<String>,
}

pub fn parse() -> CliOptions {
    let opts = CliOptions::parse_args_default_or_exit();

    if opts.version {
        println!("dgaard {VERSION}");
        std::process::exit(0);
    }

    opts
}

#[cfg(test)]
mod tests {
    use super::*;
    use gumdrop::Options;

    fn parse(args: &[&str]) -> CliOptions {
        CliOptions::parse_args_default(args).expect("failed to parse args")
    }

    #[test]
    fn defaults_are_empty() {
        let opts = parse(&[]);
        assert!(!opts.help);
        assert!(!opts.version);
        assert!(opts.config.is_none());
    }

    #[test]
    fn config_short_flag() {
        let opts = parse(&["-c", "/etc/dgaard.toml"]);
        assert_eq!(opts.config.as_deref(), Some("/etc/dgaard.toml"));
    }

    #[test]
    fn config_long_flag() {
        let opts = parse(&["--config", "/etc/dgaard.toml"]);
        assert_eq!(opts.config.as_deref(), Some("/etc/dgaard.toml"));
    }

    #[test]
    fn version_flag() {
        let opts = parse(&["--version"]);
        assert!(opts.version);
    }

    #[test]
    fn help_flag() {
        let opts = parse(&["--help"]);
        assert!(opts.help);
    }

    #[test]
    fn unknown_flag_is_error() {
        assert!(CliOptions::parse_args_default(&["--unknown"]).is_err());
    }

    #[test]
    fn version_string_contains_cargo_version() {
        assert!(
            VERSION.contains('.'),
            "version '{VERSION}' doesn't look like semver"
        );
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }
}
