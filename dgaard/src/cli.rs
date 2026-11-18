use bpaf::{OptionParser, Parser, construct, short};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct CliOptions {
    pub config: Option<String>,
}

/// `-h`/`--help` and `-v`/`--version` are handled (and exit) inside bpaf;
/// the short flags match the ones the previous parser assigned.
fn options() -> OptionParser<CliOptions> {
    let config = short('c')
        .long("config")
        .help("Path to the configuration file")
        .argument::<String>("FILE")
        .optional();
    construct!(CliOptions { config })
        .to_options()
        .descr("DNS filtering proxy with heuristic DGA detection")
        .version(VERSION)
        .version_parser(short('v').long("version").help("Print version information"))
}

pub fn parse() -> CliOptions {
    options().run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpaf::ParseFailure;

    fn parse(args: &[&str]) -> CliOptions {
        options().run_inner(args).expect("failed to parse args")
    }

    /// Text bpaf prints to stdout for `--help` / `--version`.
    fn stdout_of(args: &[&str]) -> String {
        match options().run_inner(args) {
            Err(ParseFailure::Stdout(doc, _)) => doc.to_string(),
            other => panic!("expected stdout output, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_empty() {
        let opts = parse(&[]);
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
    fn config_equals_syntax() {
        let opts = parse(&["--config=/etc/dgaard.toml"]);
        assert_eq!(opts.config.as_deref(), Some("/etc/dgaard.toml"));
    }

    #[test]
    fn config_without_value_is_error() {
        assert!(options().run_inner(&["--config"]).is_err());
    }

    #[test]
    fn version_flags_print_the_version() {
        for flag in ["--version", "-v"] {
            assert!(stdout_of(&[flag]).contains(VERSION), "{flag}");
        }
    }

    #[test]
    fn help_flags_print_usage() {
        for flag in ["--help", "-h"] {
            let help = stdout_of(&[flag]);
            assert!(help.contains("--config"), "{flag}: {help}");
            assert!(help.contains("--version"), "{flag}: {help}");
        }
    }

    #[test]
    fn unknown_flag_is_error() {
        assert!(matches!(
            options().run_inner(&["--unknown"]),
            Err(ParseFailure::Stderr(_))
        ));
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
