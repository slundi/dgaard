use std::path::PathBuf;

use bpaf::{OptionParser, Parser, construct, long, positional, short};

use crate::model::{DnsTarget, ListFormat};

#[derive(Debug, Clone)]
pub struct Opts {
    pub no_browser: bool,
    pub no_network: bool,
    /// Parsed for compatibility only: output syntax comes from `--target`.
    #[allow(dead_code)]
    pub format: Option<ListFormat>,
    pub target: Option<DnsTarget>,
    pub network_file: Option<PathBuf>,
    pub whitelist_file: Option<PathBuf>,
    pub browser_file: Option<PathBuf>,
    pub paths: Vec<String>,
}

/// `-h`/`--help` come from bpaf; the other short flags match the ones the
/// previous parser assigned (`--network-file` had none: `-n` and `-N` were
/// already taken).
fn options() -> OptionParser<Opts> {
    let no_browser = short('n')
        .long("no-browser")
        .help("Do not generate the browser blocking list")
        .switch();
    let no_network = short('N')
        .long("no-network")
        .help("Do not generate the network blocking list")
        .switch();
    let format = short('f')
        .long("format")
        .help("Deprecated and ignored: use --target to choose the output syntax.")
        .argument::<ListFormat>("FORMAT")
        .optional();
    let target = short('t')
        .long("target")
        .help(
            "DNS server target (plain, hosts, dnsmasq, unbound, pihole, adguard). \
             Determines the output syntax for the network blocking list. \
             Defaults to plain.",
        )
        .argument::<DnsTarget>("TARGET")
        .optional();
    let network_file = long("network-file")
        .help("Output file for network blocking list")
        .argument::<PathBuf>("FILE")
        .optional();
    let whitelist_file = short('w')
        .long("whitelist-file")
        .help("If applicable target, output file for whitelist")
        .argument::<PathBuf>("FILE")
        .optional();
    let browser_file = short('b')
        .long("browser-file")
        .help("Output file for browser blocking list")
        .argument::<PathBuf>("FILE")
        .optional();
    let paths = positional::<String>("PATHS")
        .help("List of paths or URL to parse")
        .many();
    construct!(Opts {
        no_browser,
        no_network,
        format,
        target,
        network_file,
        whitelist_file,
        browser_file,
        paths,
    })
    .to_options()
    .descr("Optimize and convert ad-blocking lists")
}

pub fn parse() -> Opts {
    options().run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpaf::ParseFailure;

    fn parse(args: &[&str]) -> Result<Opts, ParseFailure> {
        options().run_inner(args)
    }

    #[test]
    fn positional_args() {
        let opts = parse(&["file1.txt", "https://example.com"]).unwrap();
        assert_eq!(opts.paths, vec!["file1.txt", "https://example.com"]);
    }

    #[test]
    fn no_browser_flag() {
        let opts = parse(&["--no-browser", "file.txt"]).unwrap();
        assert!(opts.no_browser);
        assert!(!opts.no_network);
        assert_eq!(opts.paths, vec!["file.txt"]);
    }

    #[test]
    fn no_network_flag() {
        let opts = parse(&["--no-network", "file.txt"]).unwrap();
        assert!(opts.no_network);
        assert!(!opts.no_browser);
    }

    #[test]
    fn format_equals_syntax() {
        let opts = parse(&["--format=dnsmasq", "file.txt"]).unwrap();
        assert_eq!(opts.format, Some(ListFormat::Dnsmasq));
    }

    #[test]
    fn format_space_syntax() {
        let opts = parse(&["--format", "hosts", "file.txt"]).unwrap();
        assert_eq!(opts.format, Some(ListFormat::Hosts));
    }

    #[test]
    fn network_file_and_browser_file() {
        let opts = parse(&[
            "--network-file=custom.txt",
            "--browser-file=ublock_origin.txt",
            "input.txt",
        ])
        .unwrap();
        assert_eq!(opts.network_file, Some(PathBuf::from("custom.txt")));
        assert_eq!(opts.browser_file, Some(PathBuf::from("ublock_origin.txt")));
        assert_eq!(opts.paths, vec!["input.txt"]);
    }

    #[test]
    fn whitelist_file_flag() {
        let opts = parse(&["--whitelist-file", "allow.txt", "input.txt"]).unwrap();
        assert_eq!(opts.whitelist_file, Some(PathBuf::from("allow.txt")));
    }

    #[test]
    fn short_flags_match_previous_parser() {
        let opts = parse(&[
            "-n", "-N", "-f", "hosts", "-t", "unbound", "-w", "w.txt", "-b", "b.txt", "in.txt",
        ])
        .unwrap();
        assert!(opts.no_browser);
        assert!(opts.no_network);
        assert_eq!(opts.format, Some(ListFormat::Hosts));
        assert_eq!(opts.target, Some(DnsTarget::Unbound));
        assert_eq!(opts.whitelist_file, Some(PathBuf::from("w.txt")));
        assert_eq!(opts.browser_file, Some(PathBuf::from("b.txt")));
        assert_eq!(opts.paths, vec!["in.txt"]);
    }

    #[test]
    fn combined_flags_and_files() {
        let opts = parse(&["--no-browser", "--format=dnsmasq", "a.txt", "b.txt"]).unwrap();
        assert!(opts.no_browser);
        assert_eq!(opts.format, Some(ListFormat::Dnsmasq));
        assert_eq!(opts.paths, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn flags_after_paths_are_accepted() {
        let opts = parse(&["a.txt", "--no-network", "b.txt"]).unwrap();
        assert!(opts.no_network);
        assert_eq!(opts.paths, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn unknown_format_is_error() {
        assert!(parse(&["--format=bogus"]).is_err());
    }

    #[test]
    fn no_args_gives_empty_db() {
        let opts = parse(&[]).unwrap();
        assert!(opts.paths.is_empty());
    }

    #[test]
    fn target_defaults_to_none() {
        let opts = parse(&["file.txt"]).unwrap();
        assert_eq!(opts.target, None);
    }

    #[test]
    fn target_dnsmasq() {
        let opts = parse(&["--target=dnsmasq", "file.txt"]).unwrap();
        assert_eq!(opts.target, Some(DnsTarget::Dnsmasq));
    }

    #[test]
    fn target_unbound() {
        let opts = parse(&["--target", "unbound", "file.txt"]).unwrap();
        assert_eq!(opts.target, Some(DnsTarget::Unbound));
    }

    #[test]
    fn target_pihole() {
        let opts = parse(&["--target=pihole", "file.txt"]).unwrap();
        assert_eq!(opts.target, Some(DnsTarget::PiHole));
    }

    #[test]
    fn target_adguard() {
        let opts = parse(&["--target=adguard", "file.txt"]).unwrap();
        assert_eq!(opts.target, Some(DnsTarget::AdGuard));
    }

    #[test]
    fn target_plain() {
        let opts = parse(&["--target=plain", "file.txt"]).unwrap();
        assert_eq!(opts.target, Some(DnsTarget::Plain));
    }

    #[test]
    fn target_hosts() {
        let opts = parse(&["--target=hosts", "file.txt"]).unwrap();
        assert_eq!(opts.target, Some(DnsTarget::Hosts));
    }

    #[test]
    fn unknown_target_is_error() {
        assert!(parse(&["--target=bind9"]).is_err());
    }

    #[test]
    fn help_is_printed_to_stdout() {
        let Err(ParseFailure::Stdout(doc, _)) = parse(&["--help"]) else {
            panic!("--help must print usage");
        };
        let help = doc.to_string();
        assert!(help.contains("--network-file"), "{help}");
        assert!(help.contains("PATHS"), "{help}");
    }
}
