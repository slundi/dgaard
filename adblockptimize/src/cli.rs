use std::path::PathBuf;

use gumdrop::Options;

use crate::model::ListFormat;

#[derive(Debug, Options)]
pub struct Opts {
    #[options(help = "print help message")]
    pub help: bool,

    #[options(help = "Do not generate the browser blocking list")]
    pub no_browser: bool,

    #[options(help = "Do not generate the network blocking list")]
    pub no_network: bool,

    #[options(
        help = "Format for the network blocking list, some formats does not support wildcard."
    )]
    pub format: Option<ListFormat>,

    #[options(help = "Output file for network blocking list")]
    pub network_file: Option<PathBuf>,

    #[options(help = "Output file for browser blocking list")]
    pub browser_file: Option<PathBuf>,

    #[options(free, help = "List of paths or URL to parse")]
    pub paths: Vec<String>,
}

pub fn parse() -> Opts {
    let args: Vec<String> = std::env::args().collect();
    match Opts::parse_args_default(&args[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Usage: adblockptimize [OPTIONS] PATHS");
            eprintln!("{}", Opts::usage());
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gumdrop::Options;

    fn parse(args: &[&str]) -> Result<Opts, gumdrop::Error> {
        Opts::parse_args_default(args)
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
    fn combined_flags_and_files() {
        let opts = parse(&["--no-browser", "--format=dnsmasq", "a.txt", "b.txt"]).unwrap();
        assert!(opts.no_browser);
        assert_eq!(opts.format, Some(ListFormat::Dnsmasq));
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
}
