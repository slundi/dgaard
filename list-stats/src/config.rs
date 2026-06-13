/// A single blocklist source.
#[derive(Debug, Clone)]
pub struct Source {
    pub name: &'static str,
    pub url: &'static str,
    pub category: &'static str,
}

/// All built-in sources, in order.
pub const SOURCES: &[Source] = &[
    Source {
        name: "uBlock-ads",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
        category: "ads",
    },
    Source {
        name: "uBlock-privacy",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
        category: "privacy",
    },
    Source {
        name: "uBlock-malware",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
        category: "malware",
    },
    Source {
        name: "uBlock-cookies",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",
        category: "annoyances",
    },
    Source {
        name: "StevenBlack",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        category: "ads",
    },
    Source {
        name: "StevenBlack-fakenews",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
        category: "fake-news",
    },
    Source {
        name: "StevenBlack-gambling",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
        category: "gambling",
    },
    Source {
        name: "StevenBlack-porn",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
        category: "porn",
    },
    Source {
        name: "oisd-big",
        url: "https://big.oisd.nl/domainswild",
        category: "ads",
    },
];
