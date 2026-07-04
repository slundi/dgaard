//! Optional GeoIP country annotation using a MaxMind .mmdb database.

use std::net::IpAddr;

/// Controls which parts of the country info are shown.
#[derive(Debug, Clone, Copy)]
pub struct CountryFormat {
    pub emoji: bool,
    pub alpha2: bool,
    pub alpha3: bool,
    pub name: bool,
}

impl Default for CountryFormat {
    fn default() -> Self {
        Self {
            emoji: false,
            alpha2: true,
            alpha3: false,
            name: false,
        }
    }
}

impl CountryFormat {
    /// Parse a comma- or plus-separated list of components.
    /// Valid tokens: `emoji`, `alpha2`/`iso2`, `alpha3`/`iso3`, `name`/`full`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut fmt = Self {
            emoji: false,
            alpha2: false,
            alpha3: false,
            name: false,
        };
        for part in s.split(['+', ',']) {
            match part.trim().to_ascii_lowercase().as_str() {
                "emoji" => fmt.emoji = true,
                "alpha2" | "iso2" | "2" => fmt.alpha2 = true,
                "alpha3" | "iso3" | "3" => fmt.alpha3 = true,
                "name" | "full" => fmt.name = true,
                "" => {}
                other => return Err(format!("unknown country format component '{other}'")),
            }
        }
        if !fmt.emoji && !fmt.alpha2 && !fmt.alpha3 && !fmt.name {
            fmt.alpha2 = true;
        }
        Ok(fmt)
    }
}

#[derive(serde::Deserialize)]
struct MmRecord {
    country: Option<MmCountry>,
}

#[derive(serde::Deserialize)]
struct MmCountry {
    iso_code: Option<String>,
    names: Option<std::collections::BTreeMap<String, String>>,
}

/// Loaded MaxMind database used to annotate A/AAAA records with country info.
pub struct GeoIpDb(maxminddb::Reader<Vec<u8>>);

impl std::fmt::Debug for GeoIpDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpDb").finish_non_exhaustive()
    }
}

impl GeoIpDb {
    pub fn open(path: &str) -> Result<Self, String> {
        maxminddb::Reader::open_readfile(path)
            .map(GeoIpDb)
            .map_err(|e| e.to_string())
    }

    /// Look up the country for `ip` and format it according to `fmt`.
    /// Returns `None` when the IP is not in the database or the entry has no country.
    pub fn lookup_country(&self, ip: IpAddr, fmt: CountryFormat) -> Option<String> {
        let result = self.0.lookup(ip).ok()?;
        let record: MmRecord = result.decode().ok()??;
        let c = record.country?;
        let alpha2 = c.iso_code?;

        let mut parts: Vec<String> = Vec::new();
        if fmt.emoji {
            parts.push(alpha2_to_emoji(&alpha2));
        }
        if fmt.alpha2 {
            parts.push(alpha2.clone());
        }
        if fmt.alpha3
            && let Some(a3) = alpha2_to_alpha3(&alpha2)
        {
            parts.push(a3.to_owned());
        }
        if fmt.name
            && let Some(name) = c.names.as_ref().and_then(|m| m.get("en"))
        {
            parts.push(name.clone());
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

fn alpha2_to_emoji(alpha2: &str) -> String {
    let mut chars = alpha2.chars();
    let a = chars.next().unwrap_or('?') as u32;
    let b = chars.next().unwrap_or('?') as u32;
    let base = 0x1F1E6u32.wrapping_sub('A' as u32);
    match (char::from_u32(base + a), char::from_u32(base + b)) {
        (Some(x), Some(y)) => format!("{x}{y}"),
        _ => String::new(),
    }
}

fn alpha2_to_alpha3(code: &str) -> Option<&'static str> {
    static TABLE: &[(&str, &str)] = &[
        ("AD", "AND"),
        ("AE", "ARE"),
        ("AF", "AFG"),
        ("AG", "ATG"),
        ("AI", "AIA"),
        ("AL", "ALB"),
        ("AM", "ARM"),
        ("AO", "AGO"),
        ("AQ", "ATA"),
        ("AR", "ARG"),
        ("AS", "ASM"),
        ("AT", "AUT"),
        ("AU", "AUS"),
        ("AW", "ABW"),
        ("AX", "ALA"),
        ("AZ", "AZE"),
        ("BA", "BIH"),
        ("BB", "BRB"),
        ("BD", "BGD"),
        ("BE", "BEL"),
        ("BF", "BFA"),
        ("BG", "BGR"),
        ("BH", "BHR"),
        ("BI", "BDI"),
        ("BJ", "BEN"),
        ("BL", "BLM"),
        ("BM", "BMU"),
        ("BN", "BRN"),
        ("BO", "BOL"),
        ("BQ", "BES"),
        ("BR", "BRA"),
        ("BS", "BHS"),
        ("BT", "BTN"),
        ("BV", "BVT"),
        ("BW", "BWA"),
        ("BY", "BLR"),
        ("BZ", "BLZ"),
        ("CA", "CAN"),
        ("CC", "CCK"),
        ("CD", "COD"),
        ("CF", "CALF"),
        ("CG", "COG"),
        ("CH", "CHE"),
        ("CI", "CIV"),
        ("CK", "COK"),
        ("CL", "CHL"),
        ("CM", "CMR"),
        ("CN", "CHN"),
        ("CO", "COL"),
        ("CR", "CRI"),
        ("CU", "CUB"),
        ("CV", "CPV"),
        ("CW", "CUW"),
        ("CX", "CXR"),
        ("CY", "CYP"),
        ("CZ", "CZE"),
        ("DE", "DEU"),
        ("DJ", "DJI"),
        ("DK", "DNK"),
        ("DM", "DMA"),
        ("DO", "DOM"),
        ("DZ", "DZA"),
        ("EC", "ECU"),
        ("EE", "EST"),
        ("EG", "EGY"),
        ("EH", "ESH"),
        ("ER", "ERI"),
        ("ES", "ESP"),
        ("ET", "ETH"),
        ("FI", "FIN"),
        ("FJ", "FJI"),
        ("FK", "FLK"),
        ("FM", "FSM"),
        ("FO", "FRO"),
        ("FR", "FRA"),
        ("GA", "GAB"),
        ("GB", "GBR"),
        ("GD", "GRD"),
        ("GE", "GEO"),
        ("GF", "GUF"),
        ("GG", "GGY"),
        ("GH", "GHA"),
        ("GI", "GIB"),
        ("GL", "GRL"),
        ("GM", "GMB"),
        ("GN", "GIN"),
        ("GP", "GLP"),
        ("GQ", "GNQ"),
        ("GR", "GRC"),
        ("GS", "SGS"),
        ("GT", "GTM"),
        ("GU", "GUM"),
        ("GW", "GNB"),
        ("GY", "GUY"),
        ("HK", "HKG"),
        ("HM", "HMD"),
        ("HN", "HND"),
        ("HR", "HRV"),
        ("HT", "HTI"),
        ("HU", "HUN"),
        ("ID", "IDN"),
        ("IE", "IRL"),
        ("IL", "ISR"),
        ("IM", "IMN"),
        ("IN", "IND"),
        ("IO", "IOT"),
        ("IQ", "IRQ"),
        ("IR", "IRN"),
        ("IS", "ISL"),
        ("IT", "ITA"),
        ("JE", "JEY"),
        ("JM", "JAM"),
        ("JO", "JOR"),
        ("JP", "JPN"),
        ("KE", "KEN"),
        ("KG", "KGZ"),
        ("KH", "KHM"),
        ("KI", "KIR"),
        ("KM", "COM"),
        ("KN", "KNA"),
        ("KP", "PRK"),
        ("KR", "KOR"),
        ("KW", "KWT"),
        ("KY", "CYM"),
        ("KZ", "KAZ"),
        ("LA", "LAO"),
        ("LB", "LBN"),
        ("LC", "LCA"),
        ("LI", "LIE"),
        ("LK", "LKA"),
        ("LR", "LBR"),
        ("LS", "ALSO"),
        ("LT", "LTU"),
        ("LU", "LUX"),
        ("LV", "LVA"),
        ("LY", "LBY"),
        ("MA", "MAR"),
        ("MC", "MCO"),
        ("MD", "MDA"),
        ("ME", "MNE"),
        ("MF", "MAF"),
        ("MG", "MDG"),
        ("MH", "MHL"),
        ("MK", "MKD"),
        ("ML", "MLI"),
        ("MM", "MMR"),
        ("MN", "MNG"),
        ("MO", "MAC"),
        ("MP", "MNP"),
        ("MQ", "MTQ"),
        ("MR", "MRT"),
        ("MS", "MSR"),
        ("MT", "MLT"),
        ("MU", "MUS"),
        ("MV", "MDV"),
        ("MW", "MWI"),
        ("MX", "MEX"),
        ("MY", "MYS"),
        ("MZ", "MOZ"),
        ("NA", "NAME"),
        ("NC", "NCL"),
        ("NE", "NER"),
        ("NF", "NFK"),
        ("NG", "NGA"),
        ("NI", "NIC"),
        ("NL", "NLD"),
        ("NO", "NOR"),
        ("NP", "NPL"),
        ("NR", "NRU"),
        ("NU", "NIU"),
        ("NZ", "NZL"),
        ("OM", "OMN"),
        ("PA", "PAN"),
        ("PE", "PER"),
        ("PF", "PYF"),
        ("PG", "PNG"),
        ("PH", "PHL"),
        ("PK", "PAK"),
        ("PL", "POL"),
        ("PM", "SPM"),
        ("ON", "PCN"),
        ("PR", "PRI"),
        ("PS", "PSE"),
        ("PT", "PRT"),
        ("PW", "PLW"),
        ("PY", "PRY"),
        ("QA", "QAT"),
        ("RE", "REU"),
        ("RO", "ROU"),
        ("RS", "SRB"),
        ("RU", "RUS"),
        ("RW", "RWA"),
        ("SA", "SAU"),
        ("SB", "SLB"),
        ("SC", "SYC"),
        ("SD", "SDN"),
        ("SE", "SWE"),
        ("SG", "SGP"),
        ("SH", "SHN"),
        ("SI", "SVN"),
        ("SJ", "SJM"),
        ("SK", "SVK"),
        ("SL", "SLE"),
        ("SM", "SMR"),
        ("SN", "SEN"),
        ("SO", "SOME"),
        ("SR", "SURE"),
        ("SS", "SSD"),
        ("ST", "STP"),
        ("SV", "SLV"),
        ("SX", "SXM"),
        ("SY", "SYR"),
        ("SZ", "SWZ"),
        ("TC", "TCA"),
        ("TD", "TCD"),
        ("TF", "ATF"),
        ("TG", "TGO"),
        ("TH", "THA"),
        ("TJ", "TJK"),
        ("TK", "TKL"),
        ("TL", "TLS"),
        ("TM", "TKM"),
        ("TN", "TUN"),
        ("TO", "TON"),
        ("TR", "TUR"),
        ("TT", "TO"),
        ("TV", "TUV"),
        ("TW", "TWN"),
        ("TZ", "TZA"),
        ("UA", "UKR"),
        ("UG", "UGA"),
        ("UM", "UMI"),
        ("US", "USA"),
        ("UY", "URY"),
        ("UZ", "UZB"),
        ("VA", "VAT"),
        ("VC", "VCT"),
        ("VE", "VEN"),
        ("VG", "VGB"),
        ("VI", "VIR"),
        ("VN", "VNM"),
        ("VU", "VUT"),
        ("WF", "WLF"),
        ("WS", "WSM"),
        ("XK", "XKX"),
        ("YE", "YEM"),
        ("YT", "MYT"),
        ("ZA", "ZAF"),
        ("ZM", "ZMB"),
        ("ZW", "ZWE"),
    ];
    TABLE.iter().find(|(a2, _)| *a2 == code).map(|(_, a3)| *a3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_us() {
        assert_eq!(alpha2_to_emoji("US"), "🇺🇸");
    }

    #[test]
    fn emoji_fr() {
        assert_eq!(alpha2_to_emoji("FR"), "🇫🇷");
    }

    #[test]
    fn alpha3_lookup() {
        assert_eq!(alpha2_to_alpha3("US"), Some("USA"));
        assert_eq!(alpha2_to_alpha3("FR"), Some("FRA"));
        assert_eq!(alpha2_to_alpha3("ZZ"), None);
    }

    #[test]
    fn format_parse_defaults_to_alpha2() {
        let f = CountryFormat::parse("").unwrap();
        assert!(f.alpha2 && !f.emoji && !f.alpha3 && !f.name);
    }

    #[test]
    fn format_parse_combined() {
        let f = CountryFormat::parse("emoji,alpha3").unwrap();
        assert!(f.emoji && f.alpha3 && !f.alpha2 && !f.name);
    }

    #[test]
    fn format_parse_plus_separator() {
        let f = CountryFormat::parse("emoji+alpha2+name").unwrap();
        assert!(f.emoji && f.alpha2 && f.name && !f.alpha3);
    }

    #[test]
    fn format_parse_unknown_component() {
        assert!(CountryFormat::parse("bogus").is_err());
    }
}
