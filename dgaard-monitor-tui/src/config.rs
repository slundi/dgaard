/// How the country hosting a domain is shown (`[tui] country_display`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CountryDisplay {
    /// ISO 3166-1 alpha-2 code (`FR`): readable in every terminal.
    #[default]
    Code,
    /// Flag emoji (🇫🇷): needs a terminal and font that render them.
    Emoji,
}

impl CountryDisplay {
    /// The other mode, for the runtime toggle.
    pub fn toggle(self) -> Self {
        match self {
            Self::Code => Self::Emoji,
            Self::Emoji => Self::Code,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TuiConfig {
    /// Terminal refresh interval in milliseconds.
    pub tick_ms: u64,
    pub key_quit: String,
    pub key_pause: String,
    pub key_scroll_up: String,
    pub key_scroll_down: String,
    /// Initial country display; the `e` key toggles it at runtime.
    pub country_display: CountryDisplay,
}

fn default_tick_ms() -> u64 {
    250
}
fn default_key_quit() -> String {
    "q".to_string()
}
fn default_key_pause() -> String {
    "space".to_string()
}
fn default_key_scroll_up() -> String {
    "up".to_string()
}
fn default_key_scroll_down() -> String {
    "down".to_string()
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            tick_ms: default_tick_ms(),
            key_quit: default_key_quit(),
            key_pause: default_key_pause(),
            key_scroll_up: default_key_scroll_up(),
            key_scroll_down: default_key_scroll_down(),
            country_display: CountryDisplay::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_display_default_is_code() {
        assert_eq!(TuiConfig::default().country_display, CountryDisplay::Code);
    }

    #[test]
    fn test_country_display_toggle() {
        assert_eq!(CountryDisplay::Code.toggle(), CountryDisplay::Emoji);
        assert_eq!(CountryDisplay::Emoji.toggle(), CountryDisplay::Code);
    }
}
