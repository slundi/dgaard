#[derive(Debug)]
pub struct TuiConfig {
    /// Terminal refresh interval in milliseconds.
    pub tick_ms: u64,
    pub key_quit: String,
    pub key_pause: String,
    pub key_scroll_up: String,
    pub key_scroll_down: String,
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
        }
    }
}
