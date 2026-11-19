//! The `/` search prompt.
//!
//! `/` opens a one-line prompt at the bottom of the screen.  The Queries
//! filter follows the text as it is typed (`FilterMode::search`), so the
//! Queries tab and the top bar Live Feed narrow down live:
//!
//!   /192.168.1.5▏          enter keep · esc cancel · ctrl+u erase
//!
//! `enter` closes the prompt and keeps the filter; `esc` closes it and puts
//! back the filter that was there before.  Outside the prompt, `esc` clears
//! the filter.  Key handling lives in `input`.

use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::tabs::queries::FilterMode;

/// Longest search accepted: a full domain name is at most 253 characters.
pub const MAX_SEARCH_LEN: usize = 253;

/// Rows the open prompt takes at the bottom of the screen.
pub const PROMPT_HEIGHT: u16 = 1;

const HINT: &str = "enter keep · esc cancel · ctrl+u erase";

/// State of the open prompt.
#[derive(Debug, PartialEq)]
pub struct SearchPrompt {
    /// Text typed so far.
    pub text: String,
    /// Filter in force when the prompt opened, restored by `esc`.
    pub previous: FilterMode,
}

impl SearchPrompt {
    /// Open the prompt on the current filter: a `/` search is edited again,
    /// any other filter starts from an empty line.
    pub fn open(current: &FilterMode) -> Self {
        Self {
            text: current.search_text().unwrap_or_default().to_string(),
            previous: current.clone(),
        }
    }

    /// Add a typed character; `false` when the text is already full.
    pub fn push(&mut self, character: char) -> bool {
        if self.text.chars().count() >= MAX_SEARCH_LEN {
            return false;
        }
        self.text.push(character);
        true
    }

    /// The filter the current text stands for.
    pub fn filter(&self) -> FilterMode {
        FilterMode::search(&self.text)
    }
}

/// Draw the prompt into the one-row `area` and put the cursor after the text.
pub fn render_prompt(frame: &mut Frame, area: Rect, prompt: &SearchPrompt) {
    let text = Span::raw(prompt.text.as_str());
    let cursor_x = area
        .x
        .saturating_add(1)
        .saturating_add(u16::try_from(text.width()).unwrap_or(u16::MAX));
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "/",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            text,
            Span::styled(format!("   {HINT}"), Style::new().fg(Color::DarkGray)),
        ])),
        area,
    );
    if cursor_x < area.right() {
        frame.set_cursor_position(Position::new(cursor_x, area.y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::StatBlockReason;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn test_open_without_filter_is_empty() {
        let prompt = SearchPrompt::open(&FilterMode::None);
        assert_eq!(prompt.text, "");
        assert_eq!(prompt.previous, FilterMode::None);
        assert_eq!(prompt.filter(), FilterMode::None);
    }

    #[test]
    fn test_open_edits_the_current_search() {
        let current = FilterMode::search("ads");
        let prompt = SearchPrompt::open(&current);
        assert_eq!(prompt.text, "ads");
        assert_eq!(prompt.previous, current);
    }

    #[test]
    fn test_open_over_a_flag_filter_starts_empty_and_keeps_it() {
        let current = FilterMode::ByFlags(StatBlockReason::NRD_LIST);
        let prompt = SearchPrompt::open(&current);
        assert_eq!(prompt.text, "");
        assert_eq!(prompt.previous, current);
    }

    #[test]
    fn test_push_stops_at_the_limit() {
        let mut prompt = SearchPrompt::open(&FilterMode::None);
        for _ in 0..MAX_SEARCH_LEN {
            assert!(prompt.push('é'));
        }
        assert!(!prompt.push('x'));
        assert_eq!(prompt.text.chars().count(), MAX_SEARCH_LEN);
    }

    #[test]
    fn test_filter_follows_the_text() {
        let mut prompt = SearchPrompt::open(&FilterMode::None);
        prompt.push('a');
        prompt.push('d');
        assert_eq!(prompt.filter(), FilterMode::search("ad"));
    }

    fn draw(prompt: &SearchPrompt, width: u16) -> (String, Position) {
        let mut terminal = Terminal::new(TestBackend::new(width, 1)).unwrap();
        terminal
            .draw(|frame| render_prompt(frame, frame.area(), prompt))
            .unwrap();
        let line = (0..width)
            .map(|column| {
                terminal.backend().buffer()[(column, 0)]
                    .symbol()
                    .to_string()
            })
            .collect();
        let cursor = terminal.get_cursor_position().unwrap();
        (line, cursor)
    }

    #[test]
    fn test_render_shows_text_hint_and_cursor() {
        let prompt = SearchPrompt::open(&FilterMode::search("tracker"));
        let (line, cursor) = draw(&prompt, 80);
        assert!(line.starts_with("/tracker"), "{line}");
        assert!(line.contains("esc cancel"));
        assert_eq!(cursor, Position::new(8, 0));
    }

    #[test]
    fn test_render_narrow_prompt_keeps_the_text() {
        let prompt = SearchPrompt::open(&FilterMode::search("10.0.0.1"));
        let (line, _) = draw(&prompt, 12);
        assert!(line.starts_with("/10.0.0.1"), "{line}");
    }
}
