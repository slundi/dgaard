//! Scroll position of a table that only renders its visible rows.
//!
//! `ScrollState` keeps the index of the top row and the table height seen at
//! the last render, so the offset never goes past the point where the last
//! row sits at the bottom.  Tabs embed one and implement `Scrollable`, which
//! gives them the scroll operations the input handler calls.

/// Top-row offset and visible height of one scrollable table.
#[derive(Debug, Default)]
pub struct ScrollState {
    /// Index, in the filtered and sorted list, of the top row on screen.
    offset: usize,
    /// Rows the table could show at the last render.
    viewport: usize,
}

impl ScrollState {
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Largest offset that still fills the view for a list of `len` rows.
    pub fn max_offset(&self, len: usize) -> usize {
        len.saturating_sub(self.viewport)
    }

    /// Rows moved by one page; at least one before the first render.
    pub fn page_size(&self) -> usize {
        self.viewport.max(1)
    }

    /// Record the table height and keep the offset in range.
    pub fn set_viewport(&mut self, height: usize, len: usize) {
        self.viewport = height;
        self.clamp(len);
    }

    /// Move `delta` rows down (negative: up), within range.
    pub fn scroll_by(&mut self, delta: isize, len: usize) {
        self.offset = self
            .offset
            .saturating_add_signed(delta)
            .min(self.max_offset(len));
    }

    pub fn jump_to_top(&mut self) {
        self.offset = 0;
    }

    pub fn jump_to_bottom(&mut self, len: usize) {
        self.offset = self.max_offset(len);
    }

    /// Pull the offset back after the list shrank.
    pub fn clamp(&mut self, len: usize) {
        self.offset = self.offset.min(self.max_offset(len));
    }
}

/// A tab whose table scrolls with `ScrollState`.
pub trait Scrollable {
    fn scroll_state(&self) -> &ScrollState;
    fn scroll_state_mut(&mut self) -> &mut ScrollState;
    /// Rows the table scrolls over, after filtering.
    fn scroll_len(&self) -> usize;

    /// Index of the top row on screen.
    fn scroll(&self) -> usize {
        self.scroll_state().offset()
    }

    /// Largest `scroll` that still fills the view: the last row sits at the
    /// bottom of the table, never higher.
    fn max_scroll(&self) -> usize {
        self.scroll_state().max_offset(self.scroll_len())
    }

    fn page_size(&self) -> usize {
        self.scroll_state().page_size()
    }

    /// Record how many rows the table can show, and keep `scroll` in range.
    fn set_viewport(&mut self, height: usize) {
        let len = self.scroll_len();
        self.scroll_state_mut().set_viewport(height, len);
    }

    /// Move the view `delta` rows down (negative: up), within range.
    fn scroll_by(&mut self, delta: isize) {
        let len = self.scroll_len();
        self.scroll_state_mut().scroll_by(delta, len);
    }

    fn scroll_to_top(&mut self) {
        self.scroll_state_mut().jump_to_top();
    }

    fn scroll_to_bottom(&mut self) {
        let len = self.scroll_len();
        self.scroll_state_mut().jump_to_bottom(len);
    }
}

/// Draw a vertical scrollbar over the right border of the bordered table in
/// `area`, only when the rows do not all fit.
pub fn render_scrollbar(
    view: &dyn Scrollable,
    area: ratatui::layout::Rect,
    frame: &mut ratatui::Frame,
) {
    use ratatui::{
        layout::Margin,
        widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState},
    };

    let max_scroll = view.max_scroll();
    if max_scroll == 0 {
        return;
    }
    let mut scrollbar = ScrollbarState::new(max_scroll).position(view.scroll());
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_viewport(height: usize, len: usize) -> ScrollState {
        let mut state = ScrollState::default();
        state.set_viewport(height, len);
        state
    }

    #[test]
    fn test_default_is_top_with_one_row_pages() {
        let state = ScrollState::default();
        assert_eq!(state.offset(), 0);
        assert_eq!(state.page_size(), 1);
    }

    #[test]
    fn test_scroll_by_stays_in_range() {
        let mut state = with_viewport(10, 30);
        state.scroll_by(100, 30);
        assert_eq!(state.offset(), 20);
        state.scroll_by(-5, 30);
        assert_eq!(state.offset(), 15);
        state.scroll_by(isize::MIN, 30);
        assert_eq!(state.offset(), 0);
    }

    #[test]
    fn test_short_list_never_scrolls() {
        let mut state = with_viewport(10, 4);
        state.scroll_by(3, 4);
        state.jump_to_bottom(4);
        assert_eq!(state.offset(), 0);
        assert_eq!(state.max_offset(4), 0);
    }

    #[test]
    fn test_top_and_bottom() {
        let mut state = with_viewport(10, 30);
        state.jump_to_bottom(30);
        assert_eq!(state.offset(), 20);
        state.jump_to_top();
        assert_eq!(state.offset(), 0);
    }

    #[test]
    fn test_clamp_after_list_shrinks() {
        let mut state = with_viewport(10, 30);
        state.jump_to_bottom(30);
        state.clamp(15);
        assert_eq!(state.offset(), 5);
    }

    #[test]
    fn test_taller_viewport_pulls_offset_back() {
        let mut state = with_viewport(10, 30);
        state.jump_to_bottom(30);
        state.set_viewport(25, 30);
        assert_eq!(state.offset(), 5);
        assert_eq!(state.page_size(), 25);
    }
}
