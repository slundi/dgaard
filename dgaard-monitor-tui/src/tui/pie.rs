//! Pie chart widget drawn with half blocks.
//!
//! ratatui has no pie chart.  A terminal cell is about twice as tall as it
//! is wide, so splitting it into an upper and a lower half (`▀` with a
//! foreground and a background colour) gives square pixels and a round pie.
//! Slices start at twelve o'clock and run clockwise, in the order given.

use std::f64::consts::TAU;

use ratatui::{
    buffer::Buffer,
    layout::{Position, Rect},
    style::Color,
    widgets::Widget,
};

/// A pie of `(value, colour)` slices; zero-valued slices take no room.
pub struct PieChart<'slices> {
    slices: &'slices [(u64, Color)],
    total: u64,
}

impl<'slices> PieChart<'slices> {
    pub fn new(slices: &'slices [(u64, Color)]) -> Self {
        let total = slices.iter().map(|(value, _)| value).sum();
        Self { slices, total }
    }

    /// Colour of the pixel at (`column`, `row`) in pixel units of a pie
    /// `diameter` pixels wide; `None` outside the disc or for an empty pie.
    fn pixel(&self, column: u16, row: u16, diameter: u16) -> Option<Color> {
        if self.total == 0 {
            return None;
        }
        let radius = f64::from(diameter) / 2.0;
        let dx = f64::from(column) + 0.5 - radius;
        let dy = f64::from(row) + 0.5 - radius;
        if dx * dx + dy * dy > radius * radius {
            return None;
        }
        // Clockwise from twelve o'clock, in [0, 1).
        let turn = dx.atan2(-dy).rem_euclid(TAU) / TAU;
        let mut start = 0.0;
        for &(value, color) in self.slices {
            start += value as f64 / self.total as f64;
            if turn < start {
                return Some(color);
            }
        }
        // Rounding left `turn` just past the last boundary.
        self.slices
            .iter()
            .rev()
            .find(|(value, _)| *value > 0)
            .map(|&(_, color)| color)
    }
}

impl Widget for PieChart<'_> {
    /// Draw the largest pie that fits, centred in `area`.
    fn render(self, area: Rect, buf: &mut Buffer) {
        let diameter = area.width.min(area.height.saturating_mul(2));
        if diameter < 2 {
            return;
        }
        let rows = diameter.div_ceil(2);
        let left = area.x + (area.width - diameter) / 2;
        let top = area.y + (area.height - rows) / 2;
        for row in 0..rows {
            for column in 0..diameter {
                let upper = self.pixel(column, row * 2, diameter);
                let lower = self.pixel(column, row * 2 + 1, diameter);
                let Some(cell) = buf.cell_mut(Position::new(left + column, top + row)) else {
                    continue;
                };
                match (upper, lower) {
                    (Some(upper), Some(lower)) => {
                        cell.set_symbol("▀").set_fg(upper).set_bg(lower);
                    }
                    (Some(upper), None) => {
                        cell.set_symbol("▀").set_fg(upper);
                    }
                    (None, Some(lower)) => {
                        cell.set_symbol("▄").set_fg(lower);
                    }
                    (None, None) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render `slices` into a `width` × `height` buffer.
    fn draw(slices: &[(u64, Color)], width: u16, height: u16) -> Buffer {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        PieChart::new(slices).render(area, &mut buf);
        buf
    }

    /// Colours used by the half blocks of the buffer, upper and lower.
    fn colors(buf: &Buffer) -> Vec<Color> {
        buf.content()
            .iter()
            .flat_map(|cell| match cell.symbol() {
                "▀" => vec![cell.fg, cell.bg],
                "▄" => vec![cell.fg],
                _ => vec![],
            })
            .filter(|color| *color != Color::Reset)
            .collect()
    }

    fn share(buf: &Buffer, color: Color) -> f64 {
        let all = colors(buf);
        all.iter().filter(|used| **used == color).count() as f64 / all.len() as f64
    }

    #[test]
    fn test_pixel_outside_the_disc_is_empty() {
        let pie = PieChart::new(&[(1, Color::Red)]);
        assert_eq!(pie.pixel(0, 0, 20), None, "corner");
        assert_eq!(pie.pixel(10, 10, 20), Some(Color::Red), "centre");
    }

    #[test]
    fn test_pixel_slices_run_clockwise_from_noon() {
        let pie = PieChart::new(&[(1, Color::Red), (1, Color::Blue)]);
        // Right half is the first slice, left half the second.
        assert_eq!(pie.pixel(15, 5, 20), Some(Color::Red));
        assert_eq!(pie.pixel(15, 15, 20), Some(Color::Red));
        assert_eq!(pie.pixel(4, 15, 20), Some(Color::Blue));
        assert_eq!(pie.pixel(4, 5, 20), Some(Color::Blue));
    }

    #[test]
    fn test_pixel_skips_empty_slices() {
        let pie = PieChart::new(&[(0, Color::Green), (3, Color::Red), (0, Color::Blue)]);
        for (column, row) in [(10, 2), (17, 10), (10, 17), (3, 10)] {
            assert_eq!(pie.pixel(column, row, 20), Some(Color::Red));
        }
    }

    #[test]
    fn test_empty_pie_draws_nothing() {
        let buf = draw(&[(0, Color::Red)], 20, 10);
        assert!(colors(&buf).is_empty());
        let buf = draw(&[], 20, 10);
        assert!(colors(&buf).is_empty());
    }

    #[test]
    fn test_area_shares_follow_values() {
        let buf = draw(&[(3, Color::Red), (1, Color::Blue)], 40, 20);
        let red = share(&buf, Color::Red);
        assert!((red - 0.75).abs() < 0.03, "red share {red}");
        let blue = share(&buf, Color::Blue);
        assert!((blue - 0.25).abs() < 0.03, "blue share {blue}");
    }

    #[test]
    fn test_pie_is_round_and_centred() {
        // 30 columns, 10 rows: a 20-pixel pie, 20 columns wide, centred.
        let buf = draw(&[(1, Color::Red)], 30, 10);
        let drawn_columns: Vec<u16> = (0..30)
            .filter(|&column| (0..10).any(|row| buf[(column, row)].symbol() != " "))
            .collect();
        assert_eq!(drawn_columns.first(), Some(&5));
        assert_eq!(drawn_columns.last(), Some(&24));
        // Middle row spans the full diameter, top row is narrower.
        let width_of = |row: u16| {
            (0..30)
                .filter(|&col| buf[(col, row)].symbol() != " ")
                .count()
        };
        assert_eq!(width_of(5), 20);
        assert!(width_of(0) < 20);
    }

    #[test]
    fn test_edge_uses_lower_half_blocks() {
        // The top edge of the disc only fills the lower half of some cells.
        let buf = draw(&[(1, Color::Red)], 20, 10);
        assert!(buf.content().iter().any(|cell| cell.symbol() == "▄"));
    }

    #[test]
    fn test_too_small_area_draws_nothing() {
        assert!(colors(&draw(&[(1, Color::Red)], 1, 10)).is_empty());
        assert!(colors(&draw(&[(1, Color::Red)], 20, 0)).is_empty());
    }

    #[test]
    fn test_render_stays_inside_an_offset_area() {
        let full = Rect::new(0, 0, 30, 12);
        let mut buf = Buffer::empty(full);
        PieChart::new(&[(1, Color::Red)]).render(Rect::new(10, 2, 10, 5), &mut buf);
        for row in 0..12 {
            for column in 0..30 {
                let inside = (10..20).contains(&column) && (2..7).contains(&row);
                if !inside {
                    assert_eq!(buf[(column, row)].symbol(), " ", "({column}, {row})");
                }
            }
        }
    }
}
