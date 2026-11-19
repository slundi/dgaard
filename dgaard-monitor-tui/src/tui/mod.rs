//! TUI entry point — crossterm raw mode, tick loop, render dispatch.

mod app;
mod input;
mod keys;
mod pie;
mod scroll;
mod search;
mod tabs;
mod top_bar;
mod util;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{Event, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::watch;

use app::TuiApp;
use input::Flow;
use tabs::talkers::ReverseDns;
use tabs::{Tab, TabStates};

use crate::config::TuiConfig;
use dgaard_monitor_core::state::AppState;

/// Run the TUI until the user quits, the terminal fails, or `shutdown` is
/// signalled. Returning (rather than exiting the process) lets the caller run
/// its clean shutdown sequence.
pub async fn run(config: TuiConfig, state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("TUI setup failed: {e}");
            return;
        }
    };

    let mut app = TuiApp::new(&config);
    let mut tab_states = TabStates::default();
    let reverse_dns = ReverseDns::from_system();
    let mut event_rx = state.subscribe();

    // Dedicated thread for blocking crossterm key reads.
    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<KeyEvent>();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    std::thread::spawn(move || {
        loop {
            if stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match crossterm::event::poll(Duration::from_millis(50)) {
                Ok(true) => {
                    if let Ok(Event::Key(key)) = crossterm::event::read()
                        && key_tx.send(key).is_err()
                    {
                        break;
                    }
                }
                Ok(false) => {}
                Err(_) => break,
            }
        }
    });

    // `interval` panics on a zero period; the config parser rejects it too.
    let mut tick = tokio::time::interval(Duration::from_millis(config.tick_ms.max(1)));

    'main: loop {
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() { break 'main; }
            }

            Ok(event) = event_rx.recv() => {
                if !app.frozen {
                    let domain = {
                        let map = state.domain_map.read().await;
                        map.get(&event.domain_hash).cloned().unwrap_or_default()
                    };
                    if tab_states.push_event(&event, &domain) {
                        reverse_dns.lookup(event.client_ip);
                    }
                }
            }

            Some(key) = key_rx.recv() => {
                if input::handle_key(&key, &mut app, &mut tab_states) == Flow::Quit {
                    break 'main;
                }
            }

            _ = tick.tick() => {
                if terminal.draw(|f| render_frame(f, &app, &mut tab_states)).is_err() {
                    break 'main;
                }
            }
        }
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    restore_terminal(&mut terminal);
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

fn render_frame(frame: &mut ratatui::Frame, app: &TuiApp, tab_states: &mut TabStates) {
    use ratatui::layout::{Constraint, Layout};

    // The open search prompt takes the bottom row.
    let prompt_height = if app.prompt.is_some() {
        search::PROMPT_HEIGHT
    } else {
        0
    };
    let [screen, prompt_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(prompt_height)])
            .areas(frame.area());
    let areas = top_bar::layout(screen);
    top_bar::render(frame, &areas, app, tab_states);
    if let Some(prompt) = &app.prompt {
        search::render_prompt(frame, prompt_area, prompt);
    }

    let body_area = areas.body;
    match app.active_tab {
        Tab::Dashboard => {
            tabs::dashboard::render(&tab_states.dashboard, app.scroll, body_area, frame)
        }
        Tab::Queries => tabs::queries::render(
            &mut tab_states.queries,
            app.frozen,
            app.country_display,
            body_area,
            frame,
        ),
        Tab::Talkers => {
            tabs::talkers::render(&mut tab_states.talkers, app.frozen, body_area, frame)
        }
        Tab::Timelines => {
            tabs::timelines::render(&mut tab_states.timelines, app.frozen, body_area, frame)
        }
        Tab::About => tabs::about::render(&app.keymap, body_area, frame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};
    use ratatui::backend::TestBackend;
    use scroll::Scrollable;
    use search::SearchPrompt;
    use tabs::queries::FilterMode;

    fn event(timestamp: u64, last_octet: u8, action: StatAction) -> StatEvent {
        StatEvent {
            country: None,
            timestamp,
            domain_hash: 0xbeef,
            client_ip: std::net::Ipv4Addr::new(10, 0, 0, last_octet)
                .to_ipv6_mapped()
                .octets(),
            action,
        }
    }

    /// Two clients: 10.0.0.1 asks `ads.tracker.net`, 10.0.0.2 `example.com`.
    fn sample_tabs() -> TabStates {
        let mut tabs = TabStates::default();
        for timestamp in 0..6 {
            let blocked = StatAction::Blocked(StatBlockReason::ABP_RULE);
            tabs.push_event(&event(timestamp * 2, 1, blocked), "ads.tracker.net");
            let allowed = event(timestamp * 2 + 1, 2, StatAction::Allowed);
            tabs.push_event(&allowed, "example.com");
        }
        tabs
    }

    fn draw(app: &TuiApp, tabs: &mut TabStates, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render_frame(frame, app, tabs))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_render_frame_prompt_takes_the_bottom_row() {
        let mut app = TuiApp::new(&TuiConfig::default());
        app.active_tab = Tab::Queries;
        let mut tabs = sample_tabs();
        let closed = draw(&app, &mut tabs, 110, 30);
        assert!(!closed[29].starts_with('/'));
        let closed_page = tabs.queries.page_size();

        app.prompt = Some(SearchPrompt::open(&FilterMode::None));
        app.prompt.as_mut().unwrap().text = "tracker".to_string();
        tabs.queries.set_filter(FilterMode::search("tracker"));
        let open = draw(&app, &mut tabs, 110, 30);
        assert!(open[29].starts_with("/tracker"), "{}", open[29]);
        assert_eq!(tabs.queries.page_size(), closed_page - 1, "body gave a row");
        assert!(
            open.iter()
                .any(|line| line.contains("Live Feed · /tracker"))
        );
        assert!(open.iter().any(|line| line.contains("Queries 6/12")));
        assert!(!open.iter().any(|line| line.contains("example.com")));
    }

    #[test]
    fn test_render_frame_without_prompt_has_no_cursor_line() {
        let app = TuiApp::new(&TuiConfig::default());
        let mut tabs = sample_tabs();
        let lines = draw(&app, &mut tabs, 110, 30);
        assert!(lines.iter().any(|line| line.contains("Recent Domains")));
        assert!(lines[29].starts_with('└'), "{}", lines[29]);
    }
}
