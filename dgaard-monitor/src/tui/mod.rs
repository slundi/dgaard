//! TUI entry point — crossterm raw mode, tick loop, render dispatch.

mod app;
mod keys;
mod layout;
mod tabs;
mod util;
mod widgets;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::Tabs,
};
use tokio::sync::watch;

use app::TuiApp;
use keys::Action;
use tabs::Tab;
use tabs::dashboard::DashboardState;

use crate::config::TuiConfig;
use crate::state::AppState;

pub async fn run(config: TuiConfig, state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("TUI setup failed: {e}");
            return;
        }
    };

    let mut app = TuiApp::new(&config);
    let mut dashboard = DashboardState::new();
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

    let mut tick = tokio::time::interval(Duration::from_millis(config.tick_ms));
    let mut quit_requested = false;

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
                    dashboard.push_event(&event, &domain);
                }
            }

            Some(key) = key_rx.recv() => {
                if let Some(action) = app.keymap.resolve(&key_to_str(key)) {
                    match action {
                        Action::Quit => { quit_requested = true; break 'main; }
                        _ => app.apply(action),
                    }
                }
            }

            _ = tick.tick() => {
                if terminal.draw(|f| render_frame(f, &app, &dashboard)).is_err() {
                    break 'main;
                }
            }
        }
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    restore_terminal(&mut terminal);

    if quit_requested {
        std::process::exit(0);
    }
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

fn key_to_str(key: KeyEvent) -> String {
    match key.code {
        KeyCode::Char(' ') => "space".to_string(),
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                c.to_uppercase().to_string()
            } else {
                c.to_string()
            }
        }
        KeyCode::Up => "up".to_string(),
        KeyCode::Down => "down".to_string(),
        KeyCode::Left => "left".to_string(),
        KeyCode::Right => "right".to_string(),
        KeyCode::Tab => "tab".to_string(),
        KeyCode::BackTab => "backtab".to_string(),
        KeyCode::Esc => "esc".to_string(),
        KeyCode::Enter => "enter".to_string(),
        KeyCode::Backspace => "backspace".to_string(),
        KeyCode::Delete => "delete".to_string(),
        KeyCode::Home => "home".to_string(),
        KeyCode::End => "end".to_string(),
        KeyCode::PageUp => "pageup".to_string(),
        KeyCode::PageDown => "pagedown".to_string(),
        KeyCode::F(n) => format!("f{n}"),
        _ => String::new(),
    }
}

fn render_frame(frame: &mut ratatui::Frame, app: &TuiApp, dashboard: &DashboardState) {
    let area = frame.area();
    let [tab_bar_area, body_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);

    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.label())).collect();
    let active_idx = Tab::ALL
        .iter()
        .position(|t| *t == app.active_tab)
        .unwrap_or(0);
    frame.render_widget(
        Tabs::new(titles).select(active_idx).highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        tab_bar_area,
    );

    match app.active_tab {
        Tab::Dashboard => tabs::dashboard::render(dashboard, app.scroll, body_area, frame),
        Tab::Queries => tabs::queries::render(body_area, frame),
        Tab::Talkers => tabs::talkers::render(body_area, frame),
        Tab::Timelines => tabs::timelines::render(body_area, frame),
        Tab::About => tabs::about::render(&app.keymap, body_area, frame),
    }
}
