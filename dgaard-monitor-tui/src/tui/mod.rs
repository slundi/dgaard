//! TUI entry point — crossterm raw mode, tick loop, render dispatch.

mod app;
mod input;
mod keys;
mod pie;
mod scroll;
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
    let areas = top_bar::layout(frame.area());
    top_bar::render(frame, &areas, app, &tab_states.dashboard);

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
