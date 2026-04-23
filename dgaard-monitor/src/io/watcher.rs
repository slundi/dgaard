use std::sync::Arc;

use inotify::{Inotify, WatchMask};
use tokio::sync::watch;

use crate::io::index::read_host_index;
use crate::state::AppState;

/// Watch `index_path` with inotify and merge new entries into `state` on every
/// `CLOSE_WRITE` or `MOVED_TO` event (the two patterns used by atomic writers).
///
/// Returns when `shutdown` is signalled or the inotify thread exits.
pub async fn watch_index(
    index_path: String,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Channel between the blocking inotify thread and this async task.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);

    // Spawn a dedicated OS thread so the blocking read never stalls the runtime.
    let watch_path = index_path.clone();
    std::thread::spawn(move || {
        let mut inotify = match Inotify::init() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("inotify init error: {e}");
                return;
            }
        };

        if let Err(e) = inotify
            .watches()
            .add(&watch_path, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
        {
            eprintln!("inotify: failed to watch {watch_path}: {e}");
            return;
        }

        let mut buf = [0u8; 1024];
        loop {
            match inotify.read_events_blocking(&mut buf) {
                Ok(events) => {
                    // Drain the iterator (required before the next read call).
                    let _ = events.count();
                    if tx.blocking_send(()).is_err() {
                        // Async side has shut down — exit the thread.
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("inotify read error: {e}");
                    break;
                }
            }
        }
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            event = rx.recv() => {
                if event.is_none() {
                    // Watcher thread exited (e.g. inotify error).
                    break;
                }
                reload(&index_path, &state).await;
            }
        }
    }
}

async fn reload(path: &str, state: &Arc<AppState>) {
    match read_host_index(path) {
        Ok(map) => {
            let count = map.len();
            for (hash, domain) in map {
                state.insert_domain(hash, domain).await;
            }
            println!("Index reloaded: {count} domains from {path}");
        }
        Err(e) => eprintln!("Index reload failed ({path}): {e}"),
    }
}
