use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use inotify::{EventMask, Inotify, WatchMask};
use tokio::sync::{mpsc, watch};

use crate::io::index::read_host_index;
use crate::state::AppState;

/// Watch `index_path` with inotify and replace the host-index part of the
/// domain map whenever the file is rewritten in place (`CLOSE_WRITE`) or
/// atomically replaced through `rename(2)` (`MOVED_TO`).
///
/// The watch is set on the parent directory, not on the file: a file watch
/// follows the inode, which disappears with the first atomic replacement.
/// It also picks up an index that does not exist yet at startup.
///
/// Returns when `shutdown` is signalled or the inotify thread exits.
pub async fn watch_index(
    index_path: String,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some((dir, file_name)) = split_index_path(&index_path) else {
        eprintln!("inotify: invalid index path {index_path:?}, index changes will not be tracked");
        return;
    };

    // Capacity 1 coalesces bursts: a pending notification already means a
    // reload that will read the latest file.
    let (tx, mut rx) = mpsc::channel::<()>(1);

    // Dedicated OS thread so the blocking read never stalls the runtime.
    std::thread::spawn(move || watch_directory(&dir, &file_name, &tx));

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

/// Split `path` into the directory to watch and the file name to match.
fn split_index_path(path: &str) -> Option<(PathBuf, OsString)> {
    let path = Path::new(path);
    let file_name = path.file_name()?.to_os_string();
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Some((dir, file_name))
}

fn watch_directory(dir: &Path, file_name: &OsStr, tx: &mpsc::Sender<()>) {
    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("inotify init error: {e}");
            return;
        }
    };

    if let Err(e) = inotify
        .watches()
        .add(dir, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
    {
        eprintln!(
            "inotify: failed to watch {}: {e}, index changes will not be tracked",
            dir.display()
        );
        return;
    }

    let mut buf = [0u8; 4096];
    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(events) => events,
            Err(e) => {
                eprintln!("inotify read error: {e}");
                return;
            }
        };
        let mut changed = false;
        let mut watch_removed = false;
        for event in events {
            watch_removed |= event.mask.contains(EventMask::IGNORED);
            changed |= event.name == Some(file_name);
        }
        if changed {
            match tx.try_send(()) {
                // Full: a reload is already pending and will see this change.
                Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
                // Async side has shut down — exit the thread.
                Err(mpsc::error::TrySendError::Closed(())) => return,
            }
        }
        if watch_removed {
            eprintln!(
                "inotify: {} was removed, index changes will not be tracked",
                dir.display()
            );
            return;
        }
    }
}

async fn reload(path: &str, state: &AppState) {
    let owned = path.to_string();
    match tokio::task::spawn_blocking(move || read_host_index(&owned)).await {
        Ok(Ok(map)) => {
            let count = map.len();
            state.replace_index(map).await;
            eprintln!("Index reloaded: {count} domains from {path}");
        }
        Ok(Err(e)) => eprintln!("Index reload failed ({path}): {e}"),
        Err(e) => eprintln!("Index reload task failed ({path}): {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn index_bytes(entries: &[(u64, &str)]) -> Vec<u8> {
        let mut buf = b"DGHI".to_vec();
        buf.push(0x01);
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (hash, domain) in entries {
            buf.extend_from_slice(&hash.to_le_bytes());
            buf.extend_from_slice(&(domain.len() as u16).to_le_bytes());
            buf.extend_from_slice(domain.as_bytes());
        }
        buf
    }

    /// Same pattern as dgaard's `write_atomic`: temp file, then rename.
    fn write_atomic(path: &Path, entries: &[(u64, &str)]) {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, index_bytes(entries)).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    async fn wait_for_map(state: &AppState, expected: &[(u64, &str)]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let map = state.domain_map.read().await;
                let matches = map.len() == expected.len()
                    && expected
                        .iter()
                        .all(|(hash, domain)| map.get(hash).map(String::as_str) == Some(*domain));
                if matches {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "expected {expected:?}, domain map is {map:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Start the watcher and give its thread time to register the watch.
    async fn start_watcher(
        path: &Path,
    ) -> (
        Arc<AppState>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(watch_index(
            path.to_str().unwrap().to_string(),
            Arc::clone(&state),
            shutdown_rx,
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        (state, shutdown_tx, handle)
    }

    #[test]
    fn split_index_path_handles_bare_file_name() {
        let (dir, name) = split_index_path("hosts.bin").unwrap();
        assert_eq!(dir, PathBuf::from("."));
        assert_eq!(name, OsString::from("hosts.bin"));

        let (dir, name) = split_index_path("/var/dgaard/hosts.bin").unwrap();
        assert_eq!(dir, PathBuf::from("/var/dgaard"));
        assert_eq!(name, OsString::from("hosts.bin"));

        assert!(split_index_path("/").is_none());
    }

    /// Regression: the file watch used to die with the first `rename(2)`.
    /// The index is also absent at startup, which used to disable tracking.
    #[tokio::test]
    async fn reloads_on_every_atomic_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.bin");
        let (state, shutdown_tx, handle) = start_watcher(&path).await;

        write_atomic(&path, &[(1, "one.test")]);
        wait_for_map(&state, &[(1, "one.test")]).await;

        write_atomic(&path, &[(2, "two.test")]);
        wait_for_map(&state, &[(2, "two.test")]).await;

        write_atomic(&path, &[(2, "two.test"), (3, "three.test")]);
        wait_for_map(&state, &[(2, "two.test"), (3, "three.test")]).await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// Regression: with the index present at startup, a file watch saw the
    /// first replacement and then lost its inode for good.
    #[tokio::test]
    async fn existing_index_survives_repeated_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.bin");
        write_atomic(&path, &[(1, "one.test")]);
        let (state, shutdown_tx, handle) = start_watcher(&path).await;

        write_atomic(&path, &[(2, "two.test")]);
        wait_for_map(&state, &[(2, "two.test")]).await;

        write_atomic(&path, &[(3, "three.test")]);
        wait_for_map(&state, &[(3, "three.test")]).await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn reloads_on_in_place_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.bin");
        std::fs::write(&path, index_bytes(&[(1, "one.test")])).unwrap();
        let (state, shutdown_tx, handle) = start_watcher(&path).await;

        std::fs::write(&path, index_bytes(&[(4, "four.test")])).unwrap();
        wait_for_map(&state, &[(4, "four.test")]).await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn reload_keeps_runtime_mappings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.bin");
        let (state, shutdown_tx, handle) = start_watcher(&path).await;
        state.insert_domain(9, "live.test".to_string()).await;

        write_atomic(&path, &[(1, "one.test")]);
        wait_for_map(&state, &[(1, "one.test"), (9, "live.test")]).await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
