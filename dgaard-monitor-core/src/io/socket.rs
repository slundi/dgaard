use std::hash::BuildHasher;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::error::MonitorError;
use crate::protocol::StatMessage;
use crate::state::AppState;

/// Hard cap on the size of an inbound frame's `type + payload` segment.
///
/// The largest legitimate frame today is a `DomainMapping` carrying a
/// 253-byte FQDN (~264 bytes) — 4 KiB leaves comfortable headroom for
/// future extensions while preventing a malicious producer from forcing
/// up to 64 KiB allocations per frame.
pub const MAX_FRAME_PAYLOAD: usize = 4096;

pub async fn connect(path: &str) -> Result<UnixStream, MonitorError> {
    UnixStream::connect(path)
        .await
        .map_err(|e| MonitorError::SocketError(format!("connect to {path}: {e}")))
}

pub async fn read_frame(stream: &mut UnixStream) -> Result<StatMessage, MonitorError> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_le_bytes(len_buf) as usize;

    if msg_len > MAX_FRAME_PAYLOAD {
        return Err(MonitorError::InvalidMessage(format!(
            "frame length {msg_len} exceeds cap {MAX_FRAME_PAYLOAD}"
        )));
    }

    // Read the rest of the frame (msg_len bytes: type + payload)
    let mut payload_buf = vec![0u8; msg_len];
    stream.read_exact(&mut payload_buf).await?;

    // Reconstruct full frame for deserializer: [len: 2][type+payload: msg_len]
    let mut frame = Vec::with_capacity(2 + msg_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload_buf);

    // The whole frame was read, so the stream stays aligned even when the
    // content is unknown: report it as skippable, not as a broken stream.
    StatMessage::deserialize(&frame).ok_or_else(|| {
        MonitorError::UnsupportedFrame(format!(
            "type 0x{:02x}",
            payload_buf.first().copied().unwrap_or(0)
        ))
    })
}

/// Exponential reconnection backoff with "equal jitter": each delay is drawn
/// from `[base / 2, base]`, and `base` doubles from `INITIAL` up to `MAX`.
#[derive(Debug)]
pub struct Backoff {
    base: Duration,
}

impl Backoff {
    pub const INITIAL: Duration = Duration::from_millis(100);
    pub const MAX: Duration = Duration::from_secs(30);

    pub fn new() -> Self {
        Self {
            base: Self::INITIAL,
        }
    }

    /// Delay to wait before the next attempt. Grows the base for the one after.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.base;
        self.base = (self.base * 2).min(Self::MAX);
        let half = base / 2;
        half + half.mul_f64(random_unit())
    }

    /// Back to `INITIAL`, once the connection has proven healthy.
    pub fn reset(&mut self) {
        self.base = Self::INITIAL;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

/// Uniform value in `[0, 1)`. `RandomState` is seeded randomly per instance,
/// which is plenty for jitter and avoids a `rand` dependency.
fn random_unit() -> f64 {
    let bits = std::collections::hash_map::RandomState::new().hash_one(0u8);
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

/// Who may serve the stats socket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Root, this process's user, or the user owning the socket file when it
    /// sits in a directory other users cannot write to. A socket that another
    /// user planted in a world-writable directory such as `/tmp` is refused.
    #[default]
    Auto,
    /// Root or exactly this UID (`[input] peer_uid`).
    Uid(u32),
}

/// What the filesystem says about the socket, for [`decide_peer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketFacts {
    owner_uid: u32,
    /// The directory holding the socket is writable by anyone (e.g. `/tmp`),
    /// so whoever created the socket proves nothing.
    dir_world_writable: bool,
}

fn socket_facts(path: &Path) -> Option<SocketFacts> {
    let owner_uid = std::fs::metadata(path).ok()?.uid();
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let dir_mode = std::fs::metadata(dir).ok()?.mode();
    Some(SocketFacts {
        owner_uid,
        dir_world_writable: dir_mode & 0o002 != 0,
    })
}

/// Accept or refuse the process serving the socket, see [`PeerPolicy`].
fn decide_peer(
    peer_uid: u32,
    own_uid: Option<u32>,
    facts: Option<SocketFacts>,
    policy: PeerPolicy,
) -> Result<(), String> {
    if peer_uid == 0 {
        return Ok(());
    }
    match policy {
        PeerPolicy::Uid(expected) if peer_uid == expected => Ok(()),
        PeerPolicy::Uid(expected) => Err(format!(
            "served by uid {peer_uid}, expected uid {expected} ([input] peer_uid)"
        )),
        PeerPolicy::Auto => {
            if own_uid == Some(peer_uid) {
                return Ok(());
            }
            match facts {
                Some(facts) if !facts.dir_world_writable && facts.owner_uid == peer_uid => Ok(()),
                Some(facts) if !facts.dir_world_writable => Err(format!(
                    "served by uid {peer_uid}, but the socket file belongs to uid {}",
                    facts.owner_uid
                )),
                _ => Err(format!(
                    "served by uid {peer_uid}, neither root nor this user, from a directory \
                     anyone can write to; if this is dgaard, set [input] peer_uid = {peer_uid} \
                     or move the socket to a protected directory"
                )),
            }
        }
    }
}

/// Check who serves the socket at `path` before trusting what it sends: on a
/// shared machine, a local user could create the socket before dgaard does
/// and feed forged events and domain names.
fn verify_peer(
    stream: &UnixStream,
    path: &str,
    own_uid: Option<u32>,
    policy: PeerPolicy,
) -> Result<(), String> {
    let peer_uid = stream
        .peer_cred()
        .map_err(|e| format!("cannot read the peer's credentials: {e}"))?
        .uid();
    decide_peer(peer_uid, own_uid, socket_facts(Path::new(path)), policy)
}

/// This process's effective UID, read from one end of a socket pair (no
/// `libc` needed). Async because tokio sockets need a runtime.
async fn own_uid() -> Option<u32> {
    let (ours, _theirs) = UnixStream::pair().ok()?;
    ours.peer_cred().ok().map(|cred| cred.uid())
}

/// Connect to dgaard's stats socket and feed every frame into `state`,
/// reconnecting with [`Backoff`] after connect failures and stream errors.
///
/// dgaard accepts then closes clients beyond its limit, so a connection that
/// ends before any valid frame keeps growing the delay; the first valid frame
/// resets it. A peer refused by `policy` is retried the same way: dgaard
/// replaces a stale socket file when it starts. Returns when `shutdown` is
/// signalled.
pub async fn run_reader(
    path: String,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
    policy: PeerPolicy,
) {
    let mut backoff = Backoff::new();
    let own_uid = own_uid().await;
    loop {
        // Check for shutdown before attempting a (re)connection.
        if *shutdown.borrow() {
            return;
        }
        let failure = match connect(&path).await {
            Ok(stream) if let Err(reason) = verify_peer(&stream, &path, own_uid, policy) => {
                format!("Refusing {path}: {reason}")
            }
            Ok(mut stream) => {
                eprintln!("Connected to {path}");
                loop {
                    tokio::select! {
                        biased;
                        // Shutdown takes priority over reading.
                        _ = shutdown.changed() => return,
                        result = read_frame(&mut stream) => match result {
                            Ok(StatMessage::DomainMapping { hash, domain }) => {
                                backoff.reset();
                                state.insert_domain(hash, domain).await;
                            }
                            Ok(StatMessage::Event(event)) => {
                                backoff.reset();
                                state.record_event(event).await;
                            }
                            // Newer dgaard, unknown message: skip it rather
                            // than reconnect in a loop.
                            Err(MonitorError::UnsupportedFrame(_)) => continue,
                            Err(e) => break format!("Stream error: {e}"),
                        },
                    }
                }
            }
            Err(e) => format!("Connection failed: {e}"),
        };

        let delay = backoff.next_delay();
        eprintln!("{failure}, retrying in {delay:.1?}");
        // Sleep interruptibly so shutdown is not delayed.
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    async fn make_connected_pair() -> (UnixStream, UnixStream) {
        use std::sync::OnceLock;
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
        let dir = DIR.get_or_init(|| tempfile::tempdir().unwrap());
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.path().join(format!("test_{id}.sock"));

        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_read_domain_mapping_frame() {
        let (client, mut server) = make_connected_pair().await;

        let msg = StatMessage::DomainMapping {
            hash: 0xdeadbeef,
            domain: "example.com".to_string(),
        };
        let bytes = msg.serialize();
        server.write_all(&bytes).await.unwrap();
        drop(server);

        let mut stream = client;
        let decoded = read_frame(&mut stream).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn test_read_event_frame() {
        let (client, mut server) = make_connected_pair().await;

        let event = StatEvent {
            country: None,
            timestamp: 12345,
            domain_hash: 0xabcdef,
            client_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            action: StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        };
        let msg = StatMessage::Event(event);
        let bytes = msg.serialize();
        server.write_all(&bytes).await.unwrap();
        drop(server);

        let mut stream = client;
        let decoded = read_frame(&mut stream).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn test_truncated_frame_returns_error() {
        let (client, mut server) = make_connected_pair().await;

        // Write only the length prefix, then close — payload will be missing
        let len: u16 = 10;
        server.write_all(&len.to_le_bytes()).await.unwrap();
        drop(server); // EOF before payload

        let mut stream = client;
        let result = read_frame(&mut stream).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_oversized_frame_is_rejected_without_allocating() {
        let (client, mut server) = make_connected_pair().await;

        // Announce a frame larger than MAX_FRAME_PAYLOAD; the reader must
        // reject the length prefix without ever allocating a buffer for it.
        let oversized: u16 = (MAX_FRAME_PAYLOAD + 1) as u16;
        server.write_all(&oversized.to_le_bytes()).await.unwrap();
        drop(server);

        let mut stream = client;
        let result = read_frame(&mut stream).await;
        match result {
            Err(MonitorError::InvalidMessage(_)) => {}
            other => panic!("expected InvalidMessage error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_frame_is_skippable_and_stream_stays_aligned() {
        // A newer dgaard may send an event action this monitor does not
        // know: the frame is reported as unsupported (skip, not reconnect)
        // and the following frame still decodes.
        let (client, mut server) = make_connected_pair().await;
        let mut unknown = StatMessage::Event(StatEvent {
            country: None,
            timestamp: 1,
            domain_hash: 2,
            client_ip: [0; 16],
            action: StatAction::Allowed,
        })
        .serialize();
        let action_at = unknown.len() - 1;
        unknown[action_at] = 0xEE; // unknown action code
        let next = StatMessage::DomainMapping {
            hash: 9,
            domain: "next.example".to_string(),
        };
        server.write_all(&unknown).await.unwrap();
        server.write_all(&next.serialize()).await.unwrap();
        drop(server);

        let mut stream = client;
        assert!(matches!(
            read_frame(&mut stream).await,
            Err(MonitorError::UnsupportedFrame(_))
        ));
        assert_eq!(read_frame(&mut stream).await.unwrap(), next);
    }

    #[tokio::test]
    async fn test_garbage_frame_returns_error() {
        let (client, mut server) = make_connected_pair().await;

        // Send a frame that has a valid length but garbage type (0xFF)
        let payload: &[u8] = &[0xFF; 5]; // 5 bytes: invalid type + garbage
        let msg_len = payload.len() as u16;
        server.write_all(&msg_len.to_le_bytes()).await.unwrap();
        server.write_all(payload).await.unwrap();
        drop(server);

        let mut stream = client;
        let result = read_frame(&mut stream).await;
        assert!(result.is_err());
    }

    // --- Backoff ---

    #[test]
    fn backoff_doubles_with_jitter_and_caps() {
        let mut backoff = Backoff::new();
        let mut base = Backoff::INITIAL;
        for _ in 0..20 {
            let delay = backoff.next_delay();
            assert!(
                delay >= base / 2 && delay <= base,
                "delay {delay:?} outside [{:?}, {base:?}]",
                base / 2
            );
            base = (base * 2).min(Backoff::MAX);
        }
        assert_eq!(base, Backoff::MAX);
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut backoff = Backoff::new();
        for _ in 0..10 {
            backoff.next_delay();
        }
        backoff.reset();
        assert!(backoff.next_delay() <= Backoff::INITIAL);
    }

    #[test]
    fn random_unit_stays_in_range() {
        for _ in 0..1000 {
            let value = random_unit();
            assert!((0.0..1.0).contains(&value), "{value}");
        }
    }

    // --- run_reader ---

    use std::time::Instant;

    fn socket_path(dir: &tempfile::TempDir) -> String {
        dir.path().join("stats.sock").to_str().unwrap().to_string()
    }

    fn start_reader(
        path: &str,
    ) -> (
        Arc<AppState>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_reader(
            path.to_string(),
            Arc::clone(&state),
            shutdown_rx,
            PeerPolicy::Auto,
        ));
        (state, shutdown_tx, handle)
    }

    /// Regression: dgaard over `MAX_CLIENTS` accepts then closes, and the
    /// reader used to reconnect without any pause (~20 000 times per second).
    #[tokio::test]
    async fn refused_connections_are_spaced_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        let listener = UnixListener::bind(&path).unwrap();
        let (_state, shutdown_tx, handle) = start_reader(&path);

        let mut accepted = 0u32;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Ok(Ok((stream, _))) = tokio::time::timeout_at(deadline, listener.accept()).await {
            drop(stream);
            accepted += 1;
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        // Delays are at least 50 + 100 + 200 + 400 ms, so at most 5 attempts
        // fit in one second; leave headroom for scheduling.
        assert!(
            (2..=8).contains(&accepted),
            "unexpected number of connections in 1s: {accepted}"
        );
    }

    #[tokio::test]
    async fn valid_frame_resets_backoff_and_reaches_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        let listener = UnixListener::bind(&path).unwrap();
        let (state, shutdown_tx, handle) = start_reader(&path);

        // Four refused connections grow the base delay to 1.6 s.
        for _ in 0..4 {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        }
        // The fifth one delivers frames, then closes.
        let (mut stream, _) = listener.accept().await.unwrap();
        let mapping = StatMessage::DomainMapping {
            hash: 7,
            domain: "one.test".to_string(),
        };
        let event = StatMessage::Event(StatEvent {
            country: None,
            timestamp: 1,
            domain_hash: 7,
            client_ip: [0; 16],
            action: StatAction::Allowed,
        });
        stream.write_all(&mapping.serialize()).await.unwrap();
        stream.write_all(&event.serialize()).await.unwrap();
        drop(stream);
        let closed_at = Instant::now();

        let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("reader never reconnected")
            .unwrap();
        let gap = closed_at.elapsed();
        drop(stream);

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        // Reset: at most INITIAL (100 ms). Without it: at least 800 ms.
        assert!(gap < Duration::from_millis(400), "reconnect took {gap:?}");
        assert_eq!(state.stats.read().await.total, 1);
        assert_eq!(
            state.domain_map.read().await.get(&7).map(String::as_str),
            Some("one.test")
        );
    }

    // --- Peer identity ---

    const ME: u32 = 1000;
    const OTHER: u32 = 1001;

    fn facts(owner_uid: u32, dir_world_writable: bool) -> Option<SocketFacts> {
        Some(SocketFacts {
            owner_uid,
            dir_world_writable,
        })
    }

    #[test]
    fn root_and_own_user_are_always_trusted() {
        for policy in [PeerPolicy::Auto, PeerPolicy::Uid(42)] {
            assert!(decide_peer(0, Some(ME), facts(OTHER, true), policy).is_ok());
        }
        assert!(decide_peer(ME, Some(ME), facts(ME, true), PeerPolicy::Auto).is_ok());
    }

    /// Regression: any local user could create the socket in `/tmp` before
    /// dgaard and feed the monitor forged events.
    #[test]
    fn other_user_in_world_writable_dir_is_refused() {
        let err = decide_peer(OTHER, Some(ME), facts(OTHER, true), PeerPolicy::Auto).unwrap_err();
        assert!(err.contains("peer_uid = 1001"), "{err}");
        // Without filesystem facts, assume the worst.
        assert!(decide_peer(OTHER, Some(ME), None, PeerPolicy::Auto).is_err());
        assert!(decide_peer(OTHER, None, None, PeerPolicy::Auto).is_err());
    }

    /// dgaard under its own user (e.g. systemd DynamicUser) in a protected
    /// runtime directory owns the socket: trusted without configuration.
    #[test]
    fn socket_owner_in_protected_dir_is_trusted() {
        assert!(decide_peer(OTHER, Some(ME), facts(OTHER, false), PeerPolicy::Auto).is_ok());
        let err = decide_peer(OTHER, Some(ME), facts(4242, false), PeerPolicy::Auto).unwrap_err();
        assert!(err.contains("belongs to uid 4242"), "{err}");
    }

    #[test]
    fn explicit_peer_uid_is_exact() {
        assert!(decide_peer(OTHER, Some(ME), facts(OTHER, true), PeerPolicy::Uid(OTHER)).is_ok());
        // Not even this user or the socket owner, when a UID is configured.
        assert!(decide_peer(ME, Some(ME), facts(ME, false), PeerPolicy::Uid(OTHER)).is_err());
    }

    #[tokio::test]
    async fn own_uid_is_readable() {
        assert!(own_uid().await.is_some());
    }

    #[tokio::test]
    async fn socket_facts_reflect_the_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let protected = socket_facts(&path).unwrap();
        assert!(!protected.dir_world_writable);
        assert_eq!(Some(protected.owner_uid), own_uid().await);

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(socket_facts(&path).unwrap().dir_world_writable);
        assert!(socket_facts(&dir.path().join("missing.sock")).is_none());
    }

    /// End to end: a server run by this user is trusted by default.
    #[tokio::test]
    async fn reader_trusts_a_socket_served_by_this_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        let listener = UnixListener::bind(&path).unwrap();
        let (state, shutdown_tx, handle) = start_reader(&path);

        let (mut stream, _) = listener.accept().await.unwrap();
        let event = StatMessage::Event(StatEvent {
            country: None,
            timestamp: 1,
            domain_hash: 7,
            client_ip: [0; 16],
            action: StatAction::Allowed,
        });
        stream.write_all(&event.serialize()).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while state.stats.read().await.total < 1 {
            assert!(
                Instant::now() < deadline,
                "event from a trusted peer was not read"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// End to end: a peer outside the configured UID is never read from.
    #[tokio::test]
    async fn reader_refuses_an_unexpected_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(&dir);
        let listener = UnixListener::bind(&path).unwrap();
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let not_me = own_uid().await.unwrap().wrapping_add(1).max(1);
        let handle = tokio::spawn(run_reader(
            path.clone(),
            Arc::clone(&state),
            shutdown_rx,
            PeerPolicy::Uid(not_me),
        ));

        let (mut stream, _) = listener.accept().await.unwrap();
        let event = StatMessage::Event(StatEvent {
            country: None,
            timestamp: 1,
            domain_hash: 7,
            client_ip: [0; 16],
            action: StatAction::Allowed,
        });
        // The reader drops the connection without reading: writing may fail.
        let _ = stream.write_all(&event.serialize()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert_eq!(
            state.stats.read().await.total,
            0,
            "forged event was ingested"
        );
    }

    #[tokio::test]
    async fn shutdown_interrupts_backoff_sleep() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing listens here: every attempt fails and the reader sleeps.
        let path = socket_path(&dir);
        let (_state, shutdown_tx, handle) = start_reader(&path);

        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = shutdown_tx.send(true);
        // Well under the pending delay (up to 400 ms at this point).
        tokio::time::timeout(Duration::from_millis(200), handle)
            .await
            .expect("run_reader must stop promptly on shutdown")
            .unwrap();
    }
}
