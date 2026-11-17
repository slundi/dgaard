//! Per-client behavioral analytics.
//!
//! * **NXDOMAIN hunting** (`[nxdomain_hunting]`): a client that gets
//!   `threshold` NXDOMAIN answers within `window_seconds` is probably
//!   scanning for a botnet C2 (DGA candidates). The event is logged; with
//!   `action = "block_client"` the client is also refused for one window.
//!   Only NXDOMAINs from upstream (or the cache) count: dgaard's own block
//!   answers are NXDOMAIN too but say nothing about the client.
//! * **Tunneling detection** (`[tunneling_detection]`): a label longer than
//!   `max_label_length`, or more than `max_subdomains_per_minute` distinct
//!   names under one registrable domain from one client, is how data is
//!   encoded into DNS queries. The query is blocked before it leaves.
//!
//! Both trackers are bounded: past their capacity, stale entries are
//! pruned, and a new client or zone is not tracked when nothing is stale
//! (fail open rather than grow without limit).

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dgaard_engine::dga::structure::registrable_domain;
use dgaard_engine::model::BlockReason;
use twox_hash::XxHash3_64;

use crate::config::{NxdomainAction, NxdomainHuntingConfig, TunnelingDetectionConfig};

/// Upper bound on clients tracked by NXDOMAIN hunting.
const MAX_TRACKED_CLIENTS: usize = 4096;

/// Upper bound on (client, registrable domain) windows tracked by
/// tunneling detection.
const MAX_TRACKED_ZONES: usize = 16_384;

/// Tunneling detection counts distinct names over this window.
const TUNNELING_WINDOW: Duration = Duration::from_secs(60);

/// Recent NXDOMAINs of one client, and until when it is refused.
#[derive(Default)]
struct ClientNxdomains {
    recent: VecDeque<Instant>,
    refused_until: Option<Instant>,
}

impl ClientNxdomains {
    fn is_stale(&self, now: Instant, window: Duration) -> bool {
        self.refused_until.is_none_or(|until| until <= now)
            && self
                .recent
                .back()
                .is_none_or(|last| now.duration_since(*last) >= window)
    }
}

/// Distinct names one client asked under one registrable domain.
struct NameWindow {
    started: Instant,
    names: HashSet<u64>,
}

/// Process-wide behavioral state.
pub struct Behavior {
    nxdomains: DashMap<IpAddr, ClientNxdomains>,
    names: DashMap<(IpAddr, u64), NameWindow>,
}

impl Default for Behavior {
    fn default() -> Self {
        Self::new()
    }
}

impl Behavior {
    pub fn new() -> Self {
        Self {
            nxdomains: DashMap::new(),
            names: DashMap::new(),
        }
    }

    /// Record an NXDOMAIN answer served to `client`. Returns how many it got
    /// within the window when this one reaches the threshold (once per
    /// `threshold` answers, so a scanning client is not logged per query).
    pub fn record_nxdomain(
        &self,
        client: IpAddr,
        now: Instant,
        cfg: &NxdomainHuntingConfig,
    ) -> Option<usize> {
        if !cfg.enabled {
            return None;
        }
        let window = Duration::from_secs(u64::from(cfg.window_seconds));
        // No shard lock held here: `len` locks every shard.
        if !self.nxdomains.contains_key(&client) && self.nxdomains.len() >= MAX_TRACKED_CLIENTS {
            self.nxdomains
                .retain(|_, client| !client.is_stale(now, window));
            if self.nxdomains.len() >= MAX_TRACKED_CLIENTS {
                return None;
            }
        }

        let mut entry = self.nxdomains.entry(client).or_default();
        while entry
            .recent
            .front()
            .is_some_and(|seen| now.duration_since(*seen) >= window)
        {
            entry.recent.pop_front();
        }
        entry.recent.push_back(now);
        if entry.recent.len() < cfg.threshold as usize {
            return None;
        }
        let count = entry.recent.len();
        entry.recent.clear();
        if cfg.action == NxdomainAction::BlockClient {
            entry.refused_until = Some(now + window);
        }
        Some(count)
    }

    /// True while `client` is refused after crossing the NXDOMAIN threshold.
    pub fn is_refused(&self, client: IpAddr, now: Instant) -> bool {
        self.nxdomains
            .get(&client)
            .and_then(|entry| entry.refused_until)
            .is_some_and(|until| now < until)
    }

    /// Judge a query `client` is about to send upstream for `domain`.
    pub fn check_tunneling(
        &self,
        client: IpAddr,
        domain: &str,
        now: Instant,
        cfg: &TunnelingDetectionConfig,
    ) -> Option<BlockReason> {
        if !cfg.enabled {
            return None;
        }
        let domain = domain.trim_end_matches('.');
        if domain
            .split('.')
            .any(|label| label.len() > usize::from(cfg.max_label_length))
        {
            return Some(BlockReason::DnsTunneling);
        }
        // The registrable domain itself is not one of its subdomains.
        let zone = registrable_domain(domain)?;
        if zone.len() == domain.len() {
            return None;
        }

        let key = (
            client,
            XxHash3_64::oneshot(zone.to_ascii_lowercase().as_bytes()),
        );
        let name = XxHash3_64::oneshot(domain.to_ascii_lowercase().as_bytes());
        if !self.names.contains_key(&key) && self.names.len() >= MAX_TRACKED_ZONES {
            self.names
                .retain(|_, window| now.duration_since(window.started) < TUNNELING_WINDOW);
            if self.names.len() >= MAX_TRACKED_ZONES {
                return None;
            }
        }

        let mut window = self.names.entry(key).or_insert_with(|| NameWindow {
            started: now,
            names: HashSet::new(),
        });
        if now.duration_since(window.started) >= TUNNELING_WINDOW {
            window.started = now;
            window.names.clear();
        }
        if window.names.contains(&name) {
            return None;
        }
        if window.names.len() >= cfg.max_subdomains_per_minute as usize {
            return Some(BlockReason::DnsTunneling);
        }
        window.names.insert(name);
        None
    }

    /// Forget every client: tests share one process with `cargo test`.
    #[cfg(test)]
    pub fn clear(&self) {
        self.nxdomains.clear();
        self.names.clear();
    }

    #[cfg(test)]
    fn tracked(&self) -> (usize, usize) {
        (self.nxdomains.len(), self.names.len())
    }
}

/// The daemon's behavioral state.
pub static BEHAVIOR: LazyLock<Behavior> = LazyLock::new(Behavior::new);

/// True when a DNS response carries RCODE NXDOMAIN.
pub fn is_nxdomain(response: &[u8]) -> bool {
    response.len() >= 4 && response[2] & 0x80 != 0 && response[3] & 0x0F == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(last: u8) -> IpAddr {
        IpAddr::from([192, 168, 1, last])
    }

    fn hunting(threshold: u32, action: NxdomainAction) -> NxdomainHuntingConfig {
        NxdomainHuntingConfig {
            enabled: true,
            threshold,
            window_seconds: 60,
            action,
        }
    }

    fn tunneling(max_subdomains: u32) -> TunnelingDetectionConfig {
        TunnelingDetectionConfig {
            enabled: true,
            max_subdomains_per_minute: max_subdomains,
            max_label_length: 40,
        }
    }

    // ---- NXDOMAIN hunting ----

    #[test]
    fn threshold_is_reported_once_per_crossing() {
        let behavior = Behavior::new();
        let cfg = hunting(3, NxdomainAction::Log);
        let now = Instant::now();
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), None);
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), None);
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), Some(3));
        // Counting starts again: the next report needs three more.
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), None);
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), None);
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), Some(3));
    }

    #[test]
    fn old_nxdomains_leave_the_window() {
        let behavior = Behavior::new();
        let cfg = hunting(2, NxdomainAction::Log);
        let start = Instant::now();
        behavior.record_nxdomain(client(1), start, &cfg);
        let later = start + Duration::from_secs(61);
        assert_eq!(behavior.record_nxdomain(client(1), later, &cfg), None);
        assert_eq!(behavior.record_nxdomain(client(1), later, &cfg), Some(2));
    }

    #[test]
    fn clients_are_counted_apart() {
        let behavior = Behavior::new();
        let cfg = hunting(2, NxdomainAction::Log);
        let now = Instant::now();
        behavior.record_nxdomain(client(1), now, &cfg);
        assert_eq!(behavior.record_nxdomain(client(2), now, &cfg), None);
        assert_eq!(behavior.record_nxdomain(client(1), now, &cfg), Some(2));
    }

    #[test]
    fn block_client_refuses_for_one_window_and_log_never_does() {
        let behavior = Behavior::new();
        let now = Instant::now();
        let block = hunting(1, NxdomainAction::BlockClient);
        assert_eq!(behavior.record_nxdomain(client(1), now, &block), Some(1));
        assert!(behavior.is_refused(client(1), now));
        assert!(behavior.is_refused(client(1), now + Duration::from_secs(59)));
        assert!(!behavior.is_refused(client(1), now + Duration::from_secs(60)));
        assert!(!behavior.is_refused(client(2), now));

        let log = hunting(1, NxdomainAction::Log);
        assert_eq!(behavior.record_nxdomain(client(3), now, &log), Some(1));
        assert!(!behavior.is_refused(client(3), now));
    }

    #[test]
    fn disabled_hunting_records_nothing() {
        let behavior = Behavior::new();
        let cfg = NxdomainHuntingConfig {
            enabled: false,
            ..hunting(1, NxdomainAction::BlockClient)
        };
        assert_eq!(
            behavior.record_nxdomain(client(1), Instant::now(), &cfg),
            None
        );
        assert_eq!(behavior.tracked().0, 0);
    }

    #[test]
    fn tracked_clients_are_bounded() {
        let behavior = Behavior::new();
        let cfg = hunting(100, NxdomainAction::Log);
        let now = Instant::now();
        for idx in 0..MAX_TRACKED_CLIENTS as u32 + 10 {
            behavior.record_nxdomain(IpAddr::from(idx.to_be_bytes()), now, &cfg);
        }
        assert_eq!(behavior.tracked().0, MAX_TRACKED_CLIENTS);
        // Once the old entries are stale, new clients are tracked again.
        let later = now + Duration::from_secs(61);
        behavior.record_nxdomain(client(9), later, &cfg);
        assert_eq!(behavior.tracked().0, 1);
    }

    // ---- tunneling detection ----

    #[test]
    fn overlong_label_is_tunneling() {
        let behavior = Behavior::new();
        let payload = "a".repeat(41);
        let domain = format!("{payload}.exfil.example");
        assert!(matches!(
            behavior.check_tunneling(client(1), &domain, Instant::now(), &tunneling(50)),
            Some(BlockReason::DnsTunneling)
        ));
        let fine = format!("{}.exfil.example", "a".repeat(40));
        assert!(
            behavior
                .check_tunneling(client(1), &fine, Instant::now(), &tunneling(50))
                .is_none()
        );
    }

    #[test]
    fn too_many_distinct_names_under_one_domain_is_tunneling() {
        let behavior = Behavior::new();
        let cfg = tunneling(3);
        let now = Instant::now();
        for idx in 0..3 {
            let name = format!("chunk{idx}.exfil.example.com");
            assert!(
                behavior
                    .check_tunneling(client(1), &name, now, &cfg)
                    .is_none()
            );
        }
        assert!(matches!(
            behavior.check_tunneling(client(1), "chunk3.exfil.example.com", now, &cfg),
            Some(BlockReason::DnsTunneling)
        ));
        // Names already seen still resolve; other clients and domains are
        // counted apart.
        assert!(
            behavior
                .check_tunneling(client(1), "CHUNK0.exfil.example.com.", now, &cfg)
                .is_none()
        );
        assert!(
            behavior
                .check_tunneling(client(2), "chunk3.exfil.example.com", now, &cfg)
                .is_none()
        );
        assert!(
            behavior
                .check_tunneling(client(1), "www.other.com", now, &cfg)
                .is_none()
        );
        // A new minute starts a new count.
        let later = now + TUNNELING_WINDOW;
        assert!(
            behavior
                .check_tunneling(client(1), "chunk3.exfil.example.com", later, &cfg)
                .is_none()
        );
    }

    #[test]
    fn registrable_domains_themselves_are_not_counted() {
        let behavior = Behavior::new();
        let cfg = tunneling(1);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(
                behavior
                    .check_tunneling(client(1), "example.com", now, &cfg)
                    .is_none()
            );
            assert!(
                behavior
                    .check_tunneling(client(1), "bbc.co.uk", now, &cfg)
                    .is_none()
            );
        }
        assert!(
            behavior
                .check_tunneling(client(1), "com", now, &cfg)
                .is_none()
        );
        assert_eq!(behavior.tracked().1, 0);
    }

    #[test]
    fn disabled_tunneling_detection_lets_everything_through() {
        let behavior = Behavior::new();
        let cfg = TunnelingDetectionConfig {
            enabled: false,
            ..tunneling(1)
        };
        let now = Instant::now();
        let long = format!("{}.example.com", "a".repeat(63));
        assert!(
            behavior
                .check_tunneling(client(1), &long, now, &cfg)
                .is_none()
        );
        assert!(
            behavior
                .check_tunneling(client(1), "a.example.com", now, &cfg)
                .is_none()
        );
        assert!(
            behavior
                .check_tunneling(client(1), "b.example.com", now, &cfg)
                .is_none()
        );
    }

    #[test]
    fn tracked_zones_are_bounded() {
        let behavior = Behavior::new();
        let cfg = tunneling(5);
        let now = Instant::now();
        for idx in 0..MAX_TRACKED_ZONES + 10 {
            let name = format!("www.site{idx}.com");
            behavior.check_tunneling(client(1), &name, now, &cfg);
        }
        assert_eq!(behavior.tracked().1, MAX_TRACKED_ZONES);
        let later = now + TUNNELING_WINDOW;
        behavior.check_tunneling(client(1), "www.fresh.com", later, &cfg);
        assert_eq!(behavior.tracked().1, 1);
    }

    #[test]
    fn nxdomain_rcode_is_read_from_responses_only() {
        // QR=1, RCODE=3.
        assert!(is_nxdomain(&[0, 1, 0x81, 0x83]));
        assert!(!is_nxdomain(&[0, 1, 0x81, 0x80]));
        // A query (QR=0) is never an answer.
        assert!(!is_nxdomain(&[0, 1, 0x01, 0x03]));
        assert!(!is_nxdomain(&[0, 1]));
    }
}
