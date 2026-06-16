use std::{
    num::NonZeroUsize,
    sync::Mutex,
    time::{Duration, Instant},
};

use lru::LruCache;

type CacheKey = (String, u16);

struct CacheEntry {
    response: Box<[u8]>,
    expires_at: Instant,
}

/// TTL-aware LRU cache for raw DNS response bytes.
///
/// Entries expire after their TTL elapses and are evicted lazily on the next
/// access. The LRU policy bounds memory when `max_entries` is reached.
///
/// Thread-safe via an internal `Mutex`; the lock is held only during the
/// hash-map operation (no I/O inside the lock).
pub struct ResponseCache {
    inner: Mutex<LruCache<CacheKey, CacheEntry>>,
}

impl ResponseCache {
    pub fn new(max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up a cached DNS response.
    ///
    /// Returns `None` on a miss or if the entry has expired (removing the
    /// stale entry in that case). On a hit the response bytes are cloned and
    /// bytes 0–1 are patched with `original_txid` so the reply matches the
    /// client's transaction ID.
    pub fn get(&self, domain: &str, qtype: u16, original_txid: [u8; 2]) -> Option<Vec<u8>> {
        let key = (domain.to_ascii_lowercase(), qtype);
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let expired = guard.peek(&key).is_some_and(|e| e.expires_at <= now);
        if expired {
            guard.pop(&key);
            return None;
        }

        guard.get(&key).map(|entry| {
            let mut response = entry.response.to_vec();
            if response.len() >= 2 {
                response[0] = original_txid[0];
                response[1] = original_txid[1];
            }
            response
        })
    }

    /// Store a DNS response with the given TTL.
    ///
    /// If `ttl_override` is non-zero it replaces `ttl`. Entries with an
    /// effective TTL of 0 are not stored (no-cache responses or responses
    /// without answer records).
    pub fn insert(&self, domain: &str, qtype: u16, response: &[u8], ttl: u32, ttl_override: u32) {
        let effective_ttl = if ttl_override > 0 { ttl_override } else { ttl };
        if effective_ttl == 0 {
            return;
        }
        let key = (domain.to_ascii_lowercase(), qtype);
        let entry = CacheEntry {
            response: response.into(),
            expires_at: Instant::now() + Duration::from_secs(u64::from(effective_ttl)),
        };
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, entry);
    }

    /// Number of entries currently held (including potentially expired ones).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::*;

    fn txid(id: u16) -> [u8; 2] {
        [(id >> 8) as u8, id as u8]
    }

    fn response_with_txid(id: u16) -> Vec<u8> {
        // Minimal 12-byte DNS response header
        let mut r = vec![0u8; 12];
        r[0] = (id >> 8) as u8;
        r[1] = id as u8;
        r
    }

    #[test]
    fn miss_returns_none() {
        let cache = ResponseCache::new(100);
        assert!(cache.get("example.com", 1, txid(1)).is_none());
    }

    #[test]
    fn insert_then_hit_patches_txid() {
        let cache = ResponseCache::new(100);
        let original = response_with_txid(0xABCD);
        cache.insert("example.com", 1, &original, 300, 0);

        let result = cache.get("example.com", 1, txid(0x1234)).unwrap();
        assert_eq!(result[0], 0x12);
        assert_eq!(result[1], 0x34);
        assert_eq!(&result[2..], &original[2..]);
    }

    #[test]
    fn domain_is_case_insensitive() {
        let cache = ResponseCache::new(100);
        let r = response_with_txid(1);
        cache.insert("Example.COM", 1, &r, 300, 0);
        assert!(cache.get("example.com", 1, txid(1)).is_some());
        assert!(cache.get("EXAMPLE.COM", 1, txid(1)).is_some());
    }

    #[test]
    fn different_qtype_is_distinct_key() {
        let cache = ResponseCache::new(100);
        let r = response_with_txid(1);
        cache.insert("example.com", 1 /* A */, &r, 300, 0);
        assert!(cache.get("example.com", 1, txid(1)).is_some());
        assert!(cache.get("example.com", 28 /* AAAA */, txid(1)).is_none());
    }

    #[test]
    fn zero_ttl_is_not_stored() {
        let cache = ResponseCache::new(100);
        let r = response_with_txid(1);
        cache.insert("example.com", 1, &r, 0, 0);
        assert!(cache.get("example.com", 1, txid(1)).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn ttl_override_replaces_response_ttl() {
        let cache = ResponseCache::new(100);
        let r = response_with_txid(1);
        // response TTL = 0 (would normally not be cached), override = 60
        cache.insert("example.com", 1, &r, 0, 60);
        assert!(cache.get("example.com", 1, txid(1)).is_some());
    }

    #[test]
    fn expired_entry_returns_none_and_is_evicted() {
        let cache = ResponseCache::new(100);
        let r = response_with_txid(1);
        cache.insert("example.com", 1, &r, 1, 0);
        assert_eq!(cache.len(), 1);

        thread::sleep(Duration::from_millis(1100));

        assert!(cache.get("example.com", 1, txid(1)).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn lru_evicts_oldest_when_full() {
        let cache = ResponseCache::new(2);
        let r = response_with_txid(1);
        cache.insert("a.com", 1, &r, 300, 0);
        cache.insert("b.com", 1, &r, 300, 0);
        // Access a.com to make b.com the LRU candidate
        let _ = cache.get("a.com", 1, txid(1));
        // Insert c.com — should evict b.com
        cache.insert("c.com", 1, &r, 300, 0);
        assert!(cache.get("a.com", 1, txid(1)).is_some());
        assert!(cache.get("c.com", 1, txid(1)).is_some());
        assert!(cache.get("b.com", 1, txid(1)).is_none());
    }
}
