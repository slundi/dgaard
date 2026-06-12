use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, params};
use tokio::sync::{broadcast, watch};

use crate::state::AppState;
use crate::util::{EventRecord, event_to_record};

const BATCH_SIZE: usize = 256;
const FLUSH_INTERVAL_SECS: u64 = 5;

// ── Database ──────────────────────────────────────────────────────────────────

pub struct Database {
    conn: Mutex<Connection>,
    events_retention_hours: u32,
    aggregates_retention_days: u32,
}

impl Database {
    pub fn open(
        path: &str,
        events_retention_hours: u32,
        aggregates_retention_days: u32,
    ) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let db = Self {
            conn: Mutex::new(conn),
            events_retention_hours,
            aggregates_retention_days,
        };
        db.create_schema()?;
        Ok(db)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::open(":memory:", 72, 90)
    }

    fn create_schema(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS dns_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    INTEGER NOT NULL,
                domain_hash  TEXT    NOT NULL,
                domain       TEXT,
                client_ip    TEXT    NOT NULL,
                action       TEXT    NOT NULL,
                flags        INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_dns_events_ts
                 ON dns_events(timestamp);
             CREATE INDEX IF NOT EXISTS idx_dns_events_client
                 ON dns_events(client_ip);

             CREATE TABLE IF NOT EXISTS dns_stats_hourly (
                hour         INTEGER NOT NULL,
                domain_hash  TEXT    NOT NULL,
                client_ip    TEXT    NOT NULL,
                action       TEXT    NOT NULL,
                count        INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (hour, domain_hash, client_ip, action)
             );",
        )
    }

    pub fn insert_events(&self, events: &[EventRecord]) -> rusqlite::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO dns_events
                     (timestamp, domain_hash, domain, client_ip, action, flags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for e in events {
                stmt.execute(params![
                    e.timestamp as i64,
                    e.domain_hash,
                    e.domain,
                    e.client_ip,
                    e.action,
                    e.flags.map(|f| f as i64)
                ])?;
            }
        }
        tx.commit()
    }

    pub fn upsert_hourly(
        &self,
        acc: &HashMap<(u64, String, String, String), u64>,
    ) -> rusqlite::Result<()> {
        if acc.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO dns_stats_hourly (hour, domain_hash, client_ip, action, count)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(hour, domain_hash, client_ip, action)
                 DO UPDATE SET count = count + excluded.count",
            )?;
            for ((hour, domain_hash, client_ip, action), count) in acc {
                stmt.execute(params![
                    *hour as i64,
                    domain_hash,
                    client_ip,
                    action,
                    *count as i64
                ])?;
            }
        }
        tx.commit()
    }

    pub fn prune_old(&self) -> rusqlite::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let event_cutoff = now.saturating_sub(self.events_retention_hours as u64 * 3600) as i64;
        let hourly_cutoff =
            now.saturating_sub(self.aggregates_retention_days as u64 * 86_400) as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM dns_events WHERE timestamp < ?1",
            params![event_cutoff],
        )?;
        conn.execute(
            "DELETE FROM dns_stats_hourly WHERE hour < ?1",
            params![hourly_cutoff],
        )?;
        Ok(())
    }

    pub fn query_range(
        &self,
        from: u64,
        to: u64,
        client: Option<String>,
        action: Option<String>,
        limit: usize,
        offset: usize,
    ) -> rusqlite::Result<Vec<EventRecord>> {
        let conn = self.conn.lock().unwrap();
        let from_i = from as i64;
        // Clamp to i64::MAX to avoid overflow — unix timestamps fit comfortably.
        let to_i = to.min(i64::MAX as u64) as i64;
        let mut stmt = conn.prepare(
            "SELECT timestamp, domain_hash, domain, client_ip, action, flags
             FROM dns_events
             WHERE timestamp >= ?1 AND timestamp <= ?2
               AND (?3 IS NULL OR client_ip = ?3)
               AND (?4 IS NULL OR lower(action) = lower(?4))
             ORDER BY timestamp DESC
             LIMIT ?5 OFFSET ?6",
        )?;
        let rows = stmt.query_map(
            params![from_i, to_i, client, action, limit as i64, offset as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?.map(|v| v as u32),
                ))
            },
        )?;

        let mut results = Vec::new();
        for row in rows {
            let (timestamp, domain_hash, domain, client_ip, action, flags) = row?;
            let flags_labels = match flags {
                Some(bits) => {
                    use crate::protocol::StatBlockReason;
                    crate::util::reason_labels(StatBlockReason::from_bits_truncate(bits))
                }
                None => vec![],
            };
            results.push(EventRecord {
                timestamp,
                domain_hash,
                domain,
                client_ip,
                action,
                flags,
                flags_labels,
            });
        }
        Ok(results)
    }

    /// Return `(client_ip, domain_hash, domain_name, timestamp)` rows for all
    /// (client, domain) pairs that have at least `min_observations` events,
    /// ordered by `client_ip, domain_hash, timestamp` for sequential grouping.
    pub fn query_beaconing_timestamps(
        &self,
        min_observations: i64,
    ) -> rusqlite::Result<Vec<(String, String, Option<String>, u64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "WITH candidates AS (
                 SELECT client_ip, domain_hash
                 FROM dns_events
                 GROUP BY client_ip, domain_hash
                 HAVING COUNT(*) >= ?1
             )
             SELECT e.client_ip, e.domain_hash, e.domain, e.timestamp
             FROM dns_events e
             INNER JOIN candidates c
                 ON e.client_ip = c.client_ip AND e.domain_hash = c.domain_hash
             ORDER BY e.client_ip, e.domain_hash, e.timestamp",
        )?;
        let rows = stmt.query_map(params![min_observations], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)? as u64,
            ))
        })?;
        rows.collect()
    }
}

// ── Writer task ───────────────────────────────────────────────────────────────

/// Background task: subscribes to AppState events and persists them to SQLite.
///
/// Events are batched and flushed every `FLUSH_INTERVAL_SECS` seconds or when
/// `BATCH_SIZE` is reached.  Hourly aggregates are flushed event-driven: when
/// the first event of a new hour arrives the previous hour's counters are
/// written to `dns_stats_hourly`.
pub async fn run_writer(
    app: Arc<AppState>,
    db: Arc<Database>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut rx = app.subscribe();
    let mut batch: Vec<EventRecord> = Vec::with_capacity(BATCH_SIZE);
    let mut hourly_acc: HashMap<(u64, String, String, String), u64> = HashMap::new();
    let mut current_hour: u64 = 0;

    let mut flush_tick = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
    flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_tick.tick().await; // consume the immediate first tick

    let mut last_prune = tokio::time::Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = flush_tick.tick() => {
                flush_batch(&db, &mut batch).await;
                if last_prune.elapsed() >= Duration::from_secs(3600) {
                    let db2 = Arc::clone(&db);
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = db2.prune_old() {
                            eprintln!("persistence: prune error: {e}");
                        }
                    });
                    last_prune = tokio::time::Instant::now();
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        let domain_map = app.domain_map.read().await;
                        let record = event_to_record(&event, &domain_map);
                        drop(domain_map);

                        // Event-driven hourly flush: flush when the hour advances.
                        let event_hour = (event.timestamp / 3600) * 3600;
                        if current_hour != 0 && event_hour > current_hour {
                            let acc = std::mem::take(&mut hourly_acc);
                            let db2 = Arc::clone(&db);
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = db2.upsert_hourly(&acc) {
                                    eprintln!("persistence: hourly flush error: {e}");
                                }
                            })
                            .await
                            .ok();
                        }
                        current_hour = event_hour;

                        let key = (
                            event_hour,
                            record.domain_hash.clone(),
                            record.client_ip.clone(),
                            record.action.clone(),
                        );
                        *hourly_acc.entry(key).or_insert(0) += 1;

                        batch.push(record);
                        if batch.len() >= BATCH_SIZE {
                            flush_batch(&db, &mut batch).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("persistence writer: lagged by {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    // Final flush on graceful shutdown.
    flush_batch(&db, &mut batch).await;
    if !hourly_acc.is_empty() {
        let db2 = Arc::clone(&db);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = db2.upsert_hourly(&hourly_acc) {
                eprintln!("persistence: final hourly flush error: {e}");
            }
        })
        .await
        .ok();
    }
}

async fn flush_batch(db: &Arc<Database>, batch: &mut Vec<EventRecord>) {
    if batch.is_empty() {
        return;
    }
    let to_write = std::mem::take(batch);
    let db2 = Arc::clone(db);
    tokio::task::spawn_blocking(move || {
        if let Err(e) = db2.insert_events(&to_write) {
            eprintln!("persistence: batch insert error: {e}");
        }
    })
    .await
    .ok();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ts: u64, action: &str, client: &str) -> EventRecord {
        EventRecord {
            timestamp: ts,
            domain: Some("example.com".to_string()),
            domain_hash: format!("{:016x}", ts),
            client_ip: client.to_string(),
            action: action.to_string(),
            flags: None,
            flags_labels: vec![],
        }
    }

    #[test]
    fn schema_creates_tables() {
        let db = Database::open_in_memory().unwrap();
        // Should not error; tables exist
        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table'
                 AND name IN ('dns_events','dns_stats_hourly')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn insert_and_query_range() {
        let db = Database::open_in_memory().unwrap();
        db.insert_events(&[
            rec(100, "Allowed", "10.0.0.1"),
            rec(200, "Blocked", "10.0.0.2"),
            rec(300, "Allowed", "10.0.0.1"),
        ])
        .unwrap();

        let rows = db.query_range(100, 300, None, None, 100, 0).unwrap();
        assert_eq!(rows.len(), 3);
        // Ordered DESC by timestamp
        assert_eq!(rows[0].timestamp, 300);
        assert_eq!(rows[2].timestamp, 100);
    }

    #[test]
    fn query_range_filters_timestamp() {
        let db = Database::open_in_memory().unwrap();
        for ts in [50u64, 100, 200, 300, 400] {
            db.insert_events(&[rec(ts, "Allowed", "10.0.0.1")]).unwrap();
        }
        let rows = db.query_range(100, 300, None, None, 100, 0).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .all(|r| r.timestamp >= 100 && r.timestamp <= 300)
        );
    }

    #[test]
    fn query_range_filters_client() {
        let db = Database::open_in_memory().unwrap();
        db.insert_events(&[
            rec(100, "Allowed", "10.0.0.1"),
            rec(200, "Allowed", "10.0.0.2"),
        ])
        .unwrap();
        let rows = db
            .query_range(
                0,
                i64::MAX as u64,
                Some("10.0.0.1".to_string()),
                None,
                100,
                0,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].client_ip, "10.0.0.1");
    }

    #[test]
    fn query_range_filters_action_case_insensitive() {
        let db = Database::open_in_memory().unwrap();
        db.insert_events(&[
            rec(100, "Blocked", "10.0.0.1"),
            rec(200, "Allowed", "10.0.0.1"),
        ])
        .unwrap();
        let rows = db
            .query_range(
                0,
                i64::MAX as u64,
                None,
                Some("blocked".to_string()),
                100,
                0,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "Blocked");
    }

    #[test]
    fn query_range_limit_and_offset() {
        let db = Database::open_in_memory().unwrap();
        for ts in 1u64..=5 {
            db.insert_events(&[rec(ts * 100, "Allowed", "10.0.0.1")])
                .unwrap();
        }
        // DESC order: 500, 400, 300, 200, 100; skip 1, take 2 → 400, 300
        let rows = db
            .query_range(0, i64::MAX as u64, None, None, 2, 1)
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp, 400);
        assert_eq!(rows[1].timestamp, 300);
    }

    #[test]
    fn upsert_hourly_accumulates() {
        let db = Database::open_in_memory().unwrap();
        let mut acc = HashMap::new();
        acc.insert(
            (
                3600u64,
                "abc".to_string(),
                "10.0.0.1".to_string(),
                "Allowed".to_string(),
            ),
            5u64,
        );
        db.upsert_hourly(&acc).unwrap();

        // Upsert again — count should add up
        let mut acc2 = HashMap::new();
        acc2.insert(
            (
                3600u64,
                "abc".to_string(),
                "10.0.0.1".to_string(),
                "Allowed".to_string(),
            ),
            3u64,
        );
        db.upsert_hourly(&acc2).unwrap();

        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count FROM dns_stats_hourly WHERE hour=3600",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 8);
    }

    #[test]
    fn prune_old_removes_stale_events() {
        let db = Database::open_in_memory().unwrap();
        // Insert a very old event (ts=1) and a recent one (ts = now)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        db.insert_events(&[
            rec(1, "Allowed", "10.0.0.1"),
            rec(now, "Allowed", "10.0.0.1"),
        ])
        .unwrap();

        // Retention is 72 h; ts=1 is ancient, ts=now is fresh
        db.prune_old().unwrap();

        let rows = db
            .query_range(0, i64::MAX as u64, None, None, 100, 0)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp, now);
    }
}
