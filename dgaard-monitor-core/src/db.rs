use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, params};
use tokio::sync::{broadcast, mpsc, watch};

use crate::state::{AppState, Sink};
use crate::util::{EventRecord, event_to_record};

const BATCH_SIZE: usize = 256;
const FLUSH_INTERVAL_SECS: u64 = 5;
/// Jobs queued for the SQLite worker (one job: up to `BATCH_SIZE` events or
/// one hour of aggregates). Full means the disk is truly behind: the event
/// loop then waits, and the bus buffer absorbs the difference.
const WRITE_QUEUE: usize = 64;

// ── Database ──────────────────────────────────────────────────────────────────

pub struct Database {
    conn: Mutex<Connection>,
    events_retention_hours: u32,
    aggregates_retention_days: u32,
}

/// Acquire the connection mutex, recovering the guard if a previous holder
/// panicked. The SQLite connection state is managed by the C library and is
/// not invalidated by an arbitrary Rust panic, so the safe action is to
/// continue rather than cascade the panic to every subsequent caller.
fn lock_conn(m: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            eprintln!("db: recovering poisoned connection mutex");
            poisoned.into_inner()
        }
    }
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
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::open(":memory:", 72, 90)
    }

    fn create_schema(&self) -> rusqlite::Result<()> {
        let conn = lock_conn(&self.conn);
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

    /// Upgrade data written by older monitors, tracked with `user_version`.
    ///
    /// v1: IPv4 clients used to be stored as `::ffff:a.b.c.d`; rewrite them
    /// as `a.b.c.d` so history and aggregates match new rows. Hourly counts
    /// that now share a key with a newer row are summed.
    fn migrate(&self) -> rusqlite::Result<()> {
        let mut conn = lock_conn(&self.conn);
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version >= 1 {
            return Ok(());
        }
        let tx = conn.transaction()?;
        tx.execute_batch(
            "UPDATE dns_events SET client_ip = substr(client_ip, 8)
              WHERE client_ip GLOB '::ffff:*.*.*.*';
             INSERT INTO dns_stats_hourly (hour, domain_hash, client_ip, action, count)
             SELECT hour, domain_hash, substr(client_ip, 8), action, count
               FROM dns_stats_hourly
              WHERE client_ip GLOB '::ffff:*.*.*.*'
             ON CONFLICT(hour, domain_hash, client_ip, action)
             DO UPDATE SET count = count + excluded.count;
             DELETE FROM dns_stats_hourly WHERE client_ip GLOB '::ffff:*.*.*.*';
             PRAGMA user_version = 1;",
        )?;
        tx.commit()
    }

    pub fn insert_events(&self, events: &[EventRecord]) -> rusqlite::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut conn = lock_conn(&self.conn);
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
        let mut conn = lock_conn(&self.conn);
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

    /// Run `PRAGMA wal_checkpoint(TRUNCATE)` so the WAL file is flushed
    /// into the main database and truncated. Called during graceful
    /// shutdown to make sure the on-disk DB reflects every committed
    /// event before the process exits.
    pub fn wal_checkpoint(&self) -> rusqlite::Result<()> {
        let conn = lock_conn(&self.conn);
        // pragma_query_value would also work; execute_batch is sufficient
        // since we don't need to inspect the return columns.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
    }

    pub fn prune_old(&self) -> rusqlite::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let event_cutoff = now.saturating_sub(self.events_retention_hours as u64 * 3600) as i64;
        let hourly_cutoff =
            now.saturating_sub(self.aggregates_retention_days as u64 * 86_400) as i64;
        let conn = lock_conn(&self.conn);
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
        let conn = lock_conn(&self.conn);
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
                    // retain, not truncate: custom bits 16–31 have labels too.
                    crate::util::reason_labels(StatBlockReason::from_bits_retain(bits))
                }
                None => vec![],
            };
            results.push(EventRecord {
                country: None,
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
    #[allow(clippy::type_complexity)]
    pub fn query_beaconing_timestamps(
        &self,
        min_observations: i64,
    ) -> rusqlite::Result<Vec<(String, String, Option<String>, u64)>> {
        let conn = lock_conn(&self.conn);
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

/// Hourly aggregate counters, keyed by `(hour, domain_hash, client_ip, action)`.
type HourlyCounts = HashMap<(u64, String, String, String), u64>;

/// One unit of work for the SQLite worker.
enum WriteJob {
    Events(Vec<EventRecord>),
    Hourly(HourlyCounts),
    Prune,
}

/// Run every SQLite write on one blocking thread, in submission order, so
/// the event loop never waits for the disk.
fn run_jobs(db: &Database, mut jobs: mpsc::Receiver<WriteJob>) {
    while let Some(job) = jobs.blocking_recv() {
        let (what, result) = match &job {
            WriteJob::Events(records) => ("batch insert", db.insert_events(records)),
            WriteJob::Hourly(counts) => ("hourly flush", db.upsert_hourly(counts)),
            WriteJob::Prune => ("prune", db.prune_old()),
        };
        if let Err(e) = result {
            eprintln!("persistence: {what} error: {e}");
        }
    }
}

/// Queue `job` for the worker; waits only when the queue is full.
async fn submit(jobs: &mpsc::Sender<WriteJob>, job: WriteJob) {
    if jobs.send(job).await.is_err() {
        eprintln!("persistence: SQLite worker stopped, dropping a write");
    }
}

/// Background task: subscribes to AppState events and persists them to SQLite.
///
/// Events are batched and flushed every `FLUSH_INTERVAL_SECS` seconds or when
/// `BATCH_SIZE` is reached.  Hourly aggregates are flushed event-driven: when
/// the first event of a new hour arrives the previous hour's counters are
/// written to `dns_stats_hourly`. The writes themselves run on a dedicated
/// worker; events lost to bus lag are counted under `Sink::Persistence`.
pub async fn run_writer(
    app: Arc<AppState>,
    db: Arc<Database>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut rx = app.subscribe();
    let (jobs, jobs_rx) = mpsc::channel(WRITE_QUEUE);
    let worker = {
        let db = Arc::clone(&db);
        tokio::task::spawn_blocking(move || run_jobs(&db, jobs_rx))
    };

    let mut batch: Vec<EventRecord> = Vec::with_capacity(BATCH_SIZE);
    let mut hourly_acc: HourlyCounts = HashMap::new();
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
                if !batch.is_empty() {
                    submit(&jobs, WriteJob::Events(std::mem::take(&mut batch))).await;
                }
                if last_prune.elapsed() >= Duration::from_secs(3600) {
                    submit(&jobs, WriteJob::Prune).await;
                    last_prune = tokio::time::Instant::now();
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        let record = {
                            let domain_map = app.domain_map.read().await;
                            event_to_record(&event, &domain_map)
                        };

                        // Event-driven hourly flush: flush when the hour advances.
                        let event_hour = (event.timestamp / 3600) * 3600;
                        if current_hour != 0 && event_hour > current_hour {
                            submit(&jobs, WriteJob::Hourly(std::mem::take(&mut hourly_acc))).await;
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
                            submit(&jobs, WriteJob::Events(std::mem::take(&mut batch))).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        app.record_drop(Sink::Persistence, n);
                        eprintln!("persistence writer: lagged by {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    // Final flush on graceful shutdown, then let the worker drain the queue.
    if !batch.is_empty() {
        submit(&jobs, WriteJob::Events(batch)).await;
    }
    if !hourly_acc.is_empty() {
        submit(&jobs, WriteJob::Hourly(hourly_acc)).await;
    }
    drop(jobs);
    let _ = worker.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ts: u64, action: &str, client: &str) -> EventRecord {
        EventRecord {
            country: None,
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
    fn lock_conn_recovers_from_poison() {
        // Regression: a panic while holding the connection mutex used to
        // poison every subsequent .lock().unwrap() caller. lock_conn must
        // recover the inner guard instead.
        let db = Database::open_in_memory().unwrap();
        // Poison the mutex by panicking while holding the guard.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = db.conn.lock().unwrap();
            panic!("intentional");
        }));
        assert!(result.is_err());
        assert!(db.conn.is_poisoned());
        // The next normal operation must still succeed despite poisoning.
        db.insert_events(&[rec(1000, "Allowed", "1.2.3.4")])
            .unwrap();
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
    fn migration_rewrites_ipv4_mapped_clients() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.sqlite");
        let path = path.to_str().unwrap();

        // Simulate a database written by an older monitor.
        {
            let db = Database::open(path, 72, 90).unwrap();
            let conn = db.conn.lock().unwrap();
            conn.execute_batch(
                "PRAGMA user_version = 0;
                 INSERT INTO dns_events (timestamp, domain_hash, domain, client_ip, action)
                 VALUES (1, 'a', NULL, '::ffff:10.0.0.1', 'Allowed'),
                        (2, 'b', NULL, '2001:db8::1', 'Allowed'),
                        (3, 'c', NULL, '::ffff:abcd', 'Allowed');
                 INSERT INTO dns_stats_hourly (hour, domain_hash, client_ip, action, count)
                 VALUES (3600, 'a', '::ffff:10.0.0.1', 'Allowed', 5),
                        (3600, 'a', '10.0.0.1', 'Allowed', 3),
                        (7200, 'a', '::ffff:10.0.0.2', 'Blocked', 4);",
            )
            .unwrap();
        }

        let db = Database::open(path, 72, 90).unwrap();
        let conn = db.conn.lock().unwrap();
        let clients: Vec<String> = conn
            .prepare("SELECT client_ip FROM dns_events ORDER BY timestamp")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        // Only dotted IPv4-mapped text is rewritten.
        assert_eq!(clients, ["10.0.0.1", "2001:db8::1", "::ffff:abcd"]);

        let hourly: Vec<(i64, String, i64)> = conn
            .prepare("SELECT hour, client_ip, count FROM dns_stats_hourly ORDER BY hour")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            hourly,
            [
                (3600, "10.0.0.1".to_string(), 8),
                (7200, "10.0.0.2".to_string(), 4),
            ]
        );

        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn migration_runs_only_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.sqlite");
        let path = path.to_str().unwrap();
        {
            let db = Database::open(path, 72, 90).unwrap();
            // Already at v1: a legacy-looking row written now must be left alone.
            db.conn
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO dns_events (timestamp, domain_hash, client_ip, action)
                     VALUES (1, 'a', '::ffff:10.0.0.1', 'Allowed')",
                    [],
                )
                .unwrap();
        }
        let db = Database::open(path, 72, 90).unwrap();
        let client: String = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT client_ip FROM dns_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(client, "::ffff:10.0.0.1");
    }

    /// Events lost to bus lag are counted for the persistence sink, and the
    /// ones received still reach SQLite through the worker.
    #[tokio::test]
    async fn writer_counts_lagged_events_and_persists_the_rest() {
        use crate::protocol::{StatAction, StatEvent};

        let app = Arc::new(AppState::with_event_buffer(Duration::from_secs(3600), 4));
        let db = Arc::new(Database::open_in_memory().unwrap());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let writer = tokio::spawn(run_writer(Arc::clone(&app), Arc::clone(&db), shutdown_rx));
        assert!(app.wait_for_subscribers(1, Duration::from_secs(5)).await);

        // Single-threaded runtime: the writer cannot run while we publish
        // 10 events into a 4-slot bus, so it misses the first 6.
        for timestamp in 0..10 {
            app.record_event(StatEvent {
                country: None,
                timestamp,
                domain_hash: 1,
                client_ip: [0; 16],
                action: StatAction::Allowed,
            })
            .await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);
        writer.await.unwrap();

        assert_eq!(app.dropped(Sink::Persistence), 6);
        let rows = db.query_range(0, u64::MAX, None, None, 100, 0).unwrap();
        assert_eq!(rows.len(), 4);
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
