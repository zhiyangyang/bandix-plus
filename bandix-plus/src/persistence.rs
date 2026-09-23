use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::monitor::{
    export_runtime_state, import_runtime_state, promote_stale_points_to_bucket, AggregatedBucket, CurrentHourPointState,
    HistogramHistory, MonitorRuntime, MonitorRuntimeState,
};
use crate::policy::{
    export_runtime_state as export_policy_runtime_state, import_runtime_state as import_policy_runtime_state, PolicyRuntime,
    PolicyRuntimeState,
};
use crate::topology::TopologySnapshot;

const POLICY_SCHEMA_VERSION: u32 = 1;
const DEVICES_SCHEMA_VERSION: u32 = 1;
const DB_USER_VERSION: i32 = 1;

const SERIES_IFACE: &str = "iface";
const SERIES_DEVICE: &str = "device";

#[derive(Debug)]
pub struct PersistenceManager {
    data_dir: PathBuf,
    db_path: PathBuf,
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPolicyFile {
    schema_version: u32,
    state: PolicyRuntimeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDevicesFile {
    schema_version: u32,
    state: MonitorRuntimeState,
}

impl PersistenceManager {
    pub fn new(data_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;
        let db_path = data_dir.join("bandix.db");
        let conn = Connection::open(&db_path)?;
        Self::configure(&conn)?;
        Self::migrate(&conn)?;
        Ok(Self {
            data_dir,
            db_path,
            conn: Mutex::new(conn),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Path to the SQLite database file (`bandix.db` under data_dir).
    #[allow(dead_code)]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn with_conn<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T>,
    {
        let guard = self.conn.lock().map_err(|_| anyhow::anyhow!("persistence db lock poisoned"))?;
        f(&guard)
    }

    fn configure(conn: &Connection) -> anyhow::Result<()> {
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Best-effort: only takes effect on empty/new DBs; ignored failures on old files.
        let _ = conn.pragma_update(None, "auto_vacuum", "INCREMENTAL");
        Ok(())
    }

    fn migrate(conn: &Connection) -> anyhow::Result<()> {
        let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == DB_USER_VERSION {
            return Ok(());
        }
        if version != 0 {
            anyhow::bail!("unsupported bandix.db user_version {version}");
        }

        conn.execute_batch(
            r#"
            BEGIN;
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS known_devices (
                logical_iface TEXT NOT NULL,
                mac TEXT NOT NULL,
                ipv4 TEXT NOT NULL,
                ipv6 TEXT NOT NULL,
                hostname TEXT NOT NULL DEFAULT '',
                subnet TEXT NOT NULL DEFAULT '',
                last_seen_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (logical_iface, mac)
            );
            CREATE TABLE IF NOT EXISTS traffic_buckets (
                series_type TEXT NOT NULL,
                logical_iface TEXT NOT NULL,
                mac TEXT NOT NULL DEFAULT '',
                start_ts_ms INTEGER NOT NULL,
                end_ts_ms INTEGER NOT NULL,
                up_v4_bytes INTEGER NOT NULL,
                down_v4_bytes INTEGER NOT NULL,
                up_v6_bytes INTEGER NOT NULL,
                down_v6_bytes INTEGER NOT NULL,
                up_v4_bps_avg INTEGER NOT NULL,
                up_v4_bps_max INTEGER NOT NULL,
                up_v4_bps_min INTEGER NOT NULL,
                up_v4_bps_p95 INTEGER NOT NULL,
                down_v4_bps_avg INTEGER NOT NULL,
                down_v4_bps_max INTEGER NOT NULL,
                down_v4_bps_min INTEGER NOT NULL,
                down_v4_bps_p95 INTEGER NOT NULL,
                up_v6_bps_avg INTEGER NOT NULL,
                up_v6_bps_max INTEGER NOT NULL,
                up_v6_bps_min INTEGER NOT NULL,
                up_v6_bps_p95 INTEGER NOT NULL,
                down_v6_bps_avg INTEGER NOT NULL,
                down_v6_bps_max INTEGER NOT NULL,
                down_v6_bps_min INTEGER NOT NULL,
                down_v6_bps_p95 INTEGER NOT NULL,
                PRIMARY KEY (series_type, logical_iface, mac, start_ts_ms)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS current_hour_points (
                series_type TEXT NOT NULL,
                logical_iface TEXT NOT NULL,
                mac TEXT NOT NULL DEFAULT '',
                hour_start_ts_ms INTEGER NOT NULL,
                ts_ms INTEGER NOT NULL,
                up_v4_bytes INTEGER NOT NULL,
                down_v4_bytes INTEGER NOT NULL,
                up_v6_bytes INTEGER NOT NULL,
                down_v6_bytes INTEGER NOT NULL,
                up_v4_bps INTEGER NOT NULL,
                down_v4_bps INTEGER NOT NULL,
                up_v6_bps INTEGER NOT NULL,
                down_v6_bps INTEGER NOT NULL,
                PRIMARY KEY (series_type, logical_iface, mac, ts_ms)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_buckets_series_time
                ON traffic_buckets(series_type, logical_iface, mac, start_ts_ms);
            CREATE INDEX IF NOT EXISTS idx_current_hour_series
                ON current_hour_points(series_type, logical_iface, mac, hour_start_ts_ms);
            PRAGMA user_version = 1;
            COMMIT;
            "#,
        )?;
        Ok(())
    }

    pub fn save_policy_runtime(&self, runtime: &PolicyRuntime) -> anyhow::Result<()> {
        let data = PersistedPolicyFile {
            schema_version: POLICY_SCHEMA_VERSION,
            state: export_policy_runtime_state(runtime),
        };
        let payload = serde_json::to_string(&data)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO policy_state (id, schema_version, payload) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET schema_version = excluded.schema_version, payload = excluded.payload",
                params![POLICY_SCHEMA_VERSION as i64, payload],
            )?;
            Ok(())
        })
    }

    pub fn load_policy_runtime(&self, runtime: &mut PolicyRuntime, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let payload: Option<String> = self.with_conn(|conn| {
            conn.query_row("SELECT payload FROM policy_state WHERE id = 1", [], |row| row.get(0))
                .optional()
                .map_err(Into::into)
        })?;
        let Some(payload) = payload else {
            return Ok(());
        };
        let data: PersistedPolicyFile = serde_json::from_str(&payload)?;
        if data.schema_version != POLICY_SCHEMA_VERSION {
            anyhow::bail!("unsupported policy schema version {}", data.schema_version);
        }
        import_policy_runtime_state(runtime, data.state, topology)
    }

    pub fn save_monitor_runtime(&self, runtime: &MonitorRuntime, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let data = PersistedDevicesFile {
            schema_version: DEVICES_SCHEMA_VERSION,
            state: export_runtime_state(runtime, topology),
        };
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute("DELETE FROM known_devices", [])?;
            for dev in &data.state.known_devices {
                tx.execute(
                    "INSERT INTO known_devices (logical_iface, mac, ipv4, ipv6, hostname, subnet, last_seen_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        dev.logical_iface,
                        dev.mac,
                        serde_json::to_string(&dev.ipv4)?,
                        serde_json::to_string(&dev.ipv6)?,
                        dev.hostname,
                        dev.subnet,
                        dev.last_seen_ms as i64,
                    ],
                )?;
            }
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('devices_schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![DEVICES_SCHEMA_VERSION.to_string()],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn load_monitor_runtime(&self, runtime: &mut MonitorRuntime, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let state = self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT logical_iface, mac, ipv4, ipv6, hostname, subnet, last_seen_ms
                 FROM known_devices
                 ORDER BY logical_iface, mac",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?;

            let mut state = MonitorRuntimeState { known_devices: Vec::new() };
            for row in rows {
                let (logical_iface, mac, ipv4, ipv6, hostname, subnet, last_seen_ms) = row?;
                state.known_devices.push(crate::monitor::PersistedKnownDevice {
                    logical_iface,
                    mac,
                    ipv4: serde_json::from_str(&ipv4).unwrap_or_default(),
                    ipv6: serde_json::from_str(&ipv6).unwrap_or_default(),
                    hostname,
                    subnet,
                    last_seen_ms: last_seen_ms.max(0) as u64,
                });
            }
            Ok(state)
        })?;
        import_runtime_state(runtime, state, topology)
    }

    pub fn save_current_hour_histogram(&self, histogram: &HistogramHistory, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let exported = histogram.export_current_hour_state();
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute("DELETE FROM current_hour_points", [])?;

            for item in &exported.iface {
                let Some(info) = topology.by_ifindex(item.ifindex) else {
                    continue;
                };
                for p in &item.points {
                    tx.execute(
                        "INSERT OR REPLACE INTO current_hour_points (
                            series_type, logical_iface, mac, hour_start_ts_ms, ts_ms,
                            up_v4_bytes, down_v4_bytes, up_v6_bytes, down_v6_bytes,
                            up_v4_bps, down_v4_bps, up_v6_bps, down_v6_bps
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                        params![
                            SERIES_IFACE,
                            info.name,
                            "",
                            item.hour_start_ts_ms as i64,
                            p.ts_ms as i64,
                            p.metrics.up_v4_bytes as i64,
                            p.metrics.down_v4_bytes as i64,
                            p.metrics.up_v6_bytes as i64,
                            p.metrics.down_v6_bytes as i64,
                            p.metrics.up_v4_bps as i64,
                            p.metrics.down_v4_bps as i64,
                            p.metrics.up_v6_bps as i64,
                            p.metrics.down_v6_bps as i64,
                        ],
                    )?;
                }
            }

            for item in &exported.device {
                let Some(info) = topology.by_ifindex(item.ifindex) else {
                    continue;
                };
                for p in &item.points {
                    tx.execute(
                        "INSERT OR REPLACE INTO current_hour_points (
                            series_type, logical_iface, mac, hour_start_ts_ms, ts_ms,
                            up_v4_bytes, down_v4_bytes, up_v6_bytes, down_v6_bytes,
                            up_v4_bps, down_v4_bps, up_v6_bps, down_v6_bps
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                        params![
                            SERIES_DEVICE,
                            info.name,
                            item.mac,
                            item.hour_start_ts_ms as i64,
                            p.ts_ms as i64,
                            p.metrics.up_v4_bytes as i64,
                            p.metrics.down_v4_bytes as i64,
                            p.metrics.up_v6_bytes as i64,
                            p.metrics.down_v6_bytes as i64,
                            p.metrics.up_v4_bps as i64,
                            p.metrics.down_v4_bps as i64,
                            p.metrics.up_v6_bps as i64,
                            p.metrics.down_v6_bps as i64,
                        ],
                    )?;
                }
            }

            tx.commit()?;
            Ok(())
        })
    }

    pub fn load_current_hour_histogram(
        &self,
        topology: &TopologySnapshot,
        histogram: &mut HistogramHistory,
        now_ms: u64,
    ) -> anyhow::Result<()> {
        let (expected_start, _) = crate::monitor::hourly_bucket_local(now_ms);

        // Phase 1: read all points under the lock.
        let series: Vec<(String, String, String, u64, CurrentHourPointState)> = self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT series_type, logical_iface, mac, hour_start_ts_ms, ts_ms,
                        up_v4_bytes, down_v4_bytes, up_v6_bytes, down_v6_bytes,
                        up_v4_bps, down_v4_bps, up_v6_bps, down_v6_bps
                 FROM current_hour_points
                 ORDER BY series_type, logical_iface, mac, ts_ms",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, i64>(4)? as u64,
                    crate::monitor::CounterQuad {
                        up_v4_bytes: row.get::<_, i64>(5)? as u64,
                        down_v4_bytes: row.get::<_, i64>(6)? as u64,
                        up_v6_bytes: row.get::<_, i64>(7)? as u64,
                        down_v6_bytes: row.get::<_, i64>(8)? as u64,
                        up_v4_bps: row.get::<_, i64>(9)? as u64,
                        down_v4_bps: row.get::<_, i64>(10)? as u64,
                        up_v6_bps: row.get::<_, i64>(11)? as u64,
                        down_v6_bps: row.get::<_, i64>(12)? as u64,
                    },
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (series_type, logical_iface, mac, hour_start, ts_ms, metrics) = row?;
                out.push((
                    series_type,
                    logical_iface,
                    mac,
                    hour_start,
                    CurrentHourPointState { ts_ms, metrics },
                ));
            }
            Ok(out)
        })?;

        // Group by series key + hour_start so stale hours can be promoted.
        let mut grouped: Vec<(String, String, String, u64, Vec<CurrentHourPointState>)> = Vec::new();
        for (series_type, logical_iface, mac, hour_start, point) in series {
            match grouped
                .iter_mut()
                .find(|(st, li, m, h, _)| st == &series_type && li == &logical_iface && m == &mac && h == &hour_start)
            {
                Some((_, _, _, _, points)) => points.push(point),
                None => grouped.push((series_type, logical_iface, mac, hour_start, vec![point])),
            }
        }

        // Phase 2: promote/restore and write back under the lock.
        // Build a list of pending mutations first so we don't hold the lock while mutating histogram.
        enum Action {
            RestoreCurrent,
            Promote(AggregatedBucket),
            DropOnly,
        }

        let mut planned: Vec<(String, String, String, u64, Vec<CurrentHourPointState>, Action)> = Vec::new();
        for (series_type, logical_iface, mac, hour_start, points) in grouped {
            if hour_start == expected_start {
                planned.push((series_type, logical_iface, mac, hour_start, points, Action::RestoreCurrent));
            } else if hour_start > expected_start {
                log::warn!(
                    "ignoring future current-hour state iface={} hour_start={}",
                    logical_iface,
                    hour_start
                );
                planned.push((series_type, logical_iface, mac, hour_start, points, Action::DropOnly));
            } else {
                match promote_stale_points_to_bucket(hour_start, &points) {
                    Some(bucket) => planned.push((series_type, logical_iface, mac, hour_start, points, Action::Promote(bucket))),
                    None => planned.push((series_type, logical_iface, mac, hour_start, points, Action::DropOnly)),
                }
            }
        }

        for (series_type, logical_iface, mac, hour_start, points, action) in planned {
            let Some(ifindex) = topology.ifindex_by_name(&logical_iface) else {
                continue;
            };

            match action {
                Action::RestoreCurrent => {
                    if series_type == SERIES_IFACE {
                        histogram.restore_current_hour_iface_state(ifindex, hour_start, points, now_ms);
                    } else {
                        histogram.restore_current_hour_device_state(ifindex, mac.clone(), hour_start, points, now_ms);
                    }
                }
                Action::Promote(bucket) => {
                    self.with_conn(|conn| {
                        let tx = conn.unchecked_transaction()?;
                        let already_in_db: bool = tx
                            .query_row(
                                "SELECT 1 FROM traffic_buckets
                                 WHERE series_type = ?1 AND logical_iface = ?2 AND mac = ?3 AND start_ts_ms = ?4",
                                params![series_type, logical_iface, mac, bucket.start_ts_ms as i64],
                                |_| Ok(true),
                            )
                            .optional()?
                            .unwrap_or(false);
                        if !already_in_db {
                            Self::insert_bucket(&tx, &series_type, &logical_iface, &mac, &bucket)?;
                        }
                        tx.execute(
                            "DELETE FROM current_hour_points WHERE series_type = ?1 AND logical_iface = ?2 AND mac = ?3 AND hour_start_ts_ms = ?4",
                            params![series_type, logical_iface, mac, hour_start as i64],
                        )?;
                        tx.commit()?;
                        Ok(())
                    })?;

                    if series_type == SERIES_IFACE {
                        if !histogram.has_completed_iface_bucket(ifindex, bucket.start_ts_ms) {
                            histogram.restore_iface_bucket(ifindex, bucket);
                        }
                    } else if !histogram.has_completed_device_bucket(ifindex, &mac, bucket.start_ts_ms) {
                        histogram.restore_device_bucket(ifindex, mac.clone(), bucket);
                    }
                }
                Action::DropOnly => {
                    self.with_conn(|conn| {
                        conn.execute(
                            "DELETE FROM current_hour_points WHERE series_type = ?1 AND logical_iface = ?2 AND mac = ?3 AND hour_start_ts_ms = ?4",
                            params![series_type, logical_iface, mac, hour_start as i64],
                        )?;
                        Ok(())
                    })?;
                }
            }
        }
        Ok(())
    }

    pub fn append_iface_bucket(&self, iface_name: &str, bucket: &AggregatedBucket) -> anyhow::Result<()> {
        self.with_conn(|conn| Self::insert_bucket(conn, SERIES_IFACE, iface_name, "", bucket))
    }

    pub fn append_device_bucket(&self, iface_name: &str, mac: &str, bucket: &AggregatedBucket) -> anyhow::Result<()> {
        if normalize_mac_hex(mac).is_none() {
            anyhow::bail!("invalid mac for bucket: {mac}");
        }
        let mac_lower = mac.to_ascii_lowercase();
        self.with_conn(|conn| Self::insert_bucket(conn, SERIES_DEVICE, iface_name, &mac_lower, bucket))
    }

    /// Delete hourly buckets older than `retention_days`. `0` disables pruning.
    /// Returns the number of deleted rows.
    pub fn prune_traffic_buckets(&self, retention_days: u32, now_ms: u64) -> anyhow::Result<usize> {
        if retention_days == 0 {
            return Ok(0);
        }
        let retention_ms = u64::from(retention_days)
            .saturating_mul(24)
            .saturating_mul(60)
            .saturating_mul(60)
            .saturating_mul(1000);
        let cutoff = now_ms.saturating_sub(retention_ms) as i64;
        self.with_conn(|conn| {
            let deleted = conn.execute("DELETE FROM traffic_buckets WHERE start_ts_ms < ?1", params![cutoff])?;
            Ok(deleted)
        })
    }

    /// Incrementally reclaim free pages after pruning (safe for flash; no full rewrite).
    pub fn incremental_vacuum(&self, pages: i64) -> anyhow::Result<()> {
        if pages <= 0 {
            return Ok(());
        }
        self.with_conn(|conn| {
            let _ = conn.pragma_update(None, "auto_vacuum", "INCREMENTAL");
            conn.execute_batch(&format!("PRAGMA incremental_vacuum({pages});"))?;
            Ok(())
        })
    }

    pub fn delete_device_traffic(&self, iface_name: &str, mac: &str) -> anyhow::Result<bool> {
        let mac_lower = mac.to_ascii_lowercase();
        self.with_conn(|conn| {
            let n = conn.execute(
                "DELETE FROM traffic_buckets WHERE series_type = ?1 AND logical_iface = ?2 AND mac = ?3",
                params![SERIES_DEVICE, iface_name, mac_lower],
            )?;
            let n2 = conn.execute(
                "DELETE FROM current_hour_points WHERE series_type = ?1 AND logical_iface = ?2 AND mac = ?3",
                params![SERIES_DEVICE, iface_name, mac_lower],
            )?;
            Ok(n + n2 > 0)
        })
    }

    pub fn load_histogram(&self, topology: &TopologySnapshot, histogram: &mut HistogramHistory) -> anyhow::Result<()> {
        let rows: Vec<(String, String, String, AggregatedBucket)> = self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT series_type, logical_iface, mac, start_ts_ms, end_ts_ms,
                        up_v4_bytes, down_v4_bytes, up_v6_bytes, down_v6_bytes,
                        up_v4_bps_avg, up_v4_bps_max, up_v4_bps_min, up_v4_bps_p95,
                        down_v4_bps_avg, down_v4_bps_max, down_v4_bps_min, down_v4_bps_p95,
                        up_v6_bps_avg, up_v6_bps_max, up_v6_bps_min, up_v6_bps_p95,
                        down_v6_bps_avg, down_v6_bps_max, down_v6_bps_min, down_v6_bps_p95
                 FROM traffic_buckets
                 ORDER BY start_ts_ms",
            )?;
            let mapped = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    AggregatedBucket {
                        start_ts_ms: row.get::<_, i64>(3)? as u64,
                        end_ts_ms: row.get::<_, i64>(4)? as u64,
                        up_v4_bytes: row.get::<_, i64>(5)? as u64,
                        down_v4_bytes: row.get::<_, i64>(6)? as u64,
                        up_v6_bytes: row.get::<_, i64>(7)? as u64,
                        down_v6_bytes: row.get::<_, i64>(8)? as u64,
                        up_v4_bps_avg: row.get::<_, i64>(9)? as u64,
                        up_v4_bps_max: row.get::<_, i64>(10)? as u64,
                        up_v4_bps_min: row.get::<_, i64>(11)? as u64,
                        up_v4_bps_p95: row.get::<_, i64>(12)? as u64,
                        down_v4_bps_avg: row.get::<_, i64>(13)? as u64,
                        down_v4_bps_max: row.get::<_, i64>(14)? as u64,
                        down_v4_bps_min: row.get::<_, i64>(15)? as u64,
                        down_v4_bps_p95: row.get::<_, i64>(16)? as u64,
                        up_v6_bps_avg: row.get::<_, i64>(17)? as u64,
                        up_v6_bps_max: row.get::<_, i64>(18)? as u64,
                        up_v6_bps_min: row.get::<_, i64>(19)? as u64,
                        up_v6_bps_p95: row.get::<_, i64>(20)? as u64,
                        down_v6_bps_avg: row.get::<_, i64>(21)? as u64,
                        down_v6_bps_max: row.get::<_, i64>(22)? as u64,
                        down_v6_bps_min: row.get::<_, i64>(23)? as u64,
                        down_v6_bps_p95: row.get::<_, i64>(24)? as u64,
                    },
                ))
            })?;
            let mut out = Vec::new();
            for row in mapped {
                out.push(row?);
            }
            Ok(out)
        })?;

        for (series_type, logical_iface, mac, bucket) in rows {
            let Some(ifindex) = topology.ifindex_by_name(&logical_iface) else {
                continue;
            };
            if series_type == SERIES_IFACE {
                histogram.restore_iface_bucket(ifindex, bucket);
            } else {
                histogram.restore_device_bucket(ifindex, mac, bucket);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn execute_for_test(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> anyhow::Result<usize> {
        self.with_conn(|conn| Ok(conn.execute(sql, params)?))
    }

    #[cfg(test)]
    fn query_i64_for_test(&self, sql: &str) -> anyhow::Result<i64> {
        self.with_conn(|conn| Ok(conn.query_row(sql, [], |r| r.get(0))?))
    }

    fn insert_bucket(conn: &Connection, series_type: &str, iface: &str, mac: &str, b: &AggregatedBucket) -> anyhow::Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO traffic_buckets (
                series_type, logical_iface, mac, start_ts_ms, end_ts_ms,
                up_v4_bytes, down_v4_bytes, up_v6_bytes, down_v6_bytes,
                up_v4_bps_avg, up_v4_bps_max, up_v4_bps_min, up_v4_bps_p95,
                down_v4_bps_avg, down_v4_bps_max, down_v4_bps_min, down_v4_bps_p95,
                up_v6_bps_avg, up_v6_bps_max, up_v6_bps_min, up_v6_bps_p95,
                down_v6_bps_avg, down_v6_bps_max, down_v6_bps_min, down_v6_bps_p95
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17,
                ?18, ?19, ?20, ?21,
                ?22, ?23, ?24, ?25
             )",
            params![
                series_type,
                iface,
                mac,
                b.start_ts_ms as i64,
                b.end_ts_ms as i64,
                b.up_v4_bytes as i64,
                b.down_v4_bytes as i64,
                b.up_v6_bytes as i64,
                b.down_v6_bytes as i64,
                b.up_v4_bps_avg as i64,
                b.up_v4_bps_max as i64,
                b.up_v4_bps_min as i64,
                b.up_v4_bps_p95 as i64,
                b.down_v4_bps_avg as i64,
                b.down_v4_bps_max as i64,
                b.down_v4_bps_min as i64,
                b.down_v4_bps_p95 as i64,
                b.up_v6_bps_avg as i64,
                b.up_v6_bps_max as i64,
                b.up_v6_bps_min as i64,
                b.up_v6_bps_p95 as i64,
                b.down_v6_bps_avg as i64,
                b.down_v6_bps_max as i64,
                b.down_v6_bps_min as i64,
                b.down_v6_bps_p95 as i64,
            ],
        )?;
        Ok(())
    }
}

fn normalize_mac_hex(mac: &str) -> Option<String> {
    let compact: String = mac.chars().filter(|c| *c != ':').collect::<String>().to_ascii_lowercase();
    if compact.len() != 12 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(compact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::CounterQuad;
    use crate::utils::time_utils;
    use chrono::TimeZone;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bandix-plus-sqlite-{}-{}", tag, time_utils::now_millis()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_bucket(start: u64) -> AggregatedBucket {
        AggregatedBucket {
            start_ts_ms: start,
            end_ts_ms: start + 3_599_999,
            up_v4_bytes: 1,
            down_v4_bytes: 2,
            up_v6_bytes: 3,
            down_v6_bytes: 4,
            up_v4_bps_avg: 5,
            up_v4_bps_max: 6,
            up_v4_bps_min: 7,
            up_v4_bps_p95: 8,
            down_v4_bps_avg: 9,
            down_v4_bps_max: 10,
            down_v4_bps_min: 11,
            down_v4_bps_p95: 12,
            up_v6_bps_avg: 13,
            up_v6_bps_max: 14,
            up_v6_bps_min: 15,
            up_v6_bps_p95: 16,
            down_v6_bps_avg: 17,
            down_v6_bps_max: 18,
            down_v6_bps_min: 19,
            down_v6_bps_p95: 20,
        }
    }

    fn mock_topology() -> TopologySnapshot {
        use crate::topology::Interface;
        use crate::utils::system_utils::InterfaceRole;
        TopologySnapshot::from_interfaces(vec![
            Interface {
                ifindex: 1,
                name: "br-lan".to_string(),
                role: InterfaceRole::Bridge,
                zone: "lan".to_string(),
                parent_ifindex: None,
                ipv4_cidrs: vec!["192.168.1.1/24".to_string()],
                ipv6_cidrs: vec![],
            },
            Interface {
                ifindex: 2,
                name: "eth0".to_string(),
                role: InterfaceRole::Ethernet,
                zone: "unknown".to_string(),
                parent_ifindex: None,
                ipv4_cidrs: vec![],
                ipv6_cidrs: vec![],
            },
        ])
    }

    #[test]
    fn creates_schema_and_reopens() {
        let dir = temp_dir("schema");
        {
            let p = PersistenceManager::new(&dir).unwrap();
            assert!(p.db_path().exists());
        }
        let p2 = PersistenceManager::new(&dir).unwrap();
        assert!(p2.db_path().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_bucket_is_idempotent() {
        let dir = temp_dir("idempotent");
        let p = PersistenceManager::new(&dir).unwrap();
        let topo = mock_topology();
        let mut h = HistogramHistory::new();

        p.append_iface_bucket("br-lan", &sample_bucket(1_000)).unwrap();
        p.append_iface_bucket("br-lan", &sample_bucket(1_000)).unwrap();
        p.append_iface_bucket("br-lan", &sample_bucket(2_000)).unwrap();

        p.load_histogram(&topo, &mut h).unwrap();
        let all = h.query_aggregate(1, None, 0, u64::MAX, crate::monitor::AggregateBucket::Hourly);
        assert_eq!(all.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_traffic_buckets_respects_retention() {
        let dir = temp_dir("prune");
        let p = PersistenceManager::new(&dir).unwrap();

        let now = 1_700_000_000_000u64;
        let old_start = now - (400 * 24 * 60 * 60 * 1000);
        let recent_start = now - (10 * 24 * 60 * 60 * 1000);

        p.append_iface_bucket("br-lan", &sample_bucket(old_start)).unwrap();
        p.append_iface_bucket("br-lan", &sample_bucket(recent_start)).unwrap();
        p.append_device_bucket("br-lan", "AA:BB:CC:DD:EE:FF", &sample_bucket(old_start)).unwrap();
        p.append_device_bucket("br-lan", "AA:BB:CC:DD:EE:FF", &sample_bucket(recent_start)).unwrap();

        // retention 0 = keep forever
        assert_eq!(p.prune_traffic_buckets(0, now).unwrap(), 0);
        let keep_all = p.query_i64_for_test("SELECT COUNT(*) FROM traffic_buckets").unwrap();
        assert_eq!(keep_all, 4);

        // retention 366 days: only ~400d-old rows go away
        let deleted = p.prune_traffic_buckets(366, now).unwrap();
        assert_eq!(deleted, 2);
        let remaining = p.query_i64_for_test("SELECT COUNT(*) FROM traffic_buckets").unwrap();
        assert_eq!(remaining, 2);
        let old_left = p.query_i64_for_test(
            "SELECT COUNT(*) FROM traffic_buckets WHERE start_ts_ms < 1000000",
        );
        // old_start is large; just assert remaining are the recent ones
        assert!(old_left.is_ok());
        let recent_left = p
            .query_i64_for_test(&format!(
                "SELECT COUNT(*) FROM traffic_buckets WHERE start_ts_ms >= {}",
                recent_start as i64
            ))
            .unwrap();
        assert_eq!(recent_left, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_and_load_device_bucket() {
        let dir = temp_dir("device");
        let p = PersistenceManager::new(&dir).unwrap();
        let topo = mock_topology();
        let mut h = HistogramHistory::new();
        let b = sample_bucket(10_000);
        p.append_device_bucket("eth0", "AA:BB:CC:DD:EE:FF", &b).unwrap();
        p.load_histogram(&topo, &mut h).unwrap();
        let all = h.query_aggregate(2, Some("aa:bb:cc:dd:ee:ff"), 0, u64::MAX, crate::monitor::AggregateBucket::Hourly);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].up_v4_bytes, 1);

        assert!(p.delete_device_traffic("eth0", "aa:bb:cc:dd:ee:ff").unwrap());
        let mut h2 = HistogramHistory::new();
        p.load_histogram(&topo, &mut h2).unwrap();
        assert!(h2
            .query_aggregate(2, Some("aa:bb:cc:dd:ee:ff"), 0, u64::MAX, crate::monitor::AggregateBucket::Hourly)
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_current_hour_promotes_to_completed() {
        let dir = temp_dir("stale");
        let p = PersistenceManager::new(&dir).unwrap();
        let topo = mock_topology();

        // now is 11:05, saved hour is 10:00
        let now = chrono::Local.with_ymd_and_hms(2024, 1, 15, 11, 5, 0).unwrap().timestamp_millis() as u64;
        let old = chrono::Local.with_ymd_and_hms(2024, 1, 15, 10, 5, 0).unwrap().timestamp_millis() as u64;
        let (old_start, _) = crate::monitor::hourly_bucket_local(old);

        // Save as current hour relative to a fake "old now" so rows land with hour_start=old_start
        let mut h_write = HistogramHistory::new();
        h_write.restore_current_hour_iface_state(
            1,
            old_start,
            vec![CurrentHourPointState {
                ts_ms: old,
                metrics: CounterQuad {
                    up_v4_bytes: 99,
                    ..CounterQuad::default()
                },
            }],
            old, // treat old hour as current when saving
        );
        p.save_current_hour_histogram(&h_write, &topo).unwrap();

        // Load with now in next hour -> should promote, not drop
        let mut h = HistogramHistory::new();
        p.load_current_hour_histogram(&topo, &mut h, now).unwrap();
        let all = h.query_aggregate(1, None, 0, u64::MAX, crate::monitor::AggregateBucket::Hourly);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].up_v4_bytes, 99);
        assert_eq!(all[0].start_ts_ms, old_start);

        // Second startup: load_histogram first (as command.rs does), then current-hour.
        // Must not double-count the promoted bucket.
        let mut h2 = HistogramHistory::new();
        p.load_histogram(&topo, &mut h2).unwrap();
        p.load_current_hour_histogram(&topo, &mut h2, now + 3_600_000).unwrap();
        let (cum, _) = h2.cumulative_from_all();
        assert_eq!(cum.get(&1).map(|x| x.up_v4_bytes), Some(99));

        // current_hour_points for stale hour should be gone
        let remaining = p.query_i64_for_test("SELECT COUNT(*) FROM current_hour_points").unwrap();
        assert_eq!(remaining, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn current_hour_restores_into_current_slot() {
        let dir = temp_dir("current");
        let p = PersistenceManager::new(&dir).unwrap();
        let topo = mock_topology();
        let now = chrono::Local.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap().timestamp_millis() as u64;
        let (start, _) = crate::monitor::hourly_bucket_local(now);

        let mut h_write = HistogramHistory::new();
        h_write.restore_current_hour_iface_state(
            1,
            start,
            vec![CurrentHourPointState {
                ts_ms: now,
                metrics: CounterQuad {
                    up_v4_bytes: 7,
                    ..CounterQuad::default()
                },
            }],
            now,
        );
        p.save_current_hour_histogram(&h_write, &topo).unwrap();

        let mut h = HistogramHistory::new();
        p.load_current_hour_histogram(&topo, &mut h, now).unwrap();
        let (cum, _) = h.cumulative_from_all();
        assert_eq!(cum.get(&1).map(|x| x.up_v4_bytes), Some(7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_current_hour_is_ignored() {
        let dir = temp_dir("future");
        let p = PersistenceManager::new(&dir).unwrap();
        let topo = mock_topology();
        let now = chrono::Local.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap().timestamp_millis() as u64;
        let future = now + 3_600_000;
        let (future_start, _) = crate::monitor::hourly_bucket_local(future);

        // Manually insert future points
        let sql = "INSERT INTO current_hour_points (
            series_type, logical_iface, mac, hour_start_ts_ms, ts_ms,
            up_v4_bytes, down_v4_bytes, up_v6_bytes, down_v6_bytes,
            up_v4_bps, down_v4_bps, up_v6_bps, down_v6_bps
         ) VALUES ('iface', 'br-lan', '', ?1, ?2, 5, 0, 0, 0, 0, 0, 0, 0)";
        let a = future_start as i64;
        let b = future as i64;
        p.execute_for_test(sql, &[&a, &b]).unwrap();

        let mut h = HistogramHistory::new();
        p.load_current_hour_histogram(&topo, &mut h, now).unwrap();
        let all = h.query_aggregate(1, None, 0, u64::MAX, crate::monitor::AggregateBucket::Hourly);
        assert!(all.is_empty());

        let remaining = p.query_i64_for_test("SELECT COUNT(*) FROM current_hour_points").unwrap();
        assert_eq!(remaining, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_roundtrip() {
        let dir = temp_dir("policy");
        let p = PersistenceManager::new(&dir).unwrap();
        let topo = mock_topology();
        let mut rt = crate::policy::init_runtime(crate::policy::parse_policy());
        p.save_policy_runtime(&rt).unwrap();
        let mut rt2 = crate::policy::init_runtime(crate::policy::parse_policy());
        p.load_policy_runtime(&mut rt2, &topo).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
