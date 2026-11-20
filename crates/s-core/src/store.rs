//! SQLite (`events`, `causality_edges`, FTS5) + `sqlite-vec` (`vec0`) hybrid store.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use s_types::{CausalityEdge, CausalityQueryHit, MaskedMemoryBlock};
use zeroize::Zeroizing;

use crate::causality::{CausalityConfig, link_event_in_tx, load_causality_chain};
use crate::embedder::{EMBEDDING_DIM, Embedder, f32_slice_to_le_bytes, validate_embedding};
use crate::{CoreError, Result};

const SNIPPET_MAX_CHARS: usize = 200;
const VEC0_K_MAX: usize = 4096;
const TOP_APPS_LIMIT: i64 = 10;
const MS_PER_DAY: i64 = 86_400_000;
const MS_PER_HOUR: i64 = 3_600_000;

static SQLITE_VEC_INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

fn ensure_sqlite_vec_registered() -> Result<()> {
    let status =
        SQLITE_VEC_INIT.get_or_init(|| {
            // SAFETY: `sqlite_vec::sqlite3_vec_init` is the statically linked C entrypoint
            // with SQLite auto-extension signature
            // `extern "C" fn(*mut sqlite3, *mut *mut c_char, *const sqlite3_api_routines) -> c_int`.
            // Registering it once via `sqlite3_auto_extension` before connections open ensures
            // every subsequent `Connection` automatically initializes `vec0` and `vec_distance_*`.
            let res = unsafe {
                let entry = std::mem::transmute::<
                    *const (),
                    rusqlite::auto_extension::RawAutoExtension,
                >(sqlite_vec::sqlite3_vec_init as *const ());
                rusqlite::auto_extension::register_auto_extension(entry)
            };
            res.map_err(|e| e.to_string())
        });

    match status {
        Ok(()) => Ok(()),
        Err(msg) => Err(CoreError::VecRegistration(msg.clone())),
    }
}

/// Weights and parameters for hybrid (BM25 + cosine + recency) search.
#[derive(Debug, Clone)]
pub struct HybridSearchConfig {
    pub bm25_weight: f32,
    pub vector_weight: f32,
    pub recency_weight: f32,
    /// Exponential decay half-life in seconds for the recency term.
    pub recency_half_life_seconds: f64,
    /// Optional explicit anchor timestamp (`ms`); defaults to `MAX(events.timestamp_ms)`.
    pub reference_timestamp_ms: Option<u64>,
    pub max_chain_depth: usize,
    pub max_chain_edges: usize,
}

impl Default for HybridSearchConfig {
    fn default() -> Self {
        Self {
            bm25_weight: 0.45,
            vector_weight: 0.45,
            recency_weight: 0.10,
            recency_half_life_seconds: 3600.0,
            reference_timestamp_ms: None,
            max_chain_depth: 5,
            max_chain_edges: 16,
        }
    }
}

/// Aggregate memory and activity statistics returned for the Memory Panel.
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_events: u64,
    /// Local-hour event counts (`(hour_0_to_23, count)`), sorted ascending by hour.
    pub events_by_hour: Vec<(u8, u64)>,
    /// Top captured applications (`(process_name, count)`), sorted descending by count.
    pub top_apps: Vec<(String, u64)>,
    pub redactions_total: u64,
    /// Encrypted database file size in bytes on disk (`None` for `:memory:` stores).
    pub db_bytes: Option<u64>,
    /// Most recent event participating in a causality chain within the requested window.
    pub latest_chain: Option<CausalityQueryHit>,
}

#[derive(Default)]
struct CandidateScores {
    bm25: Option<f32>,
    cosine: Option<f32>,
}

/// SQLite + FTS5 + `sqlite-vec` + Causality Graph store.
///
/// Supports ephemeral in-memory storage ([`MemoryStore::open_in_memory`]) and
/// SQLCipher AES-256 encrypted persistent storage ([`MemoryStore::open_encrypted`]).
pub struct MemoryStore<E: Embedder> {
    conn: Connection,
    embedder: E,
    causality: CausalityConfig,
    db_path: Option<PathBuf>,
}

impl<E: Embedder> MemoryStore<E> {
    /// Opens a fresh in-memory SQLite store with FTS5, `sqlite-vec`, and causality tables.
    pub fn open_in_memory(embedder: E) -> Result<Self> {
        Self::open_in_memory_with_config(embedder, CausalityConfig::default())
    }

    /// Opens a fresh in-memory store with custom causality linking configuration.
    pub fn open_in_memory_with_config(embedder: E, causality: CausalityConfig) -> Result<Self> {
        validate_embedder_dim(&embedder)?;
        ensure_sqlite_vec_registered()?;
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self {
            conn,
            embedder,
            causality,
            db_path: None,
        })
    }

    /// Opens or creates an encrypted SQLCipher store at `path` using a 256-bit raw key.
    ///
    /// Enables `PRAGMA cipher_memory_security = ON`, applies the key via `PRAGMA key = "x'<hex>'"`
    /// inside a `Zeroizing<String>` buffer, and immediately verifies the key against the database
    /// header so a wrong key, plaintext SQLite file, or corrupt file fails explicitly.
    pub fn open_encrypted(path: &Path, key: &[u8; 32], embedder: E) -> Result<Self> {
        Self::open_encrypted_with_config(path, key, embedder, CausalityConfig::default())
    }

    /// Opens or creates an encrypted SQLCipher store with custom causality linking configuration.
    pub fn open_encrypted_with_config(
        path: &Path,
        key: &[u8; 32],
        embedder: E,
        causality: CausalityConfig,
    ) -> Result<Self> {
        validate_embedder_dim(&embedder)?;
        validate_encrypted_db_path(path)?;

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }

        ensure_sqlite_vec_registered()?;

        // Explicitly omit `SQLITE_OPEN_URI` so caller paths cannot invoke URI options
        // such as `?mode=memory` or `?cipher=plaintext`.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        configure_encrypted_connection(&conn, key)?;
        init_schema(&conn)?;

        Ok(Self {
            conn,
            embedder,
            causality,
            db_path: Some(path.to_path_buf()),
        })
    }

    /// Returns the loaded `sqlite-vec` version string (e.g. `v0.1.10-alpha.4`).
    pub fn vec_version(&self) -> Result<String> {
        let ver: String = self
            .conn
            .query_row("SELECT vec_version()", [], |row| row.get(0))?;
        Ok(ver)
    }

    /// Returns a shared reference to the underlying `rusqlite::Connection` for inspection/testing.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Returns the next monotonic `event_id` (`0` on an empty store, or `MAX(event_id) + 1`).
    ///
    /// Intended to be called once after opening the store and before starting
    /// `s_guard::run_with_start_id` and `run_ingestion` (ADR-001). Rejects negative
    /// or `i64::MAX` database IDs with [`CoreError::IntegerOverflow`] instead of
    /// silently falling back to `0`.
    pub fn next_event_id(&self) -> Result<u64> {
        let max_id: Option<i64> =
            self.conn
                .query_row("SELECT MAX(event_id) FROM events", [], |row| row.get(0))?;
        match max_id {
            None => Ok(0),
            Some(id) if id < 0 => Err(CoreError::IntegerOverflow(
                "negative event_id found in events table",
            )),
            Some(id) => {
                let next_i64 = id
                    .checked_add(1)
                    .ok_or(CoreError::IntegerOverflow("next event_id exceeds i64::MAX"))?;
                u64::try_from(next_i64)
                    .map_err(|_| CoreError::IntegerOverflow("next event_id out of u64 range"))
            }
        }
    }

    /// Stores a new sanitized `MaskedMemoryBlock`, indexes FTS5 + `vec0`
    /// (when `has_embedding_payload`), and computes rule-based `CausalityEdge`
    /// links against preceding events.
    ///
    /// Rejects duplicate `event_id` values with [`CoreError::DuplicateEventId`]
    /// so production ingestion never silently overwrites existing events (ADR-001).
    /// Use [`MemoryStore::upsert_block`] when explicit re-indexing is intended.
    pub fn ingest_block(&mut self, block: &MaskedMemoryBlock) -> Result<Vec<CausalityEdge>> {
        self.store_block_inner(block, false)
    }

    /// Inserts or replaces an existing `MaskedMemoryBlock` by `event_id` while
    /// preserving connected `causality_edges` (for explicit re-indexing only).
    ///
    /// Production ingestion paths must use [`MemoryStore::ingest_block`] or
    /// [`run_ingestion`] so `event_id` collisions surface as errors.
    pub fn upsert_block(&mut self, block: &MaskedMemoryBlock) -> Result<Vec<CausalityEdge>> {
        self.store_block_inner(block, true)
    }

    fn store_block_inner(
        &mut self,
        block: &MaskedMemoryBlock,
        allow_upsert: bool,
    ) -> Result<Vec<CausalityEdge>> {
        let _event_id_i64 = i64::try_from(block.event_id)
            .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
        let _timestamp_ms_i64 = i64::try_from(block.timestamp_ms)
            .map_err(|_| CoreError::IntegerOverflow("timestamp_ms exceeds i64::MAX"))?;

        let embedding = if needs_embedding(block) {
            let vec = self.embedder.embed_one(&block.clean_text)?;
            validate_embedding(&vec, EMBEDDING_DIM)?;
            Some(vec)
        } else {
            None
        };

        let tx = self.conn.transaction()?;
        let created_edges = write_block_in_tx(
            &tx,
            block,
            embedding.as_deref(),
            allow_upsert,
            &self.causality,
        )?;
        tx.commit()?;
        Ok(created_edges)
    }

    /// Ingests a slice of `MaskedMemoryBlock` events in order, returning all created causality edges.
    ///
    /// Computes embeddings for all embeddable blocks in a single [`Embedder::embed_batch`] call
    /// (allowing [`DualEmbedder`](crate::DualEmbedder) to route batch ingestion to INT8) and writes
    /// all rows and causality edges inside a single SQLite transaction.
    pub fn ingest_batch(&mut self, blocks: &[MaskedMemoryBlock]) -> Result<Vec<CausalityEdge>> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }

        let mut embed_slots: Vec<Option<usize>> = Vec::with_capacity(blocks.len());
        let mut embed_texts: Vec<&str> = Vec::new();
        for block in blocks {
            i64::try_from(block.event_id)
                .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
            i64::try_from(block.timestamp_ms)
                .map_err(|_| CoreError::IntegerOverflow("timestamp_ms exceeds i64::MAX"))?;
            if needs_embedding(block) {
                embed_slots.push(Some(embed_texts.len()));
                embed_texts.push(block.clean_text.as_str());
            } else {
                embed_slots.push(None);
            }
        }

        let vectors = if embed_texts.is_empty() {
            Vec::new()
        } else {
            let vecs = self.embedder.embed_batch(&embed_texts)?;
            if vecs.len() != embed_texts.len() {
                return Err(CoreError::EmbeddingCountMismatch {
                    expected: embed_texts.len(),
                    actual: vecs.len(),
                });
            }
            for vec in &vecs {
                validate_embedding(vec, EMBEDDING_DIM)?;
            }
            vecs
        };

        let tx = self.conn.transaction()?;
        let mut all_edges = Vec::new();
        for (block, slot) in blocks.iter().zip(embed_slots) {
            let embedding = slot.map(|idx| vectors[idx].as_slice());
            all_edges.extend(write_block_in_tx(
                &tx,
                block,
                embedding,
                false,
                &self.causality,
            )?);
        }
        tx.commit()?;
        Ok(all_edges)
    }

    /// Executes hybrid search combining FTS5 BM25, `sqlite-vec` cosine similarity, and recency,
    /// attaching each hit's connected causality chain.
    pub fn hybrid_search(&self, query: &str, k: usize) -> Result<Vec<CausalityQueryHit>> {
        self.hybrid_search_with_config(query, k, &HybridSearchConfig::default())
    }

    /// Executes hybrid search with explicit weighting and chain traversal parameters.
    pub fn hybrid_search_with_config(
        &self,
        query: &str,
        k: usize,
        config: &HybridSearchConfig,
    ) -> Result<Vec<CausalityQueryHit>> {
        if k == 0 || query.trim().is_empty() {
            return Ok(Vec::new());
        }

        let max_ts_opt: Option<i64> =
            self.conn
                .query_row("SELECT MAX(timestamp_ms) FROM events", [], |row| row.get(0))?;
        let Some(max_ts_i64) = max_ts_opt else {
            return Ok(Vec::new());
        };
        let default_ref_ts = u64::try_from(max_ts_i64)
            .map_err(|_| CoreError::IntegerOverflow("negative timestamp_ms in events table"))?;
        let reference_ts_ms = config.reference_timestamp_ms.unwrap_or(default_ref_ts);

        let candidate_limit = k.saturating_mul(4).clamp(16, 256).min(VEC0_K_MAX);
        let candidate_limit_i64 = i64::try_from(candidate_limit)
            .map_err(|_| CoreError::IntegerOverflow("candidate_limit exceeds i64::MAX"))?;

        let mut candidates: HashMap<u64, CandidateScores> = HashMap::new();

        // 1. Lexical BM25 search via FTS5.
        if let Some(fts_query) = sanitize_fts_query(query) {
            let mut stmt = self.conn.prepare_cached(
                "SELECT rowid, bm25(events_fts, 0.5, 1.0, 2.0) AS raw_bm25
                 FROM events_fts
                 WHERE events_fts MATCH ?1
                 ORDER BY raw_bm25 ASC
                 LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![fts_query, candidate_limit_i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
            })?;
            for row in rows {
                let (id_i64, raw_bm25) = row?;
                let id = u64::try_from(id_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative rowid in events_fts"))?;
                let mag = (-raw_bm25).max(0.0);
                let norm = (mag / (mag + 1.0)) as f32;
                candidates.entry(id).or_default().bm25 = Some(norm);
            }
        }

        // 2. Semantic cosine KNN search via `sqlite-vec`.
        let query_vec = self.embedder.embed_one(query)?;
        validate_embedding(&query_vec, EMBEDDING_DIM)?;
        let query_blob = f32_slice_to_le_bytes(&query_vec);

        {
            let mut stmt = self.conn.prepare_cached(
                "SELECT event_id, distance
                 FROM event_vectors
                 WHERE embedding MATCH ?1 AND k = ?2
                 ORDER BY distance ASC",
            )?;
            let rows = stmt
                .query_map(params![query_blob.as_slice(), candidate_limit_i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
                })?;
            for row in rows {
                let (id_i64, distance) = row?;
                let id = u64::try_from(id_i64).map_err(|_| {
                    CoreError::IntegerOverflow("negative event_id in event_vectors")
                })?;
                let cosine_sim = (1.0_f64 - distance).clamp(0.0, 1.0) as f32;
                candidates.entry(id).or_default().cosine = Some(cosine_sim);
            }
        }

        // 3. Cross-fill cosine similarity for BM25-only candidates.
        {
            let mut point_vec_stmt = self.conn.prepare_cached(
                "SELECT vec_distance_cosine(embedding, ?1)
                 FROM event_vectors
                 WHERE event_id = ?2",
            )?;
            for (&event_id, scores) in &mut candidates {
                if scores.cosine.is_none() {
                    let id_i64 = i64::try_from(event_id)
                        .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
                    let dist_opt: Option<f64> = point_vec_stmt
                        .query_row(params![query_blob.as_slice(), id_i64], |row| row.get(0))
                        .optional()?;
                    let cosine_sim = dist_opt
                        .map(|d| (1.0_f64 - d).clamp(0.0, 1.0) as f32)
                        .unwrap_or(0.0);
                    scores.cosine = Some(cosine_sim);
                }
            }
        }

        // 4. Score candidates by BM25 + cosine + recency.
        let weight_sum =
            (config.bm25_weight + config.vector_weight + config.recency_weight).max(f32::EPSILON);
        let half_life = config.recency_half_life_seconds.max(1.0);

        let mut event_stmt = self.conn.prepare_cached(
            "SELECT timestamp_ms, process_name, sanitized_title, clean_text
             FROM events
             WHERE event_id = ?1",
        )?;

        struct ScoredRow {
            event_id: u64,
            timestamp_ms: u64,
            score: f32,
            summary_snippet: String,
            matched_app: String,
        }

        let mut scored = Vec::with_capacity(candidates.len());
        for (event_id, cand) in candidates {
            let bm25_s = cand.bm25.unwrap_or(0.0);
            let cosine_s = cand.cosine.unwrap_or(0.0);
            if bm25_s <= 0.0 && cosine_s <= 0.0 {
                continue;
            }
            let id_i64 = i64::try_from(event_id)
                .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
            let row_opt: Option<(i64, String, String, String)> = event_stmt
                .query_row([id_i64], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .optional()?;
            let Some((ts_i64, process_name, sanitized_title, clean_text)) = row_opt else {
                continue;
            };
            let timestamp_ms = u64::try_from(ts_i64)
                .map_err(|_| CoreError::IntegerOverflow("negative timestamp_ms in events table"))?;
            let age_seconds = reference_ts_ms.saturating_sub(timestamp_ms) as f64 / 1000.0;
            let recency_s = 0.5_f64.powf(age_seconds / half_life) as f32;

            let score = (config.bm25_weight * bm25_s
                + config.vector_weight * cosine_s
                + config.recency_weight * recency_s)
                / weight_sum;

            scored.push(ScoredRow {
                event_id,
                timestamp_ms,
                score,
                summary_snippet: snippet_for_event(&clean_text, &sanitized_title),
                matched_app: process_name,
            });
        }

        scored.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| b.timestamp_ms.cmp(&a.timestamp_ms))
                .then_with(|| b.event_id.cmp(&a.event_id))
        });
        scored.truncate(k);

        // 5. Attach connected causality chain for the top-k hits.
        let mut hits = Vec::with_capacity(scored.len());
        for item in scored {
            let causality_chain = load_causality_chain(
                &self.conn,
                item.event_id,
                config.max_chain_depth,
                config.max_chain_edges,
            )?;
            hits.push(CausalityQueryHit {
                event_id: item.event_id,
                timestamp_ms: item.timestamp_ms,
                score: item.score,
                summary_snippet: item.summary_snippet,
                matched_app: item.matched_app,
                causality_chain,
            });
        }
        Ok(hits)
    }

    /// Computes aggregate Memory Panel statistics for events with `timestamp_ms >= since_ms`.
    ///
    /// `tz_offset_minutes` follows the east-of-UTC sign convention (e.g. `+180` for UTC+3,
    /// `-300` for UTC-5). `events_by_hour` returns local `(0..=23, count)` pairs sorted ascending
    /// by hour for non-empty hours. `latest_chain` returns the most recent event within the window
    /// that participates in at least one causality edge.
    pub fn memory_stats(&self, since_ms: u64, tz_offset_minutes: i32) -> Result<MemoryStats> {
        let since_i64 = i64::try_from(since_ms)
            .map_err(|_| CoreError::IntegerOverflow("since_ms exceeds i64::MAX"))?;

        let (total_i64, redactions_i64): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(redactions_count), 0)
             FROM events
             WHERE timestamp_ms >= ?1",
            [since_i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let total_events = u64::try_from(total_i64)
            .map_err(|_| CoreError::IntegerOverflow("negative event count in DB"))?;
        let redactions_total = u64::try_from(redactions_i64)
            .map_err(|_| CoreError::IntegerOverflow("negative redactions_count sum in DB"))?;

        // `timestamp_ms >= since_ms >= 0` guarantees `timestamp_ms % MS_PER_DAY >= 0`.
        // Folding `tz_offset_minutes` with `rem_euclid(MS_PER_DAY)` prevents negative modulo
        // and keeps the intermediate sum safely below `2 * MS_PER_DAY`.
        let offset_ms_in_day =
            (i64::from(tz_offset_minutes).saturating_mul(60_000)).rem_euclid(MS_PER_DAY);
        let events_by_hour = {
            let mut stmt = self.conn.prepare_cached(
                "SELECT ((timestamp_ms % ?2) + ?3) % ?2 / ?4 AS local_hour, COUNT(*)
                 FROM events
                 WHERE timestamp_ms >= ?1
                 GROUP BY local_hour
                 ORDER BY local_hour ASC",
            )?;
            let rows = stmt.query_map(
                params![since_i64, MS_PER_DAY, offset_ms_in_day, MS_PER_HOUR],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )?;
            let mut hourly = Vec::new();
            for row in rows {
                let (hr_i64, cnt_i64) = row?;
                let hour = u8::try_from(hr_i64)
                    .map_err(|_| CoreError::IntegerOverflow("local hour out of u8 range"))?;
                let count = u64::try_from(cnt_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative hourly event count"))?;
                hourly.push((hour, count));
            }
            hourly
        };

        let top_apps = {
            let mut stmt = self.conn.prepare_cached(
                "SELECT process_name, COUNT(*) AS cnt
                 FROM events
                 WHERE timestamp_ms >= ?1
                 GROUP BY process_name
                 ORDER BY cnt DESC, process_name ASC
                 LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![since_i64, TOP_APPS_LIMIT], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            let mut apps = Vec::new();
            for row in rows {
                let (process_name, cnt_i64) = row?;
                let count = u64::try_from(cnt_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative app event count"))?;
                apps.push((process_name, count));
            }
            apps
        };

        let db_bytes = self
            .db_path
            .as_deref()
            .and_then(|p| std::fs::metadata(p).ok().map(|m| m.len()));

        let latest_anchor: Option<(i64, i64, String, String, String)> = self
            .conn
            .query_row(
                "SELECT e.event_id, e.timestamp_ms, e.process_name, e.sanitized_title, e.clean_text
                 FROM events e
                 WHERE e.timestamp_ms >= ?1
                   AND EXISTS (
                       SELECT 1 FROM causality_edges c
                       WHERE c.source_event_id = e.event_id OR c.target_event_id = e.event_id
                   )
                 ORDER BY e.timestamp_ms DESC, e.event_id DESC
                 LIMIT 1",
                [since_i64],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;

        let latest_chain = match latest_anchor {
            None => None,
            Some((id_i64, ts_i64, process_name, sanitized_title, clean_text)) => {
                let event_id = u64::try_from(id_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative event_id in DB"))?;
                let timestamp_ms = u64::try_from(ts_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative timestamp_ms in DB"))?;
                let causality_chain = load_causality_chain(
                    &self.conn,
                    event_id,
                    self.causality.max_chain_depth,
                    self.causality.max_chain_edges,
                )?;
                Some(CausalityQueryHit {
                    event_id,
                    timestamp_ms,
                    score: 1.0,
                    summary_snippet: snippet_for_event(&clean_text, &sanitized_title),
                    matched_app: process_name,
                    causality_chain,
                })
            }
        };

        Ok(MemoryStats {
            total_events,
            events_by_hour,
            top_apps,
            redactions_total,
            db_bytes,
            latest_chain,
        })
    }

    /// Deletes all events with `timestamp_ms >= since_ms` along with their `event_vectors`,
    /// `events_fts` rows (via trigger), and connected `causality_edges`, returning the number
    /// of deleted events.
    pub fn delete_since(&mut self, since_ms: u64) -> Result<u64> {
        let since_i64 = i64::try_from(since_ms)
            .map_err(|_| CoreError::IntegerOverflow("since_ms exceeds i64::MAX"))?;

        let tx = self.conn.transaction()?;
        let ids: Vec<i64> = {
            let mut stmt =
                tx.prepare_cached("SELECT event_id FROM events WHERE timestamp_ms >= ?1")?;
            let rows = stmt.query_map([since_i64], |row| row.get(0))?;
            let mut collected = Vec::new();
            for row in rows {
                collected.push(row?);
            }
            collected
        };
        if ids.is_empty() {
            tx.commit()?;
            return Ok(0);
        }

        {
            let mut del_vec = tx.prepare_cached("DELETE FROM event_vectors WHERE event_id = ?1")?;
            for &id in &ids {
                del_vec.execute([id])?;
            }
        }

        tx.execute(
            "DELETE FROM causality_edges
             WHERE source_event_id IN (SELECT event_id FROM events WHERE timestamp_ms >= ?1)
                OR target_event_id IN (SELECT event_id FROM events WHERE timestamp_ms >= ?1)",
            [since_i64],
        )?;
        let deleted = tx.execute("DELETE FROM events WHERE timestamp_ms >= ?1", [since_i64])?;
        tx.commit()?;

        u64::try_from(deleted)
            .map_err(|_| CoreError::IntegerOverflow("deleted event count out of u64 range"))
    }

    /// Deletes every event, vector, FTS5 entry, and causality edge in the store, then runs
    /// `VACUUM` to reclaim database pages and returns the number of deleted events.
    pub fn delete_all(&mut self) -> Result<u64> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM event_vectors", [])?;
        tx.execute("DELETE FROM causality_edges", [])?;
        let deleted = tx.execute("DELETE FROM events", [])?;
        tx.commit()?;

        // `VACUUM` cannot run inside an open transaction.
        self.conn.execute_batch("VACUUM;")?;

        u64::try_from(deleted)
            .map_err(|_| CoreError::IntegerOverflow("deleted event count out of u64 range"))
    }
}

/// Consumes sanitized `MaskedMemoryBlock` events from `s-guard` until the channel closes.
///
/// CPU/FFI work (`embed` + SQLite write) runs on `spawn_blocking` so the Tokio runtime is
/// never blocked, while preserving FIFO ingest ordering.
pub async fn run_ingestion<E: Embedder + 'static>(
    store: Arc<Mutex<MemoryStore<E>>>,
    mut rx: tokio::sync::mpsc::Receiver<MaskedMemoryBlock>,
) -> Result<usize> {
    let mut ingested_count = 0_usize;
    while let Some(block) = rx.recv().await {
        let store_ref = Arc::clone(&store);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut guard = store_ref
                .lock()
                .map_err(|_| CoreError::Embedder("memory store mutex poisoned".to_owned()))?;
            guard.ingest_block(&block)?;
            Ok(())
        })
        .await
        .map_err(|e| CoreError::ChannelJoin(e.to_string()))??;
        ingested_count += 1;
    }
    Ok(ingested_count)
}

fn needs_embedding(block: &MaskedMemoryBlock) -> bool {
    block.has_embedding_payload && !block.clean_text.trim().is_empty()
}

fn write_block_in_tx(
    tx: &Transaction<'_>,
    block: &MaskedMemoryBlock,
    embedding: Option<&[f32]>,
    allow_upsert: bool,
    causality: &CausalityConfig,
) -> Result<Vec<CausalityEdge>> {
    let event_id_i64 = i64::try_from(block.event_id)
        .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
    let timestamp_ms_i64 = i64::try_from(block.timestamp_ms)
        .map_err(|_| CoreError::IntegerOverflow("timestamp_ms exceeds i64::MAX"))?;

    let sql = if allow_upsert {
        "INSERT INTO events (
             event_id, timestamp_ms, process_name, sanitized_title, is_browser,
             clean_text, text_hash, redactions_count, has_embedding_payload, source
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(event_id) DO UPDATE SET
             timestamp_ms = excluded.timestamp_ms,
             process_name = excluded.process_name,
             sanitized_title = excluded.sanitized_title,
             is_browser = excluded.is_browser,
             clean_text = excluded.clean_text,
             text_hash = excluded.text_hash,
             redactions_count = excluded.redactions_count,
             has_embedding_payload = excluded.has_embedding_payload,
             source = excluded.source"
    } else {
        "INSERT INTO events (
             event_id, timestamp_ms, process_name, sanitized_title, is_browser,
             clean_text, text_hash, redactions_count, has_embedding_payload, source
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
    };

    let insert_res = tx.execute(
        sql,
        params![
            event_id_i64,
            timestamp_ms_i64,
            block.app_context.process_name,
            block.app_context.sanitized_title,
            i64::from(block.app_context.is_browser),
            block.clean_text,
            block.text_hash.as_slice(),
            i64::from(block.redactions_count),
            i64::from(block.has_embedding_payload),
            block.source.as_str(),
        ],
    );

    if let Err(err) = insert_res {
        if !allow_upsert
            && let rusqlite::Error::SqliteFailure(ref ffi_err, _) = err
            && ffi_err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
        {
            return Err(CoreError::DuplicateEventId(block.event_id));
        }
        return Err(CoreError::Sqlite(err));
    }

    if allow_upsert {
        tx.execute(
            "DELETE FROM event_vectors WHERE event_id = ?1",
            [event_id_i64],
        )?;
    }
    if let Some(vec) = embedding {
        let blob = f32_slice_to_le_bytes(vec);
        tx.execute(
            "INSERT INTO event_vectors (event_id, embedding) VALUES (?1, ?2)",
            params![event_id_i64, blob],
        )?;
    }

    link_event_in_tx(tx, block, causality)
}

fn validate_embedder_dim(embedder: &impl Embedder) -> Result<()> {
    let actual = embedder.dimension();
    if actual != EMBEDDING_DIM {
        return Err(CoreError::InvalidEmbeddingDim {
            expected: EMBEDDING_DIM,
            actual,
        });
    }
    Ok(())
}

fn validate_encrypted_db_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(CoreError::InvalidDatabasePath(
            "database path must not be empty",
        ));
    }
    if path
        .to_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(":memory:"))
    {
        return Err(CoreError::InvalidDatabasePath(
            "open_encrypted requires a filesystem path, not :memory:",
        ));
    }
    if path.file_name().is_none() || path.is_dir() {
        return Err(CoreError::InvalidDatabasePath(
            "database path must point to a file, not a directory",
        ));
    }
    Ok(())
}

fn configure_encrypted_connection(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    // Enable SQLCipher memory locking and random-overwrite-on-free BEFORE submitting key
    // material so SQLite's parser/VDBE buffers for `PRAGMA key` are wiped on finalization.
    conn.execute_batch("PRAGMA cipher_memory_security = ON; PRAGMA temp_store = MEMORY;")?;

    let cipher_version: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .optional()?;
    if cipher_version
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        return Err(CoreError::Encryption(
            "SQLCipher runtime is unavailable on this SQLite build".to_owned(),
        ));
    }

    let mem_sec: Option<String> = conn
        .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
        .optional()?;
    if mem_sec.as_deref() != Some("1") {
        return Err(CoreError::Encryption(
            "SQLCipher cipher_memory_security failed to activate".to_owned(),
        ));
    }

    apply_raw_key(conn, key)?;

    // Touch page 1 immediately so wrong keys, unencrypted SQLite files, or corrupt headers
    // fail here before any schema DDL or write executes.
    let _schema_tables: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(|err| match err {
            rusqlite::Error::SqliteFailure(ffi_err, _) => CoreError::Encryption(format!(
                "unable to unlock encrypted database (wrong key, plaintext file, or corrupt header): {ffi_err}"
            )),
            _ => CoreError::Encryption(
                "unable to unlock encrypted database (wrong key, plaintext file, or corrupt header)"
                    .to_owned(),
            ),
        })?;

    Ok(())
}

fn apply_raw_key(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    const PREFIX: &str = "PRAGMA key = \"x'";
    const SUFFIX: &str = "'\";";

    // Pre-size a single `Zeroizing<String>` so the hex key never triggers a realloc
    // or leaves an unzeroized copy on the heap.
    let mut pragma_sql = Zeroizing::new(String::with_capacity(PREFIX.len() + 64 + SUFFIX.len()));
    pragma_sql.push_str(PREFIX);
    for &byte in key {
        pragma_sql.push(char::from(HEX[usize::from(byte >> 4)]));
        pragma_sql.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    pragma_sql.push_str(SUFFIX);

    // Use `execute_batch` (never `prepare_cached`) and redact any `SqlInputError`
    // so the raw key SQL never enters the statement cache or error messages.
    conn.execute_batch(&pragma_sql).map_err(|err| match err {
        rusqlite::Error::SqliteFailure(ffi_err, _) => {
            CoreError::Encryption(format!("failed to apply SQLCipher key: {ffi_err}"))
        }
        _ => CoreError::Encryption("failed to apply SQLCipher key".to_owned()),
    })?;

    Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;

         CREATE TABLE IF NOT EXISTS events (
             event_id INTEGER PRIMARY KEY,
             timestamp_ms INTEGER NOT NULL,
             process_name TEXT NOT NULL,
             sanitized_title TEXT NOT NULL,
             is_browser INTEGER NOT NULL CHECK (is_browser IN (0, 1)),
             clean_text TEXT NOT NULL,
             text_hash BLOB NOT NULL CHECK (length(text_hash) = 32),
             redactions_count INTEGER NOT NULL CHECK (redactions_count >= 0),
             has_embedding_payload INTEGER NOT NULL CHECK (has_embedding_payload IN (0, 1)),
             source TEXT NOT NULL
                 CHECK (source IN ('focus', 'clipboard', 'accessibility', 'visual'))
         );

         CREATE INDEX IF NOT EXISTS idx_events_timestamp_ms
             ON events(timestamp_ms DESC);
         CREATE INDEX IF NOT EXISTS idx_events_process_name
             ON events(process_name);

         CREATE TABLE IF NOT EXISTS causality_edges (
             source_event_id INTEGER NOT NULL,
             target_event_id INTEGER NOT NULL,
             relationship TEXT NOT NULL,
             time_delta_seconds INTEGER NOT NULL CHECK (time_delta_seconds >= 0),
             PRIMARY KEY (source_event_id, target_event_id, relationship),
             FOREIGN KEY (source_event_id) REFERENCES events(event_id) ON DELETE CASCADE,
             FOREIGN KEY (target_event_id) REFERENCES events(event_id) ON DELETE CASCADE
         );

         CREATE INDEX IF NOT EXISTS idx_edges_source
             ON causality_edges(source_event_id);
         CREATE INDEX IF NOT EXISTS idx_edges_target
             ON causality_edges(target_event_id);

         CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
             process_name,
             sanitized_title,
             clean_text,
             content='events',
             content_rowid='event_id',
             tokenize='unicode61'
         );

         CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
             INSERT INTO events_fts(rowid, process_name, sanitized_title, clean_text)
             VALUES (new.event_id, new.process_name, new.sanitized_title, new.clean_text);
         END;

         CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
             INSERT INTO events_fts(events_fts, rowid, process_name, sanitized_title, clean_text)
             VALUES ('delete', old.event_id, old.process_name, old.sanitized_title, old.clean_text);
         END;

         CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
             INSERT INTO events_fts(events_fts, rowid, process_name, sanitized_title, clean_text)
             VALUES ('delete', old.event_id, old.process_name, old.sanitized_title, old.clean_text);
             INSERT INTO events_fts(rowid, process_name, sanitized_title, clean_text)
             VALUES (new.event_id, new.process_name, new.sanitized_title, new.clean_text);
         END;

         CREATE VIRTUAL TABLE IF NOT EXISTS event_vectors USING vec0(
             event_id INTEGER PRIMARY KEY,
             embedding float[384] distance_metric=cosine
         );",
    )?;
    Ok(())
}

/// Converts arbitrary user input into a safe FTS5 `OR` query over double-quoted tokens.
pub(crate) fn sanitize_fts_query(raw: &str) -> Option<String> {
    let tokens: Vec<String> = raw
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|tok| !tok.is_empty())
        .map(|tok| format!("\"{}\"", tok.replace('"', "\"\"")))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" OR "))
    }
}

fn snippet_for_event(clean_text: &str, sanitized_title: &str) -> String {
    let source = if clean_text.trim().is_empty() {
        sanitized_title
    } else {
        clean_text
    };
    build_summary_snippet(source, SNIPPET_MAX_CHARS)
}

fn build_summary_snippet(text: &str, max_chars: usize) -> String {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = collapsed.char_indices();
    match chars.nth(max_chars) {
        None => collapsed,
        Some((byte_idx, _)) => format!("{}...", &collapsed[..byte_idx]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s_types::{AppContext, EventSource};
    use tokio::sync::mpsc;

    /// Deterministic offline bag-of-tokens embedder solely for unit-testing
    /// `vec0` cosine indexing and hybrid ranking without network access.
    struct DeterministicTestEmbedder;

    impl Embedder for DeterministicTestEmbedder {
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|t| project_text_to_unit_vec(t)).collect())
        }
    }

    fn project_text_to_unit_vec(text: &str) -> Vec<f32> {
        let mut vec = vec![0.0_f32; EMBEDDING_DIM];
        let lower = text.to_ascii_lowercase();
        let mut any = false;
        for token in lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
        {
            any = true;
            let mut hash: u64 = 0xcbf29ce484222325;
            for &b in token.as_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(0x100000001b3);
            }
            let idx = usize::try_from(hash % (EMBEDDING_DIM as u64)).unwrap_or(0);
            vec[idx] += 1.0;
        }
        if !any {
            vec[0] = 1.0;
        }
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut vec {
                *x /= norm;
            }
        }
        vec
    }

    fn block(
        event_id: u64,
        timestamp_ms: u64,
        process_name: &str,
        sanitized_title: &str,
        is_browser: bool,
        clean_text: &str,
    ) -> MaskedMemoryBlock {
        let mut hash = [0_u8; 32];
        for (i, b) in clean_text.as_bytes().iter().enumerate() {
            hash[i % 32] = hash[i % 32].wrapping_add(*b);
        }
        MaskedMemoryBlock {
            event_id,
            timestamp_ms,
            app_context: AppContext {
                process_name: process_name.to_owned(),
                sanitized_title: sanitized_title.to_owned(),
                is_browser,
            },
            clean_text: clean_text.to_owned(),
            text_hash: hash,
            redactions_count: 0,
            has_embedding_payload: !clean_text.trim().is_empty(),
            source: EventSource::Accessibility,
        }
    }

    #[test]
    fn schema_and_sqlite_vec_extension_initialize() {
        let store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("init store");
        let version = store.vec_version().expect("vec_version");
        assert!(
            version.starts_with('v'),
            "unexpected vec_version: {version}"
        );

        let tables: Vec<String> = store
            .connection()
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(tables.contains(&"events".to_owned()));
        assert!(tables.contains(&"causality_edges".to_owned()));
        assert!(tables.contains(&"events_fts".to_owned()));
        assert!(tables.contains(&"event_vectors".to_owned()));
    }

    #[test]
    fn invalid_embedding_dimensions_and_zero_vectors_are_rejected() {
        struct WrongDimEmbedder;
        impl Embedder for WrongDimEmbedder {
            fn dimension(&self) -> usize {
                128
            }
            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                Ok(vec![vec![1.0; 128]; texts.len()])
            }
        }
        assert!(matches!(
            MemoryStore::open_in_memory(WrongDimEmbedder),
            Err(CoreError::InvalidEmbeddingDim {
                expected: 384,
                actual: 128
            })
        ));

        struct ZeroEmbedder;
        impl Embedder for ZeroEmbedder {
            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                Ok(vec![vec![0.0; EMBEDDING_DIM]; texts.len()])
            }
        }
        let mut store = MemoryStore::open_in_memory(ZeroEmbedder).expect("open");
        let b = block(0, 1_000, "code.exe", "main.rs", false, "hello world");
        assert!(matches!(
            store.ingest_block(&b),
            Err(CoreError::InvalidEmbeddingVector(_))
        ));
    }

    #[test]
    fn hybrid_search_returns_causality_chain_and_handles_punctuation() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");

        let e0 = block(
            0,
            1_000_000,
            "WindowsTerminal.exe",
            "cargo build",
            false,
            "error: pyo3 abi3 symbol not found (Exit Code 1)",
        );
        let e1 = block(
            1,
            1_015_000,
            "brave.exe",
            "pyo3 abi3 symbol not found - Search",
            true,
            "Searching StackOverflow for pyo3 abi3 link fix",
        );
        let mut e2 = block(
            2,
            1_060_000,
            "clipboard",
            "Clipboard",
            false,
            "pyo3-build-config = \"0.22\" abi3-py311",
        );
        e2.source = EventSource::Clipboard;
        let e3 = block(
            3,
            1_070_000,
            "Code.exe",
            "Cargo.toml - VS Code",
            false,
            "Updated dependencies with pyo3-build-config = \"0.22\" abi3-py311",
        );
        let unrelated = block(
            4,
            1_500_000,
            "notepad.exe",
            "grocery.txt",
            false,
            "milk bread coffee beans",
        );

        store
            .ingest_batch(&[e0, e1, e2, e3, unrelated])
            .expect("ingest batch");

        let hits = store
            .hybrid_search("pyo3 abi3: symbol (not found) OR \"C:\\build.rs\"", 3)
            .expect("hybrid_search");
        assert!(!hits.is_empty());
        assert_ne!(hits[0].matched_app, "notepad.exe");
        assert_eq!(hits[0].causality_chain.len(), 3);
        assert_eq!(
            hits[0].causality_chain[0].relationship,
            "searched_after_error"
        );
        assert_eq!(
            hits[0].causality_chain[1].relationship,
            "switched_app_after"
        );
        assert_eq!(
            hits[0].causality_chain[2].relationship,
            "pasted_from_clipboard"
        );
    }

    #[test]
    fn recency_breaks_ties_and_non_embedding_blocks_still_match_bm25() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");

        let old = block(
            10,
            1_000_000,
            "Code.exe",
            "lib.rs",
            false,
            "rust ownership borrow checker notes",
        );
        let recent = block(
            11,
            5_000_000,
            "Code.exe",
            "mod.rs",
            false,
            "rust ownership borrow checker notes",
        );
        let mut no_embed = block(
            12,
            5_010_000,
            "Figma.exe",
            "Architecture Diagram Canvas",
            false,
            "",
        );
        no_embed.has_embedding_payload = false;

        store
            .ingest_batch(&[old, recent, no_embed])
            .expect("ingest");

        let hits = store
            .hybrid_search("rust ownership borrow checker", 5)
            .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(
            hits[0].event_id, 11,
            "more recent identical event must rank first"
        );
        assert_eq!(hits[1].event_id, 10);

        let title_hits = store.hybrid_search("Architecture Diagram", 5).unwrap();
        assert!(!title_hits.is_empty());
        assert_eq!(title_hits[0].event_id, 12);
        assert_eq!(title_hits[0].summary_snippet, "Architecture Diagram Canvas");
    }

    #[test]
    fn upsert_preserves_edges_and_utf8_snippets_never_panic() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        let long_turkish = "güvenlik şifreleme doğrulama ölçümü ".repeat(15);
        let mut e1 = block(
            1,
            10_000,
            "WindowsTerminal.exe",
            "err",
            false,
            "fatal error",
        );
        let e2 = block(2, 20_000, "brave.exe", "search", true, &long_turkish);
        store.ingest_batch(&[e1.clone(), e2]).expect("ingest");

        // Explicit upsert must update e1 without deleting the edge (1 -> 2) via cascade.
        e1.clean_text = "fatal error resolved".to_owned();
        store.upsert_block(&e1).expect("upsert e1");

        let hits = store.hybrid_search("şifreleme doğrulama", 2).unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].event_id, 2);
        assert!(hits[0].summary_snippet.ends_with("..."));
        assert_eq!(hits[0].causality_chain.len(), 1);
        assert_eq!(hits[0].causality_chain[0].source_event_id, 1);
        assert_eq!(hits[0].causality_chain[0].target_event_id, 2);
    }

    #[test]
    fn empty_queries_zero_k_and_empty_db_return_empty() {
        let store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        assert!(store.hybrid_search("rust", 5).unwrap().is_empty());
        assert!(store.hybrid_search("   ", 5).unwrap().is_empty());
        assert!(store.hybrid_search("rust", 0).unwrap().is_empty());
        assert!(sanitize_fts_query("--- ::: !!!").is_none());
    }

    #[tokio::test]
    async fn run_ingestion_consumes_mpsc_channel_end_to_end() {
        let store = Arc::new(Mutex::new(
            MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store"),
        ));
        let (tx, rx) = mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY);
        let handle = tokio::spawn(run_ingestion(Arc::clone(&store), rx));

        tx.send(block(
            100,
            100_000,
            "WindowsTerminal.exe",
            "term",
            false,
            "panic in worker thread",
        ))
        .await
        .unwrap();
        tx.send(block(
            101,
            110_000,
            "msedge.exe",
            "rust panic search",
            true,
            "how to catch unwind in tokio",
        ))
        .await
        .unwrap();
        drop(tx);

        let count = handle.await.unwrap().unwrap();
        assert_eq!(count, 2);

        let hits = store
            .lock()
            .unwrap()
            .hybrid_search("panic worker", 3)
            .unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].causality_chain.len(), 1);
        assert_eq!(
            hits[0].causality_chain[0].relationship,
            "searched_after_error"
        );
    }

    #[test]
    fn pure_vector_cosine_ranking_and_reindexing_work_via_vec0() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        let e1 = block(
            1,
            10_000,
            "Code.exe",
            "a.rs",
            false,
            "alpha beta gamma delta",
        );
        let e2 = block(2, 10_000, "Code.exe", "b.rs", false, "alpha omega theta");
        let e3 = block(
            3,
            10_000,
            "Code.exe",
            "c.rs",
            false,
            "completely unrelated tokens",
        );
        store.ingest_batch(&[e1.clone(), e2, e3]).expect("ingest");

        let vector_only = HybridSearchConfig {
            bm25_weight: 0.0,
            vector_weight: 1.0,
            recency_weight: 0.0,
            ..HybridSearchConfig::default()
        };
        let hits = store
            .hybrid_search_with_config("alpha beta gamma", 3, &vector_only)
            .expect("vector-only search");
        assert!(!hits.is_empty());
        assert_eq!(hits[0].event_id, 1);

        // Re-indexing event 1 via explicit upsert updates vec0 cleanly without duplicate PK errors.
        let mut e1_updated = e1;
        e1_updated.clean_text = "omega theta".to_owned();
        store.upsert_block(&e1_updated).expect("upsert e1");

        let hits_after = store
            .hybrid_search_with_config("alpha beta gamma", 3, &vector_only)
            .expect("vector-only search after reindex");
        assert!(!hits_after.is_empty());
        assert_eq!(hits_after[0].event_id, 2);
    }

    #[test]
    fn next_event_id_returns_zero_when_empty_and_tracks_max_plus_one() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        assert_eq!(store.next_event_id().expect("empty next_event_id"), 0);

        store
            .ingest_block(&block(0, 1_000, "Code.exe", "a.rs", false, "first event"))
            .expect("ingest 0");
        assert_eq!(store.next_event_id().expect("after event 0"), 1);

        store
            .ingest_block(&block(1, 2_000, "Code.exe", "b.rs", false, "second event"))
            .expect("ingest 1");
        assert_eq!(store.next_event_id().expect("after event 1"), 2);

        // Gaps in event_id (e.g. dropped packets in s-guard) jump to MAX(event_id) + 1.
        store
            .ingest_block(&block(10, 3_000, "Code.exe", "c.rs", false, "gapped event"))
            .expect("ingest 10");
        assert_eq!(store.next_event_id().expect("after event 10"), 11);

        // Corrupt negative ID must return an error rather than falling back to 0.
        let neg_store =
            MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open neg store");
        neg_store
            .connection()
            .execute(
                "INSERT INTO events (
                     event_id, timestamp_ms, process_name, sanitized_title, is_browser,
                     clean_text, text_hash, redactions_count, has_embedding_payload, source
                 ) VALUES (-1, 1000, 'Code.exe', 't', 0, 'bad', ?1, 0, 0, 'focus')",
                [[0_u8; 32].as_slice()],
            )
            .expect("insert negative event_id");
        assert!(matches!(
            neg_store.next_event_id(),
            Err(CoreError::IntegerOverflow(_))
        ));

        // i64::MAX ID cannot increment without overflowing SQLite signed i64 range.
        let mut max_store =
            MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open max store");
        max_store
            .ingest_block(&block(
                i64::MAX as u64,
                4_000,
                "Code.exe",
                "m.rs",
                false,
                "max id",
            ))
            .expect("ingest i64::MAX");
        assert!(matches!(
            max_store.next_event_id(),
            Err(CoreError::IntegerOverflow(_))
        ));
    }

    #[test]
    fn ingest_block_rejects_duplicate_event_id_without_overwriting() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        let original = block(
            7,
            10_000,
            "Code.exe",
            "main.rs",
            false,
            "original immutable payload",
        );
        store.ingest_block(&original).expect("initial ingest");

        let colliding = block(
            7,
            20_000,
            "notepad.exe",
            "other.txt",
            false,
            "conflicting overwrite attempt",
        );
        let err = store
            .ingest_block(&colliding)
            .expect_err("duplicate event_id must fail");
        assert!(matches!(err, CoreError::DuplicateEventId(7)));

        let orig_hits = store
            .hybrid_search("original immutable", 3)
            .expect("search original");
        assert_eq!(orig_hits.len(), 1);
        assert_eq!(orig_hits[0].event_id, 7);
        assert_eq!(orig_hits[0].matched_app, "Code.exe");

        let conflict_hits = store
            .hybrid_search("conflicting overwrite", 3)
            .expect("search conflict");
        assert!(conflict_hits.is_empty());
    }

    #[tokio::test]
    async fn run_ingestion_rejects_duplicate_event_id() {
        let store = Arc::new(Mutex::new(
            MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store"),
        ));
        let (tx, rx) = mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY);
        let handle = tokio::spawn(run_ingestion(Arc::clone(&store), rx));

        tx.send(block(5, 1_000, "Code.exe", "a.rs", false, "first block"))
            .await
            .unwrap();
        tx.send(block(5, 2_000, "Code.exe", "b.rs", false, "duplicate id"))
            .await
            .unwrap();
        drop(tx);

        let res = handle.await.unwrap();
        assert!(matches!(res, Err(CoreError::DuplicateEventId(5))));
    }

    #[test]
    fn ingest_block_errors_when_precursor_row_has_negative_event_id() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        store
            .connection()
            .execute(
                "INSERT INTO events (
                     event_id, timestamp_ms, process_name, sanitized_title, is_browser,
                     clean_text, text_hash, redactions_count, has_embedding_payload, source
                 ) VALUES (-2, 1000, 'Code.exe', 't', 0, 'corrupt precursor', ?1, 0, 0, 'focus')",
                [[0_u8; 32].as_slice()],
            )
            .expect("insert negative event_id");

        let err = store
            .ingest_block(&block(1, 2_000, "brave.exe", "search", true, "follow up"))
            .expect_err("negative precursor event_id must fail instead of mapping to 0");
        assert!(matches!(err, CoreError::Sqlite(_)));
    }

    #[test]
    fn event_source_is_persisted_and_schema_rejects_unknown_codes() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        for (i, source) in EventSource::ALL.into_iter().enumerate() {
            let mut b = block(
                i as u64,
                1_000 + i as u64,
                "Code.exe",
                "a.rs",
                false,
                "text",
            );
            b.source = source;
            store.ingest_block(&b).expect("ingest every source");
            let stored = store
                .connection()
                .query_row(
                    "SELECT event_id, timestamp_ms, process_name, sanitized_title, is_browser,
                            clean_text, text_hash, redactions_count, has_embedding_payload, source
                     FROM events WHERE event_id = ?1",
                    [i as i64],
                    crate::causality::row_to_masked_block,
                )
                .expect("read back");
            assert_eq!(stored.source, source);
        }

        let bad = store.connection().execute(
            "INSERT INTO events (
                 event_id, timestamp_ms, process_name, sanitized_title, is_browser,
                 clean_text, text_hash, redactions_count, has_embedding_payload, source
             ) VALUES (99, 1000, 'Code.exe', 't', 0, 'x', ?1, 0, 0, 'keyboard')",
            [[0_u8; 32].as_slice()],
        );
        assert!(
            bad.is_err(),
            "CHECK constraint must reject unknown source codes"
        );
    }

    struct TempDirGuard(std::path::PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "s-core-encrypted-{label}-{}-{seq}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn encrypted_store_persists_across_reopen_and_encrypts_file_on_disk() {
        let dir = TempDirGuard::new("persist");
        let db_path = dir.0.join("nested").join("s-recall.db");
        let key: [u8; 32] = [
            0x3a, 0x91, 0x4c, 0x7e, 0x10, 0x5f, 0x82, 0xb4, 0x67, 0xd8, 0x22, 0x09, 0xef, 0x41,
            0x73, 0xc5, 0x88, 0x1b, 0x9d, 0x2e, 0x54, 0xa0, 0x33, 0x6c, 0xf1, 0x0d, 0x47, 0xbe,
            0x29, 0x85, 0xc0, 0x16,
        ];

        {
            let mut store = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                .expect("open fresh encrypted store");

            let cipher_ver: String = store
                .connection()
                .query_row("PRAGMA cipher_version", [], |row| row.get(0))
                .expect("cipher_version");
            assert!(
                !cipher_ver.trim().is_empty(),
                "expected active SQLCipher version, got empty string"
            );

            let mem_sec: String = store
                .connection()
                .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
                .expect("cipher_memory_security");
            assert_eq!(mem_sec, "1");

            let vec_ver = store.vec_version().expect("sqlite-vec with SQLCipher");
            assert!(
                vec_ver.starts_with('v'),
                "unexpected vec_version: {vec_ver}"
            );
            assert_eq!(store.next_event_id().expect("empty next_event_id"), 0);

            let e0 = block(
                0,
                1_000_000,
                "WindowsTerminal.exe",
                "cargo build",
                false,
                "error: SQLCIPHER_AT_REST_SENTINEL_9911 build failed",
            );
            let e1 = block(
                1,
                1_012_000,
                "brave.exe",
                "SQLCIPHER_AT_REST_SENTINEL_9911 - Search",
                true,
                "Searching fix for SQLCIPHER_AT_REST_SENTINEL_9911",
            );
            let mut e2 = block(
                2,
                1_025_000,
                "Code.exe",
                "store.rs - VS Code",
                false,
                "şifreli kalıcı depolama doğrulama SQLCIPHER_AT_REST_SENTINEL_9911",
            );
            e2.source = EventSource::Clipboard;

            store.ingest_batch(&[e0, e1, e2]).expect("ingest batch");
            assert_eq!(store.next_event_id().expect("after 3 events"), 3);

            let pre_hits = store
                .hybrid_search("SQLCIPHER_AT_REST_SENTINEL_9911", 5)
                .expect("pre-close search");
            assert_eq!(pre_hits.len(), 3);
            assert!(
                pre_hits[0]
                    .causality_chain
                    .iter()
                    .any(|e| e.relationship == "searched_after_error")
            );
        }

        let raw_bytes = std::fs::read(&db_path).expect("read encrypted db bytes");
        assert!(
            raw_bytes.len() >= 4096,
            "encrypted DB file unexpectedly small: {} bytes",
            raw_bytes.len()
        );
        assert!(
            !raw_bytes.starts_with(b"SQLite format 3\0"),
            "encrypted DB must not expose plaintext SQLite magic header"
        );
        for forbidden in [
            b"SQLCIPHER_AT_REST_SENTINEL_9911".as_slice(),
            b"WindowsTerminal.exe".as_slice(),
            b"searched_after_error".as_slice(),
            "şifreli kalıcı depolama".as_bytes(),
        ] {
            assert!(
                !contains_subslice(&raw_bytes, forbidden),
                "plaintext marker `{}` leaked to disk",
                String::from_utf8_lossy(forbidden)
            );
        }

        {
            let mut reopened =
                MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                    .expect("reopen encrypted store with matching key");
            assert_eq!(
                reopened.next_event_id().expect("persisted next_event_id"),
                3
            );

            let vector_only = HybridSearchConfig {
                bm25_weight: 0.0,
                vector_weight: 1.0,
                recency_weight: 0.0,
                ..HybridSearchConfig::default()
            };
            let vec_hits = reopened
                .hybrid_search_with_config("şifreli kalıcı depolama doğrulama", 5, &vector_only)
                .expect("vector search after reopen");
            assert!(!vec_hits.is_empty());
            assert_eq!(vec_hits[0].event_id, 2);

            let hits = reopened
                .hybrid_search("SQLCIPHER_AT_REST_SENTINEL_9911", 5)
                .expect("hybrid search after reopen");
            assert_eq!(hits.len(), 3);
            assert!(
                hits[0]
                    .causality_chain
                    .iter()
                    .any(|e| e.relationship == "searched_after_error")
            );

            let dup_err = reopened
                .ingest_block(&block(2, 1_030_000, "Code.exe", "dup", false, "duplicate"))
                .expect_err("duplicate event_id must fail after reopen");
            assert!(matches!(dup_err, CoreError::DuplicateEventId(2)));

            let next_id = reopened.next_event_id().expect("next_id");
            assert_eq!(next_id, 3);
            reopened
                .ingest_block(&block(
                    next_id,
                    1_040_000,
                    "notepad.exe",
                    "notes.txt",
                    false,
                    "FOLLOWUP_PERSISTED_BLOCK_44",
                ))
                .expect("ingest after reopen");
        }

        let reopened_again = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
            .expect("third open");
        assert_eq!(reopened_again.next_event_id().expect("next_id"), 4);
        let followup = reopened_again
            .hybrid_search("FOLLOWUP_PERSISTED_BLOCK_44", 3)
            .expect("search fourth block");
        assert_eq!(followup.len(), 1);
        assert_eq!(followup[0].event_id, 3);
    }

    #[test]
    fn encrypted_store_rejects_wrong_key_plaintext_sqlite_and_invalid_paths() {
        let dir = TempDirGuard::new("reject");
        let valid_key = [0x5a_u8; 32];

        assert!(matches!(
            MemoryStore::open_encrypted(Path::new(""), &valid_key, DeterministicTestEmbedder),
            Err(CoreError::InvalidDatabasePath(_))
        ));
        assert!(matches!(
            MemoryStore::open_encrypted(
                Path::new(":memory:"),
                &valid_key,
                DeterministicTestEmbedder
            ),
            Err(CoreError::InvalidDatabasePath(_))
        ));
        assert!(matches!(
            MemoryStore::open_encrypted(&dir.0, &valid_key, DeterministicTestEmbedder),
            Err(CoreError::InvalidDatabasePath(_))
        ));

        let db_path = dir.0.join("vault.db");
        {
            let mut store =
                MemoryStore::open_encrypted(&db_path, &valid_key, DeterministicTestEmbedder)
                    .expect("create encrypted store");
            store
                .ingest_block(&block(0, 10_000, "Code.exe", "lib.rs", false, "sealed row"))
                .expect("ingest row");
        }

        let mut flipped_key = valid_key;
        flipped_key[0] ^= 0x01;
        let wrong_err =
            match MemoryStore::open_encrypted(&db_path, &flipped_key, DeterministicTestEmbedder) {
                Ok(_) => panic!("1-bit flipped key must fail to unlock encrypted DB"),
                Err(err) => err,
            };
        assert!(
            matches!(wrong_err, CoreError::Encryption(_)),
            "unexpected error for wrong key: {wrong_err}"
        );
        let err_text = wrong_err.to_string();
        assert!(
            !err_text.contains("5a5a5a5a"),
            "error message must never expose key hex"
        );

        let reopened = MemoryStore::open_encrypted(&db_path, &valid_key, DeterministicTestEmbedder)
            .expect("original key still opens encrypted DB intact");
        assert_eq!(reopened.next_event_id().expect("next_id"), 1);
        drop(reopened);

        // Unencrypted plaintext SQLite file must be rejected by open_encrypted.
        let plain_path = dir.0.join("plaintext.db");
        {
            let plain_conn = Connection::open(&plain_path).expect("create test plaintext sqlite");
            plain_conn
                .execute_batch("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('plain');")
                .expect("seed plaintext sqlite");
        }
        let plain_bytes = std::fs::read(&plain_path).expect("read plaintext sqlite");
        assert!(plain_bytes.starts_with(b"SQLite format 3\0"));

        let plain_err =
            match MemoryStore::open_encrypted(&plain_path, &valid_key, DeterministicTestEmbedder) {
                Ok(_) => panic!("open_encrypted must reject plaintext SQLite file"),
                Err(err) => err,
            };
        assert!(
            matches!(plain_err, CoreError::Encryption(_)),
            "unexpected error for plaintext SQLite: {plain_err}"
        );

        // Corrupt / non-SQLite file must also fail explicitly.
        let corrupt_path = dir.0.join("corrupt.db");
        std::fs::write(&corrupt_path, b"not-an-encrypted-sqlite-database").expect("seed corrupt");
        let corrupt_err =
            match MemoryStore::open_encrypted(&corrupt_path, &valid_key, DeterministicTestEmbedder)
            {
                Ok(_) => panic!("open_encrypted must reject corrupt file"),
                Err(err) => err,
            };
        assert!(
            matches!(corrupt_err, CoreError::Encryption(_)),
            "unexpected error for corrupt file: {corrupt_err}"
        );
    }

    #[tokio::test]
    async fn run_ingestion_persists_into_encrypted_store() {
        let dir = TempDirGuard::new("async-ingest");
        let db_path = dir.0.join("async.db");
        let key = [0x9c_u8; 32];

        let store = Arc::new(Mutex::new(
            MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                .expect("open encrypted store"),
        ));
        let (tx, rx) = mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY);
        let handle = tokio::spawn(run_ingestion(Arc::clone(&store), rx));

        tx.send(block(
            0,
            200_000,
            "WindowsTerminal.exe",
            "cargo test",
            false,
            "encrypted async ingestion test event",
        ))
        .await
        .unwrap();
        drop(tx);

        let count = handle.await.unwrap().unwrap();
        assert_eq!(count, 1);
        drop(store);

        let reopened = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
            .expect("reopen encrypted store");
        let hits = reopened
            .hybrid_search("encrypted async ingestion", 3)
            .expect("search persisted async event");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].event_id, 0);
    }

    #[test]
    fn ingest_batch_uses_embed_batch_and_search_uses_embed_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct RoutingSpyEmbedder {
            one_calls: Arc<AtomicUsize>,
            batch_calls: Arc<AtomicUsize>,
            batch_sizes: Arc<Mutex<Vec<usize>>>,
        }

        impl Embedder for RoutingSpyEmbedder {
            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                self.batch_calls.fetch_add(1, Ordering::SeqCst);
                self.batch_sizes.lock().unwrap().push(texts.len());
                Ok(texts.iter().map(|t| project_text_to_unit_vec(t)).collect())
            }

            fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
                self.one_calls.fetch_add(1, Ordering::SeqCst);
                Ok(project_text_to_unit_vec(text))
            }
        }

        let one_calls = Arc::new(AtomicUsize::new(0));
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let batch_sizes = Arc::new(Mutex::new(Vec::new()));
        let spy = RoutingSpyEmbedder {
            one_calls: Arc::clone(&one_calls),
            batch_calls: Arc::clone(&batch_calls),
            batch_sizes: Arc::clone(&batch_sizes),
        };

        let mut store = MemoryStore::open_in_memory(spy).expect("open store");
        let mut skipped = block(1, 2_000, "Code.exe", "empty", false, "");
        skipped.has_embedding_payload = false;

        let blocks = vec![
            block(0, 1_000, "Code.exe", "a.rs", false, "alpha beta"),
            skipped,
            block(2, 3_000, "Code.exe", "b.rs", false, "gamma delta"),
        ];
        store.ingest_batch(&blocks).expect("ingest_batch");
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(one_calls.load(Ordering::SeqCst), 0);
        assert_eq!(*batch_sizes.lock().unwrap(), vec![2]);

        let hits = store.hybrid_search("alpha beta", 2).expect("hybrid_search");
        assert_eq!(hits[0].event_id, 0);
        assert_eq!(one_calls.load(Ordering::SeqCst), 1);
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn memory_stats_aggregates_hours_apps_redactions_and_latest_chain() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");
        let empty = store.memory_stats(0, 180).expect("empty stats");
        assert_eq!(empty.total_events, 0);
        assert!(empty.events_by_hour.is_empty());
        assert!(empty.top_apps.is_empty());
        assert_eq!(empty.redactions_total, 0);
        assert_eq!(empty.db_bytes, None);
        assert!(empty.latest_chain.is_none());

        // Day base: 2026-11-19T00:00:00Z = 1_795_046_400_000 ms (multiple of 86_400_000).
        let day_ms: u64 = 1_795_046_400_000;
        let hour_ms: u64 = 3_600_000;

        // Isolated event before `since_ms` (should be excluded when filtering from day_ms).
        let mut old = block(
            0,
            day_ms - 2 * hour_ms,
            "OldApp.exe",
            "old",
            false,
            "before window",
        );
        old.redactions_count = 9;

        // Isolated single event inside window (no edges yet -> latest_chain remains None).
        let mut e1 = block(
            1,
            day_ms + hour_ms + 5 * 60_000, // 01:05 UTC
            "Code.exe",
            "main.rs",
            false,
            "cargo check ok",
        );
        e1.redactions_count = 2;

        store.ingest_batch(&[old, e1]).expect("ingest old + e1");
        let no_edge_stats = store.memory_stats(day_ms, 0).expect("no-edge stats");
        assert_eq!(no_edge_stats.total_events, 1);
        assert_eq!(no_edge_stats.redactions_total, 2);
        assert!(no_edge_stats.latest_chain.is_none());

        // Add error + search events at 22:30 UTC (with +180 => local 01:30, with -300 => local 17:30)
        // and another Code.exe event at 10:15 UTC.
        let mut e2 = block(
            2,
            day_ms + 10 * hour_ms + 15 * 60_000, // 10:15 UTC
            "WindowsTerminal.exe",
            "cargo test",
            false,
            "error: missing trait impl",
        );
        e2.redactions_count = 3;

        let mut e3 = block(
            3,
            day_ms + 10 * hour_ms + 15 * 60_000 + 20_000, // 10:15:20 UTC
            "brave.exe",
            "Search Rust trait",
            true,
            "searching trait impl",
        );
        e3.redactions_count = 1;

        let mut e4 = block(
            4,
            day_ms + 22 * hour_ms + 30 * 60_000, // 22:30 UTC
            "Code.exe",
            "lib.rs",
            false,
            "applied fix",
        );
        e4.redactions_count = 4;

        store.ingest_batch(&[e2, e3, e4]).expect("ingest e2..e4");

        // UTC+3 (+180 min): 01:05 -> 04, 10:15 -> 13 (x2), 22:30 -> 01 (next day).
        let stats_tr = store.memory_stats(day_ms, 180).expect("stats UTC+3");
        assert_eq!(stats_tr.total_events, 4);
        assert_eq!(stats_tr.redactions_total, 2 + 3 + 1 + 4);
        assert_eq!(stats_tr.db_bytes, None);
        assert_eq!(stats_tr.events_by_hour, vec![(1, 1), (4, 1), (13, 2)]);
        assert_eq!(
            stats_tr.top_apps,
            vec![
                ("Code.exe".to_owned(), 2),
                ("WindowsTerminal.exe".to_owned(), 1),
                ("brave.exe".to_owned(), 1),
            ]
        );
        let chain_hit = stats_tr.latest_chain.expect("expected latest_chain");
        assert_eq!(chain_hit.event_id, 3);
        assert_eq!(chain_hit.matched_app, "brave.exe");
        assert!(chain_hit.score.is_finite());
        assert!(
            chain_hit
                .causality_chain
                .iter()
                .any(|e| e.source_event_id == 2
                    && e.target_event_id == 3
                    && e.relationship == "searched_after_error")
        );

        // UTC-5 (-300 min): 01:05 -> 20, 10:15 -> 05 (x2), 22:30 -> 17.
        let stats_us = store.memory_stats(day_ms, -300).expect("stats UTC-5");
        assert_eq!(stats_us.events_by_hour, vec![(5, 2), (17, 1), (20, 1)]);

        // Encrypted store reports on-disk db_bytes = Some(len).
        let dir = TempDirGuard::new("stats-disk");
        let db_path = dir.0.join("stats.db");
        let key = [0x42_u8; 32];
        let mut enc_store =
            MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder).expect("open");
        enc_store
            .ingest_block(&block(0, day_ms, "Code.exe", "lib.rs", false, "encrypted"))
            .expect("ingest");
        let enc_stats = enc_store.memory_stats(0, 0).expect("enc stats");
        assert_eq!(enc_stats.total_events, 1);
        assert!(
            enc_stats.db_bytes.is_some_and(|b| b >= 4096),
            "expected Some(>= 4096), got {:?}",
            enc_stats.db_bytes
        );
    }

    #[test]
    fn delete_since_removes_events_vectors_fts_and_connected_edges() {
        let mut store = MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open store");

        let e0 = block(
            0,
            1_000_000,
            "WindowsTerminal.exe",
            "cargo build",
            false,
            "error: alpha build failed",
        );
        // Crosses the `since_ms = 1_050_000` boundary with an edge from e0 -> e1.
        let e1 = block(
            1,
            1_050_000,
            "brave.exe",
            "alpha build failed - Search",
            true,
            "searching BETA_RECENT_SENTINEL fix",
        );
        let e2 = block(
            2,
            1_080_000,
            "Code.exe",
            "main.rs",
            false,
            "edited BETA_RECENT_SENTINEL code",
        );
        store.ingest_batch(&[e0, e1, e2]).expect("ingest");

        // Deleting in the future removes nothing.
        assert_eq!(store.delete_since(2_000_000).expect("noop delete"), 0);

        // Inclusive `since_ms` deletes e1 and e2 while keeping e0.
        let deleted = store.delete_since(1_050_000).expect("delete_since");
        assert_eq!(deleted, 2);
        assert_eq!(store.next_event_id().expect("next_event_id"), 1);

        let stats = store.memory_stats(0, 0).expect("stats after delete_since");
        assert_eq!(stats.total_events, 1);
        assert!(stats.latest_chain.is_none());

        // Neither FTS5 nor vec0 may still return deleted tokens.
        assert!(
            store
                .hybrid_search("BETA_RECENT_SENTINEL", 5)
                .expect("search deleted")
                .is_empty()
        );
        let vec_only = HybridSearchConfig {
            bm25_weight: 0.0,
            vector_weight: 1.0,
            recency_weight: 0.0,
            ..HybridSearchConfig::default()
        };
        let vec_hits = store
            .hybrid_search_with_config("searching edited", 5, &vec_only)
            .expect("vec search");
        assert!(vec_hits.iter().all(|h| h.event_id == 0));

        // Remaining event e0 must not retain dangling edges to deleted e1.
        let e0_hits = store.hybrid_search("alpha build", 3).expect("search e0");
        assert_eq!(e0_hits.len(), 1);
        assert_eq!(e0_hits[0].event_id, 0);
        assert!(e0_hits[0].causality_chain.is_empty());

        let vec_rows: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM event_vectors", [], |r| r.get(0))
            .expect("count event_vectors");
        let edge_rows: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM causality_edges", [], |r| r.get(0))
            .expect("count causality_edges");
        assert_eq!(vec_rows, 1);
        assert_eq!(edge_rows, 0);

        store
            .connection()
            .execute_batch("INSERT INTO events_fts(events_fts) VALUES('integrity-check');")
            .expect("FTS5 integrity-check after delete_since");
    }

    #[test]
    fn delete_all_clears_encrypted_store_vacuums_and_allows_reingest() {
        let dir = TempDirGuard::new("delete-all");
        let db_path = dir.0.join("vault.db");
        let key = [0x7b_u8; 32];

        {
            let mut store = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                .expect("open encrypted store");
            let e0 = block(
                0,
                500_000,
                "WindowsTerminal.exe",
                "term",
                false,
                "error: DELETE_ALL_SENTINEL_XYZ failure",
            );
            let e1 = block(
                1,
                510_000,
                "brave.exe",
                "Search",
                true,
                "DELETE_ALL_SENTINEL_XYZ workaround",
            );
            store.ingest_batch(&[e0, e1]).expect("ingest");

            let deleted = store.delete_all().expect("delete_all");
            assert_eq!(deleted, 2);
            assert_eq!(store.next_event_id().expect("next_id after delete_all"), 0);
            assert!(
                store
                    .hybrid_search("DELETE_ALL_SENTINEL_XYZ", 5)
                    .expect("search empty")
                    .is_empty()
            );

            let vec_rows: i64 = store
                .connection()
                .query_row("SELECT COUNT(*) FROM event_vectors", [], |r| r.get(0))
                .expect("count vectors");
            let edge_rows: i64 = store
                .connection()
                .query_row("SELECT COUNT(*) FROM causality_edges", [], |r| r.get(0))
                .expect("count edges");
            assert_eq!(vec_rows, 0);
            assert_eq!(edge_rows, 0);

            store
                .connection()
                .execute_batch("INSERT INTO events_fts(events_fts) VALUES('integrity-check');")
                .expect("FTS5 integrity-check after delete_all");

            let stats = store.memory_stats(0, 0).expect("stats after delete_all");
            assert_eq!(stats.total_events, 0);
            assert!(stats.db_bytes.is_some());

            // Deleting again on empty store is a clean no-op.
            assert_eq!(store.delete_all().expect("second delete_all"), 0);
        }

        let raw_bytes = std::fs::read(&db_path).expect("read encrypted bytes");
        assert!(!raw_bytes.starts_with(b"SQLite format 3\0"));
        assert!(!contains_subslice(&raw_bytes, b"DELETE_ALL_SENTINEL_XYZ"));

        // Reopen after VACUUM and ingest fresh events starting at event_id = 0.
        let mut reopened = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
            .expect("reopen after delete_all + VACUUM");
        assert_eq!(reopened.next_event_id().expect("next_id"), 0);
        reopened
            .ingest_block(&block(
                0,
                900_000,
                "Code.exe",
                "fresh.rs",
                false,
                "FRESH_POST_VACUUM_EVENT",
            ))
            .expect("re-ingest");
        let hits = reopened
            .hybrid_search("FRESH_POST_VACUUM_EVENT", 3)
            .expect("search post-vacuum");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].event_id, 0);
    }
}
