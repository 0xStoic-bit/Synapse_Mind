//! SQLite (`events`, `causality_edges`, FTS5) + `sqlite-vec` (`vec0`) hybrid store.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use s_types::{CausalityEdge, CausalityQueryHit, MaskedMemoryBlock};
use zeroize::Zeroizing;

use crate::causality::{
    CausalityConfig, link_event_in_tx, load_causality_chain, load_causality_chains_batch,
};
use crate::embedder::{EMBEDDING_DIM, Embedder, f32_slice_to_le_bytes, validate_embedding};
use crate::{CoreError, Result};

const SNIPPET_MAX_CHARS: usize = 200;
const VEC0_K_MAX: usize = 4096;
const TOP_APPS_LIMIT: i64 = 10;
const MS_PER_DAY: i64 = 86_400_000;
const MS_PER_HOUR: i64 = 3_600_000;

/// Default UTF-8 byte ceiling for single-query vector embedding in `hybrid_search`.
/// Selected from `BGESmallENV15` FP32 release measurements alongside `DEFAULT_QUERY_MAX_TOKENS = 64`
/// to keep English (`p95 = 12.78 ms`), Turkish (`p95 = 15.31 ms`), and 4 KB pastes (`p95 = 11.19 ms`)
/// safely within the `< 20 ms` SLA.
pub const DEFAULT_MAX_VECTOR_QUERY_BYTES: usize = 200;
/// Default UTF-8 byte scan ceiling for lexical BM25 extraction in `hybrid_search`.
pub const DEFAULT_MAX_BM25_QUERY_BYTES: usize = 512;
/// Default maximum number of unique terms emitted by `sanitize_fts_query`.
pub const DEFAULT_MAX_BM25_TERMS: usize = 8;
/// Metadata key inside `store_meta` storing the `Embedder::model_id` that produced the vectors
/// currently residing in `event_vectors`.
pub const EMBEDDING_MODEL_META_KEY: &str = "embedding_model_id";

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
    /// Maximum UTF-8 byte length passed to the vector query embedder (`embed_one`),
    /// truncated cleanly on a UTF-8 and word boundary.
    pub max_vector_query_bytes: usize,
    /// Maximum UTF-8 byte length scanned for lexical BM25 term extraction.
    pub max_bm25_query_bytes: usize,
    /// Maximum number of unique case-folded terms included in the FTS5 `OR` query.
    pub max_bm25_terms: usize,
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
            max_vector_query_bytes: DEFAULT_MAX_VECTOR_QUERY_BYTES,
            max_bm25_query_bytes: DEFAULT_MAX_BM25_QUERY_BYTES,
            max_bm25_terms: DEFAULT_MAX_BM25_TERMS,
        }
    }
}

/// Detailed result from [`MemoryStore::hybrid_search_detailed`].
#[derive(Debug, Clone)]
pub struct SearchOutcome {
    pub hits: Vec<CausalityQueryHit>,
    /// `true` when the raw query exceeded vector byte, BM25 byte, or BM25 unique-term limits.
    pub query_truncated: bool,
    /// `true` when semantic vector search ran; `false` when degraded to BM25-only.
    pub semantic_used: bool,
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
        let mut store = Self {
            conn,
            embedder,
            causality,
            db_path: None,
        };
        store.reconcile_embedding_model()?;
        Ok(store)
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

        let mut store = Self {
            conn,
            embedder,
            causality,
            db_path: Some(path.to_path_buf()),
        };
        store.reconcile_embedding_model()?;
        Ok(store)
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

    /// Reads the persisted `embedding_model_id` from the encrypted `store_meta` table.
    ///
    /// Returns `None` for legacy v0.1.0 databases or stores whose embedder has not yet
    /// become ready and reconciled.
    pub fn stored_embedding_model_id(&self) -> Result<Option<String>> {
        stored_embedding_model_id_conn(&self.conn)
    }

    /// Returns how many embeddable events currently lack a vector in `event_vectors`.
    ///
    /// Queries SQLite only without invoking the embedder (safe to call even when an
    /// idle-unloaded [`ManagedEmbedder`](crate::ManagedEmbedder) is sleeping).
    pub fn pending_embedding_backfill_count(&self) -> Result<u64> {
        let count_i64: i64 = self.conn.query_row(
            "SELECT COUNT(*)
             FROM events e
             WHERE e.has_embedding_payload = 1
               AND length(trim(e.clean_text)) > 0
               AND NOT EXISTS (
                   SELECT 1 FROM event_vectors v WHERE v.event_id = e.event_id
               )",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(count_i64)
            .map_err(|_| CoreError::IntegerOverflow("negative pending backfill count"))
    }

    /// Ensures `event_vectors` matches the ready embedder's [`Embedder::model_id`].
    ///
    /// No-op (`Ok(false)`) while the embedder is not ready or the stored id already matches.
    /// Otherwise clears `event_vectors` and updates `store_meta['embedding_model_id']` in one
    /// transaction; returns `Ok(true)` when vectors were cleared.
    pub fn reconcile_embedding_model(&mut self) -> Result<bool> {
        if !self.embedder.is_ready() {
            return Ok(false);
        }
        let current_id = validated_model_id(&self.embedder)?;
        if stored_embedding_model_id_conn(&self.conn)?.as_deref() == Some(current_id) {
            return Ok(false);
        }
        let tx = self.conn.transaction()?;
        let cleared = reconcile_embedding_model_in_tx(&tx, current_id)?;
        tx.commit()?;
        Ok(cleared)
    }

    /// Returns the next monotonic `event_id` (`0` on an empty store, else `MAX(event_id) + 1`).
    /// Call once after opening, before starting the guard and ingestion tasks. Out-of-range
    /// ids return [`CoreError::IntegerOverflow`].
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

    /// Stores a sanitized block, indexes FTS5 and `vec0`, and links it to preceding events.
    /// Duplicate ids return [`CoreError::DuplicateEventId`]; use [`MemoryStore::upsert_block`]
    /// for intentional re-indexing.
    pub fn ingest_block(&mut self, block: &MaskedMemoryBlock) -> Result<Vec<CausalityEdge>> {
        self.store_block_inner(block, false)
    }

    /// Inserts or replaces a block by `event_id`, keeping its causality edges. Re-indexing only;
    /// ingestion uses [`MemoryStore::ingest_block`] so id collisions surface as errors.
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

        let embedding = if needs_embedding(block) && self.embedder.is_ready() {
            match self.embedder.embed_batch(&[block.clean_text.as_str()]) {
                Ok(mut vecs) => {
                    if vecs.len() != 1 {
                        return Err(CoreError::EmbeddingCountMismatch {
                            expected: 1,
                            actual: vecs.len(),
                        });
                    }
                    let vec = vecs.pop().ok_or(CoreError::EmbeddingCountMismatch {
                        expected: 1,
                        actual: 0,
                    })?;
                    validate_embedding(&vec, EMBEDDING_DIM)?;
                    Some(vec)
                }
                Err(CoreError::EmbedderUnavailable(_)) => None,
                Err(err) => return Err(err),
            }
        } else {
            None
        };

        let tx = self.conn.transaction()?;
        if embedding.is_some() {
            let current_id = validated_model_id(&self.embedder)?;
            let _ = reconcile_embedding_model_in_tx(&tx, current_id)?;
        }
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

    /// Ingests blocks in order with one [`Embedder::embed_batch`] call and one transaction;
    /// returns all created causality edges.
    pub fn ingest_batch(&mut self, blocks: &[MaskedMemoryBlock]) -> Result<Vec<CausalityEdge>> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }

        let can_embed = self.embedder.is_ready();
        let mut embed_slots: Vec<Option<usize>> = Vec::with_capacity(blocks.len());
        let mut embed_texts: Vec<&str> = Vec::new();
        for block in blocks {
            i64::try_from(block.event_id)
                .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
            i64::try_from(block.timestamp_ms)
                .map_err(|_| CoreError::IntegerOverflow("timestamp_ms exceeds i64::MAX"))?;
            if can_embed && needs_embedding(block) {
                embed_slots.push(Some(embed_texts.len()));
                embed_texts.push(block.clean_text.as_str());
            } else {
                embed_slots.push(None);
            }
        }

        let vectors = if embed_texts.is_empty() {
            Vec::new()
        } else {
            match self.embedder.embed_batch(&embed_texts) {
                Ok(vecs) => {
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
                }
                Err(CoreError::EmbedderUnavailable(_)) => {
                    embed_slots.fill(None);
                    Vec::new()
                }
                Err(err) => return Err(err),
            }
        };

        let tx = self.conn.transaction()?;
        if !vectors.is_empty() {
            let current_id = validated_model_id(&self.embedder)?;
            let _ = reconcile_embedding_model_in_tx(&tx, current_id)?;
        }
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
        Ok(self.hybrid_search_detailed(query, k, config)?.hits)
    }

    /// Executes hybrid search and returns hits along with query truncation and semantic fallback metadata.
    pub fn hybrid_search_detailed(
        &self,
        query: &str,
        k: usize,
        config: &HybridSearchConfig,
    ) -> Result<SearchOutcome> {
        if k == 0 || query.trim().is_empty() {
            return Ok(SearchOutcome {
                hits: Vec::new(),
                query_truncated: false,
                semantic_used: false,
            });
        }

        let max_ts_opt: Option<i64> =
            self.conn
                .query_row("SELECT MAX(timestamp_ms) FROM events", [], |row| row.get(0))?;
        let Some(max_ts_i64) = max_ts_opt else {
            return Ok(SearchOutcome {
                hits: Vec::new(),
                query_truncated: false,
                semantic_used: false,
            });
        };
        let default_ref_ts = u64::try_from(max_ts_i64)
            .map_err(|_| CoreError::IntegerOverflow("negative timestamp_ms in events table"))?;
        let reference_ts_ms = config.reference_timestamp_ms.unwrap_or(default_ref_ts);

        let candidate_limit = k.saturating_mul(4).clamp(16, 256).min(VEC0_K_MAX);
        let candidate_limit_i64 = i64::try_from(candidate_limit)
            .map_err(|_| CoreError::IntegerOverflow("candidate_limit exceeds i64::MAX"))?;

        let mut candidates: HashMap<u64, CandidateScores> = HashMap::new();

        // 1. Lexical BM25 search via FTS5 (bounded bytes and unique deduplicated terms).
        let (bm25_slice, bm25_bytes_truncated) =
            truncate_query_prefix(query, config.max_bm25_query_bytes);
        // When an oversized paste exceeded `max_bm25_query_bytes`, tighten the default OR
        // fan-out to 4 informative terms so boilerplate tails do not sweep thousands of rows,
        // while keeping up to 8 terms for normal user queries (`<= max_bm25_query_bytes`).
        let effective_max_bm25_terms =
            if bm25_bytes_truncated && config.max_bm25_terms == DEFAULT_MAX_BM25_TERMS {
                config.max_bm25_terms.min(4)
            } else {
                config.max_bm25_terms
            };
        let mut bm25_terms_truncated = false;
        if let Some((fts_query, terms_truncated)) =
            sanitize_fts_query_limited(bm25_slice, effective_max_bm25_terms)
        {
            bm25_terms_truncated = terms_truncated;
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

        // 2. Semantic cosine KNN search via `sqlite-vec` with word-boundary pre-truncation
        //    and graceful BM25-only fallback when the embedder is not ready, unavailable,
        //    or persisted vectors belong to a different embedding model not yet reconciled.
        let (vector_slice, vector_bytes_truncated) =
            truncate_query_prefix(query, config.max_vector_query_bytes);
        let vectors_compatible = if !vector_slice.is_empty() && self.embedder.is_ready() {
            let current_id = validated_model_id(&self.embedder)?;
            embedding_vectors_compatible(&self.conn, current_id)?
        } else {
            false
        };
        let mut semantic_used = false;
        let query_blob_opt = if vectors_compatible {
            match self.embedder.embed_one(vector_slice) {
                Ok(query_vec) => {
                    validate_embedding(&query_vec, EMBEDDING_DIM)?;
                    semantic_used = true;
                    Some(f32_slice_to_le_bytes(&query_vec))
                }
                Err(CoreError::EmbedderUnavailable(_)) => None,
                Err(err) => return Err(err),
            }
        } else {
            None
        };

        if let Some(query_blob) = query_blob_opt.as_deref() {
            let mut vec_matched_any = false;
            {
                let mut stmt = self.conn.prepare_cached(
                    "SELECT event_id, distance
                     FROM event_vectors
                     WHERE embedding MATCH ?1 AND k = ?2
                     ORDER BY distance ASC",
                )?;
                let rows = stmt.query_map(params![query_blob, candidate_limit_i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
                })?;
                for row in rows {
                    vec_matched_any = true;
                    let (id_i64, distance) = row?;
                    let id = u64::try_from(id_i64).map_err(|_| {
                        CoreError::IntegerOverflow("negative event_id in event_vectors")
                    })?;
                    let cosine_sim = (1.0_f64 - distance).clamp(0.0, 1.0) as f32;
                    candidates.entry(id).or_default().cosine = Some(cosine_sim);
                }
            }

            // 3. Cross-fill cosine similarity for BM25-only candidates (skip when vec0 is empty).
            if vec_matched_any {
                let missing_vec_ids: Vec<u64> = candidates
                    .iter()
                    .filter_map(|(&id, scores)| scores.cosine.is_none().then_some(id))
                    .collect();
                if !missing_vec_ids.is_empty() {
                    let mut point_vec_stmt = self.conn.prepare_cached(
                        "SELECT vec_distance_cosine(embedding, ?1)
                         FROM event_vectors
                         WHERE event_id = ?2",
                    )?;
                    for event_id in missing_vec_ids {
                        let id_i64 = i64::try_from(event_id)
                            .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
                        let dist_opt: Option<f64> = point_vec_stmt
                            .query_row(params![query_blob, id_i64], |row| row.get(0))
                            .optional()?;
                        let cosine_sim = dist_opt
                            .map(|d| (1.0_f64 - d).clamp(0.0, 1.0) as f32)
                            .unwrap_or(0.0);
                        if let Some(scores) = candidates.get_mut(&event_id) {
                            scores.cosine = Some(cosine_sim);
                        }
                    }
                }
            }
        }

        // 4. Score candidates by BM25 + cosine + recency.
        let effective_vector_weight = if semantic_used {
            config.vector_weight
        } else {
            0.0
        };
        let weight_sum = (config.bm25_weight + effective_vector_weight + config.recency_weight)
            .max(f32::EPSILON);
        let half_life = config.recency_half_life_seconds.max(1.0);

        let active_ids: Vec<u64> = candidates
            .iter()
            .filter_map(|(&event_id, cand)| {
                let bm25_s = cand.bm25.unwrap_or(0.0);
                let cosine_s = cand.cosine.unwrap_or(0.0);
                if bm25_s > 0.0 || cosine_s > 0.0 {
                    Some(event_id)
                } else {
                    None
                }
            })
            .collect();
        let candidate_timestamps = fetch_event_timestamps(&self.conn, &active_ids)?;

        struct ScoredCandidate {
            event_id: u64,
            timestamp_ms: u64,
            score: f32,
        }

        let mut scored = Vec::with_capacity(active_ids.len());
        for event_id in active_ids {
            let Some(&timestamp_ms) = candidate_timestamps.get(&event_id) else {
                continue;
            };
            let cand = &candidates[&event_id];
            let bm25_s = cand.bm25.unwrap_or(0.0);
            let cosine_s = cand.cosine.unwrap_or(0.0);
            let age_seconds = reference_ts_ms.saturating_sub(timestamp_ms) as f64 / 1000.0;
            let recency_s = 0.5_f64.powf(age_seconds / half_life) as f32;

            let score = (config.bm25_weight * bm25_s
                + effective_vector_weight * cosine_s
                + config.recency_weight * recency_s)
                / weight_sum;

            scored.push(ScoredCandidate {
                event_id,
                timestamp_ms,
                score,
            });
        }

        scored.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| b.timestamp_ms.cmp(&a.timestamp_ms))
                .then_with(|| b.event_id.cmp(&a.event_id))
        });
        scored.truncate(k);

        // 5. Batch-fetch display fields and BFS causality chains only for the top-k winners.
        let winner_ids: Vec<u64> = scored.iter().map(|s| s.event_id).collect();
        let winner_details = fetch_event_details(&self.conn, &winner_ids)?;
        let chains = load_causality_chains_batch(
            &self.conn,
            &winner_ids,
            config.max_chain_depth,
            config.max_chain_edges,
        )?;
        let mut hits = Vec::with_capacity(scored.len());
        for (item, causality_chain) in scored.into_iter().zip(chains) {
            let Some((process_name, sanitized_title, clean_text)) =
                winner_details.get(&item.event_id)
            else {
                continue;
            };
            hits.push(CausalityQueryHit {
                event_id: item.event_id,
                timestamp_ms: item.timestamp_ms,
                score: item.score,
                summary_snippet: snippet_for_event(clean_text, sanitized_title),
                matched_app: process_name.clone(),
                causality_chain,
            });
        }
        Ok(SearchOutcome {
            hits,
            query_truncated: vector_bytes_truncated || bm25_bytes_truncated || bm25_terms_truncated,
            semantic_used,
        })
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

    /// Reconciles `store_meta['embedding_model_id']` (clearing stale vectors on model change)
    /// and then computes and inserts missing `vec0` embeddings for up to `max_blocks` events
    /// (newest first).
    ///
    /// Returns `Ok(0)` without touching metadata or vectors if the embedder is not ready yet.
    pub fn backfill_missing_embeddings(&mut self, max_blocks: usize) -> Result<usize> {
        if max_blocks == 0 || !self.embedder.is_ready() {
            return Ok(0);
        }
        let _ = self.reconcile_embedding_model()?;
        let limit_i64 = i64::try_from(max_blocks)
            .map_err(|_| CoreError::IntegerOverflow("max_blocks exceeds i64::MAX"))?;
        let rows: Vec<(i64, String)> = {
            let mut stmt = self.conn.prepare_cached(
                "SELECT e.event_id, e.clean_text
                 FROM events e
                 WHERE e.has_embedding_payload = 1
                   AND length(trim(e.clean_text)) > 0
                   AND NOT EXISTS (
                       SELECT 1 FROM event_vectors v WHERE v.event_id = e.event_id
                   )
                 ORDER BY e.event_id DESC
                 LIMIT ?1",
            )?;
            let mapped = stmt.query_map([limit_i64], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut collected = Vec::new();
            for item in mapped {
                collected.push(item?);
            }
            collected
        };
        if rows.is_empty() {
            return Ok(0);
        }

        let text_refs: Vec<&str> = rows.iter().map(|(_, text)| text.as_str()).collect();
        let vectors = match self.embedder.embed_batch(&text_refs) {
            Ok(vecs) => vecs,
            Err(CoreError::EmbedderUnavailable(_)) => return Ok(0),
            Err(err) => return Err(err),
        };
        if vectors.len() != rows.len() {
            return Err(CoreError::EmbeddingCountMismatch {
                expected: rows.len(),
                actual: vectors.len(),
            });
        }
        for vec in &vectors {
            validate_embedding(vec, EMBEDDING_DIM)?;
        }

        let tx = self.conn.transaction()?;
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO event_vectors (event_id, embedding) VALUES (?1, ?2)",
            )?;
            for ((event_id, _), vec) in rows.iter().zip(&vectors) {
                let blob = f32_slice_to_le_bytes(vec);
                ins.execute(params![event_id, blob])?;
            }
        }
        tx.commit()?;
        Ok(rows.len())
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

fn prepare_bucketed_in_params(chunk: &[u64], max_chunk: usize) -> Result<(Vec<i64>, String)> {
    let bucket_len = chunk.len().next_power_of_two().min(max_chunk);
    let mut params_i64 = Vec::with_capacity(bucket_len);
    for &id in chunk {
        params_i64.push(
            i64::try_from(id)
                .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?,
        );
    }
    if let Some(&pad_id) = params_i64.first() {
        params_i64.resize(bucket_len, pad_id);
    }
    let placeholders = vec!["?"; params_i64.len()].join(",");
    Ok((params_i64, placeholders))
}

fn fetch_event_timestamps(conn: &Connection, event_ids: &[u64]) -> Result<HashMap<u64, u64>> {
    const CHUNK_SIZE: usize = 256;
    if event_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut out = HashMap::with_capacity(event_ids.len());
    for chunk in event_ids.chunks(CHUNK_SIZE) {
        let (params_i64, placeholders) = prepare_bucketed_in_params(chunk, CHUNK_SIZE)?;
        let sql =
            format!("SELECT event_id, timestamp_ms FROM events WHERE event_id IN ({placeholders})");
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params_i64.iter()), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (id_i64, ts_i64) = row?;
            let id = u64::try_from(id_i64)
                .map_err(|_| CoreError::IntegerOverflow("negative event_id in events table"))?;
            let ts = u64::try_from(ts_i64)
                .map_err(|_| CoreError::IntegerOverflow("negative timestamp_ms in events table"))?;
            out.insert(id, ts);
        }
    }
    Ok(out)
}

fn fetch_event_details(
    conn: &Connection,
    event_ids: &[u64],
) -> Result<HashMap<u64, (String, String, String)>> {
    const CHUNK_SIZE: usize = 256;
    if event_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut out = HashMap::with_capacity(event_ids.len());
    for chunk in event_ids.chunks(CHUNK_SIZE) {
        let (params_i64, placeholders) = prepare_bucketed_in_params(chunk, CHUNK_SIZE)?;
        let sql = format!(
            "SELECT event_id, process_name, sanitized_title, clean_text
             FROM events
             WHERE event_id IN ({placeholders})"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params_i64.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (id_i64, process_name, sanitized_title, clean_text) = row?;
            let id = u64::try_from(id_i64)
                .map_err(|_| CoreError::IntegerOverflow("negative event_id in events table"))?;
            out.insert(id, (process_name, sanitized_title, clean_text));
        }
    }
    Ok(out)
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

fn validated_model_id(embedder: &impl Embedder) -> Result<&str> {
    let id = embedder.model_id().trim();
    if id.is_empty() {
        return Err(CoreError::Embedder(
            "ready embedder returned empty model_id".to_owned(),
        ));
    }
    Ok(id)
}

fn stored_embedding_model_id_conn(conn: &Connection) -> Result<Option<String>> {
    let mut stmt = conn.prepare_cached("SELECT value FROM store_meta WHERE key = ?1")?;
    let value: Option<String> = stmt
        .query_row([EMBEDDING_MODEL_META_KEY], |row| row.get(0))
        .optional()?;
    Ok(value.filter(|v| !v.trim().is_empty()))
}

fn has_any_vectors(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM event_vectors)")?;
    let exists: i64 = stmt.query_row([], |row| row.get(0))?;
    Ok(exists != 0)
}

fn reconcile_embedding_model_in_tx(tx: &Transaction<'_>, current_id: &str) -> Result<bool> {
    if stored_embedding_model_id_conn(tx)?.as_deref() == Some(current_id) {
        return Ok(false);
    }
    let had_vectors = has_any_vectors(tx)?;
    if had_vectors {
        tx.execute("DELETE FROM event_vectors", [])?;
    }
    tx.execute(
        "INSERT INTO store_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![EMBEDDING_MODEL_META_KEY, current_id],
    )?;
    Ok(had_vectors)
}

fn embedding_vectors_compatible(conn: &Connection, current_id: &str) -> Result<bool> {
    if stored_embedding_model_id_conn(conn)?.as_deref() == Some(current_id) {
        return Ok(true);
    }
    Ok(!has_any_vectors(conn)?)
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
    conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;

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

    // Configure temp storage and an 8 MiB page cache only AFTER SQLCipher unlocks page 1 so
    // `PRAGMA key` executes against a pristine connection state.
    conn.execute_batch("PRAGMA temp_store = MEMORY; PRAGMA cache_size = -8192;")?;

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
         );

         CREATE TABLE IF NOT EXISTS store_meta (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );",
    )?;
    Ok(())
}

/// Trims leading/trailing whitespace and truncates `query` to at most `max_bytes` UTF-8 bytes
/// on a valid UTF-8 character and word boundary, returning `(prefix, was_truncated)`.
pub fn truncate_query_prefix(query: &str, max_bytes: usize) -> (&str, bool) {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return ("", false);
    }
    if max_bytes == 0 {
        return ("", true);
    }
    if trimmed.len() <= max_bytes {
        return (trimmed, false);
    }

    let mut end = max_bytes;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    if end == 0 {
        return ("", true);
    }

    let at_word_boundary = trimmed[end..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
        || trimmed[..end]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace);

    let cut = if at_word_boundary {
        end
    } else if let Some(ws_idx) = trimmed[..end].rfind(char::is_whitespace) {
        ws_idx
    } else if let Some(sep_idx) = trimmed[..end].rfind(|c: char| !c.is_alphanumeric() && c != '_') {
        if sep_idx > 0 { sep_idx } else { end }
    } else {
        end
    };

    let prefix = trimmed[..cut].trim_end();
    if prefix.is_empty() {
        (trimmed[..end].trim_end(), true)
    } else {
        (prefix, true)
    }
}

/// Converts arbitrary user input into a safe FTS5 `OR` query over double-quoted tokens,
/// deduplicating terms case-insensitively and capping at [`DEFAULT_MAX_BM25_TERMS`].
#[cfg(test)]
pub(crate) fn sanitize_fts_query(raw: &str) -> Option<String> {
    sanitize_fts_query_limited(raw, DEFAULT_MAX_BM25_TERMS).map(|(query, _)| query)
}

/// Builds a deduplicated FTS5 `OR` query of at most `max_terms` terms; returns
/// `(fts_query, was_term_truncated)`. When truncating, informative tokens (3+ chars, not
/// purely numeric) win over short fragments and numbers.
pub(crate) fn sanitize_fts_query_limited(raw: &str, max_terms: usize) -> Option<(String, bool)> {
    if max_terms == 0 {
        return None;
    }
    let mut seen = HashSet::new();
    let mut ordered_all: Vec<String> = Vec::new();
    let mut primary: Vec<String> = Vec::new();
    let mut secondary: Vec<String> = Vec::new();

    for tok in raw
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|tok| !tok.is_empty())
    {
        // Strip U+0307 combining dot above produced by `'İ'.to_lowercase()` so Turkish
        // `"ŞİFRELEME"` and `"Şifreleme"` deduplicate identically while keeping `'ı'` distinct.
        let normalized: String = tok
            .to_lowercase()
            .chars()
            .filter(|&c| c != '\u{0307}')
            .collect();
        if !seen.insert(normalized) {
            continue;
        }
        let quoted = format!("\"{}\"", tok.replace('"', "\"\""));
        let is_informative = tok.chars().count() >= 3 && !tok.bytes().all(|b| b.is_ascii_digit());
        if ordered_all.len() <= max_terms {
            ordered_all.push(quoted.clone());
        }
        if is_informative {
            if primary.len() < max_terms {
                primary.push(quoted);
            }
        } else if secondary.len() < max_terms {
            secondary.push(quoted);
        }
        if primary.len() >= max_terms && ordered_all.len() > max_terms {
            return Some((primary.join(" OR "), true));
        }
    }

    if ordered_all.is_empty() {
        return None;
    }
    if ordered_all.len() <= max_terms {
        return Some((ordered_all.join(" OR "), false));
    }
    let mut selected = primary;
    for tok in secondary {
        if selected.len() >= max_terms {
            break;
        }
        selected.push(tok);
    }
    Some((selected.join(" OR "), true))
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
    use crate::embedder::ManagedEmbedder;
    use s_types::{AppContext, EventSource};
    use tokio::sync::mpsc;

    /// Deterministic offline bag-of-tokens embedder solely for unit-testing
    /// `vec0` cosine indexing and hybrid ranking without network access.
    struct DeterministicTestEmbedder;

    impl Embedder for DeterministicTestEmbedder {
        fn model_id(&self) -> &str {
            crate::embedder::MODEL_ID_DEVHASH
        }

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

    #[test]
    fn truncate_query_prefix_respects_utf8_turkish_word_boundaries_and_empty_queries() {
        assert_eq!(truncate_query_prefix("", 240), ("", false));
        assert_eq!(truncate_query_prefix("   \t\n  ", 240), ("", false));
        assert_eq!(
            truncate_query_prefix("kısa sorgu", 240),
            ("kısa sorgu", false)
        );

        // Turkish multi-byte chars: "güvenlik"(9) + " "(1) + "şifreleme"(10) + " "(1) + "doğrulama"(10) = 31 bytes.
        // Cutting at 25 lands mid-word inside "doğrulama" and must back off to "güvenlik şifreleme".
        let tr = "  güvenlik şifreleme doğrulama ölçümü  ";
        let (cut, truncated) = truncate_query_prefix(tr, 25);
        assert!(truncated);
        assert_eq!(cut, "güvenlik şifreleme");
        assert!(cut.len() <= 25);

        // Cutting mid-codepoint inside 'ğ' (bytes 23..25) must also never panic and stay <= max_bytes.
        let (cut_mid, truncated_mid) = truncate_query_prefix(tr, 24);
        assert!(truncated_mid);
        assert_eq!(cut_mid, "güvenlik şifreleme");

        // Exact boundary at end of second word ("güvenlik şifreleme" = 20 bytes) keeps second word.
        let (cut_exact, truncated_exact) = truncate_query_prefix(tr, 20);
        assert!(truncated_exact);
        assert_eq!(cut_exact, "güvenlik şifreleme");

        // Unbroken Turkish token longer than max_bytes still truncates on valid char boundary.
        let unbroken = "şğüöçıŞĞÜÖÇİ".repeat(5);
        let (cut_unbroken, trunc_unbroken) = truncate_query_prefix(&unbroken, 11);
        assert!(trunc_unbroken);
        assert!(cut_unbroken.len() <= 11);
        assert!(!cut_unbroken.is_empty());
    }

    #[test]
    fn sanitize_fts_query_deduplicates_turkish_and_caps_terms() {
        assert!(sanitize_fts_query("").is_none());
        assert!(sanitize_fts_query("   \n\t ").is_none());
        assert!(sanitize_fts_query("... --- !!!").is_none());

        let (deduped, truncated) = sanitize_fts_query_limited(
            "Şifreleme şifreleme ŞİFRELEME doğrulama DOĞRULAMA ölçüm",
            10,
        )
        .expect("fts query");
        assert!(!truncated);
        assert_eq!(deduped, "\"Şifreleme\" OR \"doğrulama\" OR \"ölçüm\"");

        let many: String = (0..50)
            .map(|i| format!("terim_{i}_özgün"))
            .collect::<Vec<_>>()
            .join(" ");
        let (capped, was_capped) =
            sanitize_fts_query_limited(&many, DEFAULT_MAX_BM25_TERMS).expect("capped fts");
        assert!(was_capped);
        assert_eq!(capped.split(" OR ").count(), DEFAULT_MAX_BM25_TERMS);
    }

    #[test]
    fn hybrid_search_handles_4kb_paste_turkish_and_empty_query_with_bounded_embedder_input() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct LengthAssertingEmbedder {
            max_seen_bytes: Arc<AtomicUsize>,
        }

        impl Embedder for LengthAssertingEmbedder {
            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                Ok(texts.iter().map(|t| project_text_to_unit_vec(t)).collect())
            }

            fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
                self.max_seen_bytes.fetch_max(text.len(), Ordering::SeqCst);
                assert!(
                    text.len() <= DEFAULT_MAX_VECTOR_QUERY_BYTES,
                    "embed_one received {} bytes (> {})",
                    text.len(),
                    DEFAULT_MAX_VECTOR_QUERY_BYTES
                );
                Ok(project_text_to_unit_vec(text))
            }
        }

        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut store = MemoryStore::open_in_memory(LengthAssertingEmbedder {
            max_seen_bytes: Arc::clone(&max_seen),
        })
        .expect("open store");

        let e0 = block(
            0,
            1_000_000,
            "Code.exe",
            "vault.rs",
            false,
            "Türkçe şifreleme hatası RARE_4KB_SENTINEL_ERR99 çözüldü",
        );
        let e1 = block(
            1,
            1_005_000,
            "notepad.exe",
            "other.txt",
            false,
            "completely unrelated note",
        );
        store.ingest_batch(&[e0, e1]).expect("ingest");

        // Empty / whitespace queries return empty without invoking embed_one.
        let empty_out = store
            .hybrid_search_detailed("   \n\t  ", 5, &HybridSearchConfig::default())
            .expect("empty detailed search");
        assert!(empty_out.hits.is_empty());
        assert!(!empty_out.query_truncated);
        assert!(!empty_out.semantic_used);
        assert_eq!(max_seen.load(Ordering::SeqCst), 0);

        // 4 KB+ Turkish-accented paste: vector input capped at <= DEFAULT_MAX_VECTOR_QUERY_BYTES,
        // `query_truncated == true`, and BM25 still catches unique error code inside 4 KB!
        let mut paste_4kb = String::from("güvenlik şifreleme doğrulama çözümü ");
        while paste_4kb.len() < 3200 {
            paste_4kb.push_str("tekrarlayan gürültü kelimesi ");
        }
        paste_4kb.push_str("RARE_4KB_SENTINEL_ERR99 ");
        while paste_4kb.len() < 4200 {
            paste_4kb.push_str("ekstra metin bloğu ");
        }
        assert!(paste_4kb.len() > 4096);

        let outcome = store
            .hybrid_search_detailed(&paste_4kb, 5, &HybridSearchConfig::default())
            .expect("4kb detailed search");
        assert!(outcome.query_truncated);
        assert!(outcome.semantic_used);
        assert!(max_seen.load(Ordering::SeqCst) <= DEFAULT_MAX_VECTOR_QUERY_BYTES);
        assert!(max_seen.load(Ordering::SeqCst) > 0);
        assert!(!outcome.hits.is_empty());
        assert_eq!(outcome.hits[0].event_id, 0);
    }

    #[test]
    fn managed_embedder_failure_and_downloading_degrade_to_bm25_and_backfill_on_ready() {
        let managed = ManagedEmbedder::new();
        let mut store = MemoryStore::open_in_memory(managed.clone()).expect("open store");

        // 1. NotDownloaded: ingestion and search work via BM25 + causality without crashing.
        let e0 = block(
            0,
            1_000_000,
            "WindowsTerminal.exe",
            "cargo build",
            false,
            "error: SQLCIPHER_LINK_404 symbol missing",
        );
        let e1 = block(
            1,
            1_010_000,
            "brave.exe",
            "Search link fix",
            true,
            "searching SQLCIPHER_LINK_404 workaround",
        );
        store
            .ingest_batch(&[e0, e1])
            .expect("ingest while NotDownloaded must succeed");

        let pre_out = store
            .hybrid_search_detailed("SQLCIPHER_LINK_404", 5, &HybridSearchConfig::default())
            .expect("BM25 fallback search succeeds");
        assert!(!pre_out.semantic_used);
        assert_eq!(pre_out.hits.len(), 2);
        assert!(!pre_out.hits[0].causality_chain.is_empty());

        // 2. Failed initialization: ingestion and search STILL keep working on BM25.
        let _ = managed.initialize_with(|progress| -> Result<DeterministicTestEmbedder> {
            progress(0, Some(1024));
            Err(CoreError::Embedder(
                "offline during first launch".to_owned(),
            ))
        });
        assert!(managed.status().is_failed());

        store
            .ingest_block(&block(
                2,
                1_020_000,
                "Code.exe",
                "main.rs",
                false,
                "applied offline BM25_SURVIVED_88 patch",
            ))
            .expect("single ingest while Failed must succeed");

        let failed_out = store
            .hybrid_search_detailed("BM25_SURVIVED_88", 5, &HybridSearchConfig::default())
            .expect("search while Failed must succeed via BM25");
        assert!(!failed_out.semantic_used);
        assert_eq!(failed_out.hits.len(), 1);
        assert_eq!(failed_out.hits[0].event_id, 2);

        // No vectors exist yet while embedder was unavailable.
        let vec_count_before: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM event_vectors", [], |r| r.get(0))
            .unwrap();
        assert_eq!(vec_count_before, 0);

        // 3. Recovery / Ready: backfill missing vectors and subsequent searches use vectors.
        managed
            .initialize_with(|_| Ok(DeterministicTestEmbedder))
            .expect("recovery succeeds");
        let backfilled = store
            .backfill_missing_embeddings(16)
            .expect("backfill succeeds");
        assert_eq!(backfilled, 3);

        let ready_out = store
            .hybrid_search_detailed("SQLCIPHER_LINK_404", 5, &HybridSearchConfig::default())
            .expect("hybrid search after Ready");
        assert!(ready_out.semantic_used);
        assert_eq!(ready_out.hits.len(), 2);
    }

    #[test]
    fn sanitize_fts_query_prioritizes_informative_tokens_on_code_and_error_dumps_while_preserving_short_queries()
     {
        // Short queries within DEFAULT_MAX_BM25_TERMS (including 7-word Turkish queries) keep exact order.
        let (short_fts, short_trunc) =
            sanitize_fts_query_limited("c 1 db id", DEFAULT_MAX_BM25_TERMS)
                .expect("short query with ids");
        assert!(!short_trunc);
        assert_eq!(short_fts, "\"c\" OR \"1\" OR \"db\" OR \"id\"");

        // Error dumps starting with timestamps / PIDs prioritize informative error/symbol tokens
        // both under default 8-term budget and the 4-term oversized-paste budget.
        let dump = "[2026-11-21 15:04:09] #42 E0308 error SQLCIPHER_HMAC mismatch fn embed_one crates s_core embedder rs extra tail token";
        let (dump_default_fts, dump_default_trunc) =
            sanitize_fts_query_limited(dump, DEFAULT_MAX_BM25_TERMS).expect("error dump default");
        assert!(dump_default_trunc);
        assert_eq!(
            dump_default_fts,
            "\"E0308\" OR \"error\" OR \"SQLCIPHER_HMAC\" OR \"mismatch\" OR \"embed_one\" OR \"crates\" OR \"s_core\" OR \"embedder\""
        );
        let (dump_paste_fts, dump_paste_trunc) =
            sanitize_fts_query_limited(dump, 4).expect("error dump paste tier");
        assert!(dump_paste_trunc);
        assert_eq!(
            dump_paste_fts,
            "\"E0308\" OR \"error\" OR \"SQLCIPHER_HMAC\" OR \"mismatch\""
        );

        // When fewer than max_terms informative tokens exist, secondary tokens backfill remaining slots.
        let (mixed_fts, mixed_trunc) = sanitize_fts_query_limited("2026 11 E0308 id db 42", 4)
            .expect("mixed informative + short query");
        assert!(mixed_trunc);
        assert_eq!(mixed_fts, "\"E0308\" OR \"2026\" OR \"11\" OR \"id\"");
    }

    #[test]
    fn bm25_quality_preserves_turkish_and_code_error_dump_top1_under_default_limits() {
        let mut store =
            MemoryStore::open_in_memory(DeterministicTestEmbedder).expect("open in-memory store");

        let mut events = Vec::new();
        for i in 0..25_u64 {
            events.push(block(
                i,
                1_000_000 + i * 1_000,
                "svchost.exe",
                "System Log",
                false,
                &format!(
                    "2026-11-21 15:00:{:02} INFO worker thread heartbeat ok günlük özet kaydı olay_{i}",
                    i % 60
                ),
            ));
        }
        events.push(block(
            100,
            1_050_000,
            "WindowsTerminal.exe",
            "SynapseMind Şifreleme Günlüğü",
            false,
            "Veritabanı şifreleme anahtarı DPAPI doğrulaması başarısız oldu; çalışma dizini yetkisi kontrol edilmeli.",
        ));
        events.push(block(
            101,
            1_051_000,
            "Code.exe",
            "vault_hmac.rs",
            false,
            "Şifreleme katmanında SQLCIPHER_PAGE_HMAC uyuşmazlığı tespit edildi, geçici önbellek temizlendi.",
        ));
        events.push(block(
            102,
            1_052_000,
            "WindowsTerminal.exe",
            "cargo check",
            false,
            "error[E0308]: mismatched types in crates/s-core/src/embedder.rs — expected ManagedEmbedder, found DualEmbedder",
        ));
        store.ingest_batch(&events).expect("ingest quality corpus");

        let bm25_only = HybridSearchConfig {
            bm25_weight: 1.0,
            vector_weight: 0.0,
            recency_weight: 0.0,
            ..HybridSearchConfig::default()
        };

        // 1. Long (~2.4 KB) Turkish query with multi-byte characters and pasted boilerplate tail.
        let tr_long = format!(
            "Veritabanı şifreleme anahtarı DPAPI doğrulaması başarısız oldu. {}",
            "ilgisiz günlük sistem pencere odak geçmişi satırı ".repeat(40)
        );
        assert!(tr_long.len() > DEFAULT_MAX_BM25_QUERY_BYTES);
        let (tr_prefix, tr_byte_trunc) =
            truncate_query_prefix(&tr_long, DEFAULT_MAX_BM25_QUERY_BYTES);
        assert!(tr_byte_trunc);
        assert!(tr_prefix.len() <= DEFAULT_MAX_BM25_QUERY_BYTES);
        assert!(!tr_prefix.is_empty());

        let tr_bm25 = store
            .hybrid_search_detailed(&tr_long, 5, &bm25_only)
            .expect("Turkish long BM25");
        assert!(tr_bm25.query_truncated);
        assert_eq!(tr_bm25.hits[0].event_id, 100);
        let tr_hybrid = store
            .hybrid_search_detailed(&tr_long, 5, &HybridSearchConfig::default())
            .expect("Turkish long hybrid");
        assert_eq!(tr_hybrid.hits[0].event_id, 100);

        // 2. Turkish uppercase 'İ'/'Ş'/'Ü'/'Ç'/'Ğ' normalization parity in long diagnostic paste.
        let tr_upper_long = format!(
            "ŞİFRELEME KATMANINDA SQLCIPHER_PAGE_HMAC UYUŞMAZLIĞI TESPİT EDİLDİ {}",
            "worker thread heartbeat info status frame pointer ".repeat(35)
        );
        let tr_upper_bm25 = store
            .hybrid_search_detailed(&tr_upper_long, 5, &bm25_only)
            .expect("Turkish uppercase long BM25");
        assert!(tr_upper_bm25.query_truncated);
        assert_eq!(tr_upper_bm25.hits[0].event_id, 101);

        // 3. Long (~3 KB) compiler error dump preceded by timestamps/PID numbers.
        let err_long = format!(
            "[2026-11-21 15:04:09] #9842 error[E0308]: mismatched types in crates/s-core/src/embedder.rs — expected ManagedEmbedder {}",
            "note: required by a bound in futures::task::Spawn at library/core/src/ops/function.rs:250 ".repeat(32)
        );
        assert!(err_long.len() > 2048);
        let err_bm25 = store
            .hybrid_search_detailed(&err_long, 5, &bm25_only)
            .expect("code error dump long BM25");
        assert!(err_bm25.query_truncated);
        assert_eq!(err_bm25.hits[0].event_id, 102);
        let err_hybrid = store
            .hybrid_search_detailed(&err_long, 5, &HybridSearchConfig::default())
            .expect("code error dump long hybrid");
        assert_eq!(err_hybrid.hits[0].event_id, 102);

        // 4. Pure multi-byte Turkish UTF-8 boundary truncation at DEFAULT_MAX_BM25_QUERY_BYTES never splits a code point.
        let dense_tr = "ğüşöçıİĞÜŞÖÇ ".repeat(80);
        let (cut, cut_trunc) = truncate_query_prefix(&dense_tr, DEFAULT_MAX_BM25_QUERY_BYTES);
        assert!(cut_trunc);
        assert!(cut.len() <= DEFAULT_MAX_BM25_QUERY_BYTES);
        assert!(cut.is_char_boundary(cut.len()));
    }

    struct DistinctSemanticModelEmbedder {
        id: &'static str,
        batch_inputs: Arc<Mutex<Vec<usize>>>,
    }

    impl DistinctSemanticModelEmbedder {
        fn new(id: &'static str) -> (Self, Arc<Mutex<Vec<usize>>>) {
            let batch_inputs = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    id,
                    batch_inputs: Arc::clone(&batch_inputs),
                },
                batch_inputs,
            )
        }

        fn encode(&self, text: &str) -> Vec<f32> {
            let mut vec = vec![0.0_f32; EMBEDDING_DIM];
            let lower = text.to_ascii_lowercase();
            // Intentionally orthogonal to DevHash token projections: semantic concepts map to
            // dedicated orthogonal basis axes rather than surface lexical tokens.
            if lower.contains("automobile") || lower.contains("mechanic") || lower.contains("car") {
                vec[350] = 1.0;
            } else if lower.contains("postgresql")
                || lower.contains("deadlock")
                || lower.contains("sql")
            {
                vec[351] = 1.0;
            } else if lower.contains("sourdough") || lower.contains("bread") {
                vec[352] = 1.0;
            } else {
                vec[353] = 1.0;
            }
            vec
        }
    }

    impl Embedder for DistinctSemanticModelEmbedder {
        fn model_id(&self) -> &str {
            self.id
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.batch_inputs.lock().unwrap().push(texts.len());
            Ok(texts.iter().map(|t| self.encode(t)).collect())
        }

        fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
            Ok(self.encode(text))
        }
    }

    fn count_event_vectors<E: Embedder>(store: &MemoryStore<E>) -> i64 {
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM event_vectors", [], |r| r.get(0))
            .expect("count event_vectors")
    }

    #[test]
    fn model_id_migration_clears_devhash_vectors_and_backfills_in_chunks_on_encrypted_db() {
        let key = [0x33_u8; 32];
        let dir = TempDirGuard::new("migrate-devhash");

        for legacy_missing_meta in [false, true] {
            let db_path = dir.0.join(format!("vault_legacy_{legacy_missing_meta}.db"));

            // 1. Populate encrypted store with DevHash (`devhash-v1`), including a causality edge
            // and a non-embedding block that must remain excluded from `event_vectors`.
            {
                let mut store =
                    MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                        .expect("open encrypted store with devhash");
                assert_eq!(
                    store
                        .stored_embedding_model_id()
                        .expect("read meta")
                        .as_deref(),
                    Some(crate::embedder::MODEL_ID_DEVHASH)
                );

                let e0 = block(
                    0,
                    1_000_000,
                    "WindowsTerminal.exe",
                    "cargo test",
                    false,
                    "error: PostgreSQL deadlock transaction MIGRATION_SENTINEL_11",
                );
                let e1 = block(
                    1,
                    1_010_000,
                    "brave.exe",
                    "Search deadlock fix",
                    true,
                    "automobile mechanic brake pads MIGRATION_SENTINEL_11",
                );
                let e2 = block(
                    2,
                    1_020_000,
                    "notes.exe",
                    "bakery",
                    false,
                    "sourdough bread oven steam",
                );
                let mut e3_no_embed = block(3, 1_030_000, "Figma.exe", "canvas", false, "");
                e3_no_embed.has_embedding_payload = false;
                let e4 = block(
                    4,
                    1_040_000,
                    "excel.exe",
                    "sheet",
                    false,
                    "quarterly revenue dividend",
                );
                store
                    .ingest_batch(&[e0, e1, e2, e3_no_embed, e4])
                    .expect("ingest devhash batch");
                assert_eq!(count_event_vectors(&store), 4);

                if legacy_missing_meta {
                    // Simulate a v0.1.0 DB created before `store_meta` existed.
                    store
                        .connection()
                        .execute("DROP TABLE store_meta", [])
                        .expect("drop store_meta to simulate v0.1.0");
                }
            }

            // 2. Reopen with a different model_id (`bge-small-en-v1.5-fp32`):
            // old vectors must be cleared immediately and metadata updated atomically.
            let (model_b, batch_inputs) =
                DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32);
            let mut reopened = MemoryStore::open_encrypted(&db_path, &key, model_b)
                .expect("reopen encrypted store with new model");

            assert_eq!(
                reopened
                    .stored_embedding_model_id()
                    .expect("meta after migration")
                    .as_deref(),
                Some(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32)
            );
            assert_eq!(
                count_event_vectors(&reopened),
                0,
                "stale DevHash vectors must be cleared on model mismatch"
            );
            assert_eq!(
                reopened
                    .pending_embedding_backfill_count()
                    .expect("pending backfill count"),
                4
            );
            assert!(
                !reopened
                    .reconcile_embedding_model()
                    .expect("idempotent second reconcile"),
                "second reconcile must be a no-op"
            );

            // Events, FTS5, and causality edges remain intact.
            let bm25_hits = reopened
                .hybrid_search("MIGRATION_SENTINEL_11", 5)
                .expect("BM25 search before backfill");
            assert_eq!(bm25_hits.len(), 2);
            assert!(bm25_hits.iter().any(|h| {
                h.causality_chain
                    .iter()
                    .any(|e| e.relationship == "searched_after_error")
            }));

            // 3. Chunked backfill regenerates all 4 embeddable vectors (never touching e3_no_embed).
            assert_eq!(reopened.backfill_missing_embeddings(2).expect("chunk 1"), 2);
            assert_eq!(
                reopened
                    .pending_embedding_backfill_count()
                    .expect("pending"),
                2
            );
            assert_eq!(reopened.backfill_missing_embeddings(2).expect("chunk 2"), 2);
            assert_eq!(
                reopened
                    .pending_embedding_backfill_count()
                    .expect("pending"),
                0
            );
            assert_eq!(reopened.backfill_missing_embeddings(2).expect("chunk 3"), 0);
            assert_eq!(count_event_vectors(&reopened), 4);
            assert_eq!(*batch_inputs.lock().unwrap(), vec![2, 2]);

            // 4. Vector-only search now ranks using the new model's vector space.
            let vector_only = HybridSearchConfig {
                bm25_weight: 0.0,
                vector_weight: 1.0,
                recency_weight: 0.0,
                ..HybridSearchConfig::default()
            };
            let car_hits = reopened
                .hybrid_search_with_config("car repair", 4, &vector_only)
                .expect("vector search car");
            assert_eq!(car_hits[0].event_id, 1);
            let sql_hits = reopened
                .hybrid_search_with_config("sql lock", 4, &vector_only)
                .expect("vector search sql");
            assert_eq!(sql_hits[0].event_id, 0);

            drop(reopened);

            // 5. Disk bytes must stay encrypted: no plaintext leaks.
            let raw_bytes = std::fs::read(&db_path).expect("read encrypted bytes");
            assert!(!raw_bytes.starts_with(b"SQLite format 3\0"));
            assert!(!contains_subslice(&raw_bytes, b"MIGRATION_SENTINEL_11"));
            assert!(!contains_subslice(&raw_bytes, b"bge-small-en-v1.5-fp32"));
        }
    }

    #[test]
    fn same_model_id_reopen_keeps_existing_vectors_and_skips_backfill() {
        let dir = TempDirGuard::new("same-model");
        let db_path = dir.0.join("same.db");
        let key = [0x44_u8; 32];

        {
            let mut store = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                .expect("open initial store");
            store
                .ingest_batch(&[
                    block(
                        0,
                        1_000,
                        "Code.exe",
                        "a.rs",
                        false,
                        "rust vector preserved alpha",
                    ),
                    block(
                        1,
                        2_000,
                        "Code.exe",
                        "b.rs",
                        false,
                        "rust vector preserved beta",
                    ),
                    block(
                        2,
                        3_000,
                        "Code.exe",
                        "c.rs",
                        false,
                        "unrelated garden notes",
                    ),
                ])
                .expect("ingest initial blocks");
            assert_eq!(count_event_vectors(&store), 3);
        }

        let (spy, batch_inputs) =
            DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_DEVHASH);
        let mut reopened =
            MemoryStore::open_encrypted(&db_path, &key, spy).expect("reopen with same model_id");
        assert_eq!(
            reopened
                .stored_embedding_model_id()
                .expect("meta")
                .as_deref(),
            Some(crate::embedder::MODEL_ID_DEVHASH)
        );
        assert_eq!(count_event_vectors(&reopened), 3);
        assert_eq!(
            reopened
                .pending_embedding_backfill_count()
                .expect("pending"),
            0
        );
        assert!(!reopened.reconcile_embedding_model().expect("reconcile"));
        assert_eq!(
            reopened
                .backfill_missing_embeddings(128)
                .expect("backfill no-op"),
            0
        );
        assert!(
            batch_inputs.lock().unwrap().is_empty(),
            "same model_id must never delete or re-embed existing vectors"
        );
    }

    #[test]
    fn empty_db_and_unready_bm25_fallback_never_write_model_id_until_ready() {
        let dir = TempDirGuard::new("empty-and-unready");
        let key = [0x55_u8; 32];

        // A. Empty encrypted DB opened with unready ManagedEmbedder must not record model_id.
        let unready_db = dir.0.join("empty_unready.db");
        let managed = ManagedEmbedder::new();
        {
            let mut store = MemoryStore::open_encrypted(&unready_db, &key, managed.clone())
                .expect("open empty encrypted store with unready embedder");
            assert_eq!(store.stored_embedding_model_id().expect("meta"), None);
            assert!(
                !store
                    .reconcile_embedding_model()
                    .expect("reconcile while NotDownloaded")
            );
            assert_eq!(
                store
                    .backfill_missing_embeddings(128)
                    .expect("backfill while NotDownloaded"),
                0
            );
            assert_eq!(
                store.stored_embedding_model_id().expect("meta still none"),
                None
            );

            // Ingestion in BM25 fallback must also leave `embedding_model_id` unset.
            store
                .ingest_block(&block(
                    0,
                    1_000,
                    "Code.exe",
                    "main.rs",
                    false,
                    "UNREADY_BM25_FALLBACK_TOKEN",
                ))
                .expect("ingest while NotDownloaded");
            assert_eq!(
                store.stored_embedding_model_id().expect("meta still none"),
                None
            );
            assert_eq!(count_event_vectors(&store), 0);
            assert_eq!(
                store.pending_embedding_backfill_count().expect("pending"),
                1
            );

            // Failed download keeps BM25 working and still writes no model_id.
            assert!(
                managed
                    .initialize_with(|_| -> Result<DeterministicTestEmbedder> {
                        Err(CoreError::Embedder("offline".to_owned()))
                    })
                    .is_err()
            );
            assert_eq!(
                store.stored_embedding_model_id().expect("meta after fail"),
                None
            );

            // Once model becomes Ready, backfill writes model_id and populates vectors.
            let (model_b, _) =
                DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32);
            managed
                .initialize_with(|_| Ok(model_b))
                .expect("recover to Ready");
            assert_eq!(store.backfill_missing_embeddings(128).expect("backfill"), 1);
            assert_eq!(
                store
                    .stored_embedding_model_id()
                    .expect("meta after ready")
                    .as_deref(),
                Some(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32)
            );
            assert_eq!(count_event_vectors(&store), 1);
        }

        // B. Empty encrypted DB opened with an already-ready embedder records model_id cleanly.
        let ready_empty_db = dir.0.join("empty_ready.db");
        let mut empty_ready_store =
            MemoryStore::open_encrypted(&ready_empty_db, &key, DeterministicTestEmbedder)
                .expect("open empty DB with ready embedder");
        assert_eq!(
            empty_ready_store
                .stored_embedding_model_id()
                .expect("meta on ready empty DB")
                .as_deref(),
            Some(crate::embedder::MODEL_ID_DEVHASH)
        );
        assert_eq!(count_event_vectors(&empty_ready_store), 0);
        assert_eq!(
            empty_ready_store
                .pending_embedding_backfill_count()
                .expect("pending"),
            0
        );
        assert!(
            !empty_ready_store
                .reconcile_embedding_model()
                .expect("reconcile")
        );
        assert_eq!(
            empty_ready_store
                .backfill_missing_embeddings(128)
                .expect("backfill"),
            0
        );

        // C. Existing v0.1.0 DB opened with unready ManagedEmbedder preserves old vectors until Ready,
        // never mixes vector spaces in search even in the window between Ready and backfill.
        let legacy_db = dir.0.join("legacy_race.db");
        {
            let mut seed = MemoryStore::open_encrypted(&legacy_db, &key, DeterministicTestEmbedder)
                .expect("seed legacy");
            seed.ingest_batch(&[
                block(0, 1_000, "Code.exe", "a.rs", false, "RACE_GUARD_ALPHA car"),
                block(1, 2_000, "Code.exe", "b.rs", false, "RACE_GUARD_BETA sql"),
            ])
            .expect("ingest seed");
            seed.connection()
                .execute(
                    "DELETE FROM store_meta WHERE key = ?1",
                    [EMBEDDING_MODEL_META_KEY],
                )
                .expect("remove model meta");
        }

        let lazy = ManagedEmbedder::new();
        let mut store = MemoryStore::open_encrypted(&legacy_db, &key, lazy.clone())
            .expect("open legacy with unready ManagedEmbedder");
        assert_eq!(store.stored_embedding_model_id().expect("meta"), None);
        assert_eq!(count_event_vectors(&store), 2);
        let pre_ready = store
            .hybrid_search_detailed("RACE_GUARD_ALPHA", 5, &HybridSearchConfig::default())
            .expect("BM25 works while unready");
        assert!(!pre_ready.semantic_used);
        assert_eq!(pre_ready.hits.len(), 1);

        let (model_b, _) =
            DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32);
        lazy.initialize_with(|_| Ok(model_b)).expect("become ready");

        // Even before `backfill_missing_embeddings` runs, search must NOT query mismatched vectors.
        let pre_reconcile = store
            .hybrid_search_detailed("RACE_GUARD_ALPHA", 5, &HybridSearchConfig::default())
            .expect("BM25 fallback on mismatched vectors");
        assert!(!pre_reconcile.semantic_used);
        assert_eq!(pre_reconcile.hits.len(), 1);

        assert_eq!(store.backfill_missing_embeddings(128).expect("backfill"), 2);
        let post_backfill = store
            .hybrid_search_detailed("RACE_GUARD_ALPHA", 5, &HybridSearchConfig::default())
            .expect("semantic active after backfill");
        assert!(post_backfill.semantic_used);
        assert_eq!(post_backfill.hits[0].event_id, 0);
    }

    #[test]
    fn interrupted_migration_and_concurrent_ingest_are_idempotent_and_resumable() {
        let dir = TempDirGuard::new("resume");
        let db_path = dir.0.join("resume.db");
        let key = [0x66_u8; 32];

        {
            let mut seed = MemoryStore::open_encrypted(&db_path, &key, DeterministicTestEmbedder)
                .expect("seed encrypted DB");
            let blocks: Vec<MaskedMemoryBlock> = (0..5_u64)
                .map(|i| {
                    block(
                        i,
                        1_000 + i * 1_000,
                        "Code.exe",
                        "main.rs",
                        false,
                        &format!("sourdough bread event {i}"),
                    )
                })
                .collect();
            seed.ingest_batch(&blocks).expect("ingest 5 blocks");
            assert_eq!(count_event_vectors(&seed), 5);
        }

        // Open with new model, backfill only 2 out of 5, then close (simulating crash/exit).
        {
            let (model_b, _) =
                DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32);
            let mut partial =
                MemoryStore::open_encrypted(&db_path, &key, model_b).expect("open with new model");
            assert_eq!(count_event_vectors(&partial), 0);
            assert_eq!(
                partial.backfill_missing_embeddings(2).expect("partial 2"),
                2
            );
            assert_eq!(count_event_vectors(&partial), 2);
            assert_eq!(
                partial.pending_embedding_backfill_count().expect("pending"),
                3
            );
        }

        // Reopen with same new model: keeps the 2 completed vectors and backfills only the 3 left.
        {
            let (spy_b, batch_inputs) =
                DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32);
            let mut resumed =
                MemoryStore::open_encrypted(&db_path, &key, spy_b).expect("reopen resumed");
            assert_eq!(count_event_vectors(&resumed), 2);
            assert_eq!(
                resumed.pending_embedding_backfill_count().expect("pending"),
                3
            );
            assert!(
                !resumed
                    .reconcile_embedding_model()
                    .expect("no-op reconcile")
            );

            assert_eq!(resumed.backfill_missing_embeddings(2).expect("resume 2"), 2);
            assert_eq!(resumed.backfill_missing_embeddings(2).expect("resume 1"), 1);
            assert_eq!(
                resumed.backfill_missing_embeddings(2).expect("resume done"),
                0
            );
            assert_eq!(count_event_vectors(&resumed), 5);
            assert_eq!(*batch_inputs.lock().unwrap(), vec![2, 1]);
        }

        // Uncommitted transaction rollback leaves both `event_vectors` and `store_meta` untouched.
        {
            let (model_b, _) =
                DistinctSemanticModelEmbedder::new(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32);
            let mut store = MemoryStore::open_encrypted(&db_path, &key, model_b)
                .expect("reopen for rollback check");
            {
                let tx = store.conn.transaction().expect("begin tx");
                assert!(
                    reconcile_embedding_model_in_tx(&tx, "transient-rolled-back-id")
                        .expect("in-tx reconcile")
                );
                // Drop `tx` without commit -> SQLite rolls back both DELETE and store_meta update.
            }
            assert_eq!(
                store
                    .stored_embedding_model_id()
                    .expect("meta after rollback")
                    .as_deref(),
                Some(crate::embedder::MODEL_ID_BGE_SMALL_EN_V15_FP32)
            );
            assert_eq!(count_event_vectors(&store), 5);
        }

        // Concurrent live `ingest_block` right after `ManagedEmbedder` reaches `Ready`
        // (before `backfill_missing_embeddings` runs) must clear old vectors atomically first.
        {
            let lazy = ManagedEmbedder::new();
            let mut store =
                MemoryStore::open_encrypted(&db_path, &key, lazy.clone()).expect("open lazy");
            assert_eq!(count_event_vectors(&store), 5);

            let (model_c, _) = DistinctSemanticModelEmbedder::new("mock-v3");
            lazy.initialize_with(|_| Ok(model_c))
                .expect("ready model_c");

            let next_id = store.next_event_id().expect("next_id");
            store
                .ingest_block(&block(
                    next_id,
                    99_000,
                    "Code.exe",
                    "live.rs",
                    false,
                    "live ingest after Ready",
                ))
                .expect("live ingest reconciles atomically");
            assert_eq!(
                store
                    .stored_embedding_model_id()
                    .expect("meta after live ingest")
                    .as_deref(),
                Some("mock-v3")
            );
            assert_eq!(
                count_event_vectors(&store),
                1,
                "stale vectors must be cleared so only the new model's vector remains"
            );
            assert_eq!(
                store.pending_embedding_backfill_count().expect("pending"),
                5
            );
            assert_eq!(store.backfill_missing_embeddings(128).expect("backfill"), 5);
            assert_eq!(count_event_vectors(&store), 6);
        }
    }
}
