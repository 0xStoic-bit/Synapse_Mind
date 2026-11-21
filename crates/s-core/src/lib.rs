//! # s-core: hibrit arama ve nedensellik grafiği
//!
//! Girdi: guard'dan gelen `MaskedMemoryBlock` akışı. Çıktı: `CausalityQueryHit`.
//!
//! - SQLite şeması (`events`, `causality_edges`, `store_meta`), FTS5 BM25 ve `sqlite-vec`
//!   ([`EMBEDDING_DIM`] = 384, kosinüs).
//! - [`Embedder`] trait'i; [`ManagedEmbedder`] model inene kadar BM25 ile çalışmayı sürdürür.
//! - Model değişince vektörler silinip yeniden üretilir
//!   ([`MemoryStore::reconcile_embedding_model`], [`MemoryStore::backfill_missing_embeddings`]).
//! - Kural tabanlı nedensellik kenarları ([`CausalityConfig`], [`classify_transition`]).
//! - Sorgu uzunluğu sınırlı hibrit arama ([`MemoryStore::hybrid_search_detailed`]).
//!
//! Diske yalnızca [`MemoryStore::open_encrypted`] ile yazılır (SQLCipher, anahtar `s-guard`
//! DPAPI'den). `MemoryStore` `!Sync` olduğu için `Arc<Mutex<_>>` içinde paylaşılır; arama
//! senkron CPU işidir, async bağlamda `spawn_blocking` ile çağrılmalıdır.

pub mod causality;
pub mod embedder;
pub mod store;

use std::fmt;

pub use causality::{CausalityConfig, classify_transition};
#[cfg(feature = "fastembed")]
pub use embedder::fastembed_impl::{
    DualEmbedder, FastEmbedBackend, FastEmbedConfig, FastEmbedMode, FastEmbedder,
    fastembed_model_id, is_dual_model_cached, is_model_cached,
};
pub use embedder::{
    DEFAULT_BATCH_MAX_TOKENS, DEFAULT_IDLE_UNLOAD_TIMEOUT, DEFAULT_QUERY_MAX_TOKENS,
    EMBED_SUB_BATCH_SIZE, EMBEDDING_DIM, Embedder, EmbedderStatus, MODEL_ID_BGE_SMALL_EN_V15_FP32,
    MODEL_ID_BGE_SMALL_EN_V15_Q_INT8, MODEL_ID_DEFAULT_CUSTOM, MODEL_ID_DEVHASH, ManagedEmbedder,
    ManagedEmbedderConfig, StatusListenerId, default_model_cache_dir,
};
pub use s_types::{AppContext, CausalityEdge, CausalityQueryHit, EventSource, MaskedMemoryBlock};
pub use store::{
    DEFAULT_MAX_BM25_QUERY_BYTES, DEFAULT_MAX_BM25_TERMS, DEFAULT_MAX_VECTOR_QUERY_BYTES,
    EMBEDDING_MODEL_META_KEY, HybridSearchConfig, MemoryStats, MemoryStore, SearchOutcome,
    run_ingestion, truncate_query_prefix,
};

/// Crate-wide result alias for `s-core`.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors produced by `s-core` storage, embedding, or query operations.
#[derive(Debug)]
pub enum CoreError {
    Sqlite(rusqlite::Error),
    VecRegistration(String),
    InvalidEmbeddingDim {
        expected: usize,
        actual: usize,
    },
    InvalidEmbeddingVector(&'static str),
    EmbeddingCountMismatch {
        expected: usize,
        actual: usize,
    },
    DuplicateEventId(u64),
    IntegerOverflow(&'static str),
    InvalidDatabasePath(&'static str),
    Encryption(String),
    Io(std::io::Error),
    Embedder(String),
    /// Embedding backend is not ready yet (e.g. downloading) or failed to load;
    /// `MemoryStore` falls back to lexical BM25 + causality without crashing.
    EmbedderUnavailable(String),
    ChannelJoin(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(err) => write!(f, "sqlite error: {err}"),
            Self::VecRegistration(msg) => {
                write!(f, "failed to register sqlite-vec auto-extension: {msg}")
            }
            Self::InvalidEmbeddingDim { expected, actual } => {
                write!(
                    f,
                    "embedding dimension mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidEmbeddingVector(reason) => write!(f, "invalid embedding vector: {reason}"),
            Self::EmbeddingCountMismatch { expected, actual } => {
                write!(
                    f,
                    "embedder returned {actual} vectors for {expected} inputs"
                )
            }
            Self::DuplicateEventId(id) => {
                write!(f, "duplicate event_id {id}: already exists in store")
            }
            Self::IntegerOverflow(msg) => write!(f, "integer range overflow: {msg}"),
            Self::InvalidDatabasePath(reason) => {
                write!(f, "invalid encrypted database path: {reason}")
            }
            Self::Encryption(msg) => write!(f, "encrypted store error: {msg}"),
            Self::Io(err) => write!(f, "database I/O error: {err}"),
            Self::Embedder(msg) => write!(f, "embedder error: {msg}"),
            Self::EmbedderUnavailable(msg) => write!(f, "embedder unavailable: {msg}"),
            Self::ChannelJoin(msg) => write!(f, "async ingestion task failed: {msg}"),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for CoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
