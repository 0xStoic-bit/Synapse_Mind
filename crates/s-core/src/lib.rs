//! # s-core — Hibrit Çıkarım & Nedensellik Grafiği (Katman 3)
//!
//! Sahibi: `graph-vector-core`.
//! Girdi: `tokio::sync::mpsc::Receiver<MaskedMemoryBlock>` · Çıktı: `CausalityQueryHit` (Tauri IPC).
//!
//! ## Temel Yetenekler
//! - SQLite ilişkisel şema (`events`, `causality_edges`, `store_meta`) ve FTS5 BM25 indeksi
//! - `sqlite-vec` (`vec0`, [`EMBEDDING_DIM`] = 384 boyutlu kosinüs metriği, `BAAI/bge-small-en-v1.5`)
//! - [`Embedder`] trait'i (`model_id()` vektör uzayı kimliğiyle), [`ManagedEmbedder`] + [`EmbedderStatus`] (indirme ilerlemesi + BM25 yedek) ve `--features fastembed` altında [`FastEmbedder`] / [`DualEmbedder`]
//! - Model/mod geçişlerinde güvenli vektör uzayı göçü (`store_meta['embedding_model_id']`, [`MemoryStore::reconcile_embedding_model`], [`MemoryStore::backfill_missing_embeddings`])
//! - Kural tabanlı nedensellik kenarı üretimi ([`CausalityConfig`], [`classify_transition`])
//! - Uzunluk korumalı hibrit arama ([`MemoryStore::hybrid_search`], [`MemoryStore::hybrid_search_with_config`], [`MemoryStore::hybrid_search_detailed`])
//! - Monotonik `event_id` sürekliliği ([`MemoryStore::next_event_id`]) ve çakışma reddi (ADR-001)
//!
//! ## `overlay-ui-dev` İçin Kullanım Rehberi (`src-tauri`, ADR-001 / ADR-002)
//! - **Depolama modu (Faz 4 — Iron Rule 7):** Kalıcı disk depolaması için **yalnızca**
//!   [`MemoryStore::open_encrypted`] (veya [`MemoryStore::open_encrypted_with_config`]) kullanın.
//!   Anahtar (`&[u8; 32]`) `s-guard` DPAPI API'sinden (`unprotect_key` / `generate_db_key`)
//!   alınır ve yalnızca `zeroize::Zeroizing` içinde tutulur; diske şifresiz SQLite dosyası yazmak
//!   kesinlikle yasaktır. [`MemoryStore::open_in_memory`] yalnızca geçici/test oturumları içindir.
//! - **Paylaşılan durum ve bloklamayan IPC:** `MemoryStore<E>` içindeki `rusqlite::Connection`
//!   `!Sync` olduğundan store'u `Arc<Mutex<MemoryStore<E>>>` olarak `tauri::State` içinde yönetin.
//!   Arama (`hybrid_search` / `hybrid_search_with_config`) senkron CPU/ONNX/SQLite işi yapar;
//!   Tauri komutlarında mutlaka `tokio::task::spawn_blocking` içinde çağırın ve `k` parametresini
//!   sunucu tarafında `1..=50` aralığına sıkıştırın.
//! - **Gerçek embedding, indirme durumu ve BM25 yedeği:** `s-core` bağımlılığını
//!   `features = ["fastembed"]` ile açın ve [`ManagedEmbedder::new`] + [`ManagedEmbedder::spawn_dual_default`]
//!   kullanın (`Send + Sync + Clone`). Model dosyaları depo dışındaki kullanıcı önbellek dizinine
//!   ([`default_model_cache_dir`]) indirilir. Arayüz [`ManagedEmbedder::status`],
//!   [`ManagedEmbedder::subscribe`] (`tokio::sync::watch::Receiver<EmbedderStatus>`) veya
//!   [`ManagedEmbedder::on_status_change`] üzerinden `NotDownloaded / Downloading { bytes, total } / Ready / Failed(String)`
//!   durumlarını izleyebilir; model henüz inerken veya yüklenemezse [`MemoryStore`] çökmez ve
//!   otomatik olarak BM25 + nedensellik aramasıyla çalışmayı sürdürür (`semantic_used == false`).
//! - **Uzun sorgu koruması:** [`MemoryStore::hybrid_search_detailed`] tekil vektör sorgularını
//!   `HybridSearchConfig::max_vector_query_bytes` (varsayılan `200` B) + sorgu oturumu
//!   [`DEFAULT_QUERY_MAX_TOKENS`] (`64`) ile, BM25 sorgularını `max_bm25_query_bytes` (`512` B) +
//!   `max_bm25_terms` (`8` tekil terim; `max_bm25_query_bytes` aşılırsa `4` bilgilendirici terim)
//!   ile sınırlar ve `SearchOutcome::query_truncated` bayrağını döndürür; toplu indeksleme `512` tokende kalır.
//! - **IPC DTO dönüşümü (ADR-002):** [`CausalityQueryHit`] ve [`CausalityEdge`] bilerek
//!   `serde::Serialize` türetmez. `src-tauri` kendi `Serialize` DTO'larını (`HitDto`, `EdgeDto`)
//!   üretmeli, `!hit.score.is_finite()` olan sonuçları elemeli, arama sorgusunu (`query`) asla
//!   loglamamalı ve UI'a `text_hash`, tam `clean_text`, `sanitized_title` veya `redactions_count`
//!   taşımamalıdır.
//! - **Hattı bağlama (ADR-001):** Store açıldıktan sonra bir kez `let start_id = store.next_event_id()?;`
//!   çağırıp `s_guard::run_with_start_id(rx_raw, tx_masked, start_id)` ve
//!   [`run_ingestion`] görevlerini başlatın:
//! ```rust,ignore
//! let embedder = s_core::ManagedEmbedder::new();
//! let mut status_rx = embedder.subscribe();
//! let _init_handle = embedder.spawn_dual_default()?;
//! let store = s_core::MemoryStore::open_encrypted(&db_path, &db_key, embedder.clone())?;
//! let start_id = store.next_event_id()?; // boş DB'de 0, doluysa MAX(event_id) + 1
//! let shared_store = std::sync::Arc::new(std::sync::Mutex::new(store));
//!
//! // Tauri IPC komutu içinde:
//! let store_ref = std::sync::Arc::clone(&shared_store);
//! let outcome = tokio::task::spawn_blocking(move || {
//!     let guard = store_ref.lock().map_err(|_| s_core::CoreError::Embedder("mutex poisoned".into()))?;
//!     guard.hybrid_search_detailed(&query, k.clamp(1, 50), &s_core::HybridSearchConfig::default())
//! }).await??;
//! ```
//!
//! ## `benchmark-plotter` İçin Kullanım Rehberi (`benchmarks/`, ADR-004)
//! - **Ayrı workspace ve kilit/profil eşliği:** `benchmarks/` kök `Cargo.lock` ile tohumlanmalı ve
//!   kök `[profile.release]` (`lto = "thin"`, `codegen-units = 1`) ayarlarını aynen kopyalamalıdır.
//! - **Embedding ölçümü (`--features fastembed`):** [`FastEmbedder::try_new_default`] çağrısını
//!   ölçüm döngüsünün DIŞINDA bir kez yapın (model yükleme/indirme soğuk başlangıçtır); sıcak
//!   döngüde [`Embedder::embed_one`] ve [`Embedder::embed_batch`] p50/p95/p99 gecikmelerini ölçün.
//! - **Arama ve alım ölçümü:**
//!   - [`MemoryStore::hybrid_search`] / [`MemoryStore::hybrid_search_with_config`]: hem
//!     `FastEmbedder` ile uçtan uca sorgu gecikmesini, hem de sabit ön-hesaplanmış bir vektör
//!     döndüren `Embedder` ile izole `sqlite-vec` + FTS5 + nedensellik BFS maliyetini ayrı ayrı
//!     ölçebilirsiniz.
//!   - [`MemoryStore::ingest_block`] / [`MemoryStore::ingest_batch`]: üretim yolu aynı `event_id`
//!     tekrarında [`CoreError::DuplicateEventId`] döndürür (ADR-001). Döngüde her yineleme için
//!     `event_id` değerini artırın (`store.next_event_id()?`'den başlayarak) veya yeniden
//!     indeksleme senaryosu için açık [`MemoryStore::upsert_block`] metodunu kullanın.

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
