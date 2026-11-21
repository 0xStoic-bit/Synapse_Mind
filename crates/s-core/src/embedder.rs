//! Local text embedding abstraction and `fastembed-rs` backend (`bge-small-en-v1.5`).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::{CoreError, Result};

/// Fixed embedding dimension for `BAAI/bge-small-en-v1.5`.
pub const EMBEDDING_DIM: usize = 384;

/// Stable vector-space identifier for deterministic token-hash fallback (`DevHashEmbedder`).
pub const MODEL_ID_DEVHASH: &str = "devhash-v1";

/// Stable vector-space identifier for `BAAI/bge-small-en-v1.5` FP32 (`EmbeddingModel::BGESmallENV15`).
pub const MODEL_ID_BGE_SMALL_EN_V15_FP32: &str = "bge-small-en-v1.5-fp32";

/// Stable vector-space identifier for `BAAI/bge-small-en-v1.5` INT8 (`EmbeddingModel::BGESmallENV15Q`).
pub const MODEL_ID_BGE_SMALL_EN_V15_Q_INT8: &str = "bge-small-en-v1.5-q-int8";

/// Fallback identifier for external [`Embedder`] implementations that do not override [`Embedder::model_id`].
pub const MODEL_ID_DEFAULT_CUSTOM: &str = "custom-v1";

/// Maximum WordPiece sequence length for single search queries (`DualEmbedder` query session).
pub const DEFAULT_QUERY_MAX_TOKENS: usize = 64;

/// Maximum WordPiece sequence length for batch indexing (`DualEmbedder` batch session & `FastEmbedder`).
pub const DEFAULT_BATCH_MAX_TOKENS: usize = 512;

/// Texts per ONNX Runtime call in `FastEmbedder::embed_batch`. Attention memory grows with
/// `batch * seq_len^2` and every text is padded to the longest one: 128 texts at 512 tokens
/// peaked at 3,351 MB in one call versus 209 MB one at a time (see CHANGELOG 0.1.1).
pub const EMBED_SUB_BATCH_SIZE: usize = 1;

/// Default inactivity duration (`10 minutes`) used when idle session unloading is enabled
/// via [`ManagedEmbedderConfig`].
pub const DEFAULT_IDLE_UNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// Identifier returned by [`ManagedEmbedder::on_status_change`] to allow listener removal.
pub type StatusListenerId = u64;

type StatusCallback = Arc<dyn Fn(&EmbedderStatus) + Send + Sync>;

/// User-scoped model cache outside the repository: `FASTEMBED_CACHE_DIR` if set, else
/// `%LOCALAPPDATA%\SynapseMind\fastembed_cache` on Windows (removed with user data on
/// uninstall), the XDG/HOME cache on Unix, or the temp dir as a last resort.
pub fn default_model_cache_dir() -> PathBuf {
    default_model_cache_dir_from(
        std::env::var_os("FASTEMBED_CACHE_DIR"),
        std::env::var_os("LOCALAPPDATA"),
        std::env::var_os("USERPROFILE"),
        std::env::var_os("XDG_CACHE_HOME"),
        std::env::var_os("HOME"),
        std::env::temp_dir(),
    )
}

fn non_empty_os(val: Option<OsString>) -> Option<PathBuf> {
    val.filter(|s| !s.is_empty()).map(PathBuf::from)
}

fn default_model_cache_dir_from(
    fastembed_cache_dir: Option<OsString>,
    local_app_data: Option<OsString>,
    user_profile: Option<OsString>,
    xdg_cache_home: Option<OsString>,
    home: Option<OsString>,
    temp_dir: PathBuf,
) -> PathBuf {
    if let Some(explicit) = non_empty_os(fastembed_cache_dir) {
        return explicit;
    }

    #[cfg(windows)]
    {
        let _ = (&xdg_cache_home, &home);
        if let Some(local) = non_empty_os(local_app_data) {
            return local.join("SynapseMind").join("fastembed_cache");
        }
        if let Some(profile) = non_empty_os(user_profile) {
            return profile
                .join("AppData")
                .join("Local")
                .join("SynapseMind")
                .join("fastembed_cache");
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (&local_app_data, &user_profile);
        if let Some(xdg) = non_empty_os(xdg_cache_home) {
            return xdg.join("synapse-mind").join("fastembed_cache");
        }
        if let Some(home_dir) = non_empty_os(home) {
            return home_dir
                .join(".cache")
                .join("synapse-mind")
                .join("fastembed_cache");
        }
    }

    temp_dir.join("synapse-mind").join("fastembed_cache")
}

/// Produces fixed-dimensional dense text embeddings (`EMBEDDING_DIM` = 384).
pub trait Embedder: Send + Sync {
    /// Output vector dimensionality.
    fn dimension(&self) -> usize {
        EMBEDDING_DIM
    }

    /// Stable id of the vector space produced by [`Self::embed_batch`]. The store saves it in
    /// `store_meta` and re-embeds when it changes. Not-ready wrappers return `""`.
    fn model_id(&self) -> &str {
        MODEL_ID_DEFAULT_CUSTOM
    }

    /// Returns `true` when the embedding backend is loaded and ready to compute vectors.
    ///
    /// Stateful/lazy embedders (such as [`ManagedEmbedder`]) return `false` while models are
    /// downloading or after initialization failure so callers can continue operating in BM25 mode.
    fn is_ready(&self) -> bool {
        true
    }

    /// Generates one dense embedding vector per input string in order.
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;

    /// Convenience helper for embedding a single text input.
    fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        let mut vectors = self.embed_batch(&[text])?;
        if vectors.len() != 1 {
            return Err(CoreError::EmbeddingCountMismatch {
                expected: 1,
                actual: vectors.len(),
            });
        }
        vectors.pop().ok_or(CoreError::EmbeddingCountMismatch {
            expected: 1,
            actual: 0,
        })
    }
}

impl<T: Embedder + ?Sized> Embedder for Arc<T> {
    fn dimension(&self) -> usize {
        (**self).dimension()
    }

    fn model_id(&self) -> &str {
        (**self).model_id()
    }

    fn is_ready(&self) -> bool {
        (**self).is_ready()
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        (**self).embed_batch(texts)
    }

    fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        (**self).embed_one(text)
    }
}

impl<T: Embedder + ?Sized> Embedder for Box<T> {
    fn dimension(&self) -> usize {
        (**self).dimension()
    }

    fn model_id(&self) -> &str {
        (**self).model_id()
    }

    fn is_ready(&self) -> bool {
        (**self).is_ready()
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        (**self).embed_batch(texts)
    }

    fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        (**self).embed_one(text)
    }
}

/// Download and readiness lifecycle state for a local embedding backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedderStatus {
    /// Model files are not downloaded/initialized yet.
    NotDownloaded,
    /// Model files are currently downloading (`total` becomes `Some` once hub metadata is read).
    Downloading { bytes: u64, total: Option<u64> },
    /// Embedding model is loaded in memory and ready for vector operations.
    Ready,
    /// Initialization or download failed; the store continues serving BM25 + causality queries.
    Failed(String),
}

impl EmbedderStatus {
    /// Returns `true` when the backend is ready to produce embeddings.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Returns `true` when initialization or download failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Returns normalized download progress in `0.0..=1.0` when `Downloading` with a positive `total`.
    pub fn progress_fraction(&self) -> Option<f32> {
        match self {
            Self::Downloading {
                bytes,
                total: Some(total),
            } if *total > 0 => Some((*bytes as f64 / *total as f64).clamp(0.0, 1.0) as f32),
            _ => None,
        }
    }
}

type RepeatableReloader = Arc<dyn Fn() -> Result<Arc<dyn Embedder>> + Send + Sync>;

/// Lifecycle configuration for [`ManagedEmbedder`].
///
/// `Default::default()` leaves `idle_unload_timeout` as `None` (no automatic session
/// unloading), preserving the default v0.1.1 behavior.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagedEmbedderConfig {
    /// When `Some(timeout)`, drops the active embedding backend from memory after `timeout`
    /// without `embed_one`/`embed_batch` activity and transparently reloads it on the next
    /// embedding call (when initialized with a repeatable loader).
    pub idle_unload_timeout: Option<Duration>,
}

struct ReaperSignal {
    shutdown: Mutex<bool>,
    cv: Condvar,
}

impl ReaperSignal {
    fn new() -> Self {
        Self {
            shutdown: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    fn wake(&self) {
        self.cv.notify_all();
    }

    fn stop(&self) {
        if let Ok(mut guard) = self.shutdown.lock() {
            *guard = true;
        }
        self.cv.notify_all();
    }
}

struct ManagedEmbedderInner {
    config: ManagedEmbedderConfig,
    backend: RwLock<Option<Arc<dyn Embedder>>>,
    reloader: RwLock<Option<RepeatableReloader>>,
    model_id: OnceLock<String>,
    status_tx: watch::Sender<EmbedderStatus>,
    // Keep one receiver alive so `status_tx` never closes even before UI subscribes.
    _keep_alive_rx: watch::Receiver<EmbedderStatus>,
    listeners: Mutex<Vec<(StatusListenerId, StatusCallback)>>,
    next_listener_id: AtomicU64,
    init_mutex: Mutex<()>,
    last_emit: Mutex<Option<(Instant, u64)>>,
    epoch: Instant,
    last_activity_ms: AtomicU64,
    active_ops: AtomicUsize,
    idle_unload_count: AtomicU64,
    reload_count: AtomicU64,
    reaper_signal: Option<Arc<ReaperSignal>>,
}

impl Drop for ManagedEmbedderInner {
    fn drop(&mut self) {
        if let Some(ref signal) = self.reaper_signal {
            signal.stop();
        }
    }
}

struct ActiveOpGuard<'a> {
    inner: &'a ManagedEmbedderInner,
}

impl Drop for ActiveOpGuard<'_> {
    fn drop(&mut self) {
        self.inner.touch_activity();
        self.inner.active_ops.fetch_sub(1, Ordering::Release);
    }
}

impl ManagedEmbedderInner {
    fn elapsed_ms_since_epoch(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch_activity(&self) {
        self.last_activity_ms
            .store(self.elapsed_ms_since_epoch(), Ordering::Release);
    }

    fn wake_reaper(&self) {
        if let Some(ref signal) = self.reaper_signal {
            signal.wake();
        }
    }

    fn has_reloader(&self) -> bool {
        self.reloader.read().map(|g| g.is_some()).unwrap_or(false)
    }

    fn time_until_idle(&self, timeout: Duration) -> Option<Duration> {
        if !self.has_reloader() {
            return None;
        }
        let loaded = self.backend.read().map(|g| g.is_some()).unwrap_or(false);
        if !loaded {
            return None;
        }
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let last = self.last_activity_ms.load(Ordering::Acquire);
        let now = self.elapsed_ms_since_epoch();
        let elapsed_ms = now.saturating_sub(last);
        if elapsed_ms >= timeout_ms {
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_millis(timeout_ms - elapsed_ms))
        }
    }

    fn unload_if_idle_with_timeout(&self, timeout: Duration) -> bool {
        if self.active_ops.load(Ordering::Acquire) > 0 || !self.has_reloader() {
            return false;
        }
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let elapsed_ms = self
            .elapsed_ms_since_epoch()
            .saturating_sub(self.last_activity_ms.load(Ordering::Acquire));
        if elapsed_ms < timeout_ms {
            return false;
        }

        let Ok(_init_guard) = self.init_mutex.try_lock() else {
            return false;
        };
        if self.active_ops.load(Ordering::Acquire) > 0 || !self.has_reloader() {
            return false;
        }
        let elapsed_ms = self
            .elapsed_ms_since_epoch()
            .saturating_sub(self.last_activity_ms.load(Ordering::Acquire));
        if elapsed_ms < timeout_ms {
            return false;
        }

        let dropped = {
            let mut slot = self
                .backend
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slot.take().is_some()
        };
        if dropped {
            self.idle_unload_count.fetch_add(1, Ordering::Relaxed);
        }
        dropped
    }
}

fn spawn_idle_reaper(inner: &Arc<ManagedEmbedderInner>) {
    let Some(timeout) = inner.config.idle_unload_timeout else {
        return;
    };
    let Some(signal) = inner.reaper_signal.as_ref().map(Arc::clone) else {
        return;
    };
    let weak = Arc::downgrade(inner);
    let _ = std::thread::Builder::new()
        .name("synapse-embedder-idle-reaper".to_owned())
        .spawn(move || {
            let max_poll = Duration::from_secs(30);
            loop {
                let wait_for = {
                    let Some(strong) = weak.upgrade() else {
                        break;
                    };
                    match strong.time_until_idle(timeout) {
                        Some(remaining) if remaining.is_zero() => {
                            strong.unload_if_idle_with_timeout(timeout);
                            timeout.min(max_poll).max(Duration::from_millis(10))
                        }
                        Some(remaining) => remaining.min(max_poll).max(Duration::from_millis(10)),
                        None => timeout.min(max_poll).max(Duration::from_millis(10)),
                    }
                    // `strong` drops here so external callers dropping `ManagedEmbedder`
                    // trigger `ManagedEmbedderInner::drop` immediately without waiting.
                };

                let guard = signal
                    .shutdown
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *guard {
                    break;
                }
                let (guard, _) = signal
                    .cv
                    .wait_timeout(guard, wait_for)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *guard {
                    break;
                }
            }
        });
}

/// Thread-safe, subscribable [`Embedder`] wrapper supporting asynchronous model download/loading,
/// optional idle session unloading, and non-crashing BM25 fallback when unavailable.
#[derive(Clone)]
pub struct ManagedEmbedder {
    inner: Arc<ManagedEmbedderInner>,
}

impl Default for ManagedEmbedder {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagedEmbedder {
    /// Creates an uninitialized [`ManagedEmbedder`] in [`EmbedderStatus::NotDownloaded`] state
    /// with default configuration (idle unloading disabled).
    pub fn new() -> Self {
        Self::with_config(ManagedEmbedderConfig::default())
    }

    /// Creates an uninitialized [`ManagedEmbedder`] with explicit lifecycle configuration
    /// (such as `idle_unload_timeout`).
    pub fn with_config(config: ManagedEmbedderConfig) -> Self {
        let (status_tx, _keep_alive_rx) = watch::channel(EmbedderStatus::NotDownloaded);
        let reaper_signal = config
            .idle_unload_timeout
            .map(|_| Arc::new(ReaperSignal::new()));
        let inner = Arc::new(ManagedEmbedderInner {
            config,
            backend: RwLock::new(None),
            reloader: RwLock::new(None),
            model_id: OnceLock::new(),
            status_tx,
            _keep_alive_rx,
            listeners: Mutex::new(Vec::new()),
            next_listener_id: AtomicU64::new(1),
            init_mutex: Mutex::new(()),
            last_emit: Mutex::new(None),
            epoch: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            active_ops: AtomicUsize::new(0),
            idle_unload_count: AtomicU64::new(0),
            reload_count: AtomicU64::new(0),
            reaper_signal,
        });
        spawn_idle_reaper(&inner);
        Self { inner }
    }

    /// Creates an already-ready [`ManagedEmbedder`] wrapping an initialized backend.
    pub fn from_ready<E: Embedder + 'static>(embedder: E) -> Result<Self> {
        let actual = embedder.dimension();
        if actual != EMBEDDING_DIM {
            return Err(CoreError::InvalidEmbeddingDim {
                expected: EMBEDDING_DIM,
                actual,
            });
        }
        let model_id = embedder.model_id().trim().to_owned();
        if model_id.is_empty() {
            return Err(CoreError::Embedder(
                "embedder model_id must not be empty".to_owned(),
            ));
        }
        let model_id_lock = OnceLock::new();
        let _ = model_id_lock.set(model_id);
        let (status_tx, _keep_alive_rx) = watch::channel(EmbedderStatus::Ready);
        Ok(Self {
            inner: Arc::new(ManagedEmbedderInner {
                config: ManagedEmbedderConfig::default(),
                backend: RwLock::new(Some(Arc::new(embedder))),
                reloader: RwLock::new(None),
                model_id: model_id_lock,
                status_tx,
                _keep_alive_rx,
                listeners: Mutex::new(Vec::new()),
                next_listener_id: AtomicU64::new(1),
                init_mutex: Mutex::new(()),
                last_emit: Mutex::new(None),
                epoch: Instant::now(),
                last_activity_ms: AtomicU64::new(0),
                active_ops: AtomicUsize::new(0),
                idle_unload_count: AtomicU64::new(0),
                reload_count: AtomicU64::new(0),
                reaper_signal: None,
            }),
        })
    }

    /// Returns the lifecycle configuration used to construct this [`ManagedEmbedder`].
    pub fn config(&self) -> &ManagedEmbedderConfig {
        &self.inner.config
    }

    /// Returns the active backend's stable `model_id` when [`Embedder::is_ready`] is `true`,
    /// without waking or reloading an idle-unloaded ONNX session. Returns `None` while
    /// uninitialized, downloading, or failed.
    pub fn active_model_id(&self) -> Option<&str> {
        if !self.is_ready() {
            return None;
        }
        self.inner
            .model_id
            .get()
            .map(String::as_str)
            .filter(|id| !id.is_empty())
    }

    /// Returns `true` when an embedding session is currently resident in memory.
    ///
    /// Note: when idle unloading is active and a repeatable loader is registered, `is_loaded()`
    /// becomes `false` after unloading while [`Embedder::is_ready`] remains `true` so the next
    /// search or ingestion call transparently reloads the model from local cache.
    pub fn is_loaded(&self) -> bool {
        self.inner
            .backend
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// Returns how many times the active backend was dropped from memory via [`Self::unload`]
    /// or [`Self::unload_if_idle`].
    pub fn idle_unload_count(&self) -> u64 {
        self.inner.idle_unload_count.load(Ordering::Relaxed)
    }

    /// Returns how many times an unloaded backend was transparently reloaded on demand.
    pub fn reload_count(&self) -> u64 {
        self.inner.reload_count.load(Ordering::Relaxed)
    }

    /// Returns the current [`EmbedderStatus`] snapshot without blocking on `MemoryStore` locks.
    pub fn status(&self) -> EmbedderStatus {
        self.inner.status_tx.borrow().clone()
    }

    /// Subscribes to status updates via a `tokio::sync::watch::Receiver<EmbedderStatus>`.
    pub fn subscribe(&self) -> watch::Receiver<EmbedderStatus> {
        self.inner.status_tx.subscribe()
    }

    /// Registers a status listener callback, invoking it once immediately with the current status
    /// and on every subsequent transition. Returns a [`StatusListenerId`] for optional removal.
    pub fn on_status_change<F>(&self, callback: F) -> StatusListenerId
    where
        F: Fn(&EmbedderStatus) + Send + Sync + 'static,
    {
        let cb: StatusCallback = Arc::new(callback);
        let id = self.inner.next_listener_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut guard = self
                .inner
                .listeners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.push((id, Arc::clone(&cb)));
        }
        let current = self.status();
        cb(&current);
        id
    }

    /// Unregisters a callback previously registered via [`ManagedEmbedder::on_status_change`].
    pub fn remove_status_listener(&self, id: StatusListenerId) -> bool {
        let mut guard = self
            .inner
            .listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = guard.len();
        guard.retain(|(entry_id, _)| *entry_id != id);
        guard.len() != before
    }

    /// Unloads the resident backend from memory immediately, returning `true` if a loaded
    /// session was dropped.
    ///
    /// If a repeatable loader is registered, [`EmbedderStatus::Ready`] is preserved so the next
    /// `embed_one`/`embed_batch` call transparently reloads from local cache; otherwise status
    /// transitions back to [`EmbedderStatus::NotDownloaded`].
    pub fn unload(&self) -> bool {
        let _init_guard = self
            .inner
            .init_mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dropped = {
            let mut slot = self
                .inner
                .backend
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slot.take().is_some()
        };
        if dropped {
            self.inner.idle_unload_count.fetch_add(1, Ordering::Relaxed);
            if !self.inner.has_reloader() {
                self.set_status(EmbedderStatus::NotDownloaded);
            }
        }
        dropped
    }

    /// Drops the resident backend if `idle_unload_timeout` is configured, no embedding call is
    /// currently running, a repeatable loader is available, and inactivity has reached the timeout.
    pub fn unload_if_idle(&self) -> bool {
        let Some(timeout) = self.inner.config.idle_unload_timeout else {
            return false;
        };
        self.inner.unload_if_idle_with_timeout(timeout)
    }

    /// Initializes the underlying embedder synchronously using a custom loader closure that reports
    /// `(downloaded_bytes, total_bytes)`. If the loader fails, transitions to
    /// [`EmbedderStatus::Failed`] while leaving the handle usable in BM25-only mode.
    pub fn initialize_with<F, E>(&self, loader: F) -> Result<()>
    where
        F: FnOnce(&dyn Fn(u64, Option<u64>)) -> Result<E>,
        E: Embedder + 'static,
    {
        self.initialize_with_optional_reloader(loader, None)
    }

    /// Initializes the underlying embedder synchronously using a repeatable loader closure that can
    /// also transparently reload the session after idle unloading.
    pub fn initialize_repeatable_with<F, E>(&self, loader: F) -> Result<()>
    where
        F: Fn(&dyn Fn(u64, Option<u64>)) -> Result<E> + Send + Sync + 'static,
        E: Embedder + 'static,
    {
        let shared = Arc::new(loader);
        let reload_fn = Arc::clone(&shared);
        let reloader: RepeatableReloader = Arc::new(move || {
            let noop = |_: u64, _: Option<u64>| {};
            let embedder = reload_fn(&noop)?;
            Ok(Arc::new(embedder) as Arc<dyn Embedder>)
        });
        self.initialize_with_optional_reloader(move |progress| shared(progress), Some(reloader))
    }

    fn initialize_with_optional_reloader<F, E>(
        &self,
        loader: F,
        reloader: Option<RepeatableReloader>,
    ) -> Result<()>
    where
        F: FnOnce(&dyn Fn(u64, Option<u64>)) -> Result<E>,
        E: Embedder + 'static,
    {
        let _init_guard = self
            .inner
            .init_mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if self.is_loaded() {
            if let Some(r) = reloader {
                let mut slot = self
                    .inner
                    .reloader
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *slot = Some(r);
            }
            self.inner.touch_activity();
            self.set_status(EmbedderStatus::Ready);
            return Ok(());
        }

        if let Ok(mut last) = self.inner.last_emit.lock() {
            *last = None;
        }

        let progress_cb = |bytes: u64, total: Option<u64>| {
            self.emit_download_progress(bytes, total);
        };

        match loader(&progress_cb) {
            Ok(embedder) => {
                let actual = embedder.dimension();
                if actual != EMBEDDING_DIM {
                    let err = CoreError::InvalidEmbeddingDim {
                        expected: EMBEDDING_DIM,
                        actual,
                    };
                    self.set_status(EmbedderStatus::Failed(err.to_string()));
                    return Err(err);
                }
                let incoming_id = embedder.model_id().trim().to_owned();
                if incoming_id.is_empty() {
                    let err = CoreError::Embedder("embedder model_id must not be empty".to_owned());
                    self.set_status(EmbedderStatus::Failed(err.to_string()));
                    return Err(err);
                }
                if let Some(existing_id) = self.inner.model_id.get()
                    && existing_id != &incoming_id
                {
                    let err = CoreError::Embedder(format!(
                        "managed embedder already bound to model_id `{existing_id}`, cannot switch to `{incoming_id}`"
                    ));
                    self.set_status(EmbedderStatus::Failed(err.to_string()));
                    return Err(err);
                }
                // Record `model_id` before publishing `reloader`/`backend` or `Ready` so
                // concurrent observers never see `is_ready() == true` with an empty `model_id()`.
                let _ = self.inner.model_id.set(incoming_id);
                {
                    let mut reloader_slot = self
                        .inner
                        .reloader
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *reloader_slot = reloader;
                }
                {
                    let mut slot = self
                        .inner
                        .backend
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *slot = Some(Arc::new(embedder));
                }
                self.inner.touch_activity();
                self.inner.wake_reaper();
                self.set_status(EmbedderStatus::Ready);
                Ok(())
            }
            Err(err) => {
                self.set_status(EmbedderStatus::Failed(err.to_string()));
                Err(err)
            }
        }
    }

    /// Spawns background initialization on a dedicated OS thread without blocking startup.
    pub fn spawn_initialize_with<F, E>(
        &self,
        loader: F,
    ) -> std::io::Result<std::thread::JoinHandle<Result<()>>>
    where
        F: FnOnce(&dyn Fn(u64, Option<u64>)) -> Result<E> + Send + 'static,
        E: Embedder + 'static,
    {
        let handle = self.clone();
        std::thread::Builder::new()
            .name("synapse-embedder-init".to_owned())
            .spawn(move || handle.initialize_with(loader))
            .inspect_err(|err| {
                self.set_status(EmbedderStatus::Failed(format!(
                    "failed to spawn embedder initialization thread: {err}"
                )));
            })
    }

    /// Synchronously downloads (if needed) and loads [`DualEmbedder`] using
    /// [`default_model_cache_dir`], updating [`EmbedderStatus`] throughout.
    #[cfg(feature = "fastembed")]
    pub fn init_dual_default(&self) -> Result<()> {
        self.init_dual_with_cache(default_model_cache_dir())
    }

    /// Synchronously downloads (if needed) and loads [`DualEmbedder`] in `cache_dir`,
    /// updating [`EmbedderStatus`] throughout.
    #[cfg(feature = "fastembed")]
    pub fn init_dual_with_cache(&self, cache_dir: impl Into<PathBuf>) -> Result<()> {
        let config = fastembed_impl::FastEmbedConfig {
            cache_dir: cache_dir.into(),
            ..fastembed_impl::FastEmbedConfig::default()
        };
        self.init_fastembed(config)
    }

    /// Spawns non-blocking background initialization of [`DualEmbedder`] using
    /// [`default_model_cache_dir`].
    #[cfg(feature = "fastembed")]
    pub fn spawn_dual_default(&self) -> std::io::Result<std::thread::JoinHandle<Result<()>>> {
        self.spawn_dual_with_cache(default_model_cache_dir())
    }

    /// Spawns non-blocking background initialization of [`DualEmbedder`] in `cache_dir`.
    #[cfg(feature = "fastembed")]
    pub fn spawn_dual_with_cache(
        &self,
        cache_dir: impl Into<PathBuf>,
    ) -> std::io::Result<std::thread::JoinHandle<Result<()>>> {
        let config = fastembed_impl::FastEmbedConfig {
            cache_dir: cache_dir.into(),
            ..fastembed_impl::FastEmbedConfig::default()
        };
        self.spawn_fastembed(config)
    }

    /// Synchronously downloads (if needed) and loads a configured `fastembed` backend
    /// (`DualFp32QueryInt8Batch`, `SingleInt8`, or `SingleFp32`), registering a repeatable
    /// local reloader so idle unloading can transparently reload from `config.cache_dir`.
    #[cfg(feature = "fastembed")]
    pub fn init_fastembed(&self, config: fastembed_impl::FastEmbedConfig) -> Result<()> {
        let reload_cfg = config.clone();
        let reloader: RepeatableReloader = Arc::new(move || {
            let backend = fastembed_impl::FastEmbedBackend::try_new(&reload_cfg)?;
            Ok(Arc::new(backend) as Arc<dyn Embedder>)
        });
        self.initialize_with_optional_reloader(
            move |progress| fastembed_impl::download_and_load_with_config(&config, None, progress),
            Some(reloader),
        )
    }

    /// Spawns non-blocking background initialization of a configured `fastembed` backend
    /// (`DualFp32QueryInt8Batch`, `SingleInt8`, or `SingleFp32`).
    #[cfg(feature = "fastembed")]
    pub fn spawn_fastembed(
        &self,
        config: fastembed_impl::FastEmbedConfig,
    ) -> std::io::Result<std::thread::JoinHandle<Result<()>>> {
        let handle = self.clone();
        std::thread::Builder::new()
            .name("synapse-embedder-init".to_owned())
            .spawn(move || handle.init_fastembed(config))
            .inspect_err(|err| {
                self.set_status(EmbedderStatus::Failed(format!(
                    "failed to spawn embedder initialization thread: {err}"
                )));
            })
    }

    fn set_status(&self, status: EmbedderStatus) {
        if self.inner.status_tx.borrow().eq(&status) {
            return;
        }
        let _ = self.inner.status_tx.send(status.clone());
        let callbacks: Vec<StatusCallback> = {
            let guard = self
                .inner
                .listeners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.iter().map(|(_, cb)| Arc::clone(cb)).collect()
        };
        for cb in callbacks {
            cb(&status);
        }
    }

    fn emit_download_progress(&self, bytes: u64, total: Option<u64>) {
        const MIN_STEP_BYTES: u64 = 64 * 1024;
        const MIN_INTERVAL: Duration = Duration::from_millis(50);

        let now = Instant::now();
        let is_boundary = bytes == 0 || total.is_some_and(|t| bytes >= t);
        let should_emit = {
            let mut guard = self
                .inner
                .last_emit
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match *guard {
                None => {
                    *guard = Some((now, bytes));
                    true
                }
                Some((last_at, last_bytes)) => {
                    if is_boundary
                        || bytes.saturating_sub(last_bytes) >= MIN_STEP_BYTES
                        || now.duration_since(last_at) >= MIN_INTERVAL
                    {
                        *guard = Some((now, bytes));
                        true
                    } else {
                        false
                    }
                }
            }
        };

        if should_emit {
            self.set_status(EmbedderStatus::Downloading { bytes, total });
        }
    }

    fn unavailable_error(&self) -> CoreError {
        let reason = match self.status() {
            EmbedderStatus::NotDownloaded => "embedding model not downloaded yet".to_owned(),
            EmbedderStatus::Downloading { bytes, total } => match total {
                Some(t) => format!("embedding model downloading ({bytes}/{t} bytes)"),
                None => format!("embedding model downloading ({bytes} bytes)"),
            },
            EmbedderStatus::Failed(msg) => format!("embedding model failed to load: {msg}"),
            EmbedderStatus::Ready => "embedding backend unavailable".to_owned(),
        };
        CoreError::EmbedderUnavailable(reason)
    }

    fn acquire_backend(&self) -> Result<(Arc<dyn Embedder>, ActiveOpGuard<'_>)> {
        {
            let guard =
                self.inner.backend.read().map_err(|_| {
                    CoreError::Embedder("managed embedder lock poisoned".to_owned())
                })?;
            if let Some(ref arc) = *guard {
                self.inner.active_ops.fetch_add(1, Ordering::AcqRel);
                self.inner.touch_activity();
                return Ok((Arc::clone(arc), ActiveOpGuard { inner: &self.inner }));
            }
        }

        if !self.status().is_ready() || !self.inner.has_reloader() {
            return Err(self.unavailable_error());
        }

        let _init_guard =
            self.inner.init_mutex.lock().map_err(|_| {
                CoreError::Embedder("managed embedder init lock poisoned".to_owned())
            })?;

        {
            let guard =
                self.inner.backend.read().map_err(|_| {
                    CoreError::Embedder("managed embedder lock poisoned".to_owned())
                })?;
            if let Some(ref arc) = *guard {
                self.inner.active_ops.fetch_add(1, Ordering::AcqRel);
                self.inner.touch_activity();
                return Ok((Arc::clone(arc), ActiveOpGuard { inner: &self.inner }));
            }
        }

        let reloader = {
            let guard =
                self.inner.reloader.read().map_err(|_| {
                    CoreError::Embedder("managed embedder lock poisoned".to_owned())
                })?;
            guard.as_ref().map(Arc::clone)
        };

        let Some(reloader) = reloader else {
            return Err(self.unavailable_error());
        };
        if !self.status().is_ready() {
            return Err(self.unavailable_error());
        }

        match reloader() {
            Ok(new_backend) => {
                let actual = new_backend.dimension();
                if actual != EMBEDDING_DIM {
                    let err = CoreError::InvalidEmbeddingDim {
                        expected: EMBEDDING_DIM,
                        actual,
                    };
                    self.set_status(EmbedderStatus::Failed(err.to_string()));
                    return Err(CoreError::EmbedderUnavailable(err.to_string()));
                }
                let reloaded_id = new_backend.model_id().trim().to_owned();
                if reloaded_id.is_empty() {
                    let err = CoreError::Embedder("embedder model_id must not be empty".to_owned());
                    self.set_status(EmbedderStatus::Failed(err.to_string()));
                    return Err(CoreError::EmbedderUnavailable(err.to_string()));
                }
                if let Some(existing_id) = self.inner.model_id.get()
                    && existing_id != &reloaded_id
                {
                    let err = CoreError::Embedder(format!(
                        "reloaded backend model_id `{reloaded_id}` does not match `{existing_id}`"
                    ));
                    self.set_status(EmbedderStatus::Failed(err.to_string()));
                    return Err(CoreError::EmbedderUnavailable(err.to_string()));
                }
                let _ = self.inner.model_id.set(reloaded_id);
                {
                    let mut slot = self.inner.backend.write().map_err(|_| {
                        CoreError::Embedder("managed embedder lock poisoned".to_owned())
                    })?;
                    *slot = Some(Arc::clone(&new_backend));
                }
                self.inner.reload_count.fetch_add(1, Ordering::Relaxed);
                self.inner.active_ops.fetch_add(1, Ordering::AcqRel);
                self.inner.touch_activity();
                self.inner.wake_reaper();
                Ok((new_backend, ActiveOpGuard { inner: &self.inner }))
            }
            Err(err) => {
                self.set_status(EmbedderStatus::Failed(err.to_string()));
                Err(CoreError::EmbedderUnavailable(err.to_string()))
            }
        }
    }
}

impl Embedder for ManagedEmbedder {
    fn model_id(&self) -> &str {
        self.active_model_id().unwrap_or("")
    }

    fn is_ready(&self) -> bool {
        if self.is_loaded() {
            return true;
        }
        self.status().is_ready() && self.inner.has_reloader()
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let (backend, _op_guard) = self.acquire_backend()?;
        backend.embed_batch(texts)
    }

    fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        let (backend, _op_guard) = self.acquire_backend()?;
        backend.embed_one(text)
    }
}

/// Validates dimensionality, finiteness, and non-zero L2 norm before cosine indexing.
pub(crate) fn validate_embedding(vec: &[f32], expected_dim: usize) -> Result<()> {
    if vec.len() != expected_dim {
        return Err(CoreError::InvalidEmbeddingDim {
            expected: expected_dim,
            actual: vec.len(),
        });
    }
    let mut norm_sq = 0.0_f64;
    for &val in vec {
        if !val.is_finite() {
            return Err(CoreError::InvalidEmbeddingVector(
                "embedding contains NaN or infinite component",
            ));
        }
        let v = f64::from(val);
        norm_sq += v * v;
    }
    if norm_sq <= 0.0 {
        return Err(CoreError::InvalidEmbeddingVector(
            "embedding must have non-zero norm for cosine distance",
        ));
    }
    Ok(())
}

/// Encodes `f32` embedding components as little-endian bytes for `sqlite-vec`.
pub(crate) fn f32_slice_to_le_bytes(vec: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(vec));
    for &val in vec {
        bytes.extend_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// `fastembed-rs` implementation backed by `BAAI/bge-small-en-v1.5` (ONNX Runtime).
#[cfg(feature = "fastembed")]
pub mod fastembed_impl {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use fastembed::{EmbeddingModel, TextEmbedding, TextInitOptions};
    use hf_hub::api::Progress;
    use hf_hub::api::sync::ApiBuilder;

    use super::{
        DEFAULT_BATCH_MAX_TOKENS, DEFAULT_QUERY_MAX_TOKENS, EMBEDDING_DIM, Embedder,
        validate_embedding,
    };
    use crate::{CoreError, Result};

    /// Required Hugging Face files per `fastembed::TextEmbedding` model.
    fn model_required_files(model: &EmbeddingModel) -> Result<(String, Vec<String>)> {
        let info =
            TextEmbedding::get_model_info(model).map_err(|e| CoreError::Embedder(e.to_string()))?;
        let mut files = Vec::with_capacity(5 + info.additional_files.len());
        files.push(info.model_file.clone());
        files.extend(info.additional_files.iter().cloned());
        files.push("tokenizer.json".to_owned());
        files.push("config.json".to_owned());
        files.push("special_tokens_map.json".to_owned());
        files.push("tokenizer_config.json".to_owned());
        Ok((info.model_code.clone(), files))
    }

    fn effective_hf_cache_dir(cache_dir: &Path) -> PathBuf {
        std::env::var_os("HF_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| cache_dir.to_path_buf())
    }

    fn resolve_hf_endpoint(override_endpoint: Option<&str>) -> String {
        override_endpoint
            .map(|e| e.trim_end_matches('/').to_owned())
            .filter(|e| !e.is_empty())
            .or_else(|| {
                std::env::var("HF_ENDPOINT")
                    .ok()
                    .map(|e| e.trim_end_matches('/').to_owned())
                    .filter(|e| !e.is_empty())
            })
            .unwrap_or_else(|| "https://huggingface.co".to_owned())
    }

    fn resolve_hf_token(hf_cache_dir: &Path) -> Option<String> {
        if let Some(token) = std::env::var("HF_TOKEN")
            .ok()
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
        {
            return Some(token);
        }
        let hub_token = hf_hub::Cache::new(hf_cache_dir.join("hub")).token();
        if hub_token.is_some() {
            return hub_token;
        }
        let has_home =
            std::env::var_os("HOME").is_some() || std::env::var_os("USERPROFILE").is_some();
        if has_home {
            return hf_hub::Cache::default().token();
        }
        None
    }

    /// Session layout for local `fastembed-rs` embedding.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum FastEmbedMode {
        /// Default v0.1.1 dual-session layout: FP32 `BGESmallENV15` (64 tokens) for
        /// single queries and INT8 `BGESmallENV15Q` (512 tokens) for batch indexing.
        #[default]
        DualFp32QueryInt8Batch,
        /// Single INT8 ONNX session (`BGESmallENV15Q`, 512 tokens) shared by both single
        /// queries and batch indexing. Reduces resident RAM and uses one identical
        /// quantized vector space for queries and documents.
        SingleInt8,
        /// Single FP32 ONNX session (`BGESmallENV15`, 512 tokens) shared by both single
        /// queries and batch indexing.
        SingleFp32,
    }

    impl FastEmbedMode {
        /// Returns the stable identifier of the model that produces stored document vectors
        /// in this mode.
        ///
        /// Both [`Self::DualFp32QueryInt8Batch`] and [`Self::SingleInt8`] index documents with
        /// `BGESmallENV15Q` (`"bge-small-en-v1.5-q-int8"`), whereas [`Self::SingleFp32`] indexes
        /// with `BGESmallENV15` (`"bge-small-en-v1.5-fp32"`).
        pub const fn index_model_id(self) -> &'static str {
            match self {
                Self::DualFp32QueryInt8Batch | Self::SingleInt8 => {
                    super::MODEL_ID_BGE_SMALL_EN_V15_Q_INT8
                }
                Self::SingleFp32 => super::MODEL_ID_BGE_SMALL_EN_V15_FP32,
            }
        }
    }

    /// Returns the stable vector-space identifier for a `fastembed::EmbeddingModel`.
    pub fn fastembed_model_id(model: &EmbeddingModel) -> String {
        match model {
            EmbeddingModel::BGESmallENV15 => super::MODEL_ID_BGE_SMALL_EN_V15_FP32.to_owned(),
            EmbeddingModel::BGESmallENV15Q => super::MODEL_ID_BGE_SMALL_EN_V15_Q_INT8.to_owned(),
            other => format!("fastembed:{other}"),
        }
    }

    /// Configuration for initializing a `fastembed-rs` embedding backend.
    ///
    /// `Default::default()` matches v0.1.1 behavior (`DualFp32QueryInt8Batch`,
    /// `query_max_tokens = 64`, `batch_max_tokens = 512`, `intra_threads = None`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FastEmbedConfig {
        pub mode: FastEmbedMode,
        pub cache_dir: PathBuf,
        pub query_max_tokens: usize,
        pub batch_max_tokens: usize,
        /// Optional ONNX Runtime intra-op thread count (`None` = fastembed/ORT default).
        pub intra_threads: Option<usize>,
        /// Optional ONNX Runtime `SessionBuilder::with_config_entry` key/value pairs.
        pub session_config: Vec<(String, String)>,
    }

    impl Default for FastEmbedConfig {
        fn default() -> Self {
            Self {
                mode: FastEmbedMode::default(),
                cache_dir: super::default_model_cache_dir(),
                query_max_tokens: DEFAULT_QUERY_MAX_TOKENS,
                batch_max_tokens: DEFAULT_BATCH_MAX_TOKENS,
                intra_threads: None,
                session_config: Vec::new(),
            }
        }
    }

    fn models_for_mode(mode: FastEmbedMode) -> &'static [EmbeddingModel] {
        match mode {
            FastEmbedMode::DualFp32QueryInt8Batch => &[
                EmbeddingModel::BGESmallENV15,
                EmbeddingModel::BGESmallENV15Q,
            ],
            FastEmbedMode::SingleInt8 => &[EmbeddingModel::BGESmallENV15Q],
            FastEmbedMode::SingleFp32 => &[EmbeddingModel::BGESmallENV15],
        }
    }

    /// Returns `true` when all model and tokenizer files required for `mode` are already
    /// cached inside `cache_dir` (or `HF_HOME` if set).
    pub fn is_model_cached(cache_dir: &Path, mode: FastEmbedMode) -> Result<bool> {
        let effective = effective_hf_cache_dir(cache_dir);
        let cache = hf_hub::Cache::new(effective);
        for model in models_for_mode(mode) {
            let (model_code, files) = model_required_files(model)?;
            let repo = cache.model(model_code);
            if files.iter().any(|file| repo.get(file).is_none()) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Returns `true` when both `BGESmallENV15` (query) and `BGESmallENV15Q` (batch)
    /// model and tokenizer files are already cached inside `cache_dir` (or `HF_HOME` if set).
    pub fn is_dual_model_cached(cache_dir: &Path) -> Result<bool> {
        is_model_cached(cache_dir, FastEmbedMode::DualFp32QueryInt8Batch)
    }

    struct HfProgressAdapter<'a> {
        completed_bytes: u64,
        current_file_bytes: u64,
        total_bytes: u64,
        callback: &'a dyn Fn(u64, Option<u64>),
    }

    impl Progress for HfProgressAdapter<'_> {
        fn init(&mut self, _size: usize, _filename: &str) {
            self.current_file_bytes = 0;
            (self.callback)(self.completed_bytes, Some(self.total_bytes));
        }

        fn update(&mut self, size: usize) {
            self.current_file_bytes = self.current_file_bytes.saturating_add(size as u64);
            let combined = self
                .completed_bytes
                .saturating_add(self.current_file_bytes)
                .min(self.total_bytes);
            (self.callback)(combined, Some(self.total_bytes));
        }

        fn finish(&mut self) {
            let combined = self
                .completed_bytes
                .saturating_add(self.current_file_bytes)
                .min(self.total_bytes);
            (self.callback)(combined, Some(self.total_bytes));
        }
    }

    pub(crate) fn download_and_load_with_config(
        config: &FastEmbedConfig,
        endpoint_override: Option<&str>,
        progress: &dyn Fn(u64, Option<u64>),
    ) -> Result<FastEmbedBackend> {
        let effective_cache = effective_hf_cache_dir(&config.cache_dir);
        std::fs::create_dir_all(&effective_cache).map_err(|e| {
            CoreError::Embedder(format!(
                "failed to create fastembed cache directory `{}`: {e}",
                effective_cache.display()
            ))
        })?;

        let cache = hf_hub::Cache::new(effective_cache.clone());
        let mut missing: Vec<(String, String)> = Vec::new();
        for model in models_for_mode(config.mode) {
            let (model_code, files) = model_required_files(model)?;
            let cache_repo = cache.model(model_code.clone());
            for file in files {
                if cache_repo.get(&file).is_none() {
                    missing.push((model_code.clone(), file));
                }
            }
        }

        if !missing.is_empty() {
            progress(0, None);

            let endpoint = resolve_hf_endpoint(endpoint_override);
            let token = resolve_hf_token(&effective_cache);
            let api = ApiBuilder::from_cache(cache)
                .with_endpoint(endpoint)
                .with_token(token)
                .with_progress(false)
                .build()
                .map_err(|e| CoreError::Embedder(format!("HuggingFace API init failed: {e}")))?;

            let mut total_bytes: u64 = 0;
            let mut missing_with_sizes: Vec<(String, String, u64)> =
                Vec::with_capacity(missing.len());
            for (model_code, file) in missing {
                let repo = api.model(model_code.clone());
                let meta = api.metadata(&repo.url(&file)).map_err(|e| {
                    CoreError::Embedder(format!(
                        "failed to fetch metadata for `{model_code}/{file}`: {e}"
                    ))
                })?;
                let file_size = u64::try_from(meta.size()).unwrap_or(0);
                total_bytes = total_bytes.saturating_add(file_size);
                missing_with_sizes.push((model_code, file, file_size));
            }

            progress(0, Some(total_bytes));

            let mut completed_bytes: u64 = 0;
            for (model_code, file, file_size) in missing_with_sizes {
                let repo = api.model(model_code.clone());
                let adapter = HfProgressAdapter {
                    completed_bytes,
                    current_file_bytes: 0,
                    total_bytes,
                    callback: progress,
                };
                repo.download_with_progress(&file, adapter).map_err(|e| {
                    CoreError::Embedder(format!(
                        "failed to download model file `{model_code}/{file}`: {e}"
                    ))
                })?;
                completed_bytes = completed_bytes.saturating_add(file_size);
                progress(completed_bytes.min(total_bytes), Some(total_bytes));
            }
        }

        FastEmbedBackend::try_new(config)
    }

    #[cfg(test)]
    pub(crate) fn download_and_load_dual(
        cache_dir: &Path,
        endpoint_override: Option<&str>,
        progress: &dyn Fn(u64, Option<u64>),
    ) -> Result<DualEmbedder> {
        let config = FastEmbedConfig {
            mode: FastEmbedMode::DualFp32QueryInt8Batch,
            cache_dir: cache_dir.to_path_buf(),
            ..FastEmbedConfig::default()
        };
        match download_and_load_with_config(&config, endpoint_override, progress)? {
            FastEmbedBackend::Dual(dual) => Ok(*dual),
            FastEmbedBackend::Single(_) => Err(CoreError::Embedder(
                "unexpected single backend when dual mode requested".to_owned(),
            )),
        }
    }

    /// Local CPU embedder powered by `fastembed::TextEmbedding` (`BGESmallENV15` or `BGESmallENV15Q`).
    pub struct FastEmbedder {
        model: Mutex<TextEmbedding>,
        model_id: String,
    }

    impl FastEmbedder {
        /// Returns the user-level model cache directory used by [`FastEmbedder::try_new_default`]
        /// (always outside the repository unless `FASTEMBED_CACHE_DIR` / `HF_HOME` points inside).
        pub fn default_cache_dir() -> PathBuf {
            super::default_model_cache_dir()
        }

        /// Initializes FP32 `BAAI/bge-small-en-v1.5` using [`FastEmbedder::default_cache_dir`].
        pub fn try_new_default() -> Result<Self> {
            Self::try_new_with_cache(Self::default_cache_dir())
        }

        /// Initializes FP32 `BAAI/bge-small-en-v1.5` with an explicit local model cache directory.
        pub fn try_new_with_cache(cache_dir: impl Into<PathBuf>) -> Result<Self> {
            Self::try_new_model_with_cache(EmbeddingModel::BGESmallENV15, cache_dir)
        }

        /// Initializes a single INT8 `BGESmallENV15Q` session (`512` token window) using
        /// [`FastEmbedder::default_cache_dir`] for both queries and batch indexing.
        pub fn try_new_int8_default() -> Result<Self> {
            Self::try_new_int8_with_cache(Self::default_cache_dir())
        }

        /// Initializes a single INT8 `BGESmallENV15Q` session (`512` token window) in `cache_dir`.
        pub fn try_new_int8_with_cache(cache_dir: impl Into<PathBuf>) -> Result<Self> {
            Self::try_new_model_with_cache(EmbeddingModel::BGESmallENV15Q, cache_dir)
        }

        /// Initializes a specific `fastembed::EmbeddingModel` using an explicit local cache directory
        /// and the full 512-token sequence window ([`DEFAULT_BATCH_MAX_TOKENS`]).
        pub fn try_new_model_with_cache(
            model: EmbeddingModel,
            cache_dir: impl Into<PathBuf>,
        ) -> Result<Self> {
            Self::try_new_model_with_cache_and_max_length(
                model,
                cache_dir,
                DEFAULT_BATCH_MAX_TOKENS,
            )
        }

        /// Initializes a specific `fastembed::EmbeddingModel` using an explicit local cache directory
        /// and custom tokenizer truncation length (`TextInitOptions::with_max_length`).
        pub fn try_new_model_with_cache_and_max_length(
            model: EmbeddingModel,
            cache_dir: impl Into<PathBuf>,
            max_length: usize,
        ) -> Result<Self> {
            Self::try_new_model_with_options(model, cache_dir, max_length, None, &[])
        }

        pub(crate) fn try_new_model_with_options(
            model: EmbeddingModel,
            cache_dir: impl Into<PathBuf>,
            max_length: usize,
            intra_threads: Option<usize>,
            session_config: &[(String, String)],
        ) -> Result<Self> {
            let cache_dir = cache_dir.into();
            std::fs::create_dir_all(&cache_dir).map_err(|e| {
                CoreError::Embedder(format!(
                    "failed to create fastembed cache directory `{}`: {e}",
                    cache_dir.display()
                ))
            })?;
            let mut options = TextInitOptions::new(model)
                .with_cache_dir(cache_dir)
                .with_max_length(max_length)
                .with_show_download_progress(false);
            if let Some(threads) = intra_threads {
                options = options.with_intra_threads(threads);
            }
            for (key, value) in session_config {
                options = options.with_session_config(key, value);
            }
            Self::try_new(options)
        }

        /// Initializes `FastEmbedder` from custom `fastembed::TextInitOptions`.
        pub fn try_new(options: TextInitOptions) -> Result<Self> {
            let model_id = fastembed_model_id(&options.model_name);
            let model =
                TextEmbedding::try_new(options).map_err(|e| CoreError::Embedder(e.to_string()))?;
            Ok(Self {
                model: Mutex::new(model),
                model_id,
            })
        }
    }

    impl Embedder for FastEmbedder {
        fn model_id(&self) -> &str {
            &self.model_id
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            if texts.is_empty() {
                return Ok(Vec::new());
            }
            let mut guard = self
                .model
                .lock()
                .map_err(|_| CoreError::Embedder("fastembed mutex poisoned".to_owned()))?;
            // Sub-batch to bound peak attention memory (see `EMBED_SUB_BATCH_SIZE`).
            let vectors = guard
                .embed(texts, Some(super::EMBED_SUB_BATCH_SIZE))
                .map_err(|e| CoreError::Embedder(e.to_string()))?;
            if vectors.len() != texts.len() {
                return Err(CoreError::EmbeddingCountMismatch {
                    expected: texts.len(),
                    actual: vectors.len(),
                });
            }
            for vec in &vectors {
                validate_embedding(vec, EMBEDDING_DIM)?;
            }
            Ok(vectors)
        }
    }

    /// Dual `fastembed-rs` embedder routing single queries (`embed_one`) to FP32
    /// (`BGESmallENV15`, capped at [`DEFAULT_QUERY_MAX_TOKENS`]) and batch indexing
    /// (`embed_batch`) to INT8 (`BGESmallENV15Q`, full [`DEFAULT_BATCH_MAX_TOKENS`] = 512).
    ///
    /// Both models emit 384-dimensional cosine-compatible vectors in the same embedding space.
    pub struct DualEmbedder {
        query: FastEmbedder,
        batch: FastEmbedder,
    }

    impl DualEmbedder {
        /// Returns the user-level model cache directory used by [`DualEmbedder::try_new_default`].
        pub fn default_cache_dir() -> PathBuf {
            super::default_model_cache_dir()
        }

        /// Initializes FP32 `BGESmallENV15` (queries) and INT8 `BGESmallENV15Q` (batches)
        /// using [`DualEmbedder::default_cache_dir`].
        pub fn try_new_default() -> Result<Self> {
            Self::try_new_with_cache(Self::default_cache_dir())
        }

        /// Initializes both models using an explicit local model cache directory, applying
        /// [`DEFAULT_QUERY_MAX_TOKENS`] on the query session and [`DEFAULT_BATCH_MAX_TOKENS`] (512)
        /// on the batch indexing session.
        pub fn try_new_with_cache(cache_dir: impl Into<PathBuf>) -> Result<Self> {
            Self::try_new_with_cache_and_query_max_tokens(cache_dir, DEFAULT_QUERY_MAX_TOKENS)
        }

        /// Initializes both models using an explicit cache directory and custom query token limit
        /// (`TextInitOptions::with_max_length` for `BGESmallENV15` only; batch `BGESmallENV15Q`
        /// remains at 512 tokens).
        pub fn try_new_with_cache_and_query_max_tokens(
            cache_dir: impl Into<PathBuf>,
            query_max_tokens: usize,
        ) -> Result<Self> {
            let cache_dir = cache_dir.into();
            let query = FastEmbedder::try_new_model_with_cache_and_max_length(
                EmbeddingModel::BGESmallENV15,
                cache_dir.clone(),
                query_max_tokens,
            )?;
            let batch = FastEmbedder::try_new_model_with_cache_and_max_length(
                EmbeddingModel::BGESmallENV15Q,
                cache_dir,
                DEFAULT_BATCH_MAX_TOKENS,
            )?;
            Ok(Self { query, batch })
        }

        /// Initializes `DualEmbedder` from explicit query (FP32) and batch (INT8) options.
        pub fn try_new(
            query_options: TextInitOptions,
            batch_options: TextInitOptions,
        ) -> Result<Self> {
            let query = FastEmbedder::try_new(query_options)?;
            let batch = FastEmbedder::try_new(batch_options)?;
            Ok(Self { query, batch })
        }

        /// Returns a reference to the single-query FP32 embedder (`BGESmallENV15`).
        pub fn query_embedder(&self) -> &FastEmbedder {
            &self.query
        }

        /// Returns a reference to the batch-indexing INT8 embedder (`BGESmallENV15Q`).
        pub fn batch_embedder(&self) -> &FastEmbedder {
            &self.batch
        }
    }

    impl Embedder for DualEmbedder {
        fn model_id(&self) -> &str {
            // Stored `event_vectors` are produced by `embed_batch` (`self.batch`, INT8).
            self.batch.model_id()
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.batch.embed_batch(texts)
        }

        fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
            self.query.embed_one(text)
        }
    }

    /// Configured `fastembed-rs` backend supporting either [`DualEmbedder`] (default) or a
    /// single-session INT8/FP32 [`FastEmbedder`].
    pub enum FastEmbedBackend {
        Dual(Box<DualEmbedder>),
        Single(Box<FastEmbedder>),
    }

    impl FastEmbedBackend {
        /// Initializes a backend according to `config`.
        pub fn try_new(config: &FastEmbedConfig) -> Result<Self> {
            match config.mode {
                FastEmbedMode::DualFp32QueryInt8Batch => {
                    let query = FastEmbedder::try_new_model_with_options(
                        EmbeddingModel::BGESmallENV15,
                        config.cache_dir.clone(),
                        config.query_max_tokens,
                        config.intra_threads,
                        &config.session_config,
                    )?;
                    let batch = FastEmbedder::try_new_model_with_options(
                        EmbeddingModel::BGESmallENV15Q,
                        config.cache_dir.clone(),
                        config.batch_max_tokens,
                        config.intra_threads,
                        &config.session_config,
                    )?;
                    Ok(Self::Dual(Box::new(DualEmbedder { query, batch })))
                }
                FastEmbedMode::SingleInt8 => Ok(Self::Single(Box::new(
                    FastEmbedder::try_new_model_with_options(
                        EmbeddingModel::BGESmallENV15Q,
                        config.cache_dir.clone(),
                        config.batch_max_tokens,
                        config.intra_threads,
                        &config.session_config,
                    )?,
                ))),
                FastEmbedMode::SingleFp32 => Ok(Self::Single(Box::new(
                    FastEmbedder::try_new_model_with_options(
                        EmbeddingModel::BGESmallENV15,
                        config.cache_dir.clone(),
                        config.batch_max_tokens,
                        config.intra_threads,
                        &config.session_config,
                    )?,
                ))),
            }
        }

        /// Initializes the default dual-session backend (`DualFp32QueryInt8Batch`).
        pub fn try_new_default() -> Result<Self> {
            Self::try_new(&FastEmbedConfig::default())
        }

        /// Initializes a single INT8 (`BGESmallENV15Q`) backend using [`default_model_cache_dir`].
        pub fn try_new_single_int8_default() -> Result<Self> {
            Self::try_new(&FastEmbedConfig {
                mode: FastEmbedMode::SingleInt8,
                ..FastEmbedConfig::default()
            })
        }

        /// Initializes a single INT8 (`BGESmallENV15Q`) backend using an explicit `cache_dir`.
        pub fn try_new_single_int8_with_cache(cache_dir: impl Into<PathBuf>) -> Result<Self> {
            Self::try_new(&FastEmbedConfig {
                mode: FastEmbedMode::SingleInt8,
                cache_dir: cache_dir.into(),
                ..FastEmbedConfig::default()
            })
        }

        /// Returns `true` when this backend runs in dual-session (`DualFp32QueryInt8Batch`) mode.
        pub fn is_dual(&self) -> bool {
            matches!(self, Self::Dual(_))
        }
    }

    impl Embedder for FastEmbedBackend {
        fn dimension(&self) -> usize {
            match self {
                Self::Dual(dual) => dual.dimension(),
                Self::Single(single) => single.dimension(),
            }
        }

        fn model_id(&self) -> &str {
            match self {
                Self::Dual(dual) => dual.model_id(),
                Self::Single(single) => single.model_id(),
            }
        }

        fn is_ready(&self) -> bool {
            match self {
                Self::Dual(dual) => dual.is_ready(),
                Self::Single(single) => single.is_ready(),
            }
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            match self {
                Self::Dual(dual) => dual.embed_batch(texts),
                Self::Single(single) => single.embed_batch(texts),
            }
        }

        fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
            match self {
                Self::Dual(dual) => dual.embed_one(text),
                Self::Single(single) => single.embed_one(text),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_model_cache_dir_resolves_outside_repository() {
        let dir = default_model_cache_dir();
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = crate_dir
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        assert!(
            dir.is_absolute(),
            "cache dir must be absolute, got: {}",
            dir.display()
        );
        assert!(
            !dir.starts_with(repo_root),
            "cache dir `{}` must be outside repository `{}`",
            dir.display(),
            repo_root.display()
        );
    }

    #[test]
    fn default_model_cache_dir_precedence_and_fallbacks() {
        let temp = PathBuf::from("/tmp/fallback");
        let explicit = default_model_cache_dir_from(
            Some(OsString::from("D:\\models\\fe")),
            Some(OsString::from("C:\\Users\\u\\AppData\\Local")),
            None,
            None,
            None,
            temp.clone(),
        );
        assert_eq!(explicit, PathBuf::from("D:\\models\\fe"));

        let empty_override_falls_back = default_model_cache_dir_from(
            Some(OsString::from("")),
            Some(OsString::from("C:\\Users\\u\\AppData\\Local")),
            Some(OsString::from("C:\\Users\\u")),
            Some(OsString::from("/xdg/cache")),
            Some(OsString::from("/home/u")),
            temp.clone(),
        );
        #[cfg(windows)]
        assert_eq!(
            empty_override_falls_back,
            PathBuf::from("C:\\Users\\u\\AppData\\Local")
                .join("SynapseMind")
                .join("fastembed_cache")
        );
        #[cfg(not(windows))]
        assert_eq!(
            empty_override_falls_back,
            PathBuf::from("/xdg/cache")
                .join("synapse-mind")
                .join("fastembed_cache")
        );

        let temp_fallback = default_model_cache_dir_from(None, None, None, None, None, temp);
        assert_eq!(
            temp_fallback,
            PathBuf::from("/tmp/fallback")
                .join("synapse-mind")
                .join("fastembed_cache")
        );
    }

    struct DummyReadyEmbedder {
        one_calls: Arc<AtomicU64>,
        batch_calls: Arc<AtomicU64>,
    }

    impl Embedder for DummyReadyEmbedder {
        fn model_id(&self) -> &str {
            "dummy-ready-v1"
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.batch_calls.fetch_add(1, Ordering::Relaxed);
            Ok(texts.iter().map(|_| vec![1.0_f32; EMBEDDING_DIM]).collect())
        }

        fn embed_one(&self, _text: &str) -> Result<Vec<f32>> {
            self.one_calls.fetch_add(1, Ordering::Relaxed);
            Ok(vec![1.0_f32; EMBEDDING_DIM])
        }
    }

    #[test]
    fn arc_and_box_forward_embed_one_and_is_ready() {
        let one_calls = Arc::new(AtomicU64::new(0));
        let batch_calls = Arc::new(AtomicU64::new(0));
        let arc_emb = Arc::new(DummyReadyEmbedder {
            one_calls: Arc::clone(&one_calls),
            batch_calls: Arc::clone(&batch_calls),
        });
        assert!(arc_emb.is_ready());
        assert_eq!(arc_emb.model_id(), "dummy-ready-v1");
        arc_emb.embed_one("q").expect("arc embed_one");
        arc_emb.embed_batch(&["b"]).expect("arc embed_batch");
        assert_eq!(one_calls.load(Ordering::Relaxed), 1);
        assert_eq!(batch_calls.load(Ordering::Relaxed), 1);

        let box_emb: Box<dyn Embedder> = Box::new(DummyReadyEmbedder {
            one_calls: Arc::clone(&one_calls),
            batch_calls: Arc::clone(&batch_calls),
        });
        assert!(box_emb.is_ready());
        assert_eq!(box_emb.model_id(), "dummy-ready-v1");
        box_emb.embed_one("q").expect("box embed_one");
        assert_eq!(one_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn managed_embedder_tracks_download_progress_watch_and_callbacks() {
        let managed = ManagedEmbedder::new();
        assert_eq!(managed.status(), EmbedderStatus::NotDownloaded);
        assert!(!managed.is_ready());
        assert!(matches!(
            managed.embed_one("hello"),
            Err(CoreError::EmbedderUnavailable(_))
        ));

        let mut rx = managed.subscribe();
        assert_eq!(rx.borrow().clone(), EmbedderStatus::NotDownloaded);

        let recorded = Arc::new(Mutex::new(Vec::<EmbedderStatus>::new()));
        let recorded_ref = Arc::clone(&recorded);
        let listener_id = managed.on_status_change(move |status| {
            recorded_ref.lock().unwrap().push(status.clone());
        });

        let one_calls = Arc::new(AtomicU64::new(0));
        let batch_calls = Arc::new(AtomicU64::new(0));
        managed
            .initialize_with(|progress| {
                progress(0, None);
                progress(0, Some(200_000));
                progress(100_000, Some(200_000));
                progress(200_000, Some(200_000));
                Ok(DummyReadyEmbedder {
                    one_calls: Arc::clone(&one_calls),
                    batch_calls: Arc::clone(&batch_calls),
                })
            })
            .expect("initialize succeeds");

        assert!(managed.is_ready());
        assert_eq!(managed.status(), EmbedderStatus::Ready);
        assert!(rx.has_changed().expect("watch channel open"));
        rx.changed().await.expect("watch receives update");
        assert_eq!(rx.borrow().clone(), EmbedderStatus::Ready);

        let log = recorded.lock().unwrap().clone();
        assert_eq!(log.first(), Some(&EmbedderStatus::NotDownloaded));
        assert!(log.iter().any(|s| matches!(
            s,
            EmbedderStatus::Downloading {
                bytes: 0,
                total: None
            }
        )));
        assert!(log.iter().any(|s| matches!(
            s,
            EmbedderStatus::Downloading {
                bytes: 100_000,
                total: Some(200_000)
            }
        )));
        assert_eq!(log.last(), Some(&EmbedderStatus::Ready));

        assert!(managed.remove_status_listener(listener_id));
        assert!(!managed.remove_status_listener(listener_id));

        assert_eq!(
            managed.embed_one("query").expect("ready embed_one").len(),
            EMBEDDING_DIM
        );
        assert_eq!(one_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn managed_embedder_failure_transitions_to_failed_and_allows_retry() {
        let managed = ManagedEmbedder::new();
        let mut rx = managed.subscribe();

        let err = managed
            .initialize_with(|progress| -> Result<DummyReadyEmbedder> {
                progress(0, Some(1024));
                Err(CoreError::Embedder("network unreachable".to_owned()))
            })
            .expect_err("simulated download failure");
        assert!(matches!(err, CoreError::Embedder(_)));
        assert!(!managed.is_ready());
        assert_eq!(
            managed.status(),
            EmbedderStatus::Failed("embedder error: network unreachable".to_owned())
        );
        assert!(managed.status().is_failed());
        assert_eq!(rx.borrow_and_update().clone(), managed.status());

        // Subsequent retry succeeds without needing to restart the app.
        let one_calls = Arc::new(AtomicU64::new(0));
        let batch_calls = Arc::new(AtomicU64::new(0));
        let handle = managed
            .spawn_initialize_with(move |progress| {
                progress(512, Some(512));
                Ok(DummyReadyEmbedder {
                    one_calls,
                    batch_calls,
                })
            })
            .expect("spawn init");
        handle.join().expect("thread join").expect("retry init ok");
        assert!(managed.is_ready());
        assert_eq!(managed.status(), EmbedderStatus::Ready);
        assert_eq!(
            EmbedderStatus::Downloading {
                bytes: 512,
                total: Some(1024)
            }
            .progress_fraction(),
            Some(0.5)
        );
    }

    #[cfg(feature = "fastembed")]
    #[test]
    fn fastembed_download_reports_progress_and_handles_unreachable_endpoint() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::AtomicBool;

        struct TempDirGuard(PathBuf);
        impl TempDirGuard {
            fn new(label: &str) -> Self {
                let dir = std::env::temp_dir()
                    .join(format!("s-core-fe-dl-{label}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).expect("create temp dir");
                Self(dir)
            }
        }
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        // 1. Unreachable local endpoint: `is_dual_model_cached` is false and ManagedEmbedder
        // transitions to Failed without panicking.
        let empty_dir = TempDirGuard::new("unreachable");
        assert!(!fastembed_impl::is_dual_model_cached(&empty_dir.0).expect("cache check"));

        // Bind then drop an ephemeral listener so we get a guaranteed-closed localhost port.
        let closed_port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
            listener.local_addr().expect("local addr").port()
        };
        let closed_endpoint = format!("http://127.0.0.1:{closed_port}");
        let managed = ManagedEmbedder::new();
        let err = managed
            .initialize_with(|progress| {
                fastembed_impl::download_and_load_dual(
                    &empty_dir.0,
                    Some(&closed_endpoint),
                    progress,
                )
            })
            .expect_err("unreachable endpoint must fail cleanly");
        assert!(matches!(err, CoreError::Embedder(_)));
        assert!(managed.status().is_failed());
        assert!(!managed.is_ready());

        // 2. Local mock HTTP server: verifies real `hf_hub` `Downloading { bytes, total: Some(_) }`
        // progress updates are emitted before ONNX load.
        let mock_dir = TempDirGuard::new("mock-http");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock addr");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = Arc::clone(&stop);

        let srv = std::thread::spawn(move || {
            let payload = vec![b'X'; 2048];
            let _ = listener.set_nonblocking(true);
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0_u8; 2048];
                        let _ = stream.read(&mut buf);
                        let req = String::from_utf8_lossy(&buf);
                        let is_range_probe =
                            req.contains("bytes=0-0") || req.contains("range: bytes=0-0");
                        let body: &[u8] = if is_range_probe {
                            &payload[..1]
                        } else {
                            &payload
                        };
                        let status_line = if is_range_probe {
                            "HTTP/1.1 206 Partial Content"
                        } else {
                            "HTTP/1.1 200 OK"
                        };
                        let headers = format!(
                            "{status_line}\r\n\
                             Content-Length: {}\r\n\
                             Content-Range: bytes 0-{}/{}\r\n\
                             ETag: \"mock-etag-1\"\r\n\
                             X-Repo-Commit: 0000000000000000000000000000000000000001\r\n\
                             Connection: close\r\n\r\n",
                            body.len(),
                            body.len() - 1,
                            payload.len()
                        );
                        let _ = stream.write_all(headers.as_bytes());
                        let _ = stream.write_all(body);
                        let _ = stream.flush();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let endpoint = format!("http://{addr}");
        let dl_managed = ManagedEmbedder::new();
        let observed = Arc::new(Mutex::new(Vec::<EmbedderStatus>::new()));
        let observed_ref = Arc::clone(&observed);
        let _id = dl_managed.on_status_change(move |s| {
            observed_ref.lock().unwrap().push(s.clone());
        });

        // Downloading dummy 2048-byte placeholder files will finish the hub download step with
        // real byte totals, then fail at ONNX model validation -> verifies both Downloading and Failed.
        let _ = dl_managed.initialize_with(|progress| {
            fastembed_impl::download_and_load_dual(&mock_dir.0, Some(&endpoint), progress)
        });
        stop.store(true, Ordering::Relaxed);
        let _ = srv.join();

        let states = observed.lock().unwrap().clone();
        assert!(
            states.iter().any(|s| matches!(
                s,
                EmbedderStatus::Downloading {
                    bytes,
                    total: Some(total)
                } if *total > 0 && *bytes <= *total
            )),
            "expected Downloading with known total, got {states:?}"
        );
        assert!(matches!(states.last(), Some(EmbedderStatus::Failed(_))));
    }

    #[test]
    fn managed_embedder_default_disables_idle_unload_and_configured_idle_unloads_and_reloads() {
        struct DropTrackingEmbedder {
            drops: Arc<AtomicU64>,
            one_calls: Arc<AtomicU64>,
            batch_calls: Arc<AtomicU64>,
        }

        impl Drop for DropTrackingEmbedder {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        impl Embedder for DropTrackingEmbedder {
            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                self.batch_calls.fetch_add(1, Ordering::SeqCst);
                Ok(texts.iter().map(|_| vec![1.0_f32; EMBEDDING_DIM]).collect())
            }

            fn embed_one(&self, _text: &str) -> Result<Vec<f32>> {
                self.one_calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![1.0_f32; EMBEDDING_DIM])
            }
        }

        // Default config keeps idle unloading disabled.
        let default_managed = ManagedEmbedder::new();
        assert_eq!(default_managed.config().idle_unload_timeout, None);
        assert!(!default_managed.is_loaded());
        assert!(!default_managed.unload_if_idle());

        let loads = Arc::new(AtomicU64::new(0));
        let drops = Arc::new(AtomicU64::new(0));
        let one_calls = Arc::new(AtomicU64::new(0));
        let batch_calls = Arc::new(AtomicU64::new(0));

        // One-shot initialize_with + manual unload reverts to NotDownloaded.
        let one_shot = ManagedEmbedder::new();
        let l0 = Arc::clone(&loads);
        let d0 = Arc::clone(&drops);
        let o0 = Arc::clone(&one_calls);
        let b0 = Arc::clone(&batch_calls);
        one_shot
            .initialize_with(move |_| {
                l0.fetch_add(1, Ordering::SeqCst);
                Ok(DropTrackingEmbedder {
                    drops: d0,
                    one_calls: o0,
                    batch_calls: b0,
                })
            })
            .expect("one-shot init");
        assert!(one_shot.is_loaded());
        assert!(one_shot.unload());
        assert!(!one_shot.unload());
        assert!(!one_shot.is_loaded());
        assert!(!one_shot.is_ready());
        assert_eq!(one_shot.status(), EmbedderStatus::NotDownloaded);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        // Configured idle unload automatically drops backend and lazily reloads on next query/batch.
        let managed = ManagedEmbedder::with_config(ManagedEmbedderConfig {
            idle_unload_timeout: Some(Duration::from_millis(60)),
        });
        let l = Arc::clone(&loads);
        let d = Arc::clone(&drops);
        let o = Arc::clone(&one_calls);
        let b = Arc::clone(&batch_calls);
        managed
            .initialize_repeatable_with(move |_| {
                l.fetch_add(1, Ordering::SeqCst);
                Ok(DropTrackingEmbedder {
                    drops: Arc::clone(&d),
                    one_calls: Arc::clone(&o),
                    batch_calls: Arc::clone(&b),
                })
            })
            .expect("repeatable init");

        assert_eq!(loads.load(Ordering::SeqCst), 2);
        assert!(managed.is_loaded());
        assert!(managed.is_ready());

        // Wait up to 2 seconds for background reaper thread to drop idle backend.
        let start = Instant::now();
        while managed.is_loaded() && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !managed.is_loaded(),
            "idle reaper must unload backend after configured timeout"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(managed.idle_unload_count(), 1);
        assert_eq!(managed.status(), EmbedderStatus::Ready);
        assert!(
            managed.is_ready(),
            "reloadable backend stays ready for transparent lazy reload"
        );

        // Next embed_one lazily reloads without needing explicit re-init.
        let vec = managed
            .embed_one("after idle")
            .expect("lazy reload embed_one");
        assert_eq!(vec.len(), EMBEDDING_DIM);
        assert!(managed.is_loaded());
        assert_eq!(loads.load(Ordering::SeqCst), 3);
        assert_eq!(managed.reload_count(), 1);
        assert_eq!(one_calls.load(Ordering::SeqCst), 1);

        // Manual unload followed by embed_batch also reloads transparently.
        assert!(managed.unload());
        assert!(!managed.is_loaded());
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        let batch = managed
            .embed_batch(&["doc1", "doc2"])
            .expect("lazy reload embed_batch");
        assert_eq!(batch.len(), 2);
        assert_eq!(loads.load(Ordering::SeqCst), 4);
        assert_eq!(managed.reload_count(), 2);
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn managed_embedder_tracks_model_id_across_lifecycle_and_rejects_mismatched_reinit() {
        struct TaggedEmbedder {
            id: &'static str,
        }

        impl Embedder for TaggedEmbedder {
            fn model_id(&self) -> &str {
                self.id
            }

            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                Ok(texts.iter().map(|_| vec![1.0_f32; EMBEDDING_DIM]).collect())
            }
        }

        struct EmptyIdEmbedder;
        impl Embedder for EmptyIdEmbedder {
            fn model_id(&self) -> &str {
                "   "
            }

            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
                Ok(texts.iter().map(|_| vec![1.0_f32; EMBEDDING_DIM]).collect())
            }
        }

        let uninit = ManagedEmbedder::new();
        assert_eq!(uninit.model_id(), "");
        assert_eq!(uninit.active_model_id(), None);

        assert!(ManagedEmbedder::from_ready(EmptyIdEmbedder).is_err());

        let ready = ManagedEmbedder::from_ready(TaggedEmbedder {
            id: MODEL_ID_DEVHASH,
        })
        .expect("from_ready");
        assert_eq!(ready.model_id(), MODEL_ID_DEVHASH);
        assert_eq!(ready.active_model_id(), Some(MODEL_ID_DEVHASH));

        // Failure leaves `model_id` unset so a subsequent retry can bind to the real model.
        let retryable = ManagedEmbedder::new();
        assert!(
            retryable
                .initialize_with(|_| -> Result<TaggedEmbedder> {
                    Err(CoreError::Embedder("transient error".to_owned()))
                })
                .is_err()
        );
        assert_eq!(retryable.model_id(), "");
        assert_eq!(retryable.active_model_id(), None);
        retryable
            .initialize_with(|_| {
                Ok(TaggedEmbedder {
                    id: MODEL_ID_BGE_SMALL_EN_V15_FP32,
                })
            })
            .expect("retry succeeds");
        assert_eq!(retryable.model_id(), MODEL_ID_BGE_SMALL_EN_V15_FP32);
        assert_eq!(
            retryable.active_model_id(),
            Some(MODEL_ID_BGE_SMALL_EN_V15_FP32)
        );

        // One-shot unload drops readiness and clears visible model_id, and rejects switching
        // the same ManagedEmbedder instance to a different model_id.
        assert!(retryable.unload());
        assert!(!retryable.is_ready());
        assert_eq!(retryable.model_id(), "");
        assert_eq!(retryable.active_model_id(), None);
        assert!(
            retryable
                .initialize_with(|_| {
                    Ok(TaggedEmbedder {
                        id: MODEL_ID_BGE_SMALL_EN_V15_Q_INT8,
                    })
                })
                .is_err()
        );
        assert!(!retryable.is_ready());

        // Repeatable reloader preserves `active_model_id` while idle-unloaded without reloading.
        let loads = Arc::new(AtomicU64::new(0));
        let loads_ref = Arc::clone(&loads);
        let repeatable = ManagedEmbedder::new();
        repeatable
            .initialize_repeatable_with(move |_| {
                loads_ref.fetch_add(1, Ordering::SeqCst);
                Ok(TaggedEmbedder {
                    id: MODEL_ID_BGE_SMALL_EN_V15_FP32,
                })
            })
            .expect("repeatable init");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert!(repeatable.unload());
        assert!(!repeatable.is_loaded());
        assert!(repeatable.is_ready());
        assert_eq!(repeatable.model_id(), MODEL_ID_BGE_SMALL_EN_V15_FP32);
        assert_eq!(
            repeatable.active_model_id(),
            Some(MODEL_ID_BGE_SMALL_EN_V15_FP32)
        );
        assert_eq!(
            loads.load(Ordering::SeqCst),
            1,
            "reading model_id while idle-unloaded must not reload backend"
        );
    }
}
