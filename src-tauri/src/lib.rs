pub mod autostart;
pub mod embedder_ui;
#[cfg(feature = "gate2-hooks")]
pub mod gate2_hooks;
pub mod keystore;
pub mod singleton;
pub mod tray;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use s_core::{
    CausalityEdge, CausalityQueryHit, EmbedderStatus, HybridSearchConfig, ManagedEmbedder,
    MemoryStats, MemoryStore,
};
#[cfg(not(feature = "fastembed"))]
use s_core::{EMBEDDING_DIM, Embedder};
use s_guard::{DbKey, DropReason, GuardStats, UserBlocklist};
use s_sensor::{ControllerState, SensorConfig, SensorHandle, start_sensor_pipeline};
use s_types::{MaskedMemoryBlock, RawCapturePacket, SENSOR_CHANNEL_CAPACITY};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

/// Embedder wrapper shared between `MemoryStore` and Tauri background tasks (`ManagedEmbedder`).
pub type AppEmbedder = ManagedEmbedder;

/// Shared in-memory store managed by Tauri state.
pub type SharedMemoryStore = Arc<Mutex<MemoryStore<AppEmbedder>>>;

/// Incoming IPC search payload (`k` is clamped server-side to `1..=50`).
#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub k: u32,
}

/// Serializable IPC representation of `s_types::CausalityEdge`.
#[derive(Serialize)]
pub struct EdgeDto {
    pub source_event_id: u64,
    pub target_event_id: u64,
    pub relationship: String,
    pub time_delta_seconds: u32,
}

impl From<CausalityEdge> for EdgeDto {
    fn from(edge: CausalityEdge) -> Self {
        Self {
            source_event_id: edge.source_event_id,
            target_event_id: edge.target_event_id,
            relationship: edge.relationship,
            time_delta_seconds: edge.time_delta_seconds,
        }
    }
}

/// Serializable IPC representation of `s_types::CausalityQueryHit`.
/// Intentionally omits `text_hash`, full `clean_text`, `redactions_count`,
/// `has_embedding_payload`, and `sanitized_title`.
#[derive(Serialize)]
pub struct HitDto {
    pub event_id: u64,
    pub timestamp_ms: u64,
    pub score: f32,
    pub summary_snippet: String,
    pub matched_app: String,
    pub causality_chain: Vec<EdgeDto>,
}

impl From<CausalityQueryHit> for HitDto {
    fn from(hit: CausalityQueryHit) -> Self {
        Self {
            event_id: hit.event_id,
            timestamp_ms: hit.timestamp_ms,
            score: hit.score,
            summary_snippet: hit.summary_snippet,
            matched_app: hit.matched_app,
            causality_chain: hit.causality_chain.into_iter().map(EdgeDto::from).collect(),
        }
    }
}

/// Serializable sensor controller state for the Memory Panel.
#[derive(Debug, Clone, Serialize)]
pub struct SensorStatusDto {
    pub state: String,
    pub paused: bool,
    pub pause_remaining_secs: Option<u64>,
}

/// Serializable hourly event bucket for the Memory Panel chart.
#[derive(Debug, Clone, Serialize)]
pub struct HourlyCountDto {
    pub hour: u8,
    pub count: u64,
}

/// Serializable top-app activity entry for the Memory Panel.
#[derive(Debug, Clone, Serialize)]
pub struct AppCountDto {
    pub process_name: String,
    pub count: u64,
}

/// Serializable redaction tag counter for the Memory Panel.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TagCountDto {
    pub tag: String,
    pub label: String,
    pub count: u64,
}

/// Serializable drop-reason counter for the Memory Panel.
#[derive(Debug, Clone, Serialize)]
pub struct DropCountDto {
    pub reason: String,
    pub count: u64,
}

/// Complete, zero-trust-safe payload for the Memory Panel UI.
#[derive(Serialize)]
pub struct MemoryPanelDto {
    pub sensor: SensorStatusDto,
    pub total_events: u64,
    pub redactions_total: u64,
    pub dropped_total: u64,
    pub user_blocked_count: u64,
    pub db_bytes: Option<u64>,
    pub events_by_hour: Vec<HourlyCountDto>,
    pub top_apps: Vec<AppCountDto>,
    pub latest_chain: Option<HitDto>,
    pub redactions_by_kind: Vec<TagCountDto>,
    pub dropped_by_reason: Vec<DropCountDto>,
    pub user_blocklist: Vec<String>,
    pub last_search_ms: Option<f64>,
    pub app_memory_bytes: Option<u64>,
    pub embedder_label: String,
    pub embedder_status: embedder_ui::EmbedderStatusDto,
    pub autostart_enabled: bool,
    pub is_demo: bool,
    pub version: String,
}

/// Lock-free tracker for the most recent `search` IPC execution latency.
#[derive(Default)]
pub struct SearchLatencyTracker {
    last_micros_plus_one: AtomicU64,
}

impl SearchLatencyTracker {
    pub fn record(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX - 1);
        self.last_micros_plus_one
            .store(micros.saturating_add(1), Ordering::Relaxed);
    }

    pub fn last_ms(&self) -> Option<f64> {
        let raw = self.last_micros_plus_one.load(Ordering::Relaxed);
        if raw == 0 {
            None
        } else {
            Some((raw - 1) as f64 / 1000.0)
        }
    }
}

/// Lightweight deterministic bag-of-tokens embedder used when `fastembed` feature is disabled.
#[cfg(not(feature = "fastembed"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct DevHashEmbedder;

#[cfg(not(feature = "fastembed"))]
impl Embedder for DevHashEmbedder {
    fn model_id(&self) -> &str {
        s_core::MODEL_ID_DEVHASH
    }

    fn embed_batch(&self, texts: &[&str]) -> s_core::Result<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|t| project_tokens_to_unit(t)).collect())
    }
}

#[cfg(not(feature = "fastembed"))]
fn project_tokens_to_unit(text: &str) -> Vec<f32> {
    let mut vec = vec![0.0_f32; EMBEDDING_DIM];
    let lower = text.to_ascii_lowercase();
    let mut any_token = false;

    for token in lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|tok| !tok.is_empty())
    {
        any_token = true;
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for &byte in token.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        let idx = usize::try_from(hash % (EMBEDDING_DIM as u64)).unwrap_or(0);
        vec[idx] += 1.0;
    }

    if !any_token {
        vec[0] = 1.0;
    }

    let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in &mut vec {
            *v /= norm;
        }
    }
    vec
}

/// Uygulama gömücü yapılandırması (kullanıcı kararı, 21.11.2026; benchmark.md v0.1.1-b):
/// tek FP32 oturum (`SingleFp32`, sorgu ve indeksleme aynı vektör uzayında),
/// ONNX Runtime CPU bellek arenası kapalı ve 10 dk boşta kalınca oturum boşaltma.
/// Hedef: boşta < 50 MB, aktifken ~200 MB altı, sorgu gömme p95 < 20 ms.
#[cfg(feature = "fastembed")]
fn app_fastembed_config() -> s_core::FastEmbedConfig {
    s_core::FastEmbedConfig {
        mode: s_core::FastEmbedMode::SingleFp32,
        session_config: vec![("session.enable_cpu_mem_arena".into(), "0".into())],
        ..s_core::FastEmbedConfig::default()
    }
}

/// Model boşta boşaltıldığında (`idle_unload`) serbest kalan sayfaları Windows'a hemen iade eder.
/// Yalnızca çalışma kümesini kırpar (`SetProcessWorkingSetSize(-1, -1)`); gereken sayfalar
/// talep edildiğinde geri gelir, davranış değişmez. Ölçüm (21.11.2026): boşaltma sonrası
/// WS 64 MB / Private 30 MB; kırpma, WS'yi "boşta < 50 MB" hedefine indirmek içindir.
#[cfg(all(windows, feature = "fastembed"))]
fn spawn_working_set_trimmer(embedder: ManagedEmbedder) {
    let _ = std::thread::Builder::new()
        .name("synapse-ws-trimmer".to_owned())
        .spawn(move || {
            let mut was_loaded = embedder.is_loaded();
            loop {
                std::thread::sleep(Duration::from_secs(15));
                let loaded = embedder.is_loaded();
                if was_loaded && !loaded {
                    // SAFETY: GetCurrentProcess döndürdüğü sözde tutamaç kapatılmaz; (-1, -1)
                    // belgelenmiş "çalışma kümesini boşalt" çağrısıdır.
                    unsafe {
                        let _ = windows::Win32::System::Threading::SetProcessWorkingSetSize(
                            windows::Win32::System::Threading::GetCurrentProcess(),
                            usize::MAX,
                            usize::MAX,
                        );
                    }
                }
                was_loaded = loaded;
            }
        });
}

fn build_embedder() -> s_core::Result<AppEmbedder> {
    #[cfg(feature = "fastembed")]
    {
        #[cfg(feature = "gate2-hooks")]
        let idle_unload_timeout = gate2_hooks::idle_unload_override(std::env::args())
            .unwrap_or(s_core::DEFAULT_IDLE_UNLOAD_TIMEOUT);
        #[cfg(not(feature = "gate2-hooks"))]
        let idle_unload_timeout = s_core::DEFAULT_IDLE_UNLOAD_TIMEOUT;
        Ok(ManagedEmbedder::with_config(
            s_core::ManagedEmbedderConfig {
                idle_unload_timeout: Some(idle_unload_timeout),
            },
        ))
    }
    #[cfg(not(feature = "fastembed"))]
    {
        ManagedEmbedder::from_ready(DevHashEmbedder)
    }
}

/// Opens or creates the SQLCipher-encrypted `MemoryStore` at `db_path` using
/// the DPAPI-unwrapped 256-bit `db_key` (Iron Rule 7) and attaches `embedder`.
///
/// In debug builds, seeds synthetic `[DEMO]` blocks only when the store is empty
/// so subsequent restarts never collide on `event_id` (ADR-001).
fn init_store_with_embedder(
    db_path: &Path,
    db_key: &DbKey,
    embedder: AppEmbedder,
) -> Result<SharedMemoryStore, String> {
    #[allow(unused_mut)]
    let mut store = MemoryStore::open_encrypted(db_path, db_key.expose(), embedder)
        .map_err(|e| e.to_string())?;

    #[cfg(debug_assertions)]
    if store.next_event_id().map_err(|e| e.to_string())? == 0 {
        let blocks = demo_blocks();
        store.ingest_batch(&blocks).map_err(|e| e.to_string())?;
    }

    Ok(Arc::new(Mutex::new(store)))
}

#[cfg(test)]
fn init_store(db_path: &Path, db_key: &DbKey) -> Result<SharedMemoryStore, String> {
    let embedder = build_embedder().map_err(|e| e.to_string())?;
    init_store_with_embedder(db_path, db_key, embedder)
}

#[cfg(test)]
fn init_in_memory_store() -> s_core::Result<SharedMemoryStore> {
    let embedder = build_embedder()?;
    let mut store = MemoryStore::open_in_memory(embedder)?;
    store.ingest_batch(&demo_blocks())?;
    Ok(Arc::new(Mutex::new(store)))
}

/// Reads `MemoryStore::next_event_id()` once before starting `s-guard` and ingestion (ADR-001).
fn next_store_event_id(store: &SharedMemoryStore) -> Result<u64, String> {
    let guard = store
        .lock()
        .map_err(|_| "memory store lock poisoned".to_owned())?;
    guard.next_event_id().map_err(|e| e.to_string())
}

/// Owns the active `SensorHandle` so it stays alive until app exit and exposes
/// runtime pause/resume/state controls for the Memory Panel.
pub struct PipelineController {
    sensor: Mutex<Option<SensorHandle>>,
}

impl PipelineController {
    fn start(
        store: SharedMemoryStore,
        start_id: u64,
        guard_stats: Arc<GuardStats>,
        user_blocklist: Arc<UserBlocklist>,
    ) -> Self {
        match start_sensor_pipeline(SensorConfig::default()) {
            Ok((sensor_handle, rx_raw)) => {
                spawn_guard_and_ingestion(store, rx_raw, start_id, guard_stats, user_blocklist);
                Self {
                    sensor: Mutex::new(Some(sensor_handle)),
                }
            }
            Err(err) => {
                // `SensorError` carries only error codes/diagnostics, never raw content.
                eprintln!("synapse-mind: sensor pipeline warning: {err}");
                Self {
                    sensor: Mutex::new(None),
                }
            }
        }
    }

    fn sensor_status(&self) -> SensorStatusDto {
        let Ok(guard) = self.sensor.lock() else {
            return SensorStatusDto {
                state: "unavailable".to_owned(),
                paused: false,
                pause_remaining_secs: None,
            };
        };
        match guard.as_ref() {
            Some(handle) => SensorStatusDto {
                state: controller_state_key(handle.controller_state()).to_owned(),
                paused: handle.is_paused(),
                pause_remaining_secs: handle.pause_remaining().map(|d| d.as_secs()),
            },
            None => SensorStatusDto {
                state: "unavailable".to_owned(),
                paused: false,
                pause_remaining_secs: None,
            },
        }
    }

    pub(crate) fn raw_sensor_snapshot(&self) -> (Option<ControllerState>, bool, Option<Duration>) {
        let Ok(guard) = self.sensor.lock() else {
            return (None, false, None);
        };
        match guard.as_ref() {
            Some(handle) => (
                Some(handle.controller_state()),
                handle.is_paused(),
                handle.pause_remaining(),
            ),
            None => (None, false, None),
        }
    }

    pub(crate) fn subscribe_sensor_state(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<ControllerState>> {
        let guard = self.sensor.lock().ok()?;
        guard.as_ref().map(SensorHandle::subscribe_state)
    }

    pub(crate) fn pause_for(&self, duration: Duration) -> Result<SensorStatusDto, String> {
        let guard = self
            .sensor
            .lock()
            .map_err(|_| "sensor controller lock poisoned".to_owned())?;
        let Some(handle) = guard.as_ref() else {
            return Err("sensor pipeline is unavailable".to_owned());
        };
        handle.pause_for(duration);
        Ok(SensorStatusDto {
            state: controller_state_key(handle.controller_state()).to_owned(),
            paused: handle.is_paused(),
            pause_remaining_secs: handle.pause_remaining().map(|d| d.as_secs()),
        })
    }

    pub(crate) fn resume(&self) -> Result<SensorStatusDto, String> {
        let guard = self
            .sensor
            .lock()
            .map_err(|_| "sensor controller lock poisoned".to_owned())?;
        let Some(handle) = guard.as_ref() else {
            return Err("sensor pipeline is unavailable".to_owned());
        };
        handle.resume();
        Ok(SensorStatusDto {
            state: controller_state_key(handle.controller_state()).to_owned(),
            paused: handle.is_paused(),
            pause_remaining_secs: handle.pause_remaining().map(|d| d.as_secs()),
        })
    }

    fn stop(&self) {
        if let Ok(mut slot) = self.sensor.lock()
            && let Some(handle) = slot.take()
        {
            handle.stop();
        }
    }
}

fn controller_state_key(state: ControllerState) -> &'static str {
    match state {
        ControllerState::Active => "active",
        ControllerState::Batching => "batching",
        ControllerState::Suspended => "suspended",
    }
}

fn spawn_guard_and_ingestion(
    store: SharedMemoryStore,
    rx_raw: tokio::sync::mpsc::Receiver<RawCapturePacket>,
    start_id: u64,
    guard_stats: Arc<GuardStats>,
    user_blocklist: Arc<UserBlocklist>,
) {
    let (tx_masked, rx_masked) =
        tokio::sync::mpsc::channel::<MaskedMemoryBlock>(SENSOR_CHANNEL_CAPACITY);

    tauri::async_runtime::spawn(s_guard::run_with_options(
        rx_raw,
        tx_masked,
        start_id,
        guard_stats,
        user_blocklist,
    ));
    tauri::async_runtime::spawn(async move {
        if let Err(err) = s_core::run_ingestion(store, rx_masked).await {
            eprintln!("synapse-mind: ingestion pipeline stopped: {err}");
        }
    });
}

#[cfg(any(debug_assertions, test))]
fn demo_blocks() -> Vec<s_core::MaskedMemoryBlock> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use s_core::{AppContext, EventSource, MaskedMemoryBlock};

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(1_700_000_000_000))
        .unwrap_or(1_700_000_000_000);

    let make_hash = |seed: u8| -> [u8; 32] { [seed; 32] };

    vec![
        MaskedMemoryBlock {
            event_id: 1,
            timestamp_ms: now_ms.saturating_sub(54_000),
            app_context: AppContext {
                process_name: "WindowsTerminal.exe".to_owned(),
                sanitized_title: "[DEMO] PowerShell - cargo build".to_owned(),
                is_browser: false,
            },
            clean_text: "[DEMO] error: linking with link.exe failed (exit code 1) sqlite_vec symbol unresolved".to_owned(),
            text_hash: make_hash(0xA1),
            redactions_count: 0,
            has_embedding_payload: true,
            source: EventSource::Accessibility,
        },
        MaskedMemoryBlock {
            event_id: 2,
            timestamp_ms: now_ms.saturating_sub(40_000),
            app_context: AppContext {
                process_name: "msedge.exe".to_owned(),
                sanitized_title: "[DEMO] Search sqlite-vec static linking Rust Windows".to_owned(),
                is_browser: true,
            },
            clean_text: "[DEMO] docs.rs sqlite-vec static library build.rs configuration on Windows MSVC".to_owned(),
            text_hash: make_hash(0xB2),
            redactions_count: 0,
            has_embedding_payload: true,
            source: EventSource::Accessibility,
        },
        MaskedMemoryBlock {
            event_id: 3,
            timestamp_ms: now_ms.saturating_sub(22_000),
            app_context: AppContext {
                process_name: "clipboard".to_owned(),
                sanitized_title: "[DEMO] Clipboard - build.rs snippet".to_owned(),
                is_browser: false,
            },
            clean_text: "[DEMO] println!(\"cargo:rustc-link-lib=static=sqlite_vec\");".to_owned(),
            text_hash: make_hash(0xC3),
            redactions_count: 0,
            has_embedding_payload: true,
            source: EventSource::Clipboard,
        },
        MaskedMemoryBlock {
            event_id: 4,
            timestamp_ms: now_ms.saturating_sub(11_000),
            app_context: AppContext {
                process_name: "Code.exe".to_owned(),
                sanitized_title: "[DEMO] build.rs - S_Recall".to_owned(),
                is_browser: false,
            },
            clean_text: "[DEMO] fn main() { println!(\"cargo:rustc-link-lib=static=sqlite_vec\"); } // token=[REDACTED_API_KEY]".to_owned(),
            text_hash: make_hash(0xD4),
            redactions_count: 1,
            has_embedding_payload: true,
            source: EventSource::Accessibility,
        },
    ]
}

/// Shared pipeline handle managed by Tauri state.
pub type SharedPipeline = Arc<Mutex<Option<PipelineController>>>;

/// Shared tray handle managed by Tauri state.
pub type SharedTray = Arc<Mutex<Option<tray::TrayController>>>;

const OVERLAY_WINDOW_LABEL: &str = "main";
const PANEL_WINDOW_LABEL: &str = "panel";

pub(crate) fn open_or_focus_panel_window(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(main_win) = app.get_webview_window(OVERLAY_WINDOW_LABEL) {
        let _ = main_win.hide();
    }
    if let Some(existing) = app.get_webview_window(PANEL_WINDOW_LABEL) {
        let _ = existing.unminimize();
        let _ = exclude_from_capture(&existing);
        let _ = apply_panel_backdrop(&existing);
        existing.show().map_err(|e| e.to_string())?;
        let _ = existing.set_focus();
        let _ = existing.emit("panel://refresh", ());
        return Ok(());
    }

    let window = tauri::WebviewWindowBuilder::new(
        app,
        PANEL_WINDOW_LABEL,
        tauri::WebviewUrl::App("panel.html".into()),
    )
    .title("Synapse Mind · Hafıza Paneli")
    .inner_size(1200.0, 820.0)
    .min_inner_size(680.0, 540.0)
    .center()
    .transparent(true)
    .effects(
        tauri::window::EffectsBuilder::new()
            .effect(tauri::window::Effect::Mica)
            .build(),
    )
    .visible(false)
    .build()
    .map_err(|e| e.to_string())?;

    let _ = exclude_from_capture(&window);
    let _ = apply_panel_backdrop(&window);
    window.show().map_err(|e| e.to_string())?;
    let _ = window.set_focus();
    Ok(())
}

fn ensure_window_label(actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("command is restricted to window '{expected}'"))
    }
}

fn ensure_window_label_in(actual: &str, allowed: &[&str]) -> Result<(), String> {
    if allowed.contains(&actual) {
        Ok(())
    } else {
        Err(format!("command is restricted to windows {allowed:?}"))
    }
}

/// Tauri IPC commands for the overlay and Memory Panel frontends.
pub mod commands {
    use super::*;

    /// Searches the in-memory store via `hybrid_search` on a blocking worker thread.
    /// Restricted to the `"main"` overlay window; never logs queries or search results.
    #[tauri::command]
    pub async fn search(
        window: tauri::WebviewWindow,
        request: SearchRequest,
        store: tauri::State<'_, SharedMemoryStore>,
        latency: tauri::State<'_, Arc<SearchLatencyTracker>>,
    ) -> Result<Vec<HitDto>, String> {
        ensure_window_label(window.label(), OVERLAY_WINDOW_LABEL)?;
        let store = Arc::clone(store.inner());
        let tracker = Arc::clone(latency.inner());
        let started = Instant::now();
        let res = search_with_store(store, request).await;
        if res.is_ok() {
            tracker.record(started.elapsed());
        }
        res
    }

    /// Hides the overlay window when `Esc` is pressed in the frontend.
    #[tauri::command]
    pub fn hide_overlay(window: tauri::WebviewWindow) -> Result<(), String> {
        ensure_window_label(window.label(), OVERLAY_WINDOW_LABEL)?;
        window.hide().map_err(|e| e.to_string())
    }

    /// Indicates whether synthetic `[DEMO]` records are loaded (debug builds only).
    #[tauri::command]
    pub fn is_demo_mode(window: tauri::WebviewWindow) -> Result<bool, String> {
        ensure_window_label(window.label(), OVERLAY_WINDOW_LABEL)?;
        Ok(cfg!(debug_assertions))
    }

    /// Opens (or focuses) the Memory Panel window with `WDA_EXCLUDEFROMCAPTURE` applied
    /// before the window is shown. Restricted to `"main"`.
    ///
    /// `async`: Tauri 2'de Windows'ta senkron komut içinde pencere oluşturmak ana iş
    /// parçacığında kilitlenmeye yol açar; komut bu yüzden async (async runtime'da çalışır).
    #[tauri::command]
    pub async fn open_memory_panel(caller: tauri::WebviewWindow) -> Result<(), String> {
        ensure_window_label(caller.label(), OVERLAY_WINDOW_LABEL)?;
        open_or_focus_panel_window(caller.app_handle())
    }

    /// Opens the Spotlight overlay window, optionally pre-filling a search query.
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub fn open_overlay_with_query(
        caller: tauri::WebviewWindow,
        query: Option<String>,
    ) -> Result<(), String> {
        ensure_window_label(caller.label(), PANEL_WINDOW_LABEL)?;
        let app = caller.app_handle();
        let Some(window) = app.get_webview_window(OVERLAY_WINDOW_LABEL) else {
            return Err("overlay window unavailable".to_owned());
        };
        let _ = exclude_from_capture(&window);
        let _ = window.center();
        window.show().map_err(|e| e.to_string())?;
        let _ = window.set_focus();
        match query.map(|q| q.trim().to_owned()).filter(|q| !q.is_empty()) {
            Some(q) => {
                let _ = window.emit("overlay://prefill", q);
            }
            None => {
                let _ = window.emit("overlay://focus", ());
            }
        }
        Ok(())
    }

    /// Fetches aggregated today stats, guard counters, blocklist, and sensor state.
    /// Restricted to `"panel"`.
    #[tauri::command]
    #[allow(clippy::too_many_arguments)] // Tauri commands inject each managed `State<'_, T>` separately.
    pub async fn get_memory_panel_data(
        window: tauri::WebviewWindow,
        tz_offset_minutes: i32,
        store: tauri::State<'_, SharedMemoryStore>,
        guard_stats: tauri::State<'_, Arc<GuardStats>>,
        user_blocklist: tauri::State<'_, Arc<UserBlocklist>>,
        pipeline: tauri::State<'_, SharedPipeline>,
        latency: tauri::State<'_, Arc<SearchLatencyTracker>>,
        embedder: tauri::State<'_, AppEmbedder>,
    ) -> Result<MemoryPanelDto, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        let sensor = read_sensor_status(pipeline.inner());
        let embedder_status = embedder.status();
        let store = Arc::clone(store.inner());
        let guard_stats = Arc::clone(guard_stats.inner());
        let user_blocklist = Arc::clone(user_blocklist.inner());
        let last_search_ms = latency.last_ms();

        build_memory_panel_data(
            store,
            guard_stats,
            user_blocklist,
            sensor,
            embedder_status,
            last_search_ms,
            tz_offset_minutes,
        )
        .await
    }

    /// Pauses sensor capture for `seconds` (clamped to `1..=86400`, default 3600).
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub fn pause_capture(
        window: tauri::WebviewWindow,
        seconds: u64,
        pipeline: tauri::State<'_, SharedPipeline>,
        tray_state: tauri::State<'_, SharedTray>,
    ) -> Result<SensorStatusDto, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        let clamped = seconds.clamp(1, 86_400);
        let status = {
            let guard = pipeline
                .lock()
                .map_err(|_| "pipeline lock poisoned".to_owned())?;
            let Some(controller) = guard.as_ref() else {
                return Err("sensor pipeline is unavailable".to_owned());
            };
            controller.pause_for(Duration::from_secs(clamped))?
        };
        if let Ok(guard) = tray_state.lock()
            && let Some(tray) = guard.as_ref()
        {
            tray.sync(window.app_handle());
        }
        Ok(status)
    }

    /// Resumes sensor capture immediately after a manual pause.
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub fn resume_capture(
        window: tauri::WebviewWindow,
        pipeline: tauri::State<'_, SharedPipeline>,
        tray_state: tauri::State<'_, SharedTray>,
    ) -> Result<SensorStatusDto, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        let status = {
            let guard = pipeline
                .lock()
                .map_err(|_| "pipeline lock poisoned".to_owned())?;
            let Some(controller) = guard.as_ref() else {
                return Err("sensor pipeline is unavailable".to_owned());
            };
            controller.resume()?
        };
        if let Ok(guard) = tray_state.lock()
            && let Some(tray) = guard.as_ref()
        {
            tray.sync(window.app_handle());
        }
        Ok(status)
    }

    /// Adds a process name to the runtime `UserBlocklist` (never logged).
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub fn add_blocked_app(
        window: tauri::WebviewWindow,
        process_name: String,
        user_blocklist: tauri::State<'_, Arc<UserBlocklist>>,
    ) -> Result<Vec<String>, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        add_blocked_app_inner(user_blocklist.inner(), &process_name)
    }

    /// Removes a process name from the runtime `UserBlocklist`.
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub fn remove_blocked_app(
        window: tauri::WebviewWindow,
        process_name: String,
        user_blocklist: tauri::State<'_, Arc<UserBlocklist>>,
    ) -> Result<Vec<String>, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        user_blocklist.remove(&process_name);
        Ok(user_blocklist.list())
    }

    /// Deletes all events captured in the last `minutes` minutes (clamped `1..=1440`).
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub async fn delete_recent_memory(
        window: tauri::WebviewWindow,
        minutes: u64,
        store: tauri::State<'_, SharedMemoryStore>,
    ) -> Result<u64, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        delete_recent_memory_inner(Arc::clone(store.inner()), minutes).await
    }

    /// Permanently deletes all stored memory events, vectors, and causality edges
    /// and reclaims disk space via `VACUUM`. Requires `confirm == true`.
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub async fn delete_all_memory(
        window: tauri::WebviewWindow,
        confirm: bool,
        store: tauri::State<'_, SharedMemoryStore>,
    ) -> Result<u64, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        delete_all_memory_inner(Arc::clone(store.inner()), confirm).await
    }

    /// Enables or disables launching Synapse Mind at Windows sign-in (`HKCU\...\Run`)
    /// and synchronizes the tray menu checkmark. Restricted to `"panel"`.
    #[tauri::command]
    pub fn set_autostart(
        window: tauri::WebviewWindow,
        enabled: bool,
        tray_state: tauri::State<'_, SharedTray>,
    ) -> Result<bool, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        let actual = autostart::set_enabled(enabled)?;
        if let Ok(guard) = tray_state.lock()
            && let Some(tray) = guard.as_ref()
        {
            tray.sync_autostart(actual);
        }
        Ok(actual)
    }

    /// Returns the current semantic embedder readiness / download status.
    /// Allowed for both `"main"` overlay and `"panel"` Memory Panel windows.
    #[tauri::command]
    pub fn get_embedder_status(
        window: tauri::WebviewWindow,
        embedder: tauri::State<'_, AppEmbedder>,
    ) -> Result<embedder_ui::EmbedderStatusDto, String> {
        ensure_window_label_in(window.label(), &[OVERLAY_WINDOW_LABEL, PANEL_WINDOW_LABEL])?;
        Ok(embedder_ui::EmbedderStatusDto::from_core(
            &embedder.status(),
        ))
    }

    /// Retries initializing / downloading the local semantic embedding model.
    /// Restricted to `"panel"`.
    #[tauri::command]
    pub fn retry_embedder_download(
        window: tauri::WebviewWindow,
        embedder: tauri::State<'_, AppEmbedder>,
    ) -> Result<embedder_ui::EmbedderStatusDto, String> {
        ensure_window_label(window.label(), PANEL_WINDOW_LABEL)?;
        #[cfg(feature = "fastembed")]
        if !matches!(
            embedder.status(),
            EmbedderStatus::Ready | EmbedderStatus::Downloading { .. }
        ) {
            embedder
                .spawn_fastembed(app_fastembed_config())
                .map_err(|err| format!("model indirme başlatılamadı: {err}"))?;
        }
        Ok(embedder_ui::EmbedderStatusDto::from_core(
            &embedder.status(),
        ))
    }
}

fn read_sensor_status(pipeline: &SharedPipeline) -> SensorStatusDto {
    let Ok(guard) = pipeline.lock() else {
        return SensorStatusDto {
            state: "unavailable".to_owned(),
            paused: false,
            pause_remaining_secs: None,
        };
    };
    match guard.as_ref() {
        Some(controller) => controller.sensor_status(),
        None => SensorStatusDto {
            state: "unavailable".to_owned(),
            paused: false,
            pause_remaining_secs: None,
        },
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

fn local_day_start_ms(now_ms: u64, tz_offset_minutes: i32) -> u64 {
    const MS_PER_DAY: i64 = 86_400_000;
    let clamped_offset = tz_offset_minutes.clamp(-840, 840);
    let Ok(now_i64) = i64::try_from(now_ms) else {
        return 0;
    };
    let offset_ms = i64::from(clamped_offset).saturating_mul(60_000);
    let local_ms = now_i64.saturating_add(offset_ms);
    let local_midnight = local_ms.saturating_sub(local_ms.rem_euclid(MS_PER_DAY));
    let utc_midnight = local_midnight.saturating_sub(offset_ms).max(0);
    u64::try_from(utc_midnight).unwrap_or(0)
}

const REDACTION_LABELS: &[(&str, &str)] = &[
    ("API_KEY", "API anahtarı"),
    ("PASSWORD", "Parola"),
    ("EMAIL", "E-posta"),
    ("JWT", "JWT / oturum belirteci"),
    ("CREDIT_CARD", "Kredi kartı"),
    ("TC_KIMLIK", "TC kimlik no"),
    ("SSN", "Kimlik / SSN numarası"),
    ("PRIVATE_KEY", "Özel anahtar (PEM)"),
    ("IBAN", "IBAN"),
    ("PHONE", "Telefon"),
    ("CONNECTION_STRING", "Bağlantı dizesi"),
];

/// Maps an internal `s-guard` redaction kind (or `[REDACTED_*]` tag) to a
/// human-readable Turkish label using the single `REDACTION_LABELS` table.
pub fn redaction_display_label(kind: &str) -> &'static str {
    let normalized = kind
        .trim()
        .trim_start_matches("[REDACTED_")
        .trim_end_matches(']');
    REDACTION_LABELS
        .iter()
        .find(|(key, _)| *key == normalized)
        .map(|(_, label)| *label)
        .unwrap_or("Diğer gizli bilgi")
}

fn drop_reason_key(reason: DropReason) -> &'static str {
    match reason {
        DropReason::BlacklistedProcess => "blacklisted_process",
        DropReason::PrivateWindow => "private_window",
        DropReason::SensitiveFile => "sensitive_file",
        DropReason::IgnoredFormat => "ignored_format",
    }
}

#[cfg(windows)]
fn current_process_working_set_bytes() -> Option<u64> {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).ok()?,
        ..Default::default()
    };
    // SAFETY: `GetCurrentProcess()` returns the current-process pseudo-handle and
    // `counters.cb` is initialized to the exact size of `PROCESS_MEMORY_COUNTERS`.
    unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &raw mut counters, counters.cb) }.ok()?;
    u64::try_from(counters.WorkingSetSize).ok()
}

#[cfg(not(windows))]
fn current_process_working_set_bytes() -> Option<u64> {
    None
}

async fn build_memory_panel_data(
    store: SharedMemoryStore,
    guard_stats: Arc<GuardStats>,
    user_blocklist: Arc<UserBlocklist>,
    sensor: SensorStatusDto,
    embedder_status: EmbedderStatus,
    last_search_ms: Option<f64>,
    tz_offset_minutes: i32,
) -> Result<MemoryPanelDto, String> {
    let since_ms = local_day_start_ms(now_unix_ms(), tz_offset_minutes);
    let clamped_offset = tz_offset_minutes.clamp(-840, 840);

    let stats: MemoryStats = tokio::task::spawn_blocking(move || -> Result<MemoryStats, String> {
        let guard = store
            .lock()
            .map_err(|_| "memory store lock poisoned".to_owned())?;
        guard
            .memory_stats(since_ms, clamped_offset)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("memory stats task join failed: {e}"))??;

    let guard_snapshot = guard_stats.snapshot();
    let user_blocked_count = guard_stats.user_blocked();
    let dropped_total = guard_snapshot
        .dropped
        .iter()
        .map(|(_, count)| *count)
        .fold(0_u64, u64::saturating_add);

    Ok(MemoryPanelDto {
        sensor,
        total_events: stats.total_events,
        redactions_total: stats.redactions_total,
        dropped_total,
        user_blocked_count,
        db_bytes: stats.db_bytes,
        events_by_hour: stats
            .events_by_hour
            .into_iter()
            .map(|(hour, count)| HourlyCountDto { hour, count })
            .collect(),
        top_apps: stats
            .top_apps
            .into_iter()
            .map(|(process_name, count)| AppCountDto {
                process_name,
                count,
            })
            .collect(),
        latest_chain: stats.latest_chain.map(HitDto::from),
        redactions_by_kind: guard_snapshot
            .redactions
            .into_iter()
            .map(|(kind, count)| TagCountDto {
                tag: format!("[REDACTED_{kind}]"),
                label: redaction_display_label(kind).to_owned(),
                count,
            })
            .collect(),
        dropped_by_reason: guard_snapshot
            .dropped
            .into_iter()
            .map(|(reason, count)| DropCountDto {
                reason: drop_reason_key(reason).to_owned(),
                count,
            })
            .collect(),
        user_blocklist: user_blocklist.list(),
        last_search_ms,
        app_memory_bytes: current_process_working_set_bytes(),
        embedder_label: embedder_ui::embedder_display_label(&embedder_status),
        embedder_status: embedder_ui::EmbedderStatusDto::from_core(&embedder_status),
        autostart_enabled: autostart::is_enabled(),
        is_demo: cfg!(debug_assertions),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

fn add_blocked_app_inner(
    blocklist: &UserBlocklist,
    process_name: &str,
) -> Result<Vec<String>, String> {
    let trimmed = process_name.trim();
    if trimmed.is_empty() {
        return Err("process name cannot be empty".to_owned());
    }
    if trimmed.chars().count() > 128 {
        return Err("process name is too long".to_owned());
    }
    blocklist.add(trimmed);
    Ok(blocklist.list())
}

async fn delete_recent_memory_inner(store: SharedMemoryStore, minutes: u64) -> Result<u64, String> {
    let clamped_minutes = minutes.clamp(1, 1440);
    let since_ms = now_unix_ms().saturating_sub(clamped_minutes.saturating_mul(60_000));
    tokio::task::spawn_blocking(move || -> Result<u64, String> {
        let mut guard = store
            .lock()
            .map_err(|_| "memory store lock poisoned".to_owned())?;
        guard.delete_since(since_ms).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("delete recent task join failed: {e}"))?
}

async fn delete_all_memory_inner(store: SharedMemoryStore, confirm: bool) -> Result<u64, String> {
    if !confirm {
        return Err("confirmation required before deleting all memory".to_owned());
    }
    tokio::task::spawn_blocking(move || -> Result<u64, String> {
        let mut guard = store
            .lock()
            .map_err(|_| "memory store lock poisoned".to_owned())?;
        guard.delete_all().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("delete all task join failed: {e}"))?
}

async fn search_with_store(
    store: SharedMemoryStore,
    request: SearchRequest,
) -> Result<Vec<HitDto>, String> {
    let trimmed = request.query.trim().to_owned();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let limit = usize::try_from(request.k.clamp(1, 50)).unwrap_or(50);

    let hits = tokio::task::spawn_blocking(move || -> Result<Vec<CausalityQueryHit>, String> {
        let guard = store
            .lock()
            .map_err(|_| "memory store lock poisoned".to_owned())?;
        guard
            .hybrid_search_detailed(&trimmed, limit, &HybridSearchConfig::default())
            .map(|outcome| outcome.hits)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("search task join failed: {e}"))??;

    Ok(hits_to_dtos(hits))
}

fn hits_to_dtos(hits: Vec<CausalityQueryHit>) -> Vec<HitDto> {
    hits.into_iter()
        .filter(|hit| hit.score.is_finite())
        .map(HitDto::from)
        .collect()
}

pub(crate) fn show_overlay_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window(OVERLAY_WINDOW_LABEL) {
        let _ = exclude_from_capture(&window);
        let _ = window.center();
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("overlay://focus", ());
    }
}

pub(crate) fn toggle_overlay_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window(OVERLAY_WINDOW_LABEL) {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
        } else {
            show_overlay_window(app);
        }
    }
}

/// Result of attempting to exclude a window from screen capture / sharing / screenshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureProtectionStatus {
    ExcludedFromCapture,
    MonitorFallback,
    Failed,
    UnsupportedPlatform,
}

fn apply_affinity_with_fallback<F>(mut set_affinity: F) -> CaptureProtectionStatus
where
    F: FnMut(u32) -> Result<(), ()>,
{
    const AFFINITY_EXCLUDE_FROM_CAPTURE: u32 = 0x0000_0011; // WDA_EXCLUDEFROMCAPTURE
    const AFFINITY_MONITOR: u32 = 0x0000_0001; // WDA_MONITOR

    if set_affinity(AFFINITY_EXCLUDE_FROM_CAPTURE).is_ok() {
        eprintln!("synapse-mind: window capture protection active (WDA_EXCLUDEFROMCAPTURE)");
        return CaptureProtectionStatus::ExcludedFromCapture;
    }
    if set_affinity(AFFINITY_MONITOR).is_ok() {
        eprintln!("synapse-mind: window capture protection active (WDA_MONITOR fallback)");
        return CaptureProtectionStatus::MonitorFallback;
    }
    eprintln!("synapse-mind: window capture protection failed");
    CaptureProtectionStatus::Failed
}

#[cfg(windows)]
fn exclude_hwnd_from_capture(hwnd: windows::Win32::Foundation::HWND) -> CaptureProtectionStatus {
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WINDOW_DISPLAY_AFFINITY,
    };

    apply_affinity_with_fallback(|raw_affinity| {
        let affinity = match raw_affinity {
            0x0000_0011 => WDA_EXCLUDEFROMCAPTURE,
            0x0000_0001 => WDA_MONITOR,
            other => WINDOW_DISPLAY_AFFINITY(other),
        };
        // SAFETY: `hwnd` is passed directly to Win32 `SetWindowDisplayAffinity`, which validates
        // the handle synchronously, updates only the DWM display-affinity attribute, and retains
        // no pointers or references after returning.
        unsafe { SetWindowDisplayAffinity(hwnd, affinity) }.map_err(|_| ())
    })
}

/// Excludes a Tauri window from screen capture, screen recording, and screenshots.
///
/// Tries `WDA_EXCLUDEFROMCAPTURE` first, falls back to `WDA_MONITOR` on older Windows builds,
/// and logs only status (never content) if both fail without panicking.
pub fn exclude_from_capture(window: &tauri::WebviewWindow) -> CaptureProtectionStatus {
    #[cfg(windows)]
    {
        match window.hwnd() {
            Ok(raw_hwnd) => {
                let hwnd = windows::Win32::Foundation::HWND(raw_hwnd.0);
                exclude_hwnd_from_capture(hwnd)
            }
            Err(_) => {
                eprintln!("synapse-mind: window capture protection failed (hwnd unavailable)");
                CaptureProtectionStatus::Failed
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = window;
        CaptureProtectionStatus::UnsupportedPlatform
    }
}

/// Result of applying the Memory Panel window backdrop material (`Mica` -> `Acrylic` -> solid fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelBackdropStatus {
    Mica,
    Acrylic,
    SolidFallback,
    UnsupportedPlatform,
}

fn apply_backdrop_with_fallback<F>(mut set_backdrop: F) -> PanelBackdropStatus
where
    F: FnMut(u32) -> Result<(), ()>,
{
    const BACKDROP_MICA: u32 = 2; // DWMSBT_MAINWINDOW
    const BACKDROP_ACRYLIC: u32 = 3; // DWMSBT_TRANSIENTWINDOW

    if set_backdrop(BACKDROP_MICA).is_ok() {
        eprintln!("synapse-mind: panel backdrop active (Mica)");
        return PanelBackdropStatus::Mica;
    }
    if set_backdrop(BACKDROP_ACRYLIC).is_ok() {
        eprintln!("synapse-mind: panel backdrop active (Acrylic fallback)");
        return PanelBackdropStatus::Acrylic;
    }
    eprintln!("synapse-mind: panel backdrop fallback active (solid background)");
    PanelBackdropStatus::SolidFallback
}

#[cfg(windows)]
fn apply_hwnd_backdrop(hwnd: windows::Win32::Foundation::HWND) -> PanelBackdropStatus {
    use std::ffi::c_void;
    use windows::Win32::Graphics::Dwm::{
        DWM_SYSTEMBACKDROP_TYPE, DWMSBT_MAINWINDOW, DWMSBT_TRANSIENTWINDOW,
        DWMWA_SYSTEMBACKDROP_TYPE, DwmSetWindowAttribute,
    };

    apply_backdrop_with_fallback(|raw_backdrop| {
        let backdrop = match raw_backdrop {
            2 => DWMSBT_MAINWINDOW,
            3 => DWMSBT_TRANSIENTWINDOW,
            other => DWM_SYSTEMBACKDROP_TYPE(i32::try_from(other).unwrap_or(1)),
        };
        let size = u32::try_from(std::mem::size_of::<DWM_SYSTEMBACKDROP_TYPE>()).map_err(|_| ())?;
        // SAFETY: `hwnd` is validated synchronously by Win32 `DwmSetWindowAttribute`;
        // `&backdrop` points to a stack `DWM_SYSTEMBACKDROP_TYPE` value of exact byte length `size`
        // and no pointer is retained after the call returns.
        unsafe {
            DwmSetWindowAttribute(
                hwnd,
                DWMWA_SYSTEMBACKDROP_TYPE,
                (&raw const backdrop).cast::<c_void>(),
                size,
            )
        }
        .map_err(|_| ())
    })
}

/// Applies Windows 11 Mica to the Memory Panel window, falling back to Acrylic
/// and finally to the opaque CSS canvas if DWM backdrop attributes are unsupported.
pub fn apply_panel_backdrop(window: &tauri::WebviewWindow) -> PanelBackdropStatus {
    #[cfg(windows)]
    {
        match window.hwnd() {
            Ok(raw_hwnd) => {
                let hwnd = windows::Win32::Foundation::HWND(raw_hwnd.0);
                let status = apply_hwnd_backdrop(hwnd);
                if status == PanelBackdropStatus::Acrylic {
                    let _ = window.set_effects(
                        tauri::window::EffectsBuilder::new()
                            .effect(tauri::window::Effect::Acrylic)
                            .build(),
                    );
                }
                status
            }
            Err(_) => {
                eprintln!("synapse-mind: panel backdrop fallback active (hwnd unavailable)");
                PanelBackdropStatus::SolidFallback
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = window;
        PanelBackdropStatus::UnsupportedPlatform
    }
}

/// Starts the Tauri 2.0 overlay application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(feature = "gate2-hooks")]
    if gate2_hooks::try_signal_existing_instance() {
        return;
    }

    let _instance_guard = match singleton::acquire_default() {
        Ok(singleton::AcquireOutcome::Acquired(guard)) => guard,
        Ok(singleton::AcquireOutcome::AlreadyRunning) => {
            #[cfg(feature = "gate2-hooks")]
            if gate2_hooks::wait_and_signal_existing_instance(Duration::from_secs(3)) {
                return;
            }
            eprintln!("synapse-mind: another instance is already running; exiting.");
            return;
        }
        Err(err) => panic!("failed to acquire singleton mutex: {err}"),
    };

    let data_dir =
        keystore::resolve_data_dir().expect("failed to resolve Synapse Mind data directory");
    let key_path = data_dir.join(keystore::KEY_FILE_NAME);
    let db_path = data_dir.join(keystore::DB_FILE_NAME);
    let db_key = keystore::load_or_create_db_key(&key_path)
        .expect("failed to load or create DPAPI database key");

    let embedder = build_embedder().expect("failed to initialize embedder");
    let store = init_store_with_embedder(&db_path, &db_key, embedder.clone())
        .expect("failed to initialize MemoryStore");
    drop(db_key);

    let start_id = next_store_event_id(&store).expect("failed to read next_event_id");
    let guard_stats = GuardStats::new();
    let user_blocklist = UserBlocklist::new();
    let search_latency = Arc::new(SearchLatencyTracker::default());
    let setup_embedder = embedder.clone();
    let setup_embedder_store = Arc::clone(&store);
    #[cfg(feature = "fastembed")]
    let spawn_embedder = embedder.clone();
    let pipeline_store = Arc::clone(&store);
    let pipeline_stats = Arc::clone(&guard_stats);
    let pipeline_blocklist = Arc::clone(&user_blocklist);
    let pipeline: SharedPipeline = Arc::new(Mutex::new(None));
    let setup_pipeline = Arc::clone(&pipeline);
    let tray_pipeline = Arc::clone(&pipeline);
    let exit_pipeline = Arc::clone(&pipeline);
    let tray_state: SharedTray = Arc::new(Mutex::new(None));
    let setup_tray_state = Arc::clone(&tray_state);
    #[cfg(feature = "gate2-hooks")]
    let gate2_guard: Arc<Mutex<Option<gate2_hooks::Gate2HookGuard>>> = Arc::new(Mutex::new(None));
    #[cfg(feature = "gate2-hooks")]
    let setup_gate2_guard = Arc::clone(&gate2_guard);
    #[cfg(feature = "gate2-hooks")]
    let exit_gate2_guard = Arc::clone(&gate2_guard);

    let alt_space = Shortcut::new(Some(Modifiers::ALT), Code::Space);

    let app = tauri::Builder::default()
        .manage(store)
        .manage(embedder)
        .manage(guard_stats)
        .manage(user_blocklist)
        .manage(Arc::clone(&pipeline))
        .manage(tray_state)
        .manage(search_latency)
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(move |app, shortcut, event| {
                    if event.state() == ShortcutState::Pressed && shortcut == &alt_space {
                        toggle_overlay_window(app);
                    }
                })
                .build(),
        )
        .setup(move |app| {
            let controller = PipelineController::start(
                pipeline_store,
                start_id,
                pipeline_stats,
                pipeline_blocklist,
            );
            // Test-only (gate2-hooks): pause capture so memory measurements are
            // deterministic and not driven by desktop activity.
            #[cfg(feature = "gate2-hooks")]
            if gate2_hooks::has_pause_capture_flag(std::env::args())
                && let Err(err) = controller.pause_for(gate2_hooks::PAUSE_CAPTURE_DURATION)
            {
                eprintln!("synapse-mind: gate2-hooks pause-capture warning: {err}");
            }
            if let Ok(mut slot) = setup_pipeline.lock() {
                *slot = Some(controller);
            }

            if let Some(window) = app.get_webview_window("main") {
                let _ = exclude_from_capture(&window);
            }

            match tray::setup_tray(app.handle(), tray_pipeline) {
                Ok(tray_ctrl) => {
                    if let Ok(mut slot) = setup_tray_state.lock() {
                        *slot = Some(tray_ctrl);
                    }
                }
                Err(err) => {
                    eprintln!("synapse-mind: system tray warning: {err}");
                }
            }

            if let Err(err) = app.global_shortcut().register(alt_space) {
                eprintln!("synapse-mind: global shortcut registration warning: {err}");
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.center();
                    let _ = window.show();
                }
            }

            embedder_ui::spawn_embedder_status_relay(
                app.handle().clone(),
                setup_embedder,
                setup_embedder_store,
            );
            #[cfg(feature = "fastembed")]
            if let Err(err) = spawn_embedder.spawn_fastembed(app_fastembed_config()) {
                eprintln!("synapse-mind: embedder initialization warning: {err}");
            }
            #[cfg(all(windows, feature = "fastembed"))]
            spawn_working_set_trimmer(spawn_embedder.clone());

            #[cfg(feature = "gate2-hooks")]
            {
                let hook_guard = gate2_hooks::Gate2HookGuard::install(app.handle());
                if let Ok(mut slot) = setup_gate2_guard.lock() {
                    *slot = Some(hook_guard);
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::search,
            commands::hide_overlay,
            commands::is_demo_mode,
            commands::open_memory_panel,
            commands::open_overlay_with_query,
            commands::get_memory_panel_data,
            commands::pause_capture,
            commands::resume_capture,
            commands::add_blocked_app,
            commands::remove_blocked_app,
            commands::delete_recent_memory,
            commands::delete_all_memory,
            commands::set_autostart,
            commands::get_embedder_status,
            commands::retry_embedder_download
        ])
        .build(tauri::generate_context!())
        .expect("error while building synapse-mind");

    app.run(move |_app_handle, event| match event {
        tauri::RunEvent::ExitRequested {
            code: None, api, ..
        } => {
            api.prevent_exit();
        }
        tauri::RunEvent::Exit => {
            #[cfg(feature = "gate2-hooks")]
            if let Ok(mut slot) = exit_gate2_guard.lock() {
                drop(slot.take());
            }
            if let Ok(mut slot) = exit_pipeline.lock()
                && let Some(controller) = slot.take()
            {
                controller.stop();
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pipeline_routes_packets_through_guard_and_core_continuing_event_id() {
        let store = init_in_memory_store().expect("init in-memory store");
        let start_id = next_store_event_id(&store).expect("next_event_id");
        assert_eq!(start_id, 5, "4 demo blocks (1..=4) should yield start_id=5");

        let (tx_raw, rx_raw) =
            tokio::sync::mpsc::channel::<RawCapturePacket>(SENSOR_CHANNEL_CAPACITY);
        let (tx_masked, rx_masked) =
            tokio::sync::mpsc::channel::<MaskedMemoryBlock>(SENSOR_CHANNEL_CAPACITY);

        let guard_task = tokio::spawn(s_guard::run_with_start_id(rx_raw, tx_masked, start_id));
        let ingest_task = tokio::spawn(s_core::run_ingestion(Arc::clone(&store), rx_masked));

        let secret = "sk-live-supersecret99887766554433";
        tx_raw
            .send(RawCapturePacket {
                timestamp_ms: 2_000_000_000_001,
                process_id: 111,
                process_name: "1password.exe".to_owned(),
                window_title: "Vault".to_owned(),
                event_kind: s_types::EventKind::WindowFocusChanged,
                raw_payload: s_types::RawPayload::AccessibilityText(
                    "forbidden vault secret".to_owned(),
                ),
            })
            .await
            .expect("send blacklisted");

        tx_raw
            .send(RawCapturePacket {
                timestamp_ms: 2_000_000_000_002,
                process_id: 222,
                process_name: "Code.exe".to_owned(),
                window_title: "phase4.rs - S_Recall".to_owned(),
                event_kind: s_types::EventKind::AccessibilityTreeChanged { node_count: 2 },
                raw_payload: s_types::RawPayload::AccessibilityText(format!(
                    "phase4 pipeline verification token={secret}"
                )),
            })
            .await
            .expect("send masked");

        drop(tx_raw);
        guard_task.await.expect("guard joins");
        let ingested = ingest_task
            .await
            .expect("ingest joins")
            .expect("ingest succeeds");
        assert_eq!(
            ingested, 1,
            "only non-blacklisted packet should be ingested"
        );

        let hits = search_with_store(
            Arc::clone(&store),
            SearchRequest {
                query: "phase4 verification".to_owned(),
                k: 5,
            },
        )
        .await
        .expect("search succeeds");
        assert!(!hits.is_empty(), "ingested packet must be searchable");
        let hit = &hits[0];
        assert_eq!(
            hit.event_id, 6,
            "dropped packet consumed event_id=5; accepted packet gets 6"
        );
        assert!(!hit.summary_snippet.contains(secret));
        assert!(hit.summary_snippet.contains("[REDACTED_API_KEY]"));

        let next_after = next_store_event_id(&store).expect("next_event_id after ingest");
        assert_eq!(next_after, 7);
    }

    #[tokio::test]
    async fn search_returns_dto_with_causality_chain_and_never_exposes_text_hash() {
        let embedder = build_embedder().expect("embedder");
        let mut store = MemoryStore::open_in_memory(embedder).expect("open in-memory store");
        store.ingest_batch(&demo_blocks()).expect("ingest demo");
        let store = Arc::new(Mutex::new(store));

        let hits = search_with_store(
            Arc::clone(&store),
            SearchRequest {
                query: "sqlite-vec".to_owned(),
                k: 5,
            },
        )
        .await
        .expect("search succeeds");
        assert!(!hits.is_empty(), "expected at least one demo hit");
        assert!(
            hits.iter().any(|h| h.summary_snippet.contains("[DEMO]")),
            "demo hits must be clearly labeled [DEMO]"
        );
        assert!(
            hits.iter().any(|h| !h.causality_chain.is_empty()),
            "expected causality chain on demo hits"
        );

        let serialized = serde_json::to_value(&hits).expect("serialize HitDto");
        let json_text = serialized.to_string();
        for forbidden in [
            "text_hash",
            "clean_text",
            "redactions_count",
            "has_embedding_payload",
            "sanitized_title",
        ] {
            assert!(
                !json_text.contains(forbidden),
                "{forbidden} must never be serialized to UI"
            );
        }
    }

    #[tokio::test]
    async fn blank_query_returns_empty_without_error() {
        let store = init_in_memory_store().expect("init in-memory store");
        let hits = search_with_store(
            store,
            SearchRequest {
                query: "   ".to_owned(),
                k: 10,
            },
        )
        .await
        .expect("blank query succeeds");
        assert!(hits.is_empty());
    }

    #[test]
    fn non_finite_scores_are_dropped_before_ipc() {
        let hits = vec![
            CausalityQueryHit {
                event_id: 1,
                timestamp_ms: 10,
                score: f32::NAN,
                summary_snippet: "bad nan".to_owned(),
                matched_app: "app.exe".to_owned(),
                causality_chain: Vec::new(),
            },
            CausalityQueryHit {
                event_id: 2,
                timestamp_ms: 11,
                score: f32::INFINITY,
                summary_snippet: "bad inf".to_owned(),
                matched_app: "app.exe".to_owned(),
                causality_chain: Vec::new(),
            },
            CausalityQueryHit {
                event_id: 3,
                timestamp_ms: 12,
                score: 0.75,
                summary_snippet: "valid".to_owned(),
                matched_app: "app.exe".to_owned(),
                causality_chain: Vec::new(),
            },
        ];

        let dtos = hits_to_dtos(hits);
        assert_eq!(dtos.len(), 1);
        assert_eq!(dtos[0].event_id, 3);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn encrypted_store_persists_pipeline_events_across_reopen_with_dpapi_key() {
        struct TempDirGuard(std::path::PathBuf);
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let dir = TempDirGuard(
            std::env::temp_dir().join(format!("synapse-mind-phase4-e2e-{}", std::process::id())),
        );
        let _ = std::fs::remove_dir_all(&dir.0);
        let key_path = dir.0.join(keystore::KEY_FILE_NAME);
        let db_path = dir.0.join(keystore::DB_FILE_NAME);

        let key_first = keystore::load_or_create_db_key(&key_path).expect("create dpapi key");
        let store = init_store(&db_path, &key_first).expect("open encrypted store");
        let start_id = next_store_event_id(&store).expect("initial next_event_id");

        let (tx_raw, rx_raw) =
            tokio::sync::mpsc::channel::<RawCapturePacket>(SENSOR_CHANNEL_CAPACITY);
        let (tx_masked, rx_masked) =
            tokio::sync::mpsc::channel::<MaskedMemoryBlock>(SENSOR_CHANNEL_CAPACITY);

        let guard_task = tokio::spawn(s_guard::run_with_start_id(rx_raw, tx_masked, start_id));
        let ingest_task = tokio::spawn(s_core::run_ingestion(Arc::clone(&store), rx_masked));

        let secret = "sk-live-phase4reopen998877665544";
        tx_raw
            .send(RawCapturePacket {
                timestamp_ms: 2_000_000_000_123,
                process_id: 333,
                process_name: "Code.exe".to_owned(),
                window_title: "vault.rs - S_Recall".to_owned(),
                event_kind: s_types::EventKind::AccessibilityTreeChanged { node_count: 1 },
                raw_payload: s_types::RawPayload::AccessibilityText(format!(
                    "encrypted reopen check token={secret}"
                )),
            })
            .await
            .expect("send packet");

        drop(tx_raw);
        guard_task.await.expect("guard joins");
        assert_eq!(
            ingest_task.await.expect("ingest joins").expect("ingest ok"),
            1
        );
        drop(store);
        drop(key_first);

        let db_bytes = std::fs::read(&db_path).expect("encrypted db exists on disk");
        assert!(
            !db_bytes.starts_with(b"SQLite format 3\0"),
            "database file on disk must be SQLCipher-encrypted, never plaintext SQLite"
        );

        let key_reloaded = keystore::load_or_create_db_key(&key_path).expect("reload dpapi key");
        let wrong_key = DbKey::generate();
        assert!(
            init_store(&db_path, &wrong_key).is_err(),
            "wrong key must be rejected when reopening encrypted store"
        );

        let reopened = init_store(&db_path, &key_reloaded).expect("reopen with valid dpapi key");
        let next_after = next_store_event_id(&reopened).expect("next_event_id after reopen");
        assert_eq!(next_after, start_id + 1);

        let hits = search_with_store(
            reopened,
            SearchRequest {
                query: "encrypted reopen check".to_owned(),
                k: 5,
            },
        )
        .await
        .expect("search after reopen");
        assert!(
            !hits.is_empty(),
            "persisted event must be searchable after reopen"
        );
        assert_eq!(hits[0].event_id, start_id);
        assert!(!hits[0].summary_snippet.contains(secret));
        assert!(hits[0].summary_snippet.contains("[REDACTED_API_KEY]"));
    }

    #[test]
    fn capture_protection_fallback_and_failure_never_panic() {
        let mut calls = Vec::new();
        let ok = apply_affinity_with_fallback(|flag| {
            calls.push(flag);
            Ok(())
        });
        assert_eq!(ok, CaptureProtectionStatus::ExcludedFromCapture);
        assert_eq!(calls, vec![0x0000_0011]);

        let mut calls = Vec::new();
        let fallback = apply_affinity_with_fallback(|flag| {
            calls.push(flag);
            if flag == 0x0000_0011 { Err(()) } else { Ok(()) }
        });
        assert_eq!(fallback, CaptureProtectionStatus::MonitorFallback);
        assert_eq!(calls, vec![0x0000_0011, 0x0000_0001]);

        let mut calls = Vec::new();
        let failed = apply_affinity_with_fallback(|flag| {
            calls.push(flag);
            Err(())
        });
        assert_eq!(failed, CaptureProtectionStatus::Failed);
        assert_eq!(calls, vec![0x0000_0011, 0x0000_0001]);
    }

    #[cfg(windows)]
    #[test]
    fn capture_protection_handles_invalid_and_real_hwnd_without_panic() {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WS_POPUP,
        };
        use windows::core::PCWSTR;

        // Invalid/null HWND must hit the real Win32 error path without panicking.
        assert_eq!(
            exclude_hwnd_from_capture(HWND::default()),
            CaptureProtectionStatus::Failed
        );

        let class_name: Vec<u16> = "STATIC".encode_utf16().chain(std::iter::once(0)).collect();
        let title: Vec<u16> = "synapse-mind-wda-test"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `class_name` and `title` are null-terminated UTF-16 strings alive across
        // `CreateWindowExW`; a valid top-level `STATIC` window is created and destroyed below.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(title.as_ptr()),
                WS_POPUP,
                0,
                0,
                1,
                1,
                None,
                None,
                None,
                None,
            )
        }
        .expect("create hidden top-level test window");

        let status = exclude_hwnd_from_capture(hwnd);
        // SAFETY: `hwnd` was created by `CreateWindowExW` above and is destroyed once.
        let _ = unsafe { DestroyWindow(hwnd) };

        assert!(
            matches!(
                status,
                CaptureProtectionStatus::ExcludedFromCapture
                    | CaptureProtectionStatus::MonitorFallback
            ),
            "expected capture protection to succeed on real top-level HWND, got {status:?}"
        );
    }

    #[test]
    fn local_day_start_computes_utc_midnight_for_positive_and_negative_offsets() {
        // 2026-11-19T01:30:00Z = 1_795_051_800_000 ms (if epoch-based exact multiple)
        let day_ms: u64 = 86_400_000;
        let utc_midnight: u64 = 20_000 * day_ms;
        let ts_01_30_utc = utc_midnight + 90 * 60_000;

        // UTC+3 (tz_offset_minutes = +180): local time is 04:30 -> local midnight is 21:00Z prev day
        assert_eq!(
            local_day_start_ms(ts_01_30_utc, 180),
            utc_midnight - 180 * 60_000
        );

        // UTC-5 (tz_offset_minutes = -300): local time is 20:30 prev day -> local midnight is 05:00Z prev day
        assert_eq!(
            local_day_start_ms(ts_01_30_utc, -300),
            utc_midnight - day_ms + 300 * 60_000
        );
    }

    #[tokio::test]
    async fn memory_panel_data_reflects_guard_stats_blocklist_and_deletions() {
        let store = init_in_memory_store().expect("init in-memory store");
        let start_id = next_store_event_id(&store).expect("next_event_id");
        let guard_stats = GuardStats::new();
        let blocklist = UserBlocklist::new();
        let added = add_blocked_app_inner(&blocklist, "Slack.exe").expect("add blocked app");
        assert_eq!(added, vec!["slack".to_owned()]);
        assert!(add_blocked_app_inner(&blocklist, "   ").is_err());

        let (tx_raw, rx_raw) =
            tokio::sync::mpsc::channel::<RawCapturePacket>(SENSOR_CHANNEL_CAPACITY);
        let (tx_masked, rx_masked) =
            tokio::sync::mpsc::channel::<MaskedMemoryBlock>(SENSOR_CHANNEL_CAPACITY);

        let guard_task = tokio::spawn(s_guard::run_with_options(
            rx_raw,
            tx_masked,
            start_id,
            Arc::clone(&guard_stats),
            Arc::clone(&blocklist),
        ));
        let ingest_task = tokio::spawn(s_core::run_ingestion(Arc::clone(&store), rx_masked));

        let now_ms = now_unix_ms();
        tx_raw
            .send(RawCapturePacket {
                timestamp_ms: now_ms,
                process_id: 101,
                process_name: "Slack.exe".to_owned(),
                window_title: "General".to_owned(),
                event_kind: s_types::EventKind::WindowFocusChanged,
                raw_payload: s_types::RawPayload::AccessibilityText("blocked chat".to_owned()),
            })
            .await
            .expect("send user-blocked packet");

        let secret = "sk-live-paneltest998877665544";
        tx_raw
            .send(RawCapturePacket {
                timestamp_ms: now_ms,
                process_id: 102,
                process_name: "Code.exe".to_owned(),
                window_title: "panel.rs - S_Recall".to_owned(),
                event_kind: s_types::EventKind::AccessibilityTreeChanged { node_count: 1 },
                raw_payload: s_types::RawPayload::AccessibilityText(format!(
                    "panel stats verification token={secret}"
                )),
            })
            .await
            .expect("send masked packet");

        drop(tx_raw);
        guard_task.await.expect("guard joins");
        assert_eq!(
            ingest_task.await.expect("ingest joins").expect("ingest ok"),
            1
        );

        let panel = build_memory_panel_data(
            Arc::clone(&store),
            Arc::clone(&guard_stats),
            Arc::clone(&blocklist),
            SensorStatusDto {
                state: "active".to_owned(),
                paused: false,
                pause_remaining_secs: None,
            },
            EmbedderStatus::Ready,
            Some(12.5),
            180,
        )
        .await
        .expect("build panel data");

        assert_eq!(panel.total_events, 5);
        assert_eq!(panel.dropped_total, 1);
        assert_eq!(panel.user_blocked_count, 1);
        assert_eq!(panel.user_blocklist, vec!["slack".to_owned()]);
        assert_eq!(panel.last_search_ms, Some(12.5));
        assert!(panel.redactions_total >= 2);
        assert!(
            panel
                .redactions_by_kind
                .iter()
                .any(|t| t.tag == "[REDACTED_API_KEY]" && t.count == 1)
        );
        let serialized = serde_json::to_string(&panel).expect("serialize MemoryPanelDto");
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains("text_hash"));
        assert!(!serialized.contains("clean_text"));

        let deleted_recent = delete_recent_memory_inner(Arc::clone(&store), 15)
            .await
            .expect("delete recent");
        assert_eq!(deleted_recent, 5);

        assert!(
            delete_all_memory_inner(Arc::clone(&store), false)
                .await
                .is_err(),
            "delete_all without explicit confirm=true must error"
        );
        let deleted_all = delete_all_memory_inner(Arc::clone(&store), true)
            .await
            .expect("delete all");
        assert_eq!(deleted_all, 0);
    }

    #[test]
    fn window_label_guard_rejects_cross_window_calls() {
        assert!(ensure_window_label("panel", PANEL_WINDOW_LABEL).is_ok());
        assert!(ensure_window_label("main", OVERLAY_WINDOW_LABEL).is_ok());
        assert!(ensure_window_label("main", PANEL_WINDOW_LABEL).is_err());
        assert!(ensure_window_label("panel", OVERLAY_WINDOW_LABEL).is_err());
    }

    #[test]
    fn redaction_label_table_maps_all_known_kinds_and_unknown_fallback() {
        let stats = GuardStats::new();
        for (kind, _) in stats.snapshot().redactions {
            let label = redaction_display_label(kind);
            assert_ne!(
                label, "Diğer gizli bilgi",
                "missing Turkish label mapping for s-guard kind '{kind}'"
            );
        }

        assert_eq!(redaction_display_label("API_KEY"), "API anahtarı");
        assert_eq!(
            redaction_display_label("[REDACTED_JWT]"),
            "JWT / oturum belirteci"
        );
        assert_eq!(redaction_display_label("IBAN"), "IBAN");
        assert_eq!(redaction_display_label("PHONE"), "Telefon");
        assert_eq!(
            redaction_display_label("CONNECTION_STRING"),
            "Bağlantı dizesi"
        );
        assert_eq!(
            redaction_display_label("UNKNOWN_SECRET"),
            "Diğer gizli bilgi"
        );
    }

    #[test]
    fn panel_backdrop_fallback_chain_tries_mica_then_acrylic_then_solid() {
        let mut calls = Vec::new();
        let mica = apply_backdrop_with_fallback(|kind| {
            calls.push(kind);
            Ok(())
        });
        assert_eq!(mica, PanelBackdropStatus::Mica);
        assert_eq!(calls, vec![2]);

        let mut calls = Vec::new();
        let acrylic = apply_backdrop_with_fallback(|kind| {
            calls.push(kind);
            if kind == 2 { Err(()) } else { Ok(()) }
        });
        assert_eq!(acrylic, PanelBackdropStatus::Acrylic);
        assert_eq!(calls, vec![2, 3]);

        let mut calls = Vec::new();
        let solid = apply_backdrop_with_fallback(|kind| {
            calls.push(kind);
            Err(())
        });
        assert_eq!(solid, PanelBackdropStatus::SolidFallback);
        assert_eq!(calls, vec![2, 3]);
    }

    #[cfg(windows)]
    #[test]
    fn panel_backdrop_handles_invalid_and_real_hwnd_without_panic() {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WS_POPUP,
        };
        use windows::core::PCWSTR;

        assert_eq!(
            apply_hwnd_backdrop(HWND::default()),
            PanelBackdropStatus::SolidFallback
        );

        let class_name: Vec<u16> = "STATIC".encode_utf16().chain(std::iter::once(0)).collect();
        let title: Vec<u16> = "synapse-mind-backdrop-test"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `class_name` and `title` are null-terminated UTF-16 strings alive across
        // `CreateWindowExW`; the hidden top-level window is destroyed immediately after the test.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(title.as_ptr()),
                WS_POPUP,
                0,
                0,
                1,
                1,
                None,
                None,
                None,
                None,
            )
        }
        .expect("create hidden top-level backdrop test window");

        let status = apply_hwnd_backdrop(hwnd);
        // SAFETY: `hwnd` was created by `CreateWindowExW` above and is destroyed once.
        let _ = unsafe { DestroyWindow(hwnd) };

        assert!(
            matches!(
                status,
                PanelBackdropStatus::Mica
                    | PanelBackdropStatus::Acrylic
                    | PanelBackdropStatus::SolidFallback
            ),
            "unexpected backdrop status: {status:?}"
        );
    }

    #[test]
    fn gate2_hooks_feature_is_off_by_default() {
        #[cfg(not(feature = "gate2-hooks"))]
        const {
            assert!(!cfg!(feature = "gate2-hooks"));
        }
        #[cfg(feature = "gate2-hooks")]
        const {
            assert!(cfg!(feature = "gate2-hooks"));
        }
    }

    #[test]
    fn multi_window_label_guard_allows_listed_windows_only() {
        assert!(
            ensure_window_label_in("main", &[OVERLAY_WINDOW_LABEL, PANEL_WINDOW_LABEL]).is_ok()
        );
        assert!(
            ensure_window_label_in("panel", &[OVERLAY_WINDOW_LABEL, PANEL_WINDOW_LABEL]).is_ok()
        );
        assert!(
            ensure_window_label_in("other", &[OVERLAY_WINDOW_LABEL, PANEL_WINDOW_LABEL]).is_err()
        );
    }

    #[tokio::test]
    async fn search_falls_back_to_bm25_when_managed_embedder_downloading_or_failed() {
        struct UnreachableEmbedder;
        impl s_core::Embedder for UnreachableEmbedder {
            fn embed_batch(&self, texts: &[&str]) -> s_core::Result<Vec<Vec<f32>>> {
                Ok(vec![vec![0.0_f32; s_core::EMBEDDING_DIM]; texts.len()])
            }
        }

        let managed = ManagedEmbedder::new();
        assert_eq!(managed.status(), EmbedderStatus::NotDownloaded);

        let mut store = MemoryStore::open_in_memory(managed.clone()).expect("open in-memory");
        store.ingest_batch(&demo_blocks()).expect("ingest demo");
        let shared = Arc::new(Mutex::new(store));

        // 1) While model is not yet ready, keyword BM25 search continues returning hits cleanly.
        let hits = search_with_store(
            Arc::clone(&shared),
            SearchRequest {
                query: "sqlite_vec".to_owned(),
                k: 5,
            },
        )
        .await
        .expect("BM25 search succeeds before model download completes");
        assert!(!hits.is_empty());

        // 2) Simulate download progress callback followed by offline failure -> Failed state.
        let err = managed
            .initialize_with::<_, UnreachableEmbedder>(|progress| {
                progress(33_550_000, Some(67_100_000));
                Err(s_core::CoreError::EmbedderUnavailable(
                    "simulated network failure".to_owned(),
                ))
            })
            .expect_err("simulated loader failure should return error");
        assert!(err.to_string().contains("simulated"));
        assert!(managed.status().is_failed());

        let dto = embedder_ui::EmbedderStatusDto::from_core(&managed.status());
        assert_eq!(dto.state, embedder_ui::EmbedderStateKind::Failed);
        assert_eq!(
            dto.message.as_deref(),
            Some(embedder_ui::SEMANTIC_DISABLED_NOTE)
        );

        let fallback_hits = search_with_store(
            shared,
            SearchRequest {
                query: "sqlite_vec".to_owned(),
                k: 5,
            },
        )
        .await
        .expect("BM25 search remains available when embedder failed");
        assert!(!fallback_hits.is_empty());
    }
}
