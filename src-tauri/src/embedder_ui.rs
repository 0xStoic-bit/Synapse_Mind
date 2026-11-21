//! Embedder lifecycle status DTOs and Tauri event relay for Görev 3.

use std::time::{Duration, Instant};

use s_core::{EmbedderStatus, ManagedEmbedder};
use serde::Serialize;
use tauri::Emitter;

use crate::SharedMemoryStore;

/// Tauri event emitted to all windows whenever semantic embedder readiness changes.
pub const EMBEDDER_STATUS_EVENT: &str = "embedder://status";

/// User-facing fallback notice displayed when the local embedding model fails to load.
pub const SEMANTIC_DISABLED_NOTE: &str = "Anlamsal arama kapalı, kelime araması çalışıyor";

const DOWNLOAD_EMIT_THROTTLE: Duration = Duration::from_millis(120);
const BACKFILL_BATCH_LIMIT: usize = 128;

/// Coarse semantic embedder lifecycle phase exposed to frontend windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedderStateKind {
    NotDownloaded,
    Downloading,
    Ready,
    Failed,
}

/// Zero-trust-safe IPC snapshot of [`s_core::EmbedderStatus`].
/// Never forwards raw filesystem paths or internal error text to WebView windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmbedderStatusDto {
    pub state: EmbedderStateKind,
    pub bytes: Option<u64>,
    pub total: Option<u64>,
    pub progress_pct: Option<u8>,
    pub message: Option<String>,
}

impl EmbedderStatusDto {
    /// Converts `s_core::EmbedderStatus` into a frontend-safe DTO.
    pub fn from_core(status: &EmbedderStatus) -> Self {
        match status {
            EmbedderStatus::NotDownloaded => Self {
                state: EmbedderStateKind::NotDownloaded,
                bytes: None,
                total: None,
                progress_pct: None,
                message: None,
            },
            EmbedderStatus::Downloading { bytes, total } => {
                let progress_pct = total.and_then(|total_bytes| {
                    if total_bytes == 0 {
                        None
                    } else {
                        let pct = (u128::from(*bytes).saturating_mul(100)
                            / u128::from(total_bytes))
                        .min(100);
                        u8::try_from(pct).ok()
                    }
                });
                Self {
                    state: EmbedderStateKind::Downloading,
                    bytes: Some(*bytes),
                    total: *total,
                    progress_pct,
                    message: None,
                }
            }
            EmbedderStatus::Ready => Self {
                state: EmbedderStateKind::Ready,
                bytes: None,
                total: None,
                progress_pct: Some(100),
                message: None,
            },
            EmbedderStatus::Failed(_) => Self {
                state: EmbedderStateKind::Failed,
                bytes: None,
                total: None,
                progress_pct: None,
                message: Some(SEMANTIC_DISABLED_NOTE.to_owned()),
            },
        }
    }
}

/// Human-readable status label for the Memory Panel's System card.
pub fn embedder_display_label(status: &EmbedderStatus) -> String {
    if !cfg!(feature = "fastembed") {
        return "DevHashEmbedder (dev) · yerel".to_owned();
    }
    match status {
        EmbedderStatus::Ready => "bge-small-en-v1.5 (FP32+INT8) · yerel".to_owned(),
        EmbedderStatus::Downloading { .. } => {
            "bge-small-en-v1.5 (indiriliyor · BM25 aktif)".to_owned()
        }
        EmbedderStatus::NotDownloaded => "bge-small-en-v1.5 (beklemede · BM25 aktif)".to_owned(),
        EmbedderStatus::Failed(_) => "bge-small-en-v1.5 (devre dışı · kelime araması)".to_owned(),
    }
}

/// Decides whether a new [`EmbedderStatusDto`] should be emitted over Tauri IPC.
/// Variant transitions and initial total-byte discoveries bypass throttling.
pub fn should_emit_status(
    previous: &EmbedderStatusDto,
    next: &EmbedderStatusDto,
    elapsed_since_last: Duration,
    throttle: Duration,
) -> bool {
    if previous.state != next.state {
        return true;
    }
    if next.state != EmbedderStateKind::Downloading {
        return previous != next;
    }
    if previous.total.is_none() && next.total.is_some() {
        return true;
    }
    previous != next && elapsed_since_last >= throttle
}

/// Subscribes to `embedder` status transitions, emits `embedder://status` to all
/// Tauri windows, and runs a chunked background embedding backfill when the embedder is (or becomes) `Ready`.
pub fn spawn_embedder_status_relay(
    app: tauri::AppHandle,
    embedder: ManagedEmbedder,
    store: SharedMemoryStore,
) {
    let mut rx = embedder.subscribe();
    let initial = EmbedderStatusDto::from_core(&rx.borrow().clone());
    let _ = app.emit(EMBEDDER_STATUS_EVENT, &initial);
    if initial.state == EmbedderStateKind::Ready {
        spawn_chunked_backfill(std::sync::Arc::clone(&store));
    }

    tauri::async_runtime::spawn(async move {
        let mut last_emitted = initial;
        let mut last_emit_at = Instant::now();

        while rx.changed().await.is_ok() {
            let next_raw = rx.borrow_and_update().clone();
            let next_dto = EmbedderStatusDto::from_core(&next_raw);
            let became_ready = last_emitted.state != EmbedderStateKind::Ready
                && next_dto.state == EmbedderStateKind::Ready;

            if should_emit_status(
                &last_emitted,
                &next_dto,
                last_emit_at.elapsed(),
                DOWNLOAD_EMIT_THROTTLE,
            ) {
                let _ = app.emit(EMBEDDER_STATUS_EVENT, &next_dto);
                last_emitted = next_dto;
                last_emit_at = Instant::now();
            }

            if became_ready {
                spawn_chunked_backfill(std::sync::Arc::clone(&store));
            }
        }
    });
}

/// Pause between backfill chunks so live capture and Alt+Space searches can take the store
/// lock in between and the CPU is not monopolized on first launch after an upgrade.
const BACKFILL_CHUNK_PAUSE: Duration = Duration::from_millis(50);
/// Upper bound on chunks per run (128 × 4096 ≈ 520k events); a later `Ready` resumes.
const BACKFILL_MAX_CHUNKS: usize = 4096;

/// Re-embeds events without vectors in chunks of [`BACKFILL_BATCH_LIMIT`], releasing the
/// store lock between chunks. `backfill_missing_embeddings` first reconciles the stored
/// embedding model id, so a v0.1.0 database (DevHash vectors) is cleared and fully
/// re-vectorized with the real model; an interrupted run resumes on the next launch.
fn spawn_chunked_backfill(store: SharedMemoryStore) {
    tauri::async_runtime::spawn_blocking(move || {
        for _ in 0..BACKFILL_MAX_CHUNKS {
            let filled = match store.lock() {
                Ok(mut guard) => match guard.backfill_missing_embeddings(BACKFILL_BATCH_LIMIT) {
                    Ok(n) => n,
                    Err(err) => {
                        eprintln!("synapse-mind: embedding backfill warning: {err}");
                        return;
                    }
                },
                Err(_) => return,
            };
            if filled == 0 {
                return;
            }
            std::thread::sleep(BACKFILL_CHUNK_PAUSE);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_dto_maps_all_embedder_variants_safely() {
        let not_dl = EmbedderStatusDto::from_core(&EmbedderStatus::NotDownloaded);
        assert_eq!(not_dl.state, EmbedderStateKind::NotDownloaded);
        assert_eq!(not_dl.progress_pct, None);
        assert_eq!(not_dl.message, None);

        let dl_known = EmbedderStatusDto::from_core(&EmbedderStatus::Downloading {
            bytes: 33_550_000,
            total: Some(67_100_000),
        });
        assert_eq!(dl_known.state, EmbedderStateKind::Downloading);
        assert_eq!(dl_known.progress_pct, Some(50));
        assert_eq!(dl_known.bytes, Some(33_550_000));
        assert_eq!(dl_known.total, Some(67_100_000));

        let dl_unknown = EmbedderStatusDto::from_core(&EmbedderStatus::Downloading {
            bytes: 1024,
            total: None,
        });
        assert_eq!(dl_unknown.state, EmbedderStateKind::Downloading);
        assert_eq!(dl_unknown.progress_pct, None);

        let dl_zero_total = EmbedderStatusDto::from_core(&EmbedderStatus::Downloading {
            bytes: 100,
            total: Some(0),
        });
        assert_eq!(dl_zero_total.progress_pct, None);

        let ready = EmbedderStatusDto::from_core(&EmbedderStatus::Ready);
        assert_eq!(ready.state, EmbedderStateKind::Ready);
        assert_eq!(ready.progress_pct, Some(100));

        let secret_path = r"C:\Users\alice\AppData\Local\SynapseMind\models\onnx";
        let failed = EmbedderStatusDto::from_core(&EmbedderStatus::Failed(format!(
            "download failed at {secret_path}"
        )));
        assert_eq!(failed.state, EmbedderStateKind::Failed);
        assert_eq!(failed.message.as_deref(), Some(SEMANTIC_DISABLED_NOTE));
        assert!(
            !failed
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("alice"),
            "raw OS paths must never reach frontend DTOs"
        );
    }

    #[test]
    fn emit_throttle_passes_transitions_and_caps_frequent_chunks() {
        let dl1 = EmbedderStatusDto::from_core(&EmbedderStatus::Downloading {
            bytes: 1000,
            total: Some(10_000),
        });
        let dl2 = EmbedderStatusDto::from_core(&EmbedderStatus::Downloading {
            bytes: 1500,
            total: Some(10_000),
        });
        let ready = EmbedderStatusDto::from_core(&EmbedderStatus::Ready);
        let throttle = Duration::from_millis(120);

        assert!(!should_emit_status(
            &dl1,
            &dl2,
            Duration::from_millis(20),
            throttle
        ));
        assert!(should_emit_status(
            &dl1,
            &dl2,
            Duration::from_millis(150),
            throttle
        ));
        assert!(
            should_emit_status(&dl2, &ready, Duration::from_millis(1), throttle),
            "terminal state transitions must never be throttled"
        );
    }
}
