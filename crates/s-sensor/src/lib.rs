//! # s-sensor — Olay Güdümlü Sensörler (Katman 1)
//!
//! Sahibi: `os-sensor-agent`. Çıktı: `RawCapturePacket` →
//! `tokio::sync::mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY)`.
//!
//! Kapsam:
//! - `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` odak değişimi takibi
//! - Odaktaki pencerede `AccessibilityTreeChanged` metin akışı takibi (debounce + değişim eşiği)
//! - Windows UI Automation ile odaktaki pencerenin metin düğümleri (`AccessibilityText`)
//! - `AddClipboardFormatListener` ile pano dinleyicisi ve format sınıflandırması (`ClipboardFormat`)
//! - Kaynak farkındalıklı kontrolcü (`Active` / `Batching` / `Suspended`)
//! - `tokio::sync::mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY)` (128) hattı
//!
//! Periyodik ekran görüntüsü YASAK; xcap/pHash fallback henüz eklenmemiştir.

pub mod clipboard;
pub mod controller;
pub mod uia;
pub mod uia_worker;

#[cfg(windows)]
mod win32_hook;

use std::fmt;
use std::time::Duration;

pub use controller::{
    BatchQueue, ControllerConfig, ControllerMachineState, ControllerState, PowerSignals,
    ResourceSignals, StepOutcome, UserNotificationState, step_controller_state,
    step_controller_state_with_pause,
};
pub use s_types::{
    ClipboardFormat, EventKind, RawCapturePacket, RawPayload, SENSOR_CHANNEL_CAPACITY,
};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::watch;
pub use uia::{
    AccessibilityStreamConfig, FocusGate, TextDelta, TextDeltaTracker, TreeChangeDebouncer,
    meets_change_threshold,
};
pub use uia_worker::{
    DEFAULT_WORKER_TIMEOUT, ExtractionStats, UiaIsolation, UiaProbe, WORKER_ARG,
    run_uia_worker_if_requested,
};

/// Odak değişimi sonrası pencere yerleşme beklemesi (Alt+Tab ara pencerelerini eler).
pub const DEFAULT_FOCUS_SETTLE: Duration = Duration::from_millis(250);
/// Aynı `(HWND, başlık)` için yeniden odak çıkarımı soğuma süresi.
pub const DEFAULT_FOCUS_COOLDOWN: Duration = Duration::from_millis(2000);

/// UI Automation, pano okuma ve kaynak kontrolcüsü yapılandırması.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SensorConfig {
    /// UIA ağacında inilecek en fazla derinlik.
    pub max_uia_depth: usize,
    /// Tek odak olayında ziyaret edilecek en fazla UIA düğüm sayısı.
    pub max_uia_nodes: u32,
    /// Tek pakette toplanacak en fazla metin boyutu (bayt).
    pub max_uia_text_bytes: usize,
    /// Odak aynı HWND'de bu kadar kalmadan çıkarım yapılmaz (varsayılan: 250 ms).
    pub focus_settle: Duration,
    /// Aynı HWND + aynı başlık için yeniden odak çıkarımı soğuma süresi (varsayılan: 2 s).
    pub focus_cooldown: Duration,
    /// Odaktaki pencerenin `AccessibilityTreeChanged` metin akışı eşikleri.
    pub accessibility_stream: AccessibilityStreamConfig,
    /// Kaynak farkındalıklı kontrolcü aralık ve eşikleri.
    pub controller: ControllerConfig,
    /// UIA çıkarımının yalıtımı (varsayılan: önceden ısıtılmış tek kullanımlık işçi süreç).
    pub uia_isolation: UiaIsolation,
    /// İşçi süreç başına zaman aşımı (ısıtma / çıkarım); aşılırsa işçi öldürülür.
    pub uia_worker_timeout: Duration,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            max_uia_depth: 12,
            max_uia_nodes: 256,
            max_uia_text_bytes: 64 * 1024,
            focus_settle: DEFAULT_FOCUS_SETTLE,
            focus_cooldown: DEFAULT_FOCUS_COOLDOWN,
            accessibility_stream: AccessibilityStreamConfig::default(),
            controller: ControllerConfig::default(),
            uia_isolation: UiaIsolation::default(),
            uia_worker_timeout: DEFAULT_WORKER_TIMEOUT,
        }
    }
}

/// Yalnızca güvenli metadata alanlarını taşır.
///
/// Ham pencere başlığı, süreç adı veya ham içerik ASLA bu yapıda yer almaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    pub event_kind: EventKind,
    pub process_id: u32,
    pub timestamp_ms: u64,
    pub text_len: usize,
}

impl fmt::Display for PacketMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "event={:?} pid={} ts_ms={} text_len={}",
            self.event_kind, self.process_id, self.timestamp_ms, self.text_len
        )
    }
}

/// `RawCapturePacket` içinden kopyalama veya taşıma yapmadan yalnızca metadata çıkarır.
pub fn extract_metadata(packet: &RawCapturePacket) -> PacketMetadata {
    let text_len = match &packet.raw_payload {
        RawPayload::AccessibilityText(s) | RawPayload::ClipboardText(s) => s.len(),
        RawPayload::ScreenFrame { pixels_rgba, .. } => pixels_rgba.len(),
    };

    PacketMetadata {
        event_kind: packet.event_kind.clone(),
        process_id: packet.process_id,
        timestamp_ms: packet.timestamp_ms,
        text_len,
    }
}

/// Sensör başlatma ve çalışma hataları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensorError {
    ComInitFailed(i32),
    UiaInitFailed(i32),
    Win32SetupFailed(i32),
    ThreadSpawnFailed(String),
    UnsupportedPlatform,
    /// `UiaIsolation::Worker` istendi ama ana `main` [`run_uia_worker_if_requested`] çağırmadı.
    UiaWorkerHostMissing,
    /// İşçi el sıkışması başarısız (statik sebep etiketi; ham içerik yok).
    UiaWorkerUnavailable(&'static str),
}

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComInitFailed(hr) => write!(f, "COM başlatılamadı (HRESULT=0x{hr:08X})"),
            Self::UiaInitFailed(hr) => {
                write!(f, "UI Automation başlatılamadı (HRESULT=0x{hr:08X})")
            }
            Self::Win32SetupFailed(code) => {
                write!(f, "Win32 kanca kurulumu başarısız (kod={code})")
            }
            Self::ThreadSpawnFailed(msg) => write!(f, "sensör iş parçacığı başlatılamadı: {msg}"),
            Self::UnsupportedPlatform => {
                write!(f, "s-sensor Win32/UIA yalnızca Windows'ta desteklenir")
            }
            Self::UiaWorkerHostMissing => write!(
                f,
                "UIA işçi kancası kurulu değil: main başında s_sensor::run_uia_worker_if_requested() çağrılmalı"
            ),
            Self::UiaWorkerUnavailable(why) => write!(f, "UIA işçi süreci kullanılamıyor ({why})"),
        }
    }
}

impl std::error::Error for SensorError {}

/// Çalışan Win32/UIA sensör ve kontrolcü iş parçacıklarının yaşam döngüsü tutamacı.
pub struct SensorHandle {
    #[cfg(windows)]
    inner: win32_hook::Win32SensorHandles,
    #[cfg(not(windows))]
    state_rx: watch::Receiver<ControllerState>,
}

impl SensorHandle {
    /// Kontrolcünün güncel durumunu döndürür.
    pub fn controller_state(&self) -> ControllerState {
        #[cfg(windows)]
        {
            *self.inner.state_rx.borrow()
        }
        #[cfg(not(windows))]
        {
            *self.state_rx.borrow()
        }
    }

    /// Kontrolcü durum geçişlerini izlemek için `watch::Receiver<ControllerState>` döndürür.
    pub fn subscribe_state(&self) -> watch::Receiver<ControllerState> {
        #[cfg(windows)]
        {
            self.inner.state_rx.clone()
        }
        #[cfg(not(windows))]
        {
            self.state_rx.clone()
        }
    }

    /// Sensör yakalamasını belirtilen süre boyunca manuel olarak duraklatır (`Suspended`).
    ///
    /// Süre dolduğunda veya [`SensorHandle::resume`] çağrıldığında kontrolcü
    /// donanım/güç sinyallerine göre `Active` veya `Batching` durumuna döner.
    /// `Duration::ZERO` verilirse varsa aktif manuel duraklatmayı sonlandırır.
    pub fn pause_for(&self, duration: Duration) {
        #[cfg(windows)]
        self.inner.pause_for(duration);
        #[cfg(not(windows))]
        let _ = duration;
    }

    /// Manuel duraklatmayı erken sonlandırır ve kontrolcüyü canlı sinyallerle devam ettirir.
    pub fn resume(&self) {
        #[cfg(windows)]
        self.inner.resume();
    }

    /// Manuel `pause_for` duraklatmasının halen aktif olup olmadığını döndürür.
    pub fn is_paused(&self) -> bool {
        #[cfg(windows)]
        {
            self.inner.is_paused()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Aktif bir manuel duraklatma varsa kalan süreyi döndürür.
    pub fn pause_remaining(&self) -> Option<Duration> {
        #[cfg(windows)]
        {
            self.inner.pause_remaining()
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// Sensör kancalarını ve kontrolcüyü kapatır, arka plan iş parçacıklarını bekler.
    pub fn stop(mut self) {
        #[cfg(windows)]
        self.inner.stop_inner();
    }
}

/// Verilen `tokio::sync::mpsc::Sender<RawCapturePacket>` hattına olay üreten
/// Win32 odak + UIA + pano sensörlerini ve kaynak kontrolcüsünü başlatır.
pub fn spawn_sensor(
    tx: Sender<RawCapturePacket>,
    config: SensorConfig,
) -> Result<SensorHandle, SensorError> {
    #[cfg(windows)]
    {
        let inner = win32_hook::spawn_win32_sensors(tx, config)?;
        Ok(SensorHandle { inner })
    }

    #[cfg(not(windows))]
    {
        let _ = (tx, config, watch::channel::<ControllerState>);
        Err(SensorError::UnsupportedPlatform)
    }
}

/// `tokio::sync::mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY)` hattını kurar ve
/// sensörleri başlatarak `(SensorHandle, Receiver<RawCapturePacket>)` döndürür.
pub fn start_sensor_pipeline(
    config: SensorConfig,
) -> Result<(SensorHandle, Receiver<RawCapturePacket>), SensorError> {
    let (tx, rx) = channel::<RawCapturePacket>(SENSOR_CHANNEL_CAPACITY);
    let handle = spawn_sensor(tx, config)?;
    Ok((handle, rx))
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::clipboard::classify_clipboard_formats;
    use crate::uia::join_unique_text_nodes;

    #[test]
    fn sensor_channel_capacity_matches_contract() {
        assert_eq!(SENSOR_CHANNEL_CAPACITY, 128);
    }

    #[test]
    fn clipboard_classification_covers_all_variants() {
        const RTF: u32 = 49_200;
        const HTML: u32 = 49_201;

        assert_eq!(
            classify_clipboard_formats(&[13, RTF], RTF, HTML),
            ClipboardFormat::RichText
        );
        assert_eq!(
            classify_clipboard_formats(&[13, HTML], RTF, HTML),
            ClipboardFormat::RichText
        );
        assert_eq!(
            classify_clipboard_formats(&[13], RTF, HTML),
            ClipboardFormat::PlainText
        );
        assert_eq!(
            classify_clipboard_formats(&[1], RTF, HTML),
            ClipboardFormat::PlainText
        );
        assert_eq!(
            classify_clipboard_formats(&[15], RTF, HTML),
            ClipboardFormat::FileDropList
        );
        assert_eq!(
            classify_clipboard_formats(&[8], RTF, HTML),
            ClipboardFormat::ImageBitmap
        );
        assert_eq!(
            classify_clipboard_formats(&[2], RTF, HTML),
            ClipboardFormat::ImageBitmap
        );
        assert_eq!(
            classify_clipboard_formats(&[17], RTF, HTML),
            ClipboardFormat::ImageBitmap
        );
        assert_eq!(
            classify_clipboard_formats(&[9999], RTF, HTML),
            ClipboardFormat::IgnoredFormat
        );
        assert_eq!(
            classify_clipboard_formats(&[], RTF, HTML),
            ClipboardFormat::IgnoredFormat
        );
    }

    #[test]
    fn uia_join_deduplicates_trims_and_respects_utf8_cap() {
        let nodes = vec![
            Zeroizing::new(String::from("  Merhaba  ")),
            Zeroizing::new(String::from("   ")),
            Zeroizing::new(String::from("Merhaba")),
            Zeroizing::new(String::from("Dünya")),
        ];
        assert_eq!(join_unique_text_nodes(nodes, 1024), "Merhaba\nDünya");

        // UTF-8 çok baytlı karakter sınırında bozulmadan kesme ("ğ" = 2 bayt).
        let utf8_nodes = vec![Zeroizing::new(String::from("ağb"))];
        assert_eq!(join_unique_text_nodes(utf8_nodes, 2), "a");
        assert_eq!(
            join_unique_text_nodes(vec![Zeroizing::new(String::from("x"))], 0),
            ""
        );
    }

    #[test]
    fn metadata_extraction_never_leaks_sensitive_fields() {
        let secret_title = "Gizli Banka Hesabi - 1234";
        let secret_proc = "keepassxc.exe";
        let secret_payload = "sk-live-super-secret-token-9999";

        let packet = RawCapturePacket {
            timestamp_ms: 1_700_000_123_456,
            process_id: 9876,
            process_name: String::from(secret_proc),
            window_title: String::from(secret_title),
            event_kind: EventKind::ClipboardCopied {
                format: ClipboardFormat::PlainText,
            },
            raw_payload: RawPayload::ClipboardText(String::from(secret_payload)),
        };

        let meta = extract_metadata(&packet);
        assert_eq!(meta.process_id, 9876);
        assert_eq!(meta.timestamp_ms, 1_700_000_123_456);
        assert_eq!(meta.text_len, secret_payload.len());
        assert_eq!(
            meta.event_kind,
            EventKind::ClipboardCopied {
                format: ClipboardFormat::PlainText
            }
        );

        let rendered = format!("{meta} | {meta:?}");
        assert!(!rendered.contains(secret_title));
        assert!(!rendered.contains(secret_proc));
        assert!(!rendered.contains(secret_payload));
    }

    #[tokio::test]
    async fn mpsc_pipeline_delivers_packet_without_cloning() {
        let (tx, mut rx) = channel::<RawCapturePacket>(SENSOR_CHANNEL_CAPACITY);
        let packet = RawCapturePacket {
            timestamp_ms: 42,
            process_id: 77,
            process_name: String::from("notepad.exe"),
            window_title: String::from("taslak.txt"),
            event_kind: EventKind::WindowFocusChanged,
            raw_payload: RawPayload::AccessibilityText(String::from("örnek düğüm")),
        };
        let expected_len = "örnek düğüm".len();

        tx.send(packet).await.expect("kanal açık olmalı");
        drop(tx);

        let received = rx.recv().await.expect("paket alınmalı");
        let meta = extract_metadata(&received);
        assert_eq!(meta.event_kind, EventKind::WindowFocusChanged);
        assert_eq!(meta.process_id, 77);
        assert_eq!(meta.timestamp_ms, 42);
        assert_eq!(meta.text_len, expected_len);
        drop(received);
    }

    /// Test ikilisi işçi kancasını kurmaz; hat testleri süreç içi UIA kullanır.
    #[cfg(windows)]
    fn in_process_config() -> SensorConfig {
        SensorConfig {
            uia_isolation: UiaIsolation::InProcess,
            ..SensorConfig::default()
        }
    }

    #[cfg(windows)]
    static WIN32_PIPELINE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(windows)]
    #[test]
    fn win32_sensor_pipeline_starts_and_stops_cleanly() {
        let _guard = WIN32_PIPELINE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (handle, _rx) =
            start_sensor_pipeline(in_process_config()).expect("Win32 sensör hattı başlamalı");
        let state = handle.controller_state();
        assert_eq!(*handle.subscribe_state().borrow(), state);
        assert!(!handle.is_paused());
        assert_eq!(handle.pause_remaining(), None);
        handle.stop();
    }

    #[cfg(windows)]
    #[test]
    fn win32_sensor_pause_for_and_resume_updates_controller_state() {
        let _guard = WIN32_PIPELINE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (handle, _rx) =
            start_sensor_pipeline(in_process_config()).expect("Win32 sensör hattı başlamalı");
        let initial_state = handle.controller_state();
        let mut state_rx = handle.subscribe_state();
        let _ = *state_rx.borrow_and_update();

        // 1 saat duraklat -> hemen Suspended ve is_paused=true.
        handle.pause_for(Duration::from_secs(3600));
        assert_eq!(handle.controller_state(), ControllerState::Suspended);
        assert!(handle.is_paused());
        assert!(handle.pause_remaining().is_some());
        if initial_state != ControllerState::Suspended {
            assert_eq!(*state_rx.borrow_and_update(), ControllerState::Suspended);
        }

        // Erken devam et -> eski duruma döner ve pause temizlenir.
        handle.resume();
        assert!(!handle.is_paused());
        assert_eq!(handle.pause_remaining(), None);
        assert_eq!(handle.controller_state(), initial_state);

        // Kısa duraklatma süresi dolunca kontrolcü iş parçacığı otomatik devam ettirir.
        handle.pause_for(Duration::from_millis(80));
        assert_eq!(handle.controller_state(), ControllerState::Suspended);
        assert!(handle.is_paused());

        let wait_start = std::time::Instant::now();
        while handle.is_paused() && wait_start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(!handle.is_paused(), "kısa duraklatma süresi dolmalı");
        assert_eq!(handle.pause_remaining(), None);
        if initial_state != ControllerState::Suspended {
            let poll_start = std::time::Instant::now();
            while handle.controller_state() == ControllerState::Suspended
                && poll_start.elapsed() < Duration::from_secs(1)
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(handle.controller_state(), initial_state);
        }

        handle.stop();
    }

    #[test]
    fn tree_debouncer_coalesces_bursts_and_caps_continuous_stream() {
        use std::time::{Duration, Instant};

        let cfg = AccessibilityStreamConfig {
            debounce: Duration::from_millis(500),
            max_wait: Duration::from_millis(1200),
            ..Default::default()
        };
        let mut debouncer = TreeChangeDebouncer::new();
        let t0 = Instant::now();

        debouncer.note_activity(101, t0, 1000);
        assert!(debouncer.has_pending());
        assert_eq!(
            debouncer.next_deadline(&cfg),
            Some(t0 + Duration::from_millis(500))
        );
        assert_eq!(
            debouncer.poll_ready(t0 + Duration::from_millis(499), &cfg),
            None
        );

        // Yeni olay sessizlik süresini öteler (burst birleştirme).
        debouncer.note_activity(101, t0 + Duration::from_millis(300), 1300);
        assert_eq!(
            debouncer.next_deadline(&cfg),
            Some(t0 + Duration::from_millis(800))
        );
        assert_eq!(
            debouncer.poll_ready(t0 + Duration::from_millis(600), &cfg),
            None
        );

        // Sürekli akışta dahi `max_wait` (1200ms) sınırı aşılmaz.
        debouncer.note_activity(101, t0 + Duration::from_millis(700), 1700);
        debouncer.note_activity(101, t0 + Duration::from_millis(1000), 2000);
        assert_eq!(
            debouncer.next_deadline(&cfg),
            Some(t0 + Duration::from_millis(1200))
        );
        assert_eq!(
            debouncer.poll_ready(t0 + Duration::from_millis(1200), &cfg),
            Some((101, 2000))
        );
        assert!(!debouncer.has_pending());

        // Pencere değişimi veya clear bekleyen olayı iptal eder; disabled iken deadline None döner.
        debouncer.note_activity(202, t0 + Duration::from_millis(1500), 2500);
        let disabled = AccessibilityStreamConfig {
            enabled: false,
            ..cfg
        };
        assert_eq!(debouncer.next_deadline(&disabled), None);
        debouncer.clear();
        assert!(!debouncer.has_pending());
    }

    #[test]
    fn text_delta_tracker_enforces_noise_floor_ratio_and_focus_baseline() {
        let cfg = AccessibilityStreamConfig {
            min_changed_bytes: 32,
            min_change_ratio: 0.15,
            unconditional_changed_bytes: 128,
            ..Default::default()
        };
        let mut tracker = TextDeltaTracker::new();

        // FocusChanged ile taban anlık görüntü kaydedilir.
        let initial = "Ana panel durumu hazir ve tum servisler sorunsuz calisiyor saat 12:04";
        tracker.record_snapshot(77, initial);

        // Aynı metin veya küçük saat güncellemesi eşiği geçemez.
        assert!(!tracker.should_emit_and_update(77, initial, &cfg));
        let minor_tick = "Ana panel durumu hazir ve tum servisler sorunsuz calisiyor saat 12:05";
        assert!(!tracker.should_emit_and_update(77, minor_tick, &cfg));

        // Boşluk farkı eşiği geçemez.
        let whitespace_only =
            "Ana   panel durumu hazir ve tum servisler sorunsuz calisiyor saat 12:04";
        assert!(!tracker.should_emit_and_update(77, whitespace_only, &cfg));

        // 32+ bayt ve >= %15 oransal değişim eşiği geçer.
        let expanded = "Ana panel durumu hazir ve tum servisler sorunsuz calisiyor saat 12:05\nYeni hata kaydi: connection refused upstream 502";
        assert!(tracker.should_emit_and_update(77, expanded, &cfg));

        // Yayınlandıktan hemen sonra aynı metin tekrar tetiklenmez.
        assert!(!tracker.should_emit_and_update(77, expanded, &cfg));

        // Büyük belgede (>=128 bayt) mutlak değişim eşiği oransal sınırı aşmadan da tetikler.
        let large_base = "kelime ".repeat(300);
        tracker.record_snapshot(88, &large_base);
        let large_small_edit = format!("{large_base} kisa");
        assert!(!tracker.should_emit_and_update(88, &large_small_edit, &cfg));
        let large_big_addition = format!(
            "{large_base} {}",
            "yeni_satir_icerigi_uzun_ornek_log_kaydi ".repeat(5)
        );
        assert!(tracker.should_emit_and_update(88, &large_big_addition, &cfg));

        // Farklı pencereye geçince taban sıfırlanır; yeterli uzunluktaki metin yayına girer.
        assert!(!tracker.should_emit_and_update(99, "kisa", &cfg));
        assert!(tracker.should_emit_and_update(
            99,
            "Yeni pencere yuklendi ve yeterli metin icerigi olustu",
            &cfg
        ));
    }

    #[test]
    fn accessibility_tree_changed_respects_controller_states() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
        };

        use crate::controller::{BatchQueue, handle_signal_with_state};

        let cfg = AccessibilityStreamConfig::default();
        let mut tracker = TextDeltaTracker::new();
        let shared_state = Arc::new(AtomicU8::new(ControllerState::Suspended as u8));
        let batch_queue = Arc::new(Mutex::new(BatchQueue::new(8)));
        let (tx, mut rx) = channel::<RawCapturePacket>(SENSOR_CHANNEL_CAPACITY);

        // Suspended -> closure çalışmaz, tracker güncellenmez, paket üretilmez.
        handle_signal_with_state(&shared_state, &batch_queue, &tx, || {
            let text = String::from("Suspended durumunda asla islenmemesi gereken uzun metin");
            assert!(tracker.should_emit_and_update(55, &text, &cfg));
            Some(RawCapturePacket {
                timestamp_ms: 10,
                process_id: 55,
                process_name: String::from("app.exe"),
                window_title: String::from("pencere"),
                event_kind: EventKind::AccessibilityTreeChanged { node_count: 3 },
                raw_payload: RawPayload::AccessibilityText(text),
            })
        });
        assert!(batch_queue.lock().unwrap().is_empty());
        assert!(rx.try_recv().is_err());

        // Batching -> paket BatchQueue içinde bekletilir.
        shared_state.store(ControllerState::Batching as u8, Ordering::SeqCst);
        handle_signal_with_state(&shared_state, &batch_queue, &tx, || {
            let text = String::from("Pil modunda biriktirilen anlamli erisilebilirlik metni");
            assert!(tracker.should_emit_and_update(55, &text, &cfg));
            Some(RawCapturePacket {
                timestamp_ms: 20,
                process_id: 55,
                process_name: String::from("app.exe"),
                window_title: String::from("pencere"),
                event_kind: EventKind::AccessibilityTreeChanged { node_count: 11 },
                raw_payload: RawPayload::AccessibilityText(text),
            })
        });
        assert_eq!(batch_queue.lock().unwrap().len(), 1);
        assert!(rx.try_recv().is_err());

        // Active -> BatchQueue FIFO olarak boşaltılır, ardından yeni paket gönderilir.
        shared_state.store(ControllerState::Active as u8, Ordering::SeqCst);
        handle_signal_with_state(&shared_state, &batch_queue, &tx, || {
            let text =
                String::from("AC gucunde gelen ikinci anlamli erisilebilirlik metin degisimi");
            assert!(tracker.should_emit_and_update(55, &text, &cfg));
            Some(RawCapturePacket {
                timestamp_ms: 30,
                process_id: 55,
                process_name: String::from("app.exe"),
                window_title: String::from("pencere"),
                event_kind: EventKind::AccessibilityTreeChanged { node_count: 19 },
                raw_payload: RawPayload::AccessibilityText(text),
            })
        });
        assert!(batch_queue.lock().unwrap().is_empty());

        let first = rx.try_recv().unwrap();
        let first_meta = extract_metadata(&first);
        assert_eq!(
            first_meta.event_kind,
            EventKind::AccessibilityTreeChanged { node_count: 11 }
        );
        assert_eq!(first_meta.timestamp_ms, 20);
        drop(first);

        let second = rx.try_recv().unwrap();
        let second_meta = extract_metadata(&second);
        assert_eq!(
            second_meta.event_kind,
            EventKind::AccessibilityTreeChanged { node_count: 19 }
        );
        assert_eq!(second_meta.timestamp_ms, 30);
        drop(second);
    }

    #[test]
    fn focus_gate_enforces_250ms_settle_and_2s_same_title_cooldown() {
        use std::time::{Duration, Instant};

        let mut gate = FocusGate::new();
        let t0 = Instant::now();
        let settle = DEFAULT_FOCUS_SETTLE;
        let cooldown = DEFAULT_FOCUS_COOLDOWN;

        // Alt+Tab ara pencereleri (< 250 ms) elenir; yalnızca son settled pencere çıkar.
        gate.note_focus(100, t0, 1000, settle);
        gate.note_focus(200, t0 + Duration::from_millis(80), 1080, settle);
        gate.note_focus(300, t0 + Duration::from_millis(160), 1160, settle);
        assert_eq!(gate.poll_ready(t0 + Duration::from_millis(409)), None);
        assert_eq!(
            gate.poll_ready(t0 + Duration::from_millis(410)),
            Some((300, 1160))
        );

        // İlk yayın kabul edilir; aynı HWND + aynı başlık 2 s içinde engellenir.
        let emit_t = t0 + Duration::from_millis(410);
        assert!(gate.should_emit_focus(300, "Belge - Editor", emit_t, cooldown));
        assert!(!gate.should_emit_focus(
            300,
            "Belge - Editor",
            emit_t + Duration::from_millis(1999),
            cooldown
        ));
        // Aynı HWND'de başlık değişirse (örn. tarayıcı sekmesi değişti) soğuma baypas edilir.
        assert!(gate.should_emit_focus(
            300,
            "Yeni Sekme - Editor",
            emit_t + Duration::from_millis(500),
            cooldown
        ));
        // 2 s dolunca yeniden izin verilir.
        assert!(gate.should_emit_focus(
            300,
            "Yeni Sekme - Editor",
            emit_t + Duration::from_millis(2500),
            cooldown
        ));
    }

    #[test]
    fn focus_gate_30s_alttab_simulation_limits_worker_spawns() {
        use std::time::{Duration, Instant};

        // 30 sn boyunca kullanıcı her 500 ms'de bir Alt+Tab ile 4 ara pencereden geçip
        // 2 hedef pencere arasında (aynı başlıkla) gidip gelir -> toplam 300 odak olayı.
        let mut gate = FocusGate::new();
        let t0 = Instant::now();
        let settle = DEFAULT_FOCUS_SETTLE;
        let cooldown = DEFAULT_FOCUS_COOLDOWN;

        let mut total_focus_events = 0u64;
        let mut settled_events = 0u64;
        let mut worker_extractions = 0u64;

        let mut now = t0;
        for cycle in 0..60usize {
            let target_hwnd = if cycle % 2 == 0 { 1001 } else { 1002 };
            let target_title = if cycle % 2 == 0 {
                "Terminal - PowerShell"
            } else {
                "Notes - Notepad"
            };
            // 4 hızlı Alt+Tab adımı (80 ms aralıklı = 240 ms) + hedefe yerleşme.
            for step in 0..4 {
                let h = if step < 3 {
                    2000 + step as isize
                } else {
                    target_hwnd
                };
                let step_t = now + Duration::from_millis((step as u64) * 80);
                gate.note_focus(h, step_t, step as u64, settle);
                total_focus_events += 1;
            }
            // Döngü sonu (+500 ms -> yerleşme 240+250 = 490 ms < 500 ms, yani tam yerleşir).
            let check_t = now + Duration::from_millis(500);
            if let Some((hwnd, _)) = gate.poll_ready(check_t) {
                settled_events += 1;
                if gate.should_emit_focus(hwnd, target_title, check_t, cooldown) {
                    worker_extractions += 1;
                }
            }
            now = check_t;
        }

        // 240 odak olayından yalnızca 60'ı yerleşir, 2 s soğuma ile yalnızca ~30'u işçi tüketir
        // (dakikada 60 işçi başlatma; soğuma/yerleşme olmasaydı 480/dk olurdu).
        assert_eq!(total_focus_events, 240);
        assert_eq!(settled_events, 60);
        assert_eq!(worker_extractions, 30);
    }
}
