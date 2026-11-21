//! Kaynak farkındalıklı sensör kontrolcüsü (Resource-Aware Controller).
//!
//! Görevler:
//! 1. Exclusive fullscreen tespiti (`SHQueryUserNotificationState` + ön plan penceresi monitör sınırları)
//! 2. GPU 3D yükü (`\GPU Engine(*engtype_3D)\Utilization Percentage` PDH toplamı, histerezisli)
//! 3. Güç durumu (`GetSystemPowerStatus`: AC/pil ve pil tasarrufu)
//! 4. Durum makinesi (`Active` / `Batching` / `Suspended`) ve sınırlı bellek kuyruğu (`BatchQueue`)

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use s_types::RawCapturePacket;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::watch;

const MIN_SLEEP_MS: Duration = Duration::from_millis(50);
const MAX_MANUAL_PAUSE: Duration = Duration::from_secs(86_400 * 365 * 10);

/// Kaynak farkındalıklı kontrolcünün çalışma durumları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControllerState {
    /// Normal yakalama: olaylar doğrudan `mpsc` hattına gönderilir.
    Active = 0,
    /// Pil veya pil tasarrufu: paketler bellekte sınırlı kuyrukta bekletilir,
    /// AC gücüne dönülünce boşaltılır.
    Batching = 1,
    /// Tam ekran oyun/sunum veya sürekli yüksek GPU yükü: sensör yakalaması
    /// duraklatılır; hook geri çağrıları UIA veya pano çağrısı yapmaz.
    Suspended = 2,
}

impl ControllerState {
    /// Durumun yalnızca güvenli etiket adını döndürür.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Batching => "Batching",
            Self::Suspended => "Suspended",
        }
    }

    pub(crate) const fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::Batching,
            2 => Self::Suspended,
            _ => Self::Active,
        }
    }
}

impl fmt::Display for ControllerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `SHQueryUserNotificationState` çıktısının platformdan bağımsız temsili.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserNotificationState {
    #[default]
    AcceptsNotifications,
    NotPresent,
    Busy,
    RunningD3dFullScreen,
    PresentationMode,
    QuietTime,
    App,
}

impl UserNotificationState {
    /// `QUNS_RUNNING_D3D_FULL_SCREEN` veya `QUNS_PRESENTATION_MODE` durumlarında `true` döndürür.
    pub const fn is_exclusive_or_presentation(self) -> bool {
        matches!(self, Self::RunningD3dFullScreen | Self::PresentationMode)
    }

    /// `QUNS_RUNNING_D3D_FULL_SCREEN`, `QUNS_PRESENTATION_MODE` veya `QUNS_BUSY`
    /// durumlarında `true` döndürür.
    pub const fn is_exclusive_or_busy(self) -> bool {
        matches!(
            self,
            Self::RunningD3dFullScreen | Self::PresentationMode | Self::Busy
        )
    }
}

/// `GetSystemPowerStatus` çıktısının platformdan bağımsız temsili.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PowerSignals {
    /// `ACLineStatus == 0` olduğunda `true` (pil gücü). `1` (AC) veya `255` (bilinmiyor) `false`.
    pub on_battery: bool,
    /// `SystemStatusFlag & 1 != 0` olduğunda `true` (pil tasarrufu etkin).
    pub battery_saver: bool,
}

/// Kontrolcünün tek örnekleme adımında değerlendirdiği kaynak sinyalleri.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ResourceSignals {
    pub notification_state: UserNotificationState,
    /// Ön plan penceresinin (masaüstü/kabuk hariç) monitör sınırlarını tam kaplaması.
    pub foreground_covers_monitor: bool,
    /// `\GPU Engine(*engtype_3D)\Utilization Percentage` sayaç toplamı (%).
    pub gpu_3d_utilization_pct: f64,
    pub power: PowerSignals,
}

/// Yapılandırılabilir kontrolcü örnekleme aralıkları, eşikleri ve kuyruk sınırı.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ControllerConfig {
    /// `Active` ve `Batching` durumlarında kaynak örnekleme aralığı.
    pub sample_interval: Duration,
    /// `Suspended` durumunda kontrolcünün kendi CPU maliyetini en aza indiren örnekleme aralığı.
    pub suspended_sample_interval: Duration,
    /// GPU 3D yükü üst eşiği (%). Varsayılan: `80.0`.
    pub gpu_high_threshold_pct: f64,
    /// GPU aşırı yük durumundan çıkış alt eşiği (%). Varsayılan: `70.0`.
    pub gpu_low_threshold_pct: f64,
    /// `Suspended` durumuna geçmek için gereken ardışık yüksek GPU örneği sayısı. Varsayılan: `3`.
    pub gpu_high_consecutive_samples: u32,
    /// GPU aşırı yükünden çıkmak için gereken ardışık düşük GPU örneği sayısı. Varsayılan: `3`.
    pub gpu_low_consecutive_samples: u32,
    /// `Batching` sırasında bellekte tutulacak en fazla paket sayısı.
    pub batch_queue_capacity: usize,
    /// Tam ekran / sunum tespitinde `Suspended` geçişini etkinleştirir.
    pub suspend_on_fullscreen: bool,
    /// Pil gücünde `Batching` geçişini etkinleştirir.
    pub batch_on_battery: bool,
    /// Pil tasarrufu modunda `Batching` geçişini etkinleştirir.
    pub batch_on_battery_saver: bool,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_millis(1000),
            suspended_sample_interval: Duration::from_millis(3000),
            gpu_high_threshold_pct: 80.0,
            gpu_low_threshold_pct: 70.0,
            gpu_high_consecutive_samples: 3,
            gpu_low_consecutive_samples: 3,
            batch_queue_capacity: 64,
            suspend_on_fullscreen: true,
            batch_on_battery: true,
            batch_on_battery_saver: true,
        }
    }
}

/// Durum makinesinin histerezis sayaçlarını tutan saf durum değeri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerMachineState {
    pub state: ControllerState,
    pub gpu_overloaded: bool,
    pub gpu_high_streak: u32,
    pub gpu_low_streak: u32,
}

impl Default for ControllerMachineState {
    fn default() -> Self {
        Self {
            state: ControllerState::Active,
            gpu_overloaded: false,
            gpu_high_streak: 0,
            gpu_low_streak: 0,
        }
    }
}

/// Tek kontrolcü adımının saf çıktı özeti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepOutcome {
    pub next: ControllerMachineState,
    pub previous_state: ControllerState,
    pub transitioned: bool,
    /// `Active` durumda bekleyen batch kuyruğunun boşaltılması gerektiğini bildirir.
    pub should_flush_batch: bool,
}

/// Saf durum makinesi geçiş fonksiyonu (OS çağrısı içermez).
pub fn step_controller_state(
    machine: ControllerMachineState,
    signals: ResourceSignals,
    config: &ControllerConfig,
) -> StepOutcome {
    let gpu_pct = if signals.gpu_3d_utilization_pct.is_finite() {
        signals.gpu_3d_utilization_pct.max(0.0)
    } else {
        0.0
    };

    let high_required = config.gpu_high_consecutive_samples.max(1);
    let low_required = config.gpu_low_consecutive_samples.max(1);
    let low_threshold = config
        .gpu_low_threshold_pct
        .min(config.gpu_high_threshold_pct);

    let mut gpu_overloaded = machine.gpu_overloaded;
    let mut gpu_high_streak = machine.gpu_high_streak;
    let mut gpu_low_streak = machine.gpu_low_streak;

    if !gpu_overloaded {
        gpu_low_streak = 0;
        if gpu_pct >= config.gpu_high_threshold_pct {
            gpu_high_streak = gpu_high_streak.saturating_add(1);
            if gpu_high_streak >= high_required {
                gpu_overloaded = true;
                gpu_high_streak = 0;
            }
        } else {
            gpu_high_streak = 0;
        }
    } else {
        gpu_high_streak = 0;
        if gpu_pct <= low_threshold {
            gpu_low_streak = gpu_low_streak.saturating_add(1);
            if gpu_low_streak >= low_required {
                gpu_overloaded = false;
                gpu_low_streak = 0;
            }
        } else {
            gpu_low_streak = 0;
        }
    }

    // `QUNS_BUSY`, Windows 10/11'de Focus Assist veya odak penceresiz arka plan
    // oturumlarında da dönebildiğinden yalnızca ön plan penceresi monitörü tam
    // kapladığında exclusive fullscreen sayılır.
    let fullscreen_active = config.suspend_on_fullscreen
        && (signals.notification_state.is_exclusive_or_presentation()
            || (signals.notification_state == UserNotificationState::Busy
                && signals.foreground_covers_monitor));

    let batch_power_active = (config.batch_on_battery && signals.power.on_battery)
        || (config.batch_on_battery_saver && signals.power.battery_saver);

    let next_state = if fullscreen_active || gpu_overloaded {
        ControllerState::Suspended
    } else if batch_power_active {
        ControllerState::Batching
    } else {
        ControllerState::Active
    };

    let next = ControllerMachineState {
        state: next_state,
        gpu_overloaded,
        gpu_high_streak,
        gpu_low_streak,
    };

    StepOutcome {
        next,
        previous_state: machine.state,
        transitioned: next_state != machine.state,
        should_flush_batch: next_state == ControllerState::Active,
    }
}

/// Saf durum makinesi adımı. Manuel duraklatma (`pause_for`) aktifken durum her zaman
/// `Suspended` olur; GPU histerezisi sinyallerle güncellenmeye devam eder.
pub fn step_controller_state_with_pause(
    machine: ControllerMachineState,
    signals: ResourceSignals,
    config: &ControllerConfig,
    manual_paused: bool,
    previous_effective_state: ControllerState,
) -> StepOutcome {
    let base = step_controller_state(machine, signals, config);
    if manual_paused {
        let mut next = base.next;
        next.state = ControllerState::Suspended;
        StepOutcome {
            next,
            previous_state: previous_effective_state,
            transitioned: ControllerState::Suspended != previous_effective_state,
            should_flush_batch: false,
        }
    } else {
        StepOutcome {
            next: base.next,
            previous_state: previous_effective_state,
            transitioned: base.next.state != previous_effective_state,
            should_flush_batch: base.should_flush_batch,
        }
    }
}

/// Bir pencere dikdörtgeninin monitör sınırlarını (`rcMonitor`) tam kapsayıp kapsamadığını sınar.
pub(crate) const fn rect_covers_monitor(
    win: (i32, i32, i32, i32),
    mon: (i32, i32, i32, i32),
) -> bool {
    let (wl, wt, wr, wb) = win;
    let (ml, mt, mr, mb) = mon;
    wr > wl && wb > wt && mr > ml && mb > mt && wl <= ml && wt <= mt && wr >= mr && wb >= mb
}

/// `Batching` modunda `RawCapturePacket` örneklerini tutan sınırlı FIFO bellek kuyruğu.
///
/// Sınır aşılırsa en eski paket çıkarılıp `drop` edilir ve `ZeroizeOnDrop` ile RAM'den silinir.
pub struct BatchQueue {
    capacity: usize,
    queue: VecDeque<RawCapturePacket>,
    dropped_oldest_count: u64,
}

impl BatchQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            dropped_oldest_count: 0,
        }
    }

    /// Kuyruğa yeni paket ekler; sınır aşılırsa en eski paketi düşürür ve zeroize eder.
    pub fn push(&mut self, packet: RawCapturePacket) {
        if self.capacity == 0 {
            drop(packet);
            self.dropped_oldest_count = self.dropped_oldest_count.saturating_add(1);
            return;
        }
        while self.queue.len() >= self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                drop(oldest);
                self.dropped_oldest_count = self.dropped_oldest_count.saturating_add(1);
            }
        }
        self.queue.push_back(packet);
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped_oldest_count(&self) -> u64 {
        self.dropped_oldest_count
    }

    /// Kuyruktaki bekleyen paketleri FIFO sırasıyla `tx` kanalına boşaltır.
    pub fn flush_to(&mut self, tx: &Sender<RawCapturePacket>) -> usize {
        let mut flushed = 0usize;
        while let Some(packet) = self.queue.pop_front() {
            match tx.try_send(packet) {
                Ok(()) => {
                    flushed += 1;
                }
                Err(TrySendError::Full(pkt)) => {
                    // Sırayı korumak için geri koyup kanal açılana kadar bekle.
                    self.queue.push_front(pkt);
                    break;
                }
                Err(TrySendError::Closed(pkt)) => {
                    drop(pkt);
                    self.queue.clear();
                    break;
                }
            }
        }
        flushed
    }

    /// Kalan tüm paketleri düşürüp `ZeroizeOnDrop` ile temizler.
    pub fn clear_and_zeroize(&mut self) {
        self.queue.clear();
    }
}

/// Duruma göre sinyal üretme/yönlendirme kapısı.
///
/// `Suspended` iken `build_packet` (UIA / pano çıkarımı) hiç çağrılmaz.
pub(crate) fn handle_signal_with_state<F>(
    shared_state: &AtomicU8,
    batch_queue: &Mutex<BatchQueue>,
    tx: &Sender<RawCapturePacket>,
    build_packet: F,
) where
    F: FnOnce() -> Option<RawCapturePacket>,
{
    let initial = ControllerState::from_u8(shared_state.load(Ordering::Acquire));
    if initial == ControllerState::Suspended {
        return;
    }

    let Some(packet) = build_packet() else {
        return;
    };

    // Çıkarım sırasında `Suspended` durumuna geçildiyse paketi anında düşür ve zeroize et.
    let current = ControllerState::from_u8(shared_state.load(Ordering::Acquire));
    match current {
        ControllerState::Suspended => {
            drop(packet);
        }
        ControllerState::Batching => {
            if let Ok(mut queue) = batch_queue.lock() {
                queue.push(packet);
            } else {
                drop(packet);
            }
        }
        ControllerState::Active => {
            let can_send_direct = if let Ok(mut queue) = batch_queue.lock() {
                if !queue.is_empty() {
                    let _ = queue.flush_to(tx);
                }
                queue.is_empty()
            } else {
                true
            };

            if can_send_direct {
                let _ = tx.try_send(packet);
            } else if let Ok(mut queue) = batch_queue.lock() {
                queue.push(packet);
            } else {
                drop(packet);
            }
        }
    }
}

struct ControllerRuntime {
    machine: ControllerMachineState,
    last_signals: ResourceSignals,
    manual_pause_until: Option<Instant>,
    stopped: bool,
    wake_seq: u64,
}

pub(crate) type StateListener = Arc<dyn Fn(ControllerState) + Send + Sync>;

/// Çalışan kontrolcü döngüsü ile `SensorHandle` (`pause_for` / `resume`) arasındaki
/// eşzamanlı durum koordinatörü.
pub(crate) struct ControllerControl {
    config: ControllerConfig,
    runtime: Mutex<ControllerRuntime>,
    cvar: Condvar,
    shared_state: Arc<AtomicU8>,
    batch_queue: Arc<Mutex<BatchQueue>>,
    tx: Sender<RawCapturePacket>,
    state_watch_tx: watch::Sender<ControllerState>,
    state_listener: Option<StateListener>,
}

impl ControllerControl {
    #[cfg_attr(not(windows), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_listener(
        config: ControllerConfig,
        shared_state: Arc<AtomicU8>,
        batch_queue: Arc<Mutex<BatchQueue>>,
        tx: Sender<RawCapturePacket>,
        state_watch_tx: watch::Sender<ControllerState>,
        initial_machine: ControllerMachineState,
        initial_signals: ResourceSignals,
        state_listener: Option<StateListener>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            runtime: Mutex::new(ControllerRuntime {
                machine: initial_machine,
                last_signals: initial_signals,
                manual_pause_until: None,
                stopped: false,
                wake_seq: 0,
            }),
            cvar: Condvar::new(),
            shared_state,
            batch_queue,
            tx,
            state_watch_tx,
            state_listener,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn new(
        config: ControllerConfig,
        shared_state: Arc<AtomicU8>,
        batch_queue: Arc<Mutex<BatchQueue>>,
        tx: Sender<RawCapturePacket>,
        state_watch_tx: watch::Sender<ControllerState>,
        initial_machine: ControllerMachineState,
        initial_signals: ResourceSignals,
    ) -> Arc<Self> {
        Self::new_with_listener(
            config,
            shared_state,
            batch_queue,
            tx,
            state_watch_tx,
            initial_machine,
            initial_signals,
            None,
        )
    }

    fn publish_state(&self, next_state: ControllerState) -> bool {
        self.shared_state.store(next_state as u8, Ordering::Release);
        self.state_watch_tx.send_if_modified(|current| {
            if *current != next_state {
                *current = next_state;
                true
            } else {
                false
            }
        })
    }

    fn notify_listener_if_changed(&self, changed: bool, next_state: ControllerState) {
        if changed && let Some(cb) = &self.state_listener {
            cb(next_state);
        }
    }

    fn flush_batch_if_needed(&self, should_flush: bool) {
        if should_flush
            && let Ok(mut queue) = self.batch_queue.lock()
            && !queue.is_empty()
        {
            let _ = queue.flush_to(&self.tx);
        }
    }

    pub(crate) fn pause_for(&self, duration: Duration) {
        if duration.is_zero() {
            self.resume();
            return;
        }
        let clamped = duration.min(MAX_MANUAL_PAUSE);
        let now = Instant::now();
        let deadline = now.checked_add(clamped).unwrap_or(now);

        let (next_state, changed) = {
            let mut rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt.manual_pause_until = Some(deadline);
            rt.wake_seq = rt.wake_seq.wrapping_add(1);
            let prev = rt.machine.state;
            let outcome = step_controller_state_with_pause(
                rt.machine,
                rt.last_signals,
                &self.config,
                true,
                prev,
            );
            rt.machine = outcome.next;
            let changed = self.publish_state(outcome.next.state);
            (outcome.next.state, changed)
        };
        self.notify_listener_if_changed(changed, next_state);
        self.cvar.notify_all();
    }

    pub(crate) fn resume(&self) {
        let (should_flush, next_state, changed) = {
            let mut rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt.manual_pause_until = None;
            rt.wake_seq = rt.wake_seq.wrapping_add(1);
            let prev = rt.machine.state;
            let outcome = step_controller_state_with_pause(
                rt.machine,
                rt.last_signals,
                &self.config,
                false,
                prev,
            );
            rt.machine = outcome.next;
            let changed = self.publish_state(outcome.next.state);
            (outcome.should_flush_batch, outcome.next.state, changed)
        };
        self.notify_listener_if_changed(changed, next_state);
        self.flush_batch_if_needed(should_flush);
        self.cvar.notify_all();
    }

    pub(crate) fn pause_remaining(&self) -> Option<Duration> {
        let rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = rt.manual_pause_until?;
        let now = Instant::now();
        if now < deadline {
            Some(deadline.duration_since(now))
        } else {
            None
        }
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.pause_remaining().is_some()
    }

    pub(crate) fn apply_sample(&self, signals: ResourceSignals) -> StepOutcome {
        let (outcome, changed) = {
            let mut rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            if let Some(deadline) = rt.manual_pause_until
                && now >= deadline
            {
                rt.manual_pause_until = None;
            }
            let manual_paused = rt.manual_pause_until.is_some();
            rt.last_signals = signals;
            let prev = rt.machine.state;
            let outcome = step_controller_state_with_pause(
                rt.machine,
                signals,
                &self.config,
                manual_paused,
                prev,
            );
            rt.machine = outcome.next;
            let changed = self.publish_state(outcome.next.state);
            (outcome, changed)
        };
        self.notify_listener_if_changed(changed, outcome.next.state);
        self.flush_batch_if_needed(outcome.should_flush_batch);
        outcome
    }

    #[cfg(windows)]
    pub(crate) fn next_sleep_params(&self) -> Option<(Duration, u64)> {
        let rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        if rt.stopped {
            return None;
        }
        let now = Instant::now();
        let sleep_dur = if let Some(deadline) = rt.manual_pause_until {
            if now >= deadline {
                Duration::ZERO
            } else {
                let rem = deadline.duration_since(now);
                let base = self.config.suspended_sample_interval.max(MIN_SLEEP_MS);
                rem.min(base).max(Duration::from_millis(1))
            }
        } else if rt.machine.state == ControllerState::Suspended {
            self.config.suspended_sample_interval.max(MIN_SLEEP_MS)
        } else {
            self.config.sample_interval.max(MIN_SLEEP_MS)
        };
        Some((sleep_dur, rt.wake_seq))
    }

    #[cfg(windows)]
    pub(crate) fn wait_for_next_tick(&self, sleep_dur: Duration, observed_seq: u64) -> bool {
        let rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        if rt.stopped {
            return true;
        }
        if rt.wake_seq != observed_seq {
            return false;
        }
        let (rt_after, _) = self
            .cvar
            .wait_timeout_while(rt, sleep_dur, |r| !r.stopped && r.wake_seq == observed_seq)
            .unwrap_or_else(|e| e.into_inner());
        rt_after.stopped
    }

    #[cfg(windows)]
    pub(crate) fn is_tx_closed(&self) -> bool {
        self.tx.is_closed()
    }

    #[cfg(windows)]
    pub(crate) fn mark_stopped(&self) {
        {
            let mut rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt.stopped = true;
            rt.wake_seq = rt.wake_seq.wrapping_add(1);
        }
        self.cvar.notify_all();
    }

    #[cfg(windows)]
    pub(crate) fn clear_batch_on_stop(&self) {
        if let Ok(mut queue) = self.batch_queue.lock() {
            queue.clear_and_zeroize();
        }
    }
}

#[cfg(windows)]
pub(crate) mod win32 {
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use windows::Win32::Foundation::RECT;
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
    };
    use windows::Win32::System::Performance::{
        PDH_CSTATUS_NEW_DATA, PDH_CSTATUS_VALID_DATA, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE,
        PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA, PdhAddEnglishCounterW, PdhCloseQuery,
        PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
    };
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    use windows::Win32::UI::Shell::{
        QUNS_ACCEPTS_NOTIFICATIONS, QUNS_APP, QUNS_BUSY, QUNS_NOT_PRESENT, QUNS_PRESENTATION_MODE,
        QUNS_QUIET_TIME, QUNS_RUNNING_D3D_FULL_SCREEN, SHQueryUserNotificationState,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetDesktopWindow, GetForegroundWindow, GetShellWindow, GetWindowRect, IsIconic,
        IsWindowVisible,
    };
    use windows::core::{PCWSTR, w};

    use super::{
        ControllerControl, PowerSignals, ResourceSignals, UserNotificationState,
        rect_covers_monitor,
    };
    use crate::SensorError;

    pub(crate) fn query_user_notification_state() -> UserNotificationState {
        // SAFETY: Salt-okunur Windows kabuk bildirim durumu sorgusu.
        match unsafe { SHQueryUserNotificationState() } {
            Ok(state) if state == QUNS_RUNNING_D3D_FULL_SCREEN => {
                UserNotificationState::RunningD3dFullScreen
            }
            Ok(state) if state == QUNS_PRESENTATION_MODE => UserNotificationState::PresentationMode,
            Ok(state) if state == QUNS_BUSY => UserNotificationState::Busy,
            Ok(state) if state == QUNS_NOT_PRESENT => UserNotificationState::NotPresent,
            Ok(state) if state == QUNS_QUIET_TIME => UserNotificationState::QuietTime,
            Ok(state) if state == QUNS_APP => UserNotificationState::App,
            Ok(state) if state == QUNS_ACCEPTS_NOTIFICATIONS => {
                UserNotificationState::AcceptsNotifications
            }
            Ok(_) | Err(_) => UserNotificationState::AcceptsNotifications,
        }
    }

    pub(crate) fn is_foreground_covering_monitor() -> bool {
        // SAFETY: Salt-okunur ön plan penceresi tutamacı sorgusu.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0.is_null() {
            return false;
        }

        // Masaüstü ve kabuk pencereleri tam ekran uygulama sayılmaz.
        // SAFETY: Salt-okunur kabuk pencere tutamacı.
        let shell = unsafe { GetShellWindow() };
        // SAFETY: Salt-okunur masaüstü pencere tutamacı.
        let desktop = unsafe { GetDesktopWindow() };
        if hwnd == shell || hwnd == desktop {
            return false;
        }

        // SAFETY: `hwnd` boş olmayan bir penceredir; görünürlük ve simge durumu okunur.
        if !unsafe { IsWindowVisible(hwnd) }.as_bool() || unsafe { IsIconic(hwnd) }.as_bool() {
            return false;
        }

        let mut win_rect = RECT::default();
        // SAFETY: `hwnd` geçerli pencere tutamacıdır; `win_rect` geçerli yığın yapısıdır.
        if unsafe { GetWindowRect(hwnd, &mut win_rect) }.is_err() {
            return false;
        }

        // SAFETY: Pencereye en yakın monitör tutamacı alınır.
        let hmon = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
        if hmon.is_invalid() {
            return false;
        }

        let mut mi = MONITORINFO {
            cbSize: core::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: `hmon` geçerli monitör tutamacıdır; `mi.cbSize` başlatılmıştır.
        if !unsafe { GetMonitorInfoW(hmon, &mut mi) }.as_bool() {
            return false;
        }

        rect_covers_monitor(
            (win_rect.left, win_rect.top, win_rect.right, win_rect.bottom),
            (
                mi.rcMonitor.left,
                mi.rcMonitor.top,
                mi.rcMonitor.right,
                mi.rcMonitor.bottom,
            ),
        )
    }

    pub(crate) fn query_power_signals() -> PowerSignals {
        let mut status = SYSTEM_POWER_STATUS::default();
        // SAFETY: `status` başlatılmış `SYSTEM_POWER_STATUS` yığın yapısıdır.
        if unsafe { GetSystemPowerStatus(&mut status) }.is_err() {
            return PowerSignals::default();
        }
        PowerSignals {
            on_battery: status.ACLineStatus == 0,
            battery_saver: (status.SystemStatusFlag & 1) != 0,
        }
    }

    struct GpuPdhSampler {
        query: PDH_HQUERY,
        counter: PDH_HCOUNTER,
        has_baseline: bool,
        // `PDH_FMT_COUNTERVALUE_ITEM_W` için en az 8 bayt hizalama sağlayan yeniden kullanılabilir tampon.
        buffer: Vec<u64>,
    }

    impl GpuPdhSampler {
        fn new() -> Option<Self> {
            let mut query = PDH_HQUERY::default();
            // SAFETY: `PCWSTR::null()` canlı sistem verisi açar; `query` çıkış tutamacıdır.
            if unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut query) } != 0 || query.is_invalid() {
                return None;
            }

            let mut counter = PDH_HCOUNTER::default();
            let path = w!("\\GPU Engine(*engtype_3D)\\Utilization Percentage");
            // SAFETY: `query` açık PDH sorgusudur; `path` sabit null-sonlandırılmış İngilizce sayaç yoludur.
            if unsafe { PdhAddEnglishCounterW(query, path, 0, &mut counter) } != 0
                || counter.is_invalid()
            {
                // SAFETY: Başarısız sayaç eklemesi sonrası açık PDH sorgusu kapatılır.
                let _ = unsafe { PdhCloseQuery(query) };
                return None;
            }

            // Oran/yüzde sayacı için başlangıç taban örneği toplanır.
            // SAFETY: `query` geçerli ve açık PDH sorgusudur.
            let has_baseline = unsafe { PdhCollectQueryData(query) } == 0;

            Some(Self {
                query,
                counter,
                has_baseline,
                buffer: Vec::new(),
            })
        }

        fn sample_3d_utilization_pct(&mut self) -> f64 {
            // SAFETY: `self.query` açık ve geçerli bir PDH sorgusudur.
            let collect_status = unsafe { PdhCollectQueryData(self.query) };
            if collect_status != 0 {
                return 0.0;
            }
            if !self.has_baseline {
                self.has_baseline = true;
                return 0.0;
            }

            let mut buf_bytes: u32 = 0;
            let mut item_count: u32 = 0;
            // SAFETY: Boyut öğrenme çağrısı; `itembuffer = None` iken yalnızca `buf_bytes` ve `item_count` yazılır.
            let probe_status = unsafe {
                PdhGetFormattedCounterArrayW(
                    self.counter,
                    PDH_FMT_DOUBLE,
                    &mut buf_bytes,
                    &mut item_count,
                    None,
                )
            };
            if probe_status != PDH_MORE_DATA || buf_bytes == 0 {
                return 0.0;
            }

            const {
                assert!(
                    core::mem::align_of::<PDH_FMT_COUNTERVALUE_ITEM_W>()
                        <= core::mem::align_of::<u64>()
                );
            }
            let needed_u64 = (buf_bytes as usize).div_ceil(core::mem::size_of::<u64>());
            if self.buffer.len() < needed_u64 {
                self.buffer.resize(needed_u64, 0);
            }

            let ptr = self
                .buffer
                .as_mut_ptr()
                .cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
            // SAFETY: `self.buffer` en az `buf_bytes` kapasiteye ve yeterli hizalamaya sahiptir.
            let read_status = unsafe {
                PdhGetFormattedCounterArrayW(
                    self.counter,
                    PDH_FMT_DOUBLE,
                    &mut buf_bytes,
                    &mut item_count,
                    Some(ptr),
                )
            };
            if read_status != 0 || item_count == 0 {
                return 0.0;
            }

            // SAFETY: `PdhGetFormattedCounterArrayW` başarılı oldu ve `item_count` adet geçerli öğe yazdı.
            let items =
                unsafe { core::slice::from_raw_parts(ptr.cast_const(), item_count as usize) };
            let mut total = 0.0_f64;
            for item in items {
                let cstatus = item.FmtValue.CStatus;
                if cstatus == PDH_CSTATUS_VALID_DATA || cstatus == PDH_CSTATUS_NEW_DATA {
                    // SAFETY: `PDH_FMT_DOUBLE` biçimi istendiğinde geçerli öğelerde `doubleValue` aktiftir.
                    let v = unsafe { item.FmtValue.Anonymous.doubleValue };
                    if v.is_finite() && v > 0.0 {
                        total += v;
                    }
                }
            }
            total
        }
    }

    impl Drop for GpuPdhSampler {
        fn drop(&mut self) {
            if !self.query.is_invalid() {
                // SAFETY: `self.query` `PdhOpenQueryW` ile açılmış geçerli tutamaçtır.
                let _ = unsafe { PdhCloseQuery(self.query) };
            }
        }
    }

    pub(crate) struct ResourceMonitor {
        gpu_pdh: Option<GpuPdhSampler>,
    }

    impl ResourceMonitor {
        pub(crate) fn new() -> Self {
            Self {
                gpu_pdh: GpuPdhSampler::new(),
            }
        }

        pub(crate) fn sample(&mut self) -> ResourceSignals {
            let notification_state = query_user_notification_state();
            let foreground_covers_monitor = is_foreground_covering_monitor();
            let power = query_power_signals();
            let gpu_3d_utilization_pct = self
                .gpu_pdh
                .as_mut()
                .map_or(0.0, GpuPdhSampler::sample_3d_utilization_pct);

            ResourceSignals {
                notification_state,
                foreground_covers_monitor,
                gpu_3d_utilization_pct,
                power,
            }
        }
    }

    pub(crate) struct ControllerThreadHandle {
        control: Arc<ControllerControl>,
        thread: Option<JoinHandle<()>>,
    }

    impl ControllerThreadHandle {
        pub(crate) fn stop(&mut self) {
            self.control.mark_stopped();
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
        }
    }

    impl Drop for ControllerThreadHandle {
        fn drop(&mut self) {
            self.stop();
        }
    }

    pub(crate) fn spawn_controller_thread(
        control: Arc<ControllerControl>,
    ) -> Result<ControllerThreadHandle, SensorError> {
        let worker_control = Arc::clone(&control);

        let thread = std::thread::Builder::new()
            .name(String::from("s-sensor-controller"))
            .spawn(move || {
                let mut monitor = ResourceMonitor::new();

                while let Some((sleep_dur, observed_seq)) = worker_control.next_sleep_params() {
                    if !sleep_dur.is_zero()
                        && worker_control.wait_for_next_tick(sleep_dur, observed_seq)
                    {
                        break;
                    }

                    if worker_control.is_tx_closed() {
                        break;
                    }

                    let signals = monitor.sample();
                    let _ = worker_control.apply_sample(signals);
                }

                worker_control.clear_batch_on_stop();
            })
            .map_err(|e| SensorError::ThreadSpawnFailed(e.to_string()))?;

        Ok(ControllerThreadHandle {
            control,
            thread: Some(thread),
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::channel;

    use super::*;

    fn dummy_packet(ts: u64, marker: &str) -> RawCapturePacket {
        RawCapturePacket {
            timestamp_ms: ts,
            process_id: 100 + ts as u32,
            process_name: String::from("app.exe"),
            window_title: format!("title-{marker}"),
            event_kind: s_types::EventKind::WindowFocusChanged,
            raw_payload: s_types::RawPayload::AccessibilityText(format!("text-{marker}")),
        }
    }

    #[test]
    fn pure_state_machine_exclusive_fullscreen_quns_suspends() {
        let cfg = ControllerConfig::default();
        let initial = ControllerMachineState::default();

        for quns in [
            UserNotificationState::RunningD3dFullScreen,
            UserNotificationState::PresentationMode,
        ] {
            let outcome = step_controller_state(
                initial,
                ResourceSignals {
                    notification_state: quns,
                    ..Default::default()
                },
                &cfg,
            );
            assert_eq!(outcome.next.state, ControllerState::Suspended);
            assert!(outcome.transitioned);
            assert!(!outcome.should_flush_batch);
        }

        // `QUNS_BUSY` tek başına (ör. Focus Assist / fg=0) yanlış pozitif Suspend üretmez.
        let busy_no_fg = step_controller_state(
            initial,
            ResourceSignals {
                notification_state: UserNotificationState::Busy,
                foreground_covers_monitor: false,
                ..Default::default()
            },
            &cfg,
        );
        assert_eq!(busy_no_fg.next.state, ControllerState::Active);

        // `QUNS_BUSY` + ön plan penceresi monitörü tam kaplarsa Suspend tetiklenir.
        let busy_with_fg = step_controller_state(
            initial,
            ResourceSignals {
                notification_state: UserNotificationState::Busy,
                foreground_covers_monitor: true,
                ..Default::default()
            },
            &cfg,
        );
        assert_eq!(busy_with_fg.next.state, ControllerState::Suspended);
        assert!(busy_with_fg.transitioned);

        // Normal masaüstü bildirim durumu Active kalır.
        let active = step_controller_state(
            initial,
            ResourceSignals {
                notification_state: UserNotificationState::AcceptsNotifications,
                ..Default::default()
            },
            &cfg,
        );
        assert_eq!(active.next.state, ControllerState::Active);
        assert!(!active.transitioned);
    }

    #[test]
    fn pure_state_machine_foreground_monitor_coverage_suspends() {
        let cfg = ControllerConfig::default();
        let initial = ControllerMachineState::default();

        assert!(rect_covers_monitor((0, 0, 1920, 1080), (0, 0, 1920, 1080)));
        assert!(!rect_covers_monitor((0, 0, 1920, 1032), (0, 0, 1920, 1080)));
        assert!(rect_covers_monitor(
            (1920, 0, 3840, 1080),
            (1920, 0, 3840, 1080)
        ));
        assert!(!rect_covers_monitor((0, 0, 0, 0), (0, 0, 1920, 1080)));

        // Monitör kapsaması tek başına `AcceptsNotifications` iken otomatik gizlenen görev çubuğu
        // yanlış pozitifini önler; `QUNS_BUSY` ile birleştiğinde Suspend olur.
        let non_busy = step_controller_state(
            initial,
            ResourceSignals {
                notification_state: UserNotificationState::AcceptsNotifications,
                foreground_covers_monitor: true,
                ..Default::default()
            },
            &cfg,
        );
        assert_eq!(non_busy.next.state, ControllerState::Active);

        let busy_full = step_controller_state(
            initial,
            ResourceSignals {
                notification_state: UserNotificationState::Busy,
                foreground_covers_monitor: true,
                ..Default::default()
            },
            &cfg,
        );
        assert_eq!(busy_full.next.state, ControllerState::Suspended);
    }

    #[test]
    fn pure_state_machine_gpu_hysteresis_requires_consecutive_samples() {
        let cfg = ControllerConfig::default(); // >=80% x3 up, <=70% x3 down
        let mut m = ControllerMachineState::default();

        // 2 ardışık yüksek örnek henüz Suspend yapmaz.
        for _ in 0..2 {
            let out = step_controller_state(
                m,
                ResourceSignals {
                    gpu_3d_utilization_pct: 85.0,
                    ..Default::default()
                },
                &cfg,
            );
            m = out.next;
            assert_eq!(m.state, ControllerState::Active);
        }

        // Arada tek düşük örnek sayacı sıfırlar.
        m = step_controller_state(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: 50.0,
                ..Default::default()
            },
            &cfg,
        )
        .next;
        assert_eq!(m.gpu_high_streak, 0);
        assert_eq!(m.state, ControllerState::Active);

        // 3 ardışık >= %80 örnek Suspend tetikler.
        for i in 0..3 {
            let out = step_controller_state(
                m,
                ResourceSignals {
                    gpu_3d_utilization_pct: 80.0 + i as f64,
                    ..Default::default()
                },
                &cfg,
            );
            m = out.next;
            if i < 2 {
                assert_eq!(m.state, ControllerState::Active);
            } else {
                assert_eq!(m.state, ControllerState::Suspended);
                assert!(m.gpu_overloaded);
                assert!(out.transitioned);
            }
        }

        // Histerezis bandı (%75: 70..80 arası) içinde Suspended korunur.
        m = step_controller_state(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: 75.0,
                ..Default::default()
            },
            &cfg,
        )
        .next;
        assert_eq!(m.state, ControllerState::Suspended);

        // 2 düşük örnek yetmez, 3. düşük örnekte Active'e döner.
        for i in 0..3 {
            let out = step_controller_state(
                m,
                ResourceSignals {
                    gpu_3d_utilization_pct: 60.0,
                    ..Default::default()
                },
                &cfg,
            );
            m = out.next;
            if i < 2 {
                assert_eq!(m.state, ControllerState::Suspended);
            } else {
                assert_eq!(m.state, ControllerState::Active);
                assert!(!m.gpu_overloaded);
                assert!(out.should_flush_batch);
            }
        }
    }

    #[test]
    fn pure_state_machine_power_batching_and_priority_transitions() {
        let cfg = ControllerConfig::default();
        let mut m = ControllerMachineState::default();

        // Pil gücü -> Batching
        let out = step_controller_state(
            m,
            ResourceSignals {
                power: PowerSignals {
                    on_battery: true,
                    battery_saver: false,
                },
                ..Default::default()
            },
            &cfg,
        );
        m = out.next;
        assert_eq!(m.state, ControllerState::Batching);
        assert!(out.transitioned);
        assert!(!out.should_flush_batch);

        // Pil + Tam ekran -> Suspended önceliklidir.
        let out = step_controller_state(
            m,
            ResourceSignals {
                notification_state: UserNotificationState::RunningD3dFullScreen,
                power: PowerSignals {
                    on_battery: true,
                    battery_saver: false,
                },
                ..Default::default()
            },
            &cfg,
        );
        m = out.next;
        assert_eq!(m.state, ControllerState::Suspended);

        // Tam ekrandan çıkınca hala pildeyse Batching'e döner.
        let out = step_controller_state(
            m,
            ResourceSignals {
                power: PowerSignals {
                    on_battery: true,
                    battery_saver: false,
                },
                ..Default::default()
            },
            &cfg,
        );
        m = out.next;
        assert_eq!(m.state, ControllerState::Batching);
        assert!(!out.should_flush_batch);

        // AC'ye dönülünce ama pil tasarrufu açıksa yine Batching.
        let out = step_controller_state(
            m,
            ResourceSignals {
                power: PowerSignals {
                    on_battery: false,
                    battery_saver: true,
                },
                ..Default::default()
            },
            &cfg,
        );
        m = out.next;
        assert_eq!(m.state, ControllerState::Batching);

        // AC + pil tasarrufu kapalı -> Active ve kuyruk boşaltma sinyali.
        let out = step_controller_state(m, ResourceSignals::default(), &cfg);
        assert_eq!(out.next.state, ControllerState::Active);
        assert!(out.transitioned);
        assert!(out.should_flush_batch);
    }

    #[test]
    fn configurable_thresholds_and_nan_safety() {
        let cfg = ControllerConfig {
            gpu_high_threshold_pct: 60.0,
            gpu_low_threshold_pct: 40.0,
            gpu_high_consecutive_samples: 2,
            gpu_low_consecutive_samples: 1,
            ..Default::default()
        };

        let m = ControllerMachineState::default();
        let m = step_controller_state(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: f64::NAN,
                ..Default::default()
            },
            &cfg,
        )
        .next;
        assert_eq!(m.state, ControllerState::Active);

        let m = step_controller_state(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: 62.0,
                ..Default::default()
            },
            &cfg,
        )
        .next;
        assert_eq!(m.state, ControllerState::Active);

        let m = step_controller_state(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: 62.0,
                ..Default::default()
            },
            &cfg,
        )
        .next;
        assert_eq!(m.state, ControllerState::Suspended);

        let m = step_controller_state(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: 40.0,
                ..Default::default()
            },
            &cfg,
        )
        .next;
        assert_eq!(m.state, ControllerState::Active);
    }

    #[test]
    fn batch_queue_evicts_oldest_on_overflow_and_flushes_fifo_on_ac() {
        let mut q = BatchQueue::new(3);
        q.push(dummy_packet(1, "bir"));
        q.push(dummy_packet(2, "iki"));
        q.push(dummy_packet(3, "uc"));
        q.push(dummy_packet(4, "dort"));
        q.push(dummy_packet(5, "bes"));

        assert_eq!(q.len(), 3);
        assert_eq!(q.dropped_oldest_count(), 2);

        let (tx, mut rx) = channel::<RawCapturePacket>(8);
        let flushed = q.flush_to(&tx);
        assert_eq!(flushed, 3);
        assert!(q.is_empty());

        let p1 = rx.try_recv().unwrap();
        let p2 = rx.try_recv().unwrap();
        let p3 = rx.try_recv().unwrap();
        assert_eq!(p1.timestamp_ms, 3);
        assert_eq!(p2.timestamp_ms, 4);
        assert_eq!(p3.timestamp_ms, 5);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn suspended_state_skips_uia_and_produces_zero_packets() {
        use std::sync::atomic::AtomicBool;

        let shared_state = AtomicU8::new(ControllerState::Suspended as u8);
        let batch_queue = Mutex::new(BatchQueue::new(4));
        let (tx, mut rx) = channel::<RawCapturePacket>(8);
        let extractor_called = AtomicBool::new(false);

        handle_signal_with_state(&shared_state, &batch_queue, &tx, || {
            extractor_called.store(true, Ordering::SeqCst);
            Some(dummy_packet(10, "asla"))
        });

        assert!(
            !extractor_called.load(Ordering::SeqCst),
            "Suspended durumunda UIA/pano çıkarıcısı çağrılmamalı"
        );
        assert!(batch_queue.lock().unwrap().is_empty());
        assert!(rx.try_recv().is_err());

        // Batching -> kuyruğa alır, kanala henüz göndermez.
        shared_state.store(ControllerState::Batching as u8, Ordering::SeqCst);
        handle_signal_with_state(&shared_state, &batch_queue, &tx, || {
            Some(dummy_packet(20, "batch"))
        });
        assert_eq!(batch_queue.lock().unwrap().len(), 1);
        assert!(rx.try_recv().is_err());

        // Active -> önce bekleyen batch'i boşaltır, sonra yeni paketi gönderir.
        shared_state.store(ControllerState::Active as u8, Ordering::SeqCst);
        handle_signal_with_state(&shared_state, &batch_queue, &tx, || {
            Some(dummy_packet(30, "active"))
        });
        assert!(batch_queue.lock().unwrap().is_empty());
        assert_eq!(rx.try_recv().unwrap().timestamp_ms, 20);
        assert_eq!(rx.try_recv().unwrap().timestamp_ms, 30);
    }

    #[test]
    fn manual_pause_for_and_resume_coordinates_state_watch_and_batch_flush() {
        let cfg = ControllerConfig::default();
        let shared_state = Arc::new(AtomicU8::new(ControllerState::Active as u8));
        let batch_queue = Arc::new(Mutex::new(BatchQueue::new(8)));
        let (tx, mut rx) = channel::<RawCapturePacket>(8);
        let (watch_tx, mut watch_rx) = watch::channel(ControllerState::Active);

        let control = ControllerControl::new(
            cfg,
            Arc::clone(&shared_state),
            Arc::clone(&batch_queue),
            tx,
            watch_tx,
            ControllerMachineState::default(),
            ResourceSignals::default(),
        );

        assert!(!control.is_paused());
        assert_eq!(control.pause_remaining(), None);

        // `Batching` sırasında kuyruğa bir paket alalım, ardından manuel duraklatma başlatalım.
        let batch_signals = ResourceSignals {
            power: PowerSignals {
                on_battery: true,
                battery_saver: false,
            },
            ..Default::default()
        };
        let out = control.apply_sample(batch_signals);
        assert_eq!(out.next.state, ControllerState::Batching);
        assert_eq!(*watch_rx.borrow_and_update(), ControllerState::Batching);
        batch_queue
            .lock()
            .unwrap()
            .push(dummy_packet(100, "queued"));

        control.pause_for(Duration::from_secs(3600));
        assert!(control.is_paused());
        assert!(control.pause_remaining().is_some());
        assert_eq!(
            ControllerState::from_u8(shared_state.load(Ordering::Acquire)),
            ControllerState::Suspended
        );
        assert_eq!(*watch_rx.borrow_and_update(), ControllerState::Suspended);

        // Duraklatma aktifken AC gücüne geçilse bile `Suspended` korunur ve kuyruk boşaltılmaz.
        let ac_out = control.apply_sample(ResourceSignals::default());
        assert_eq!(ac_out.next.state, ControllerState::Suspended);
        assert!(!ac_out.should_flush_batch);
        assert_eq!(batch_queue.lock().unwrap().len(), 1);
        assert!(rx.try_recv().is_err());

        // `resume()` AC sinyalleriyle hemen `Active`e geçer ve bekleyen kuyruğu boşaltır.
        control.resume();
        assert!(!control.is_paused());
        assert_eq!(control.pause_remaining(), None);
        assert_eq!(
            ControllerState::from_u8(shared_state.load(Ordering::Acquire)),
            ControllerState::Active
        );
        assert_eq!(*watch_rx.borrow_and_update(), ControllerState::Active);
        assert!(batch_queue.lock().unwrap().is_empty());
        assert_eq!(rx.try_recv().unwrap().timestamp_ms, 100);

        // `Duration::ZERO` aktif duraklatmayı temizler.
        control.pause_for(Duration::from_secs(60));
        assert!(control.is_paused());
        control.pause_for(Duration::ZERO);
        assert!(!control.is_paused());
        assert_eq!(
            ControllerState::from_u8(shared_state.load(Ordering::Acquire)),
            ControllerState::Active
        );

        // Süresi dolmuş kısa duraklatma `apply_sample` içinde temizlenir.
        control.pause_for(Duration::from_millis(25));
        assert!(control.is_paused());
        std::thread::sleep(Duration::from_millis(40));
        let expired_out = control.apply_sample(ResourceSignals::default());
        assert!(!control.is_paused());
        assert_eq!(expired_out.next.state, ControllerState::Active);
        assert!(expired_out.transitioned);
    }

    #[test]
    fn step_controller_state_with_pause_preserves_gpu_hysteresis() {
        let cfg = ControllerConfig::default();
        let mut m = ControllerMachineState::default();

        // Manuel duraklatma sırasında gelen 3 yüksek GPU örneği histerezisi günceller,
        // ancak `resume` edilince otomatik `Suspended` durumu devam eder.
        for _ in 0..3 {
            let out = step_controller_state_with_pause(
                m,
                ResourceSignals {
                    gpu_3d_utilization_pct: 90.0,
                    ..Default::default()
                },
                &cfg,
                true,
                m.state,
            );
            m = out.next;
            assert_eq!(m.state, ControllerState::Suspended);
            assert!(!out.should_flush_batch);
        }
        assert!(m.gpu_overloaded);

        let after_resume = step_controller_state_with_pause(
            m,
            ResourceSignals {
                gpu_3d_utilization_pct: 75.0,
                ..Default::default()
            },
            &cfg,
            false,
            ControllerState::Suspended,
        );
        assert_eq!(after_resume.next.state, ControllerState::Suspended);
        assert!(!after_resume.transitioned);
    }
}
