//! Win32 olay kancaları ve pano dinleyici mesaj pompası.
//!
//! - `s-sensor-win32-pump`: gizli mesaj penceresi, pano dinleyicisi ve `SetWinEventHook`;
//!   sinyalleri sınırlı kuyruğa iletir.
//! - `s-sensor-uia-worker`: UIA okumasını yönetir (varsayılan: işçi süreç, bkz.
//!   `crate::uia_worker`), odak yerleşme (250 ms) ve soğuma (2 s) uygular, paketleri
//!   kopyalamadan `mpsc` hattına gönderir.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use s_types::{EventKind, RawCapturePacket, RawPayload};
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, EVENT_OBJECT_CONTENTSCROLLED,
    EVENT_OBJECT_DESCRIPTIONCHANGE, EVENT_OBJECT_LIVEREGIONCHANGED, EVENT_OBJECT_NAMECHANGE,
    EVENT_OBJECT_REORDER, EVENT_OBJECT_TEXTSELECTIONCHANGED, EVENT_OBJECT_VALUECHANGE,
    EVENT_SYSTEM_FOREGROUND, GA_ROOT, GetAncestor, GetForegroundWindow, GetMessageW,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, HWND_MESSAGE, MSG,
    PostMessageW, PostQuitMessage, PostThreadMessageW, RegisterClassExW, TranslateMessage,
    UnregisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS, WM_CLIPBOARDUPDATE, WM_CLOSE, WM_DESTROY, WM_QUIT, WNDCLASSEXW,
};
use windows::core::{PCWSTR, PWSTR, s, w};
use zeroize::Zeroizing;

use crate::controller::win32::{ControllerThreadHandle, ResourceMonitor, spawn_controller_thread};
use crate::controller::{
    BatchQueue, ControllerControl, ControllerMachineState, ControllerState, StateListener,
    handle_signal_with_state, step_controller_state,
};
use crate::uia::win32::UiaExtraction;
use crate::uia::{FocusGate, TextDeltaTracker, TreeChangeDebouncer};
use crate::uia_worker::win32::{UiaBackend, WorkerPool};
use crate::uia_worker::{UiaIsolation, WORKER_ARG};
use crate::{SensorConfig, SensorError};

const INTERNAL_SIGNAL_QUEUE_CAPACITY: usize = 64;
static NEXT_CLASS_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
enum RawOsSignal {
    ForegroundChanged { hwnd_raw: isize, timestamp_ms: u64 },
    ClipboardUpdated { timestamp_ms: u64 },
    TreeActivity,
}

#[derive(Clone)]
struct TreeCoalesceState {
    wake_pending: Arc<AtomicBool>,
    latest_hwnd: Arc<AtomicIsize>,
    latest_timestamp_ms: Arc<AtomicU64>,
}

impl TreeCoalesceState {
    fn new() -> Self {
        Self {
            wake_pending: Arc::new(AtomicBool::new(false)),
            latest_hwnd: Arc::new(AtomicIsize::new(0)),
            latest_timestamp_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn record_from_pump(&self, hwnd_raw: isize, timestamp_ms: u64) -> bool {
        self.latest_hwnd.store(hwnd_raw, Ordering::Release);
        self.latest_timestamp_ms
            .store(timestamp_ms, Ordering::Release);
        !self.wake_pending.swap(true, Ordering::AcqRel)
    }

    fn cancel_wake(&self) {
        self.wake_pending.store(false, Ordering::Release);
    }

    fn take_latest(&self) -> (isize, u64) {
        self.wake_pending.store(false, Ordering::Release);
        (
            self.latest_hwnd.load(Ordering::Acquire),
            self.latest_timestamp_ms.load(Ordering::Acquire),
        )
    }
}

struct PumpContext {
    sig_tx: SyncSender<RawOsSignal>,
    state: Arc<AtomicU8>,
    tree: TreeCoalesceState,
    self_excl: Arc<SelfExclusion>,
}

thread_local! {
    static PUMP_CTX: RefCell<Option<PumpContext>> = const { RefCell::new(None) };
}

fn is_pump_suspended() -> bool {
    PUMP_CTX.with(|slot| {
        slot.borrow().as_ref().is_some_and(|ctx| {
            ControllerState::from_u8(ctx.state.load(Ordering::Acquire))
                == ControllerState::Suspended
        })
    })
}

fn is_pump_hwnd_excluded(hwnd: HWND) -> bool {
    let excl = PUMP_CTX.with(|slot| slot.borrow().as_ref().map(|ctx| Arc::clone(&ctx.self_excl)));
    if let Some(excl) = excl
        && excl.is_hwnd_excluded(hwnd)
    {
        excl.record_drop();
        return true;
    }
    false
}

fn emit_signal(signal: RawOsSignal) {
    PUMP_CTX.with(|slot| {
        if let Some(ctx) = slot.borrow().as_ref() {
            if ControllerState::from_u8(ctx.state.load(Ordering::Acquire))
                == ControllerState::Suspended
            {
                return;
            }
            // Mesaj pompası iş parçacığı asla bloklanmaz; taşma olursa en yeni olay düşer.
            let _ = ctx.sig_tx.try_send(signal);
        }
    });
}

fn emit_tree_activity(hwnd_raw: isize, timestamp_ms: u64) {
    PUMP_CTX.with(|slot| {
        if let Some(ctx) = slot.borrow().as_ref() {
            if ControllerState::from_u8(ctx.state.load(Ordering::Acquire))
                == ControllerState::Suspended
            {
                return;
            }
            if ctx.tree.record_from_pump(hwnd_raw, timestamp_ms)
                && ctx.sig_tx.try_send(RawOsSignal::TreeActivity).is_err()
            {
                ctx.tree.cancel_wake();
            }
        }
    });
}

pub(crate) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `HandleGuard` yalnızca `OpenProcess` ile açılmış geçerli tutamaçları sarar.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

fn decode_utf16_exact(wide: &[u16]) -> Zeroizing<String> {
    if wide.is_empty() {
        return Zeroizing::new(String::new());
    }
    let cap = wide.len().saturating_mul(3);
    let mut out = Zeroizing::new(String::with_capacity(cap));
    for ch in char::decode_utf16(wide.iter().copied()) {
        out.push(ch.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    out
}

/// Pencere tutamacından `(process_id, process_name, window_title)` bilgisini okur.
///
/// Ham başlık ve süreç adı yalnızca `RawCapturePacket` içine yerleştirilmek üzere üretilir.
pub(crate) fn query_window_attribution(hwnd: HWND) -> (u32, Zeroizing<String>, Zeroizing<String>) {
    if hwnd.0.is_null() {
        return (
            0,
            Zeroizing::new(String::from("unknown")),
            Zeroizing::new(String::new()),
        );
    }

    let mut pid: u32 = 0;
    // SAFETY: `hwnd` boş olmayan bir pencere tutamacıdır; `pid` geçerli yığın değişkenidir.
    let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

    let process_name = if pid != 0 {
        query_process_basename(pid).unwrap_or_else(|| Zeroizing::new(String::from("unknown")))
    } else {
        Zeroizing::new(String::from("unknown"))
    };

    let window_title = query_window_title(hwnd);
    (pid, process_name, window_title)
}

fn query_process_image_utf16(handle: HANDLE) -> Option<(Zeroizing<Vec<u16>>, usize)> {
    let mut buf = Zeroizing::new(vec![0u16; 1024]);
    let mut len = buf.len() as u32;
    // SAFETY: `handle` geçerli süreç tutamacıdır; `buf` `len` eleman kapasitelidir.
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .ok()?;
    let used = (len as usize).min(buf.len());
    Some((buf, used))
}

fn path_basename_slice(path_slice: &[u16]) -> &[u16] {
    match path_slice
        .iter()
        .rposition(|&c| c == u16::from(b'\\') || c == u16::from(b'/'))
    {
        Some(pos) => &path_slice[pos + 1..],
        None => path_slice,
    }
}

fn query_process_basename(pid: u32) -> Option<Zeroizing<String>> {
    // SAFETY: Sadece salt-okunur süreç yolu sorgusu için en düşük yetki (`PROCESS_QUERY_LIMITED_INFORMATION`) istenir.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let _guard = HandleGuard(handle);

    let (buf, used) = query_process_image_utf16(handle)?;
    Some(decode_utf16_exact(path_basename_slice(&buf[..used])))
}

const SELF_EXCL_CACHE_TTL: Duration = Duration::from_secs(5);
const SELF_EXCL_CACHE_MAX_ENTRIES: usize = 256;
const MAX_PARENT_CHAIN_DEPTH: usize = 16;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

/// Synapse Mind'ın kendi sürecini, UIA işçi alt süreçlerini ve WebView2 çocuklarını
/// olay yakalama ve pano okuma hattından en erken noktada hariç tutar.
pub(crate) struct SelfExclusion {
    self_pid: u32,
    self_exe_lower: Option<String>,
    worker_pool: Option<Arc<WorkerPool>>,
    cache: Mutex<HashMap<u32, (bool, Instant)>>,
    dropped_events: AtomicU64,
}

impl SelfExclusion {
    pub(crate) fn new(worker_pool: Option<Arc<WorkerPool>>) -> Self {
        // SAFETY: `GetCurrentProcessId` ve `GetCurrentProcess` salt-okunur sözde-tutamac/PID döndürür.
        let (self_pid, current_proc) = unsafe { (GetCurrentProcessId(), GetCurrentProcess()) };
        let self_exe_lower = query_process_image_utf16(current_proc)
            .map(|(buf, used)| decode_utf16_exact(&buf[..used]).to_ascii_lowercase());
        Self {
            self_pid,
            self_exe_lower,
            worker_pool,
            cache: Mutex::new(HashMap::with_capacity(64)),
            dropped_events: AtomicU64::new(0),
        }
    }

    pub(crate) fn record_drop(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn dropped_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub(crate) fn is_hwnd_excluded(&self, hwnd: HWND) -> bool {
        if hwnd.0.is_null() {
            return false;
        }
        let pid = window_pid(hwnd);
        if pid != 0 && self.is_pid_excluded(pid) {
            return true;
        }
        // SAFETY: `hwnd` boş olmayan pencere tutamacıdır; üst kök pencere salt-okunur sorgulanır.
        let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
        if !root.0.is_null() && root != hwnd {
            let root_pid = window_pid(root);
            if root_pid != 0 && self.is_pid_excluded(root_pid) {
                return true;
            }
        }
        false
    }

    pub(crate) fn is_pid_excluded(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        if pid == self.self_pid {
            return true;
        }
        if self
            .worker_pool
            .as_ref()
            .is_some_and(|pool| pool.contains_worker_pid(pid))
        {
            return true;
        }

        let now = Instant::now();
        {
            let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(&(excluded, expires_at)) = guard.get(&pid)
                && now < expires_at
            {
                return excluded;
            }
        }

        let excluded = self.inspect_pid_slow(pid);
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= SELF_EXCL_CACHE_MAX_ENTRIES {
            guard.retain(|_, &mut (_, exp)| now < exp);
            if guard.len() >= SELF_EXCL_CACHE_MAX_ENTRIES {
                guard.clear();
            }
        }
        guard.insert(pid, (excluded, now + SELF_EXCL_CACHE_TTL));
        excluded
    }

    fn inspect_pid_slow(&self, pid: u32) -> bool {
        // SAFETY: Yalnızca süreç yolu ve gerekirse komut satırını salt-okunur denetlemek için açılır.
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return false;
        };
        let _guard = HandleGuard(handle);

        let Some((path_buf, used)) = query_process_image_utf16(handle) else {
            return false;
        };
        let path_slice = &path_buf[..used];
        let base_lower = decode_utf16_exact(path_basename_slice(path_slice)).to_ascii_lowercase();

        if base_lower == "msedgewebview2.exe" {
            return self.has_self_ancestor(pid);
        }

        if let Some(self_exe) = &self.self_exe_lower {
            let full_lower = decode_utf16_exact(path_slice).to_ascii_lowercase();
            if &full_lower == self_exe {
                return process_cmdline_has_worker_arg(handle);
            }
        }

        false
    }

    fn has_self_ancestor(&self, pid: u32) -> bool {
        // SAFETY: Tüm süreçlerin (PID, ParentPID) tablosunu almak için salt-okunur ToolHelp anlık görüntüsü.
        let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
            return false;
        };
        let _guard = HandleGuard(snapshot);

        let mut parents: Vec<(u32, u32)> = Vec::with_capacity(256);
        let mut entry = PROCESSENTRY32W {
            dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // SAFETY: `snapshot` geçerli süreç anlık görüntüsü, `entry.dwSize` başlatılmıştır.
        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_err() {
            return false;
        }
        loop {
            parents.push((entry.th32ProcessID, entry.th32ParentProcessID));
            // SAFETY: Aynı geçerli `snapshot` üzerinde sıradaki `PROCESSENTRY32W` kaydı okunur.
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }

        let mut current = pid;
        let mut visited = [0u32; MAX_PARENT_CHAIN_DEPTH];
        let mut depth = 0usize;
        while current != 0 && depth < MAX_PARENT_CHAIN_DEPTH {
            if visited[..depth].contains(&current) {
                break;
            }
            visited[depth] = current;
            depth += 1;

            let Some(ppid) = parents
                .iter()
                .find_map(|&(child, parent)| (child == current).then_some(parent))
            else {
                break;
            };
            if ppid == 0 || ppid == current {
                break;
            }
            if ppid == self.self_pid
                || self
                    .worker_pool
                    .as_ref()
                    .is_some_and(|pool| pool.contains_worker_pid(ppid))
            {
                return true;
            }
            current = ppid;
        }
        false
    }
}

fn window_pid(hwnd: HWND) -> u32 {
    if hwnd.0.is_null() {
        return 0;
    }
    let mut pid = 0u32;
    // SAFETY: `hwnd` boş olmayan bir pencere tutamacıdır; `pid` geçerli yığın değişkenidir.
    let _ = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    pid
}

fn process_cmdline_has_worker_arg(handle: HANDLE) -> bool {
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;

    // SAFETY: `ntdll.dll` her Windows kullanıcı kipi sürecine yüklüdür ve sabit adı taşır.
    let Ok(ntdll) = (unsafe { GetModuleHandleW(w!("ntdll.dll")) }) else {
        return false;
    };
    // SAFETY: `NtQueryInformationProcess` sembolü `ntdll.dll` içinden çözülür.
    let Some(proc_addr) = (unsafe { GetProcAddress(ntdll, s!("NtQueryInformationProcess")) })
    else {
        return false;
    };
    // SAFETY: `NtQueryInformationProcessFn` Win32/Native API çağrı sözleşmesi ile eşleşir.
    let nt_query: NtQueryInformationProcessFn = unsafe { core::mem::transmute(proc_addr) };

    const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 512]);
    let mut ret_len: u32 = 0;
    // SAFETY: `handle` geçerli süreç tutamacıdır; `buf` `ret_len` çıktısı için geçerli bellektir.
    let mut status = unsafe {
        nt_query(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut ret_len,
        )
    };

    if matches!(
        status,
        STATUS_BUFFER_OVERFLOW | STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL
    ) && (ret_len as usize) > buf.len()
        && ret_len <= 32 * 1024
    {
        buf = Zeroizing::new(vec![0u8; ret_len as usize]);
        // SAFETY: `buf` istenen `ret_len` kapasitesiyle yeniden ayrıldı.
        status = unsafe {
            nt_query(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut ret_len,
            )
        };
    }

    if status < 0 || buf.len() < core::mem::size_of::<UnicodeString>() {
        return false;
    }

    // SAFETY: `buf.len() >= size_of::<UnicodeString>()` doğrulandı; başlık hizadan bağımsız okunur.
    let us = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<UnicodeString>()) };
    if us.buffer.is_null() || us.length == 0 {
        return false;
    }

    let buf_start = buf.as_ptr() as usize;
    let buf_end = buf_start + buf.len();
    let ptr_addr = us.buffer as usize;
    let byte_len = us.length as usize;
    if ptr_addr < buf_start || ptr_addr > buf_end || byte_len > buf_end - ptr_addr {
        return false;
    }

    let offset = ptr_addr - buf_start;
    let raw_bytes = &buf[offset..offset + byte_len];
    let mut wide = Zeroizing::new(Vec::with_capacity(byte_len / 2));
    for pair in raw_bytes.chunks_exact(2) {
        wide.push(u16::from_ne_bytes([pair[0], pair[1]]));
    }
    let cmd = decode_utf16_exact(&wide);
    cmd.contains(WORKER_ARG)
}

fn query_window_title(hwnd: HWND) -> Zeroizing<String> {
    // SAFETY: `hwnd` geçerli bir pencere tutamacıdır; uzunluk sorgusu salt-okunurdur.
    let expected_len = unsafe { GetWindowTextLengthW(hwnd) };
    if expected_len <= 0 {
        return Zeroizing::new(String::new());
    }

    let cap = (expected_len as usize).saturating_add(1);
    let mut buf = Zeroizing::new(vec![0u16; cap]);
    // SAFETY: `buf` `expected_len + 1` adet `u16` kapasitesine sahiptir ve yeniden tahsis yapmaz.
    let copied = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if copied <= 0 {
        return Zeroizing::new(String::new());
    }
    let copied_len = (copied as usize).min(buf.len());
    decode_utf16_exact(&buf[..copied_len])
}

const fn is_tree_change_event(event: u32) -> bool {
    matches!(
        event,
        EVENT_OBJECT_REORDER
            | EVENT_OBJECT_NAMECHANGE
            | EVENT_OBJECT_DESCRIPTIONCHANGE
            | EVENT_OBJECT_VALUECHANGE
            | EVENT_OBJECT_TEXTSELECTIONCHANGED
            | EVENT_OBJECT_CONTENTSCROLLED
            | EVENT_OBJECT_LIVEREGIONCHANGED
    )
}

fn unhook_all(hooks: Vec<HWINEVENTHOOK>) {
    for hook in hooks {
        if !hook.is_invalid() {
            // SAFETY: Her `hook` bu iş parçacığında `SetWinEventHook` ile kurulmuş geçerli bir tutamaçtır.
            let _ = unsafe { UnhookWinEvent(hook) };
        }
    }
}

fn install_win_event_hooks(accessibility_enabled: bool) -> Option<Vec<HWINEVENTHOOK>> {
    let mut ranges = Vec::with_capacity(5);
    ranges.push((EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND));
    if accessibility_enabled {
        ranges.push((EVENT_OBJECT_REORDER, EVENT_OBJECT_REORDER));
        ranges.push((EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_VALUECHANGE));
        ranges.push((
            EVENT_OBJECT_TEXTSELECTIONCHANGED,
            EVENT_OBJECT_CONTENTSCROLLED,
        ));
        ranges.push((
            EVENT_OBJECT_LIVEREGIONCHANGED,
            EVENT_OBJECT_LIVEREGIONCHANGED,
        ));
    }

    let mut hooks = Vec::with_capacity(ranges.len());
    for (event_min, event_max) in ranges {
        // SAFETY: `WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS` modunda kanca bu
        // iş parçacığının mesaj döngüsü üzerinden güvenli şekilde tetiklenir.
        let hook = unsafe {
            SetWinEventHook(
                event_min,
                event_max,
                None,
                Some(win_event_proc),
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            )
        };
        if hook.is_invalid() {
            unhook_all(hooks);
            return None;
        }
        hooks.push(hook);
    }
    Some(hooks)
}

#[allow(clippy::too_many_arguments)]
fn try_extract_focus_packet(
    hwnd_raw: isize,
    fg_raw: isize,
    timestamp_ms: u64,
    self_excl: &SelfExclusion,
    config: &SensorConfig,
    focus_gate: &mut FocusGate,
    delta_tracker: &mut TextDeltaTracker,
    extract_fn: impl FnOnce(HWND) -> UiaExtraction,
) -> Option<RawCapturePacket> {
    if hwnd_raw == 0 || fg_raw != hwnd_raw {
        return None;
    }

    let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);
    if self_excl.is_hwnd_excluded(hwnd) {
        self_excl.record_drop();
        return None;
    }

    let (process_id, mut process_name, mut window_title) = query_window_attribution(hwnd);
    if !focus_gate.should_emit_focus(
        hwnd_raw,
        &window_title,
        Instant::now(),
        config.focus_cooldown,
    ) {
        return None;
    }

    let mut extraction = extract_fn(hwnd);
    let _empty_reason = extraction.empty_reason;
    let _node_count = extraction.node_count;
    delta_tracker.record_snapshot(hwnd_raw, &extraction.text);

    Some(RawCapturePacket {
        timestamp_ms,
        process_id,
        process_name: core::mem::take(&mut *process_name),
        window_title: core::mem::take(&mut *window_title),
        event_kind: EventKind::WindowFocusChanged,
        raw_payload: RawPayload::AccessibilityText(core::mem::take(&mut *extraction.text)),
    })
}

#[allow(clippy::too_many_arguments)]
fn process_focus_settle_fire(
    hwnd_raw: isize,
    timestamp_ms: u64,
    extractor: &UiaBackend,
    self_excl: &SelfExclusion,
    config: &SensorConfig,
    worker_state: &AtomicU8,
    worker_batch_queue: &Mutex<BatchQueue>,
    worker_tx: &Sender<RawCapturePacket>,
    focus_gate: &mut FocusGate,
    delta_tracker: &mut TextDeltaTracker,
) {
    handle_signal_with_state(worker_state, worker_batch_queue, worker_tx, || {
        // SAFETY: Salt-okunur ön plan penceresi tutamacı sorgusu.
        let fg = unsafe { GetForegroundWindow() };
        try_extract_focus_packet(
            hwnd_raw,
            fg.0 as isize,
            timestamp_ms,
            self_excl,
            config,
            focus_gate,
            delta_tracker,
            |hwnd| extractor.extract(hwnd, config),
        )
    });
}

#[allow(clippy::too_many_arguments)]
fn try_extract_tree_packet(
    hwnd_raw: isize,
    fg_raw: isize,
    timestamp_ms: u64,
    self_excl: &SelfExclusion,
    config: &SensorConfig,
    delta_tracker: &mut TextDeltaTracker,
    extract_fn: impl FnOnce(HWND) -> UiaExtraction,
) -> Option<RawCapturePacket> {
    if hwnd_raw == 0 || fg_raw != hwnd_raw {
        return None;
    }

    let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);
    if self_excl.is_hwnd_excluded(hwnd) {
        self_excl.record_drop();
        return None;
    }

    let mut extraction = extract_fn(hwnd);
    let _empty_reason = extraction.empty_reason;

    if extraction.text.is_empty() {
        return None;
    }

    if !delta_tracker.should_emit_and_update(
        hwnd_raw,
        &extraction.text,
        &config.accessibility_stream,
    ) {
        return None;
    }

    let (process_id, mut process_name, mut window_title) = query_window_attribution(hwnd);

    Some(RawCapturePacket {
        timestamp_ms,
        process_id,
        process_name: core::mem::take(&mut *process_name),
        window_title: core::mem::take(&mut *window_title),
        event_kind: EventKind::AccessibilityTreeChanged {
            node_count: extraction.node_count,
        },
        raw_payload: RawPayload::AccessibilityText(core::mem::take(&mut *extraction.text)),
    })
}

#[allow(clippy::too_many_arguments)]
fn process_tree_debounce_fire(
    hwnd_raw: isize,
    timestamp_ms: u64,
    extractor: &UiaBackend,
    self_excl: &SelfExclusion,
    config: &SensorConfig,
    worker_state: &AtomicU8,
    worker_batch_queue: &Mutex<BatchQueue>,
    worker_tx: &Sender<RawCapturePacket>,
    delta_tracker: &mut TextDeltaTracker,
) {
    handle_signal_with_state(worker_state, worker_batch_queue, worker_tx, || {
        // SAFETY: Salt-okunur ön plan penceresi tutamacı sorgusu.
        let fg = unsafe { GetForegroundWindow() };
        try_extract_tree_packet(
            hwnd_raw,
            fg.0 as isize,
            timestamp_ms,
            self_excl,
            config,
            delta_tracker,
            |hwnd| extractor.extract(hwnd, config),
        )
    });
}

// SAFETY: Win32 `SetWinEventHook` tarafından mesaj pompası iş parçacığında çağrılır;
// `Suspended` iken veya Synapse Mind öz süreç pencerelerinde sinyal üretmeden hemen döner.
unsafe extern "system" fn win_event_proc(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _id_event_thread: u32,
    _dwms_event_time: u32,
) {
    if is_pump_suspended() || hwnd.0.is_null() {
        return;
    }
    // Yalnızca üst düzey pencere odak değişimleri (OBJID_WINDOW == 0, CHILDID_SELF == 0).
    if event == EVENT_SYSTEM_FOREGROUND && id_object == 0 && id_child == 0 {
        if is_pump_hwnd_excluded(hwnd) {
            return;
        }
        emit_signal(RawOsSignal::ForegroundChanged {
            hwnd_raw: hwnd.0 as isize,
            timestamp_ms: current_timestamp_ms(),
        });
        return;
    }

    if is_tree_change_event(event) {
        if is_pump_hwnd_excluded(hwnd) {
            return;
        }
        // SAFETY: Salt-okunur ön plan penceresi tutamacı sorgusu.
        let fg = unsafe { GetForegroundWindow() };
        if fg.0.is_null() {
            return;
        }
        if fg != hwnd && is_pump_hwnd_excluded(fg) {
            return;
        }
        let belongs_to_fg = if hwnd == fg {
            true
        } else {
            // SAFETY: `hwnd` boş olmayan bir pencere tutamacıdır; kök üst penceresi sorgulanır.
            let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
            root == fg
        };
        if belongs_to_fg {
            emit_tree_activity(fg.0 as isize, current_timestamp_ms());
        }
    }
}

// SAFETY: Win32 pencere mesaj dağıtıcısı tarafından mesaj pompası iş parçacığında çağrılır.
// Her alt Win32 çağrısı kendi `unsafe` bloğunda doğrulanır.
unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CLIPBOARDUPDATE => {
            if !is_pump_suspended() {
                emit_signal(RawOsSignal::ClipboardUpdated {
                    timestamp_ms: current_timestamp_ms(),
                });
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            // SAFETY: `hwnd` kapanmadan önce pano dinleyicisinden çıkarılır ve yok edilir.
            let _ = unsafe { RemoveClipboardFormatListener(hwnd) };
            // SAFETY: `hwnd`, bu `wnd_proc`'a ait geçerli mesaj penceresidir.
            let _ = unsafe { DestroyWindow(hwnd) };
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: Pencere yok edilirken mesaj döngüsünü sonlandırmak için `PostQuitMessage` çağrılır.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => {
            // SAFETY: İşlenmeyen standart mesajlar `DefWindowProcW`'e devredilir.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

pub(crate) struct Win32SensorHandles {
    msg_hwnd_raw: isize,
    pump_thread_id: u32,
    stopped: AtomicBool,
    worker_pool: Option<Arc<WorkerPool>>,
    control: Arc<ControllerControl>,
    controller_thread: Option<ControllerThreadHandle>,
    pump_thread: Option<JoinHandle<()>>,
    worker_thread: Option<JoinHandle<()>>,
    pub(crate) state_rx: watch::Receiver<ControllerState>,
}

impl Win32SensorHandles {
    pub(crate) fn pause_for(&self, duration: Duration) {
        self.control.pause_for(duration);
    }

    pub(crate) fn resume(&self) {
        self.control.resume();
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.control.is_paused()
    }

    pub(crate) fn pause_remaining(&self) -> Option<Duration> {
        self.control.pause_remaining()
    }

    pub(crate) fn stop_inner(&mut self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }

        // Uçuştaki ve boşta bekleyen UIA işçilerini hemen öldür (5 s zaman aşımı beklenmez).
        if let Some(pool) = &self.worker_pool {
            pool.shutdown();
        }

        if let Some(mut controller) = self.controller_thread.take() {
            controller.stop();
        }

        let hwnd = HWND(self.msg_hwnd_raw as *mut core::ffi::c_void);
        if !hwnd.0.is_null() {
            // SAFETY: `hwnd` mesaj pompası iş parçacığının oluşturduğu gizli penceredir;
            // `WM_CLOSE` pencereyi yok edip `PostQuitMessage(0)` tetikler.
            let posted = unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) };
            if posted.is_err() && self.pump_thread_id != 0 {
                // SAFETY: `pump_thread_id` canlı Win32 mesaj pompası iş parçacığı kimliğidir.
                let _ = unsafe {
                    PostThreadMessageW(self.pump_thread_id, WM_QUIT, WPARAM(0), LPARAM(0))
                };
            }
        }

        if let Some(handle) = self.pump_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Win32SensorHandles {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

pub(crate) fn spawn_win32_sensors(
    tx: Sender<RawCapturePacket>,
    config: SensorConfig,
) -> Result<Win32SensorHandles, SensorError> {
    let initial_signals = ResourceMonitor::new().sample();
    let initial_outcome = step_controller_state(
        ControllerMachineState::default(),
        initial_signals,
        &config.controller,
    );
    let initial_machine = initial_outcome.next;

    let shared_state = Arc::new(AtomicU8::new(initial_machine.state as u8));
    let batch_queue = Arc::new(Mutex::new(BatchQueue::new(
        config.controller.batch_queue_capacity,
    )));
    let (state_watch_tx, state_watch_rx) = watch::channel(initial_machine.state);

    let (sig_tx, sig_rx) = sync_channel::<RawOsSignal>(INTERNAL_SIGNAL_QUEUE_CAPACITY);
    let (worker_ready_tx, worker_ready_rx) = sync_channel::<Result<(), SensorError>>(1);
    let (pump_ready_tx, pump_ready_rx) = sync_channel::<Result<(isize, u32), SensorError>>(1);
    let tree_coalesce = TreeCoalesceState::new();

    let worker_pool = match config.uia_isolation {
        UiaIsolation::InProcess => None,
        UiaIsolation::Worker => {
            if !crate::uia_worker::host_hook_installed() {
                return Err(SensorError::UiaWorkerHostMissing);
            }
            let warm_initial = initial_machine.state == ControllerState::Active;
            Some(WorkerPool::new(config.uia_worker_timeout, warm_initial)?)
        }
    };

    let self_exclusion = Arc::new(SelfExclusion::new(worker_pool.clone()));

    let worker_state = Arc::clone(&shared_state);
    let worker_batch_queue = Arc::clone(&batch_queue);
    let worker_tx = tx.clone();
    let worker_tree = tree_coalesce.clone();
    let worker_pool_for_thread = worker_pool.clone();
    let worker_self_excl = Arc::clone(&self_exclusion);
    let pump_self_excl = Arc::clone(&self_exclusion);

    let worker_thread = std::thread::Builder::new()
        .name(String::from("s-sensor-uia-worker"))
        .spawn(move || {
            let extractor = match worker_pool_for_thread {
                Some(pool) => {
                    let _ = worker_ready_tx.send(Ok(()));
                    UiaBackend::Worker(pool)
                }
                None => match UiaBackend::new(&config) {
                    Ok(ext) => {
                        let _ = worker_ready_tx.send(Ok(()));
                        ext
                    }
                    Err(err) => {
                        let _ = worker_ready_tx.send(Err(err));
                        return;
                    }
                },
            };

            let mut focus_gate = FocusGate::new();
            let mut debouncer = TreeChangeDebouncer::new();
            let mut delta_tracker = TextDeltaTracker::new();

            loop {
                if worker_tx.is_closed() {
                    break;
                }

                let now = Instant::now();
                if ControllerState::from_u8(worker_state.load(Ordering::Acquire))
                    == ControllerState::Suspended
                {
                    focus_gate.clear_pending();
                    debouncer.clear();
                } else if let Some((hwnd_raw, timestamp_ms)) = focus_gate.poll_ready(now) {
                    process_focus_settle_fire(
                        hwnd_raw,
                        timestamp_ms,
                        &extractor,
                        &worker_self_excl,
                        &config,
                        &worker_state,
                        &worker_batch_queue,
                        &worker_tx,
                        &mut focus_gate,
                        &mut delta_tracker,
                    );
                    continue;
                } else if let Some((hwnd_raw, timestamp_ms)) =
                    debouncer.poll_ready(now, &config.accessibility_stream)
                {
                    process_tree_debounce_fire(
                        hwnd_raw,
                        timestamp_ms,
                        &extractor,
                        &worker_self_excl,
                        &config,
                        &worker_state,
                        &worker_batch_queue,
                        &worker_tx,
                        &mut delta_tracker,
                    );
                    continue;
                }

                let earliest_deadline = match (
                    focus_gate.next_deadline(),
                    debouncer.next_deadline(&config.accessibility_stream),
                ) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };

                let next_msg = match earliest_deadline {
                    Some(deadline) => {
                        let wait = deadline.saturating_duration_since(Instant::now());
                        match sig_rx.recv_timeout(wait) {
                            Ok(sig) => Some(sig),
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    None => match sig_rx.recv() {
                        Ok(sig) => Some(sig),
                        Err(_) => break,
                    },
                };

                let Some(sig) = next_msg else {
                    continue;
                };

                match sig {
                    RawOsSignal::ForegroundChanged {
                        hwnd_raw,
                        timestamp_ms,
                    } => {
                        debouncer.clear();
                        if ControllerState::from_u8(worker_state.load(Ordering::Acquire))
                            != ControllerState::Suspended
                        {
                            focus_gate.note_focus(
                                hwnd_raw,
                                Instant::now(),
                                timestamp_ms,
                                config.focus_settle,
                            );
                        }
                    }
                    RawOsSignal::ClipboardUpdated { timestamp_ms } => {
                        handle_signal_with_state(
                            &worker_state,
                            &worker_batch_queue,
                            &worker_tx,
                            || {
                                crate::clipboard::win32::capture_clipboard_packet(
                                    timestamp_ms,
                                    config.max_uia_text_bytes,
                                    |owner_hwnd| {
                                        if worker_self_excl.is_hwnd_excluded(owner_hwnd) {
                                            worker_self_excl.record_drop();
                                            true
                                        } else {
                                            false
                                        }
                                    },
                                )
                            },
                        );
                    }
                    RawOsSignal::TreeActivity => {
                        let (hwnd_raw, timestamp_ms) = worker_tree.take_latest();
                        if ControllerState::from_u8(worker_state.load(Ordering::Acquire))
                            != ControllerState::Suspended
                        {
                            debouncer.note_activity(hwnd_raw, Instant::now(), timestamp_ms);
                        }
                    }
                }
            }
        })
        .map_err(|e| SensorError::ThreadSpawnFailed(e.to_string()))?;

    // Önce UIA / COM işçi iş parçacığının hazır olduğundan emin ol.
    match worker_ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let _ = worker_thread.join();
            return Err(err);
        }
        Err(_) => {
            let _ = worker_thread.join();
            return Err(SensorError::ThreadSpawnFailed(String::from(
                "UIA worker terminated before ready",
            )));
        }
    }

    let pump_state = Arc::clone(&shared_state);
    let accessibility_enabled = config.accessibility_stream.enabled;
    let pump_thread = std::thread::Builder::new()
        .name(String::from("s-sensor-win32-pump"))
        .spawn(move || {
            PUMP_CTX.with(|slot| {
                *slot.borrow_mut() = Some(PumpContext {
                    sig_tx,
                    state: pump_state,
                    tree: tree_coalesce,
                    self_excl: pump_self_excl,
                });
            });

            let seq = NEXT_CLASS_SEQ.fetch_add(1, Ordering::Relaxed);
            let class_name_str = Zeroizing::new(format!("SRecallSensorMsgWindow_{seq}\0"));
            let mut class_name_utf16 = Zeroizing::new(Vec::with_capacity(class_name_str.len()));
            class_name_utf16.extend(class_name_str.encode_utf16());
            let class_pcwstr = PCWSTR(class_name_utf16.as_ptr());

            // SAFETY: `None` parametresi mevcut modülün (`exe`) `HMODULE` tutamacını döndürür.
            let hmodule = match unsafe { GetModuleHandleW(None) } {
                Ok(m) => m,
                Err(e) => {
                    PUMP_CTX.with(|slot| *slot.borrow_mut() = None);
                    let _ = pump_ready_tx.send(Err(SensorError::Win32SetupFailed(e.code().0)));
                    return;
                }
            };
            let hinstance: HINSTANCE = hmodule.into();

            let wc = WNDCLASSEXW {
                cbSize: core::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinstance,
                lpszClassName: class_pcwstr,
                ..Default::default()
            };

            // SAFETY: `wc` geçerli `cbSize`, `wnd_proc` ve null-sonlandırılmış sınıf adına sahiptir.
            let atom = unsafe { RegisterClassExW(&wc) };
            if atom == 0 {
                PUMP_CTX.with(|slot| *slot.borrow_mut() = None);
                let _ = pump_ready_tx.send(Err(SensorError::Win32SetupFailed(-1)));
                return;
            }

            // SAFETY: Kayıtlı sınıf adıyla yalnızca mesaj alan (`HWND_MESSAGE`) gizli pencere açılır.
            let hwnd = match unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    class_pcwstr,
                    PCWSTR::null(),
                    WINDOW_STYLE(0),
                    0,
                    0,
                    0,
                    0,
                    Some(HWND_MESSAGE),
                    None,
                    Some(hinstance),
                    None,
                )
            } {
                Ok(h) => h,
                Err(e) => {
                    // SAFETY: Kayıtlı sınıf temizlenir.
                    let _ = unsafe { UnregisterClassW(class_pcwstr, Some(hinstance)) };
                    PUMP_CTX.with(|slot| *slot.borrow_mut() = None);
                    let _ = pump_ready_tx.send(Err(SensorError::Win32SetupFailed(e.code().0)));
                    return;
                }
            };

            // SAFETY: `hwnd` bu iş parçacığına ait geçerli gizli penceredir.
            if let Err(e) = unsafe { AddClipboardFormatListener(hwnd) } {
                // SAFETY: Hata durumunda açılan pencere ve sınıf temizlenir.
                let _ = unsafe { DestroyWindow(hwnd) };
                // SAFETY: Kayıtlı sınıf temizlenir.
                let _ = unsafe { UnregisterClassW(class_pcwstr, Some(hinstance)) };
                PUMP_CTX.with(|slot| *slot.borrow_mut() = None);
                let _ = pump_ready_tx.send(Err(SensorError::Win32SetupFailed(e.code().0)));
                return;
            }

            let Some(hooks) = install_win_event_hooks(accessibility_enabled) else {
                // SAFETY: Kurulan pano dinleyicisi ve pencere temizlenir.
                let _ = unsafe { RemoveClipboardFormatListener(hwnd) };
                // SAFETY: Açılan pencere yok edilir.
                let _ = unsafe { DestroyWindow(hwnd) };
                // SAFETY: Kayıtlı sınıf temizlenir.
                let _ = unsafe { UnregisterClassW(class_pcwstr, Some(hinstance)) };
                PUMP_CTX.with(|slot| *slot.borrow_mut() = None);
                let _ = pump_ready_tx.send(Err(SensorError::Win32SetupFailed(-2)));
                return;
            };

            // SAFETY: Mevcut OS iş parçacığı kimliğini döndürür.
            let tid = unsafe { GetCurrentThreadId() };
            let _ = pump_ready_tx.send(Ok((hwnd.0 as isize, tid)));

            let mut msg = MSG::default();
            loop {
                // SAFETY: `msg` geçerli yığın yapısıdır; `None` tüm iş parçacığı/pencere mesajlarını çeker.
                let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                if ret.0 <= 0 {
                    break;
                }
                // SAFETY: `msg` `GetMessageW` ile doldurulmuş geçerli bir Win32 mesajıdır.
                let _ = unsafe { TranslateMessage(&msg) };
                // SAFETY: `msg` pencere yordamına (`wnd_proc`) dağıtılır.
                let _ = unsafe { DispatchMessageW(&msg) };
            }

            unhook_all(hooks);
            // SAFETY: `hwnd` kapanmadan önce pano dinleyicisinden çıkarılır.
            let _ = unsafe { RemoveClipboardFormatListener(hwnd) };
            // SAFETY: Pencere zaten `WM_CLOSE` ile yok edilmediyse temizlenir.
            let _ = unsafe { DestroyWindow(hwnd) };
            // SAFETY: Sınıf kaydı kaldırılır.
            let _ = unsafe { UnregisterClassW(class_pcwstr, Some(hinstance)) };
            PUMP_CTX.with(|slot| *slot.borrow_mut() = None);
        })
        .map_err(|e| SensorError::ThreadSpawnFailed(e.to_string()))?;

    let (msg_hwnd_raw, pump_thread_id) = match pump_ready_rx.recv() {
        Ok(Ok(ids)) => ids,
        Ok(Err(err)) => {
            let _ = pump_thread.join();
            let _ = worker_thread.join();
            return Err(err);
        }
        Err(_) => {
            let _ = pump_thread.join();
            let _ = worker_thread.join();
            return Err(SensorError::ThreadSpawnFailed(String::from(
                "Win32 message pump terminated before ready",
            )));
        }
    };

    let state_listener: Option<StateListener> = worker_pool.as_ref().map(|pool| {
        let p = Arc::clone(pool);
        Arc::new(move |state: ControllerState| p.on_controller_state(state)) as StateListener
    });

    let control = ControllerControl::new_with_listener(
        config.controller,
        Arc::clone(&shared_state),
        Arc::clone(&batch_queue),
        tx,
        state_watch_tx,
        initial_machine,
        initial_signals,
        state_listener,
    );

    let controller_thread = match spawn_controller_thread(Arc::clone(&control)) {
        Ok(ctrl) => ctrl,
        Err(err) => {
            let mut handles = Win32SensorHandles {
                msg_hwnd_raw,
                pump_thread_id,
                stopped: AtomicBool::new(false),
                worker_pool,
                control,
                controller_thread: None,
                pump_thread: Some(pump_thread),
                worker_thread: Some(worker_thread),
                state_rx: state_watch_rx,
            };
            handles.stop_inner();
            return Err(err);
        }
    };

    Ok(Win32SensorHandles {
        msg_hwnd_raw,
        pump_thread_id,
        stopped: AtomicBool::new(false),
        worker_pool,
        control,
        controller_thread: Some(controller_thread),
        pump_thread: Some(pump_thread),
        worker_thread: Some(worker_thread),
        state_rx: state_watch_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSelfWindowGuard {
        hwnd: HWND,
        class_name: Vec<u16>,
        hinstance: HINSTANCE,
    }

    unsafe extern "system" fn test_wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // SAFETY: Test penceresi için standart Win32 mesaj işleyicisine devredilir.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    impl TestSelfWindowGuard {
        fn create(seq: u64) -> Self {
            let class_name: Vec<u16> = format!("SRecallSelfExclTestWnd_{seq}\0")
                .encode_utf16()
                .collect();
            // SAFETY: Mevcut test sürecinin modül tutamacı alınır.
            let hmodule = unsafe { GetModuleHandleW(None) }.expect("GetModuleHandleW");
            let hinstance: HINSTANCE = hmodule.into();
            let wc = WNDCLASSEXW {
                cbSize: core::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(test_wnd_proc),
                hInstance: hinstance,
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            // SAFETY: `wc` geçerli sınıf yapısı ve null-sonlandırılmış sınıf adı taşır.
            let atom = unsafe { RegisterClassExW(&wc) };
            assert_ne!(atom, 0, "RegisterClassExW başarısız");

            // SAFETY: Mesaj-yalnızca gizli test penceresi bu sürece ait olarak oluşturulur.
            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(class_name.as_ptr()),
                    PCWSTR::null(),
                    WINDOW_STYLE(0),
                    0,
                    0,
                    0,
                    0,
                    Some(HWND_MESSAGE),
                    None,
                    Some(hinstance),
                    None,
                )
            }
            .expect("CreateWindowExW");

            Self {
                hwnd,
                class_name,
                hinstance,
            }
        }
    }

    impl Drop for TestSelfWindowGuard {
        fn drop(&mut self) {
            // SAFETY: `self.hwnd` bu test penceresinin geçerli tutamacıdır.
            let _ = unsafe { DestroyWindow(self.hwnd) };
            // SAFETY: Aynı sınıf adı ve modül ile kayıt kaldırılır.
            let _ =
                unsafe { UnregisterClassW(PCWSTR(self.class_name.as_ptr()), Some(self.hinstance)) };
        }
    }

    #[test]
    fn self_exclusion_drops_self_pid_and_self_hwnd_before_uia_or_packet() {
        // SAFETY: `GetCurrentProcessId` salt-okunur geçerli süreç PID'sini döndürür.
        let current_pid = unsafe { GetCurrentProcessId() };
        let self_excl = Arc::new(SelfExclusion::new(None));

        assert!(self_excl.is_pid_excluded(current_pid));
        assert!(!self_excl.is_pid_excluded(0));
        assert!(!self_excl.is_hwnd_excluded(HWND(core::ptr::null_mut())));
        // SAFETY: Test sürecinin kendi komut satırı `--s-sensor-uia-worker` içermez.
        assert!(!process_cmdline_has_worker_arg(unsafe {
            GetCurrentProcess()
        }));

        let wnd = TestSelfWindowGuard::create(NEXT_CLASS_SEQ.fetch_add(1, Ordering::Relaxed));
        assert!(self_excl.is_hwnd_excluded(wnd.hwnd));

        let hwnd_raw = wnd.hwnd.0 as isize;
        let cfg = SensorConfig::default();
        let mut focus_gate = FocusGate::new();
        let mut delta_tracker = TextDeltaTracker::new();
        let mut uia_calls = 0u64;

        let focus_pkt = try_extract_focus_packet(
            hwnd_raw,
            hwnd_raw,
            100,
            &self_excl,
            &cfg,
            &mut focus_gate,
            &mut delta_tracker,
            |_| {
                uia_calls += 1;
                UiaExtraction {
                    text: Zeroizing::new(String::from("asla uretilmemeli")),
                    node_count: 1,
                    empty_reason: None,
                }
            },
        );
        assert!(focus_pkt.is_none());
        assert_eq!(uia_calls, 0);
        assert_eq!(self_excl.dropped_count(), 1);

        let tree_pkt = try_extract_tree_packet(
            hwnd_raw,
            hwnd_raw,
            200,
            &self_excl,
            &cfg,
            &mut delta_tracker,
            |_| {
                uia_calls += 1;
                UiaExtraction {
                    text: Zeroizing::new(String::from("asla uretilmemeli tree")),
                    node_count: 2,
                    empty_reason: None,
                }
            },
        );
        assert!(tree_pkt.is_none());
        assert_eq!(uia_calls, 0);
        assert_eq!(self_excl.dropped_count(), 2);

        // Pompa geri çağırma yolu (`win_event_proc`) öz pencere için sinyal dahi kuyruklamaz.
        let (sig_tx, sig_rx) = sync_channel::<RawOsSignal>(8);
        let pump_state = Arc::new(AtomicU8::new(ControllerState::Active as u8));
        PUMP_CTX.with(|slot| {
            *slot.borrow_mut() = Some(PumpContext {
                sig_tx,
                state: pump_state,
                tree: TreeCoalesceState::new(),
                self_excl: Arc::clone(&self_excl),
            });
        });

        // SAFETY: Geçerli öz pencere tutamacıyla odak olayı simüle edilir.
        unsafe {
            win_event_proc(
                HWINEVENTHOOK::default(),
                EVENT_SYSTEM_FOREGROUND,
                wnd.hwnd,
                0,
                0,
                0,
                0,
            );
        }
        PUMP_CTX.with(|slot| *slot.borrow_mut() = None);

        assert!(sig_rx.try_recv().is_err());
        assert_eq!(self_excl.dropped_count(), 3);

        // Pano sahibi Synapse Mind öz penceresiyse pano açılmadan atlanır.
        let clip_pkt = crate::clipboard::win32::capture_clipboard_packet_for_owner(
            wnd.hwnd,
            300,
            cfg.max_uia_text_bytes,
            |owner| {
                if self_excl.is_hwnd_excluded(owner) {
                    self_excl.record_drop();
                    true
                } else {
                    false
                }
            },
        );
        assert!(clip_pkt.is_none());
        assert_eq!(self_excl.dropped_count(), 4);
    }
}
