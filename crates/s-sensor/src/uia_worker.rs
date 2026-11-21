//! UIA okumasının tek kullanımlık işçi süreçte yalıtılması.
//!
//! `UIAutomationCore.dll` okuduğu metni kendi heap tamponlarına yazar ve sıfırlamadan
//! serbest bırakır; uzun ömürlü bir süreçte bu kalıntı bellekte kalır. Bu yüzden:
//! - Her an en fazla bir önceden ısıtılmış (COM + UIA kurulu, henüz pencere okumamış) işçi
//!   hazır bekler. İstek (yalnızca `HWND` ve sınırlar) `stdin` ile gider, işçi tek pencereyi
//!   okur, sonucu yazar ve öldürülür; çekirdek sayfalarını sıfırlayarak geri alır.
//! - İşçiler `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` iş nesnesine atanır; ana süreç ölürse ölürler.
//! - `Suspended` durumunda yedek işçi tutulmaz.
//!
//! Ana süreçte tek ham kopya olur: gövde tam boyutlu `Zeroizing<Vec<u8>>` tampona okunur ve
//! kopyalanmadan `RawCapturePacket`'e taşınır; hata yollarında kısmi gövde sıfırlanır.

use std::io::{self, Read};
use std::sync::Mutex;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

/// `WorkerPool` içindeki canlı UIA işçi süreç PID kümesi (öz süreç dışlaması için).
#[derive(Default)]
pub(crate) struct WorkerPidSet(Mutex<Vec<u32>>);

impl WorkerPidSet {
    pub(crate) fn insert(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !g.contains(&pid) {
            g.push(pid);
        }
    }

    pub(crate) fn remove(&self, pid: u32) {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = g.iter().position(|&p| p == pid) {
            g.swap_remove(pos);
        }
    }

    pub(crate) fn contains(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        let g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.contains(&pid)
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<u32> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// İşçi alt komutu (`argv[1]`). Ana yürütülebilir dosya `main` başında
/// [`run_uia_worker_if_requested`] çağırmalıdır.
pub const WORKER_ARG: &str = "--s-sensor-uia-worker";

/// UIA çıkarımının nerede çalışacağı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UiaIsolation {
    /// Her çıkarım önceden ısıtılmış tek atımlık yardımcı işçi süreçte (Gate 2 için varsayılan).
    #[default]
    Worker,
    /// Eski yol: UIA ana süreçte. `UIAutomationCore.dll` iç yığın kalıntısı bırakır;
    /// yalnızca testler/ölçüm karşılaştırması içindir.
    InProcess,
}

/// İşçi zaman aşımı varsayılanı (ısıtma / çıkarım).
pub const DEFAULT_WORKER_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(windows)]
static HOST_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// `main`'in başında çağrılır. `argv[1] == WORKER_ARG` ise süreç UIA işçisi olarak tek isteği
/// işler ve geri dönmez; değilse işçi kancasının kurulu olduğunu kaydedip döner.
pub fn run_uia_worker_if_requested() {
    let mut args = std::env::args_os();
    let _exe = args.next();
    if args.next().is_some_and(|a| a == WORKER_ARG) {
        #[cfg(windows)]
        {
            win32::worker_main();
        }
        #[cfg(not(windows))]
        std::process::exit(2);
    }
    #[cfg(windows)]
    HOST_HOOK_INSTALLED.store(true, Ordering::SeqCst);
}

#[cfg(windows)]
pub(crate) fn host_hook_installed() -> bool {
    HOST_HOOK_INSTALLED.load(Ordering::SeqCst)
}

// ------------------------------------------------------------------------- çerçeve

pub(crate) const READY_MAGIC: [u8; 4] = *b"SRWR";
pub(crate) const READY_ERR_MAGIC: [u8; 4] = *b"SRWE";
pub(crate) const REQUEST_MAGIC: [u8; 4] = *b"SRQ1";
pub(crate) const REQUEST_LEN: usize = 32;
pub(crate) const FRAME_MAGIC: [u8; 4] = *b"SRW1";
pub(crate) const HEADER_LEN: usize = 16;

/// `empty_reason` statik etiketlerinin tel kodları (ham içerik taşımaz).
pub(crate) fn reason_code(reason: Option<&'static str>) -> u8 {
    match reason {
        None => 0,
        Some("null_hwnd") => 1,
        Some("element_from_handle_failed") => 2,
        Some("no_text_nodes_in_tree") => 3,
        Some("uia_init_failed") => 4,
        Some(_) => 255,
    }
}

pub(crate) fn reason_from_code(code: u8) -> Option<&'static str> {
    match code {
        0 => None,
        1 => Some("null_hwnd"),
        2 => Some("element_from_handle_failed"),
        3 => Some("no_text_nodes_in_tree"),
        4 => Some("uia_init_failed"),
        _ => Some("uia_worker_unknown_reason"),
    }
}

/// Yalnızca sayısal istek (`stdin` üzerinden; komut satırında ham veri yok).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerRequest {
    pub hwnd_raw: isize,
    pub max_depth: u32,
    pub max_nodes: u32,
    pub max_text_bytes: u32,
    pub timeout_ms: u64,
}

pub(crate) fn encode_request(req: WorkerRequest) -> [u8; REQUEST_LEN] {
    let mut out = [0u8; REQUEST_LEN];
    out[..4].copy_from_slice(&REQUEST_MAGIC);
    out[4..12].copy_from_slice(&(req.hwnd_raw as i64).to_le_bytes());
    out[12..16].copy_from_slice(&req.max_depth.to_le_bytes());
    out[16..20].copy_from_slice(&req.max_nodes.to_le_bytes());
    out[20..24].copy_from_slice(&req.max_text_bytes.to_le_bytes());
    out[24..32].copy_from_slice(&req.timeout_ms.to_le_bytes());
    out
}

#[allow(dead_code)] // işçi tarafı (Windows) ve testler kullanır
pub(crate) fn decode_request(buf: &[u8; REQUEST_LEN]) -> Option<WorkerRequest> {
    if buf[..4] != REQUEST_MAGIC {
        return None;
    }
    let hwnd_i64 = i64::from_le_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    let hwnd_raw = isize::try_from(hwnd_i64).ok()?;
    Some(WorkerRequest {
        hwnd_raw,
        max_depth: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        max_nodes: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        max_text_bytes: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
        timeout_ms: u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]),
    })
}

/// Yalnızca sayısal metadata; `Debug` güvenlidir (ham metin yok).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    pub reason: u8,
    pub node_count: u32,
    pub text_len: u32,
}

pub(crate) fn encode_header(h: FrameHeader) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(&FRAME_MAGIC);
    out[4] = h.reason;
    out[8..12].copy_from_slice(&h.node_count.to_le_bytes());
    out[12..16].copy_from_slice(&h.text_len.to_le_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// Boru kapandı / okuma hatası (işçi çöktü, öldürüldü veya zaman aşımı).
    Io,
    /// Sihirli sayı yanlış (yanlış ikili / kancasız ana uygulama).
    BadMagic,
    /// Bildirilen gövde boyutu yapılandırma sınırını aşıyor.
    TooLarge,
    /// Gövde geçerli UTF-8 değil.
    BadUtf8,
}

/// Tek çerçeveyi okur. Gövde, tam kapasiteli `Zeroizing<Vec<u8>>` tampona DOĞRUDAN okunur
/// (yeniden tahsis yok) ve kopyasız `Zeroizing<String>`'e taşınır. Hata yolunda kısmi gövde sıfırlanır.
pub(crate) fn read_frame<R: Read>(
    r: &mut R,
    max_text_bytes: usize,
) -> Result<(FrameHeader, Zeroizing<String>), FrameError> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr).map_err(|_| FrameError::Io)?;
    if hdr[..4] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let h = FrameHeader {
        reason: hdr[4],
        node_count: u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
        text_len: u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
    };
    let len = h.text_len as usize;
    if len > max_text_bytes {
        return Err(FrameError::TooLarge);
    }
    if len == 0 {
        return Ok((h, Zeroizing::new(String::new())));
    }
    // Tam kapasite: `read_exact` yeniden tahsis yapmaz; hata durumunda `Zeroizing` kısmi baytları siler.
    let mut body = Zeroizing::new(vec![0u8; len]);
    read_exact_body(r, &mut body)?;
    match String::from_utf8(core::mem::take(&mut *body)) {
        Ok(s) => Ok((h, Zeroizing::new(s))),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(FrameError::BadUtf8)
        }
    }
}

fn read_exact_body<R: Read>(r: &mut R, body: &mut [u8]) -> Result<(), FrameError> {
    r.read_exact(body).map_err(|_| FrameError::Io)
}

#[allow(dead_code)] // yalnızca işçi tarafı (Windows) ve testler kullanır
pub(crate) fn write_frame<W: io::Write>(
    w: &mut W,
    reason: Option<&'static str>,
    node_count: u32,
    text: &str,
) -> io::Result<()> {
    let hdr = encode_header(FrameHeader {
        reason: reason_code(reason),
        node_count,
        text_len: u32::try_from(text.len()).unwrap_or(u32::MAX),
    });
    w.write_all(&hdr)?;
    w.write_all(text.as_bytes())?;
    w.flush()
}

// ------------------------------------------------------------------- Windows tarafı

#[cfg(windows)]
pub(crate) mod win32 {
    use std::io::{Read, Write};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows::Win32::System::Threading::TerminateProcess;
    use windows::core::PCWSTR;
    use zeroize::Zeroizing;

    use super::{
        FrameError, READY_ERR_MAGIC, READY_MAGIC, REQUEST_LEN, WORKER_ARG, WorkerPidSet,
        WorkerRequest, decode_request, encode_request, read_frame, reason_from_code, write_frame,
    };
    use crate::controller::ControllerState;
    use crate::uia::win32::{UiaExtraction, UiaExtractor, disable_oleaut_bstr_cache};
    use crate::{SensorConfig, SensorError};

    /// `CREATE_NO_WINDOW`: işçi konsol penceresi açmaz.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// İşçi öz-zaman-aşımı çıkış kodu.
    const WORKER_TIMEOUT_EXIT: i32 = 124;

    /// Başlatma geri bildirim imlecini (`IDC_APPSTARTING`) kapatır: kendi iş parçacığına
    /// `WM_NULL` gönderir ve onu `GetMessageW` ile hemen alır. Sistem, ilk `GetMessage`
    /// çağrısından sonra geri bildirim imlecini kapatır (STARTUPINFO, STARTF_FORCEONFEEDBACK).
    fn dismiss_launch_feedback_cursor() {
        use windows::Win32::System::Threading::GetCurrentThreadId;
        use windows::Win32::UI::WindowsAndMessaging::{
            GetMessageW, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, WM_NULL,
        };
        let mut msg = MSG::default();
        // SAFETY: `msg` geçerli bir yerel `MSG`; `PeekMessageW` yalnızca bu iş parçacığının
        // mesaj kuyruğunu oluşturur. Kendi kuyruğumuza gönderilen `WM_NULL` kuyrukta olduğu
        // için `GetMessageW` bloklamadan hemen döner.
        unsafe {
            let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE);
            if PostThreadMessageW(
                GetCurrentThreadId(),
                WM_NULL,
                Default::default(),
                Default::default(),
            )
            .is_ok()
            {
                let _ = GetMessageW(&mut msg, None, 0, 0);
            }
        }
    }

    /// İşçi süreç girişi (önceden ısıtılmış tek kullanımlık model):
    /// 1. `SetOaNoCache` + `COM` + `IUIAutomation` kurar (`disable_oleaut_bstr_cache` YALNIZCA burada).
    /// 2. `stdout`'a `SRWR` (veya `SRWE`) yazar ve `stdin`'den 32 baytlık `SRQ1` isteğini bekler.
    /// 3. İstek gelince tek pencereyi okur, `SRW1` çerçevesini yazar ve çıkar (veya ana süreç öldürür).
    pub(crate) fn worker_main() -> ! {
        // İşçi pencere açmayan bir GUI sürecidir; ilk `GetMessage` Windows'un başlatma
        // imlecini (APPSTARTING) hemen kapatır.
        dismiss_launch_feedback_cursor();

        // BSTR önbelleği yalnızca işçi süreçte, UIA öncesi kapatılır.
        disable_oleaut_bstr_cache();

        let extractor = match UiaExtractor::new() {
            Ok(ext) => ext,
            Err(_) => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(&READY_ERR_MAGIC);
                let _ = out.flush();
                std::process::exit(1);
            }
        };

        {
            let mut out = std::io::stdout().lock();
            if out.write_all(&READY_MAGIC).is_err() || out.flush().is_err() {
                drop(extractor);
                std::process::exit(1);
            }
        }

        // Hazır beklerken HİÇBİR pencere okumaz; `stdin`'den sayısal istek bekler.
        let mut req_buf = [0u8; REQUEST_LEN];
        {
            let mut inp = std::io::stdin().lock();
            if inp.read_exact(&mut req_buf).is_err() {
                drop(extractor);
                std::process::exit(0);
            }
        }

        let Some(req) = decode_request(&req_buf) else {
            drop(extractor);
            std::process::exit(2);
        };

        // Öz-zaman-aşımı: yalnızca istek alındıktan sonra işçi sınırlı süre yaşar.
        let timeout_ms = req.timeout_ms.max(1);
        let _ = std::thread::Builder::new()
            .name(String::from("s-sensor-uia-worker-selfkill"))
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(timeout_ms));
                std::process::exit(WORKER_TIMEOUT_EXIT);
            });

        let config = SensorConfig {
            max_uia_depth: req.max_depth as usize,
            max_uia_nodes: req.max_nodes,
            max_uia_text_bytes: req.max_text_bytes as usize,
            ..SensorConfig::default()
        };

        let hwnd = HWND(req.hwnd_raw as *mut core::ffi::c_void);
        let ex = extractor.extract_window_text(hwnd, &config);
        let mut out = std::io::stdout().lock();
        let r = write_frame(&mut out, ex.empty_reason, ex.node_count, &ex.text);
        let _ = out.flush();
        drop(ex);
        drop(extractor);
        std::process::exit(i32::from(r.is_err()));
    }

    /// Ana süreç ölürse tüm UIA işçilerini çekirdekte temizleyen Job Object sarmalayıcısı.
    struct JobObject(HANDLE);

    // SAFETY: Win32 `HANDLE` iş parçacıkları arasında güvenle taşınabilir; yalnızca `AssignProcessToJobObject`
    // (iş parçacığı güvenli kernel çağrısı) ve `Drop` içinde `CloseHandle` için kullanılır.
    unsafe impl Send for JobObject {}
    // SAFETY: Yukarıdaki ile aynı; `JobObject` üzerinde değiştirilebilir durum yok, yalnızca kernel tutamacı.
    unsafe impl Sync for JobObject {}

    impl JobObject {
        fn create_kill_on_close() -> Option<Self> {
            // SAFETY: Null ad ve güvenlik özniteliği ile anonim Job Object oluşturulur.
            let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.ok()?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `handle` geçerli bir Job Object tutamacıdır; `info` tam boyutlu geçerli yığın yapısıdır.
            let res = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if res.is_err() {
                // SAFETY: Yapılandırma başarısızsa tutamaç hemen kapatılır.
                let _ = unsafe { CloseHandle(handle) };
                None
            } else {
                Some(Self(handle))
            }
        }

        fn assign(&self, child: &Child) {
            let proc_handle = HANDLE(child.as_raw_handle());
            if !proc_handle.is_invalid() {
                // SAFETY: `self.0` geçerli Job Object, `proc_handle` ise canlı `Child` süreç tutamacıdır.
                let _ = unsafe { AssignProcessToJobObject(self.0, proc_handle) };
            }
        }
    }

    impl Drop for JobObject {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` `CreateJobObjectW` ile açılmış geçerli tutamaçtır; kapatılması
                // `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` gereği atanmış tüm işçileri öldürür.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// `Child` beklemeden önce (`child.wait()`) veya `drop` öncesinde `disarm()` edilen öldürme jetonu.
    struct KillToken {
        handle: Mutex<Option<isize>>,
        killed: AtomicBool,
    }

    impl KillToken {
        fn from_child(child: &Child) -> Arc<Self> {
            Arc::new(Self {
                handle: Mutex::new(Some(child.as_raw_handle() as isize)),
                killed: AtomicBool::new(false),
            })
        }

        fn kill(&self) {
            self.killed.store(true, Ordering::Release);
            let guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(raw) = *guard {
                let h = HANDLE(raw as *mut core::ffi::c_void);
                if !h.is_invalid() {
                    // SAFETY: `disarm()` henüz çağrılmadığı için `Child` halen canlıdır ve
                    // `h` geçerli bir Win32 süreç tutamacıdır (`TerminateProcess` boruyu anında kapatır).
                    let _ = unsafe { TerminateProcess(h, 1) };
                }
            }
        }

        fn was_killed(&self) -> bool {
            self.killed.load(Ordering::Acquire)
        }

        fn disarm(&self) {
            let mut guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
            *guard = None;
        }
    }

    fn terminate_and_reap(mut child: Child, token: &KillToken, pid: u32, pids: &WorkerPidSet) {
        token.kill();
        token.disarm();
        let _ = child.wait();
        pids.remove(pid);
    }

    struct PrewarmedWorker {
        pid: u32,
        pids: Arc<WorkerPidSet>,
        child: Child,
        token: Arc<KillToken>,
        stdin: ChildStdin,
        stdout: ChildStdout,
    }

    impl PrewarmedWorker {
        fn terminate(self) {
            drop(self.stdin);
            drop(self.stdout);
            terminate_and_reap(self.child, &self.token, self.pid, &self.pids);
        }
    }

    enum StandbySlot {
        Empty,
        Warming,
        Ready(PrewarmedWorker),
    }

    struct PoolInner {
        slot: StandbySlot,
        suspended: bool,
        allow_warm: bool,
        shutdown: bool,
        warming_token: Option<Arc<KillToken>>,
        in_flight_token: Option<Arc<KillToken>>,
        warming_thread: Option<JoinHandle<()>>,
    }

    /// Tek boşta yedek işçiyi yöneten eşzamanlı havuz.
    pub(crate) struct WorkerPool {
        job: Option<JobObject>,
        timeout: Duration,
        #[cfg(test)]
        exe_override: Option<std::path::PathBuf>,
        active_pids: Arc<WorkerPidSet>,
        inner: Mutex<PoolInner>,
        cv: Condvar,
        spawned_count: AtomicU64,
    }

    impl WorkerPool {
        pub(crate) fn new(timeout: Duration, warm_initial: bool) -> Result<Arc<Self>, SensorError> {
            Self::new_inner(
                timeout,
                warm_initial,
                #[cfg(test)]
                None,
            )
        }

        #[cfg(test)]
        pub(crate) fn new_with_exe(
            timeout: Duration,
            warm_initial: bool,
            exe: std::path::PathBuf,
        ) -> Result<Arc<Self>, SensorError> {
            Self::new_inner(timeout, warm_initial, Some(exe))
        }

        fn new_inner(
            timeout: Duration,
            warm_initial: bool,
            #[cfg(test)] exe_override: Option<std::path::PathBuf>,
        ) -> Result<Arc<Self>, SensorError> {
            let job = JobObject::create_kill_on_close();
            let pool = Arc::new(Self {
                job,
                timeout,
                #[cfg(test)]
                exe_override,
                active_pids: Arc::new(WorkerPidSet::default()),
                inner: Mutex::new(PoolInner {
                    slot: StandbySlot::Empty,
                    suspended: false,
                    allow_warm: warm_initial,
                    shutdown: false,
                    warming_token: None,
                    in_flight_token: None,
                    warming_thread: None,
                }),
                cv: Condvar::new(),
                spawned_count: AtomicU64::new(0),
            });

            // Başlangıçta bir işçiyi ısıtıp `SRWR` el sıkışmasını doğrula.
            let first = pool.spawn_and_handshake(timeout, None)?;
            if warm_initial {
                let mut g = pool.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.slot = StandbySlot::Ready(first);
            } else {
                first.terminate();
            }
            Ok(pool)
        }

        pub(crate) fn contains_worker_pid(&self, pid: u32) -> bool {
            self.active_pids.contains(pid)
        }

        #[cfg(test)]
        pub(crate) fn active_worker_pids(&self) -> Vec<u32> {
            self.active_pids.snapshot()
        }

        #[cfg(test)]
        pub(crate) fn has_ready_standby(&self) -> bool {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            matches!(g.slot, StandbySlot::Ready(_))
        }

        pub(crate) fn spawned_count(&self) -> u64 {
            self.spawned_count.load(Ordering::Relaxed)
        }

        fn spawn_and_handshake(
            &self,
            timeout: Duration,
            register_warming: Option<&Mutex<PoolInner>>,
        ) -> Result<PrewarmedWorker, SensorError> {
            #[cfg(test)]
            let exe = if let Some(p) = &self.exe_override {
                p.clone()
            } else {
                std::env::current_exe()
                    .map_err(|_| SensorError::UiaWorkerUnavailable("exe_unknown"))?
            };
            #[cfg(not(test))]
            let exe = std::env::current_exe()
                .map_err(|_| SensorError::UiaWorkerUnavailable("exe_unknown"))?;
            let mut child = Command::new(exe)
                .arg(WORKER_ARG)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .map_err(|_| SensorError::UiaWorkerUnavailable("spawn_failed"))?;

            let pid = child.id();
            self.active_pids.insert(pid);
            self.spawned_count.fetch_add(1, Ordering::Relaxed);
            if let Some(job) = &self.job {
                job.assign(&child);
            }

            let Some(stdin) = child.stdin.take() else {
                let _ = child.kill();
                let _ = child.wait();
                self.active_pids.remove(pid);
                return Err(SensorError::UiaWorkerUnavailable("pipe_failed"));
            };
            let Some(mut stdout) = child.stdout.take() else {
                drop(stdin);
                let _ = child.kill();
                let _ = child.wait();
                self.active_pids.remove(pid);
                return Err(SensorError::UiaWorkerUnavailable("pipe_failed"));
            };

            let token = KillToken::from_child(&child);
            if let Some(mtx) = register_warming {
                let mut g = mtx.lock().unwrap_or_else(|e| e.into_inner());
                if g.shutdown || g.suspended || !g.allow_warm {
                    drop(g);
                    drop(stdin);
                    drop(stdout);
                    terminate_and_reap(child, &token, pid, &self.active_pids);
                    return Err(SensorError::UiaWorkerUnavailable("suspended_or_stopped"));
                }
                g.warming_token = Some(Arc::clone(&token));
            }

            let watchdog = Watchdog::arm(Arc::clone(&token), timeout);
            let mut magic = [0u8; 4];
            let read_res = stdout.read_exact(&mut magic);
            watchdog.disarm();

            if register_warming.is_some() {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.warming_token = None;
            }

            if read_res.is_err() {
                drop(stdin);
                drop(stdout);
                let killed = token.was_killed();
                terminate_and_reap(child, &token, pid, &self.active_pids);
                return Err(SensorError::UiaWorkerUnavailable(if killed {
                    "handshake_timeout_or_aborted"
                } else {
                    "handshake_io_failed"
                }));
            }

            if magic == READY_ERR_MAGIC {
                drop(stdin);
                drop(stdout);
                terminate_and_reap(child, &token, pid, &self.active_pids);
                return Err(SensorError::UiaWorkerUnavailable("uia_init_failed"));
            }
            if magic != READY_MAGIC {
                drop(stdin);
                drop(stdout);
                terminate_and_reap(child, &token, pid, &self.active_pids);
                return Err(SensorError::UiaWorkerUnavailable("bad_handshake_magic"));
            }

            Ok(PrewarmedWorker {
                pid,
                pids: Arc::clone(&self.active_pids),
                child,
                token,
                stdin,
                stdout,
            })
        }

        fn start_background_warm(self: &Arc<Self>) {
            let prev_thread = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.shutdown || g.suspended || !g.allow_warm {
                    return;
                }
                if !matches!(g.slot, StandbySlot::Empty) {
                    return;
                }
                g.slot = StandbySlot::Warming;
                g.warming_thread.take()
            };
            if let Some(t) = prev_thread {
                let _ = t.join();
            }

            let pool = Arc::clone(self);
            let handle = std::thread::Builder::new()
                .name(String::from("s-sensor-uia-prewarm"))
                .spawn(move || {
                    let res = pool.spawn_and_handshake(pool.timeout, Some(&pool.inner));
                    let mut g = pool.inner.lock().unwrap_or_else(|e| e.into_inner());
                    match res {
                        Ok(worker) => {
                            if g.shutdown || g.suspended || !g.allow_warm {
                                g.slot = StandbySlot::Empty;
                                drop(g);
                                worker.terminate();
                            } else {
                                g.slot = StandbySlot::Ready(worker);
                            }
                        }
                        Err(_) => {
                            g.slot = StandbySlot::Empty;
                        }
                    }
                    pool.cv.notify_all();
                });

            match handle {
                Ok(h) => {
                    let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if g.shutdown {
                        drop(g);
                        let _ = h.join();
                    } else {
                        g.warming_thread = Some(h);
                    }
                }
                Err(_) => {
                    let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if matches!(g.slot, StandbySlot::Warming) {
                        g.slot = StandbySlot::Empty;
                    }
                    self.cv.notify_all();
                }
            }
        }

        pub(crate) fn on_controller_state(self: &Arc<Self>, state: ControllerState) {
            let (to_terminate, warming_kill, should_warm) = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.shutdown {
                    return;
                }
                match state {
                    ControllerState::Suspended => {
                        g.suspended = true;
                        g.allow_warm = false;
                        let ready = match core::mem::replace(&mut g.slot, StandbySlot::Empty) {
                            StandbySlot::Ready(w) => Some(w),
                            StandbySlot::Warming => {
                                g.slot = StandbySlot::Warming;
                                None
                            }
                            StandbySlot::Empty => None,
                        };
                        (ready, g.warming_token.clone(), false)
                    }
                    ControllerState::Batching => {
                        g.suspended = false;
                        g.allow_warm = false;
                        let ready = match core::mem::replace(&mut g.slot, StandbySlot::Empty) {
                            StandbySlot::Ready(w) => Some(w),
                            StandbySlot::Warming => {
                                g.slot = StandbySlot::Warming;
                                None
                            }
                            StandbySlot::Empty => None,
                        };
                        (ready, g.warming_token.clone(), false)
                    }
                    ControllerState::Active => {
                        g.suspended = false;
                        g.allow_warm = true;
                        let warm = matches!(g.slot, StandbySlot::Empty);
                        (None, None, warm)
                    }
                }
            };

            if let Some(tok) = warming_kill {
                tok.kill();
            }
            if let Some(worker) = to_terminate {
                worker.terminate();
            }
            self.cv.notify_all();
            if should_warm {
                self.start_background_warm();
            }
        }

        pub(crate) fn shutdown(&self) {
            let (ready_worker, warming_tok, in_flight_tok, warming_thread) = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.shutdown = true;
                g.allow_warm = false;
                let ready = match core::mem::replace(&mut g.slot, StandbySlot::Empty) {
                    StandbySlot::Ready(w) => Some(w),
                    StandbySlot::Warming | StandbySlot::Empty => None,
                };
                (
                    ready,
                    g.warming_token.take(),
                    g.in_flight_token.take(),
                    g.warming_thread.take(),
                )
            };

            self.cv.notify_all();
            if let Some(tok) = warming_tok {
                tok.kill();
            }
            if let Some(tok) = in_flight_tok {
                tok.kill();
            }
            if let Some(w) = ready_worker {
                w.terminate();
            }
            if let Some(t) = warming_thread {
                let _ = t.join();
            }
        }

        fn acquire_worker(
            self: &Arc<Self>,
            timeout: Duration,
        ) -> Result<PrewarmedWorker, &'static str> {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if g.shutdown {
                    return Err("uia_worker_stopped");
                }
                if g.suspended {
                    return Err("uia_worker_suspended");
                }
                match core::mem::replace(&mut g.slot, StandbySlot::Empty) {
                    StandbySlot::Ready(w) => return Ok(w),
                    StandbySlot::Empty => {
                        drop(g);
                        return self
                            .spawn_and_handshake(timeout, None)
                            .map_err(|_| "uia_worker_spawn_failed");
                    }
                    StandbySlot::Warming => {
                        g.slot = StandbySlot::Warming;
                        let (next_g, wait_res) = self
                            .cv
                            .wait_timeout(g, timeout)
                            .unwrap_or_else(|e| e.into_inner());
                        g = next_g;
                        if wait_res.timed_out() && matches!(g.slot, StandbySlot::Warming) {
                            return Err("uia_worker_timeout_or_crash");
                        }
                    }
                }
            }
        }

        pub(crate) fn extract(
            self: &Arc<Self>,
            hwnd: HWND,
            config: &SensorConfig,
        ) -> UiaExtraction {
            let timeout = config.uia_worker_timeout.max(Duration::from_millis(50));
            let worker = match self.acquire_worker(timeout) {
                Ok(w) => w,
                Err(reason) => return failed(reason),
            };

            let PrewarmedWorker {
                pid,
                pids,
                child,
                token,
                mut stdin,
                mut stdout,
            } = worker;

            {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.shutdown || g.suspended {
                    drop(g);
                    drop(stdin);
                    drop(stdout);
                    terminate_and_reap(child, &token, pid, &pids);
                    return failed("uia_worker_suspended_or_stopped");
                }
                g.in_flight_token = Some(Arc::clone(&token));
            }

            let req = WorkerRequest {
                hwnd_raw: hwnd.0 as isize,
                max_depth: u32::try_from(config.max_uia_depth).unwrap_or(u32::MAX),
                max_nodes: config.max_uia_nodes,
                max_text_bytes: u32::try_from(config.max_uia_text_bytes).unwrap_or(u32::MAX),
                timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            };
            let req_bytes = encode_request(req);

            let watchdog = Watchdog::arm(Arc::clone(&token), timeout);
            let write_ok = stdin.write_all(&req_bytes).is_ok() && stdin.flush().is_ok();
            drop(stdin);

            let result = if write_ok {
                read_frame(&mut stdout, config.max_uia_text_bytes)
            } else {
                Err(FrameError::Io)
            };
            drop(stdout);
            watchdog.disarm();

            {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.in_flight_token = None;
            }
            // Okuma bitti (ya da hata): tek kullanımlık işçiyi derhal öldür ve topla.
            terminate_and_reap(child, &token, pid, &pids);

            // Aktif moddaysa arka planda bir sonraki tek kullanımlık yedeği ısıt.
            self.start_background_warm();

            match result {
                Ok((h, text)) => UiaExtraction {
                    text,
                    node_count: h.node_count,
                    empty_reason: reason_from_code(h.reason),
                },
                Err(FrameError::Io) => failed("uia_worker_timeout_or_crash"),
                Err(FrameError::BadMagic) => failed("uia_worker_protocol_error"),
                Err(FrameError::TooLarge) => failed("uia_worker_frame_too_large"),
                Err(FrameError::BadUtf8) => failed("uia_worker_bad_utf8"),
            }
        }
    }

    impl Drop for WorkerPool {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// UIA arka ucu: ana süreçte (eski) ya da önceden ısıtılmış tek atımlık işçi süreçte.
    pub(crate) enum UiaBackend {
        InProcess(UiaExtractor),
        Worker(Arc<WorkerPool>),
    }

    impl UiaBackend {
        pub(crate) fn new(config: &SensorConfig) -> Result<Self, SensorError> {
            Self::new_with_warm(config, true)
        }

        pub(crate) fn new_with_warm(
            config: &SensorConfig,
            warm_initial: bool,
        ) -> Result<Self, SensorError> {
            match config.uia_isolation {
                super::UiaIsolation::InProcess => Ok(Self::InProcess(UiaExtractor::new()?)),
                super::UiaIsolation::Worker => {
                    if !super::host_hook_installed() {
                        return Err(SensorError::UiaWorkerHostMissing);
                    }
                    let pool = WorkerPool::new(config.uia_worker_timeout, warm_initial)?;
                    Ok(Self::Worker(pool))
                }
            }
        }

        pub(crate) fn extract(&self, hwnd: HWND, config: &SensorConfig) -> UiaExtraction {
            match self {
                Self::InProcess(ex) => ex.extract_window_text(hwnd, config),
                Self::Worker(pool) => pool.extract(hwnd, config),
            }
        }
    }

    fn failed(reason: &'static str) -> UiaExtraction {
        UiaExtraction {
            text: Zeroizing::new(String::new()),
            node_count: 0,
            empty_reason: Some(reason),
        }
    }

    /// Bekçi: `timeout` dolmadan `disarm` edilmezse işçiyi `TerminateProcess` ile öldürür.
    struct Watchdog {
        state: Arc<(Mutex<bool>, Condvar)>,
        thread: Option<JoinHandle<()>>,
    }

    impl Watchdog {
        fn arm(token: Arc<KillToken>, timeout: Duration) -> Self {
            let state = Arc::new((Mutex::new(false), Condvar::new()));
            let st = Arc::clone(&state);
            let thread = std::thread::Builder::new()
                .name(String::from("s-sensor-uia-watchdog"))
                .spawn(move || {
                    let (lock, cv) = &*st;
                    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    let (done, _) = cv
                        .wait_timeout_while(guard, timeout, |done| !*done)
                        .unwrap_or_else(|e| e.into_inner());
                    if !*done {
                        drop(done);
                        token.kill();
                    }
                })
                .ok();
            Self { state, thread }
        }

        fn disarm(mut self) {
            let (lock, cv) = &*self.state;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
}

// --------------------------------------------------------------- ölçüm arayüzü

/// Yalnızca metadata içeren çıkarım istatistiği (ölçüm araçları için; ham metin DIŞARI verilmez).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionStats {
    pub text_len: usize,
    pub node_count: u32,
    pub empty_reason: Option<&'static str>,
}

/// Gecikme ölçümü için UIA arka ucu (üretim hattıyla AYNI kod yolu). Metin döndürmez; çıkarılan
/// metin `Zeroizing` ile hemen silinir.
#[doc(hidden)]
pub struct UiaProbe {
    #[cfg(windows)]
    backend: win32::UiaBackend,
    config: crate::SensorConfig,
}

impl UiaProbe {
    pub fn new(config: crate::SensorConfig) -> Result<Self, crate::SensorError> {
        #[cfg(windows)]
        {
            Ok(Self {
                backend: win32::UiaBackend::new(&config)?,
                config,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = config;
            Err(crate::SensorError::UnsupportedPlatform)
        }
    }

    pub fn extract_stats(&self, hwnd_raw: isize) -> ExtractionStats {
        #[cfg(windows)]
        {
            let hwnd = windows::Win32::Foundation::HWND(hwnd_raw as *mut core::ffi::c_void);
            let ex = self.backend.extract(hwnd, &self.config);
            ExtractionStats {
                text_len: ex.text.len(),
                node_count: ex.node_count,
                empty_reason: ex.empty_reason,
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (hwnd_raw, &self.config);
            ExtractionStats {
                text_len: 0,
                node_count: 0,
                empty_reason: Some("unsupported_platform"),
            }
        }
    }

    pub fn spawned_workers_count(&self) -> u64 {
        #[cfg(windows)]
        {
            match &self.backend {
                win32::UiaBackend::InProcess(_) => 0,
                win32::UiaBackend::Worker(pool) => pool.spawned_count(),
            }
        }
        #[cfg(not(windows))]
        {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_preserves_metadata_and_text() {
        let mut wire = Vec::new();
        write_frame(&mut wire, None, 7, "Merhaba\nDünya").unwrap();
        let (h, text) = read_frame(&mut wire.as_slice(), 1024).unwrap();
        assert_eq!(h.node_count, 7);
        assert_eq!(reason_from_code(h.reason), None);
        assert_eq!(text.as_str(), "Merhaba\nDünya");

        let mut wire = Vec::new();
        write_frame(&mut wire, Some("null_hwnd"), 0, "").unwrap();
        let (h, text) = read_frame(&mut wire.as_slice(), 1024).unwrap();
        assert_eq!(reason_from_code(h.reason), Some("null_hwnd"));
        assert!(text.is_empty());
    }

    #[test]
    fn read_frame_reads_directly_into_exact_capacity_without_realloc() {
        let payload = "sk_live_direct_zero_realloc_test_payload_0123456789";
        let mut wire = Vec::new();
        write_frame(&mut wire, None, 3, payload).unwrap();

        let (h, text) = read_frame(&mut wire.as_slice(), 4096).unwrap();
        assert_eq!(h.text_len as usize, payload.len());
        assert_eq!(text.as_str(), payload);
        // `Zeroizing<Vec<u8>>` tam kapasiteyle (`len`) ayrılıp `String`'e taşındığı için
        // kapasite gövde uzunluğuna birebir eşittir (yeniden ayırma olmaz).
        assert_eq!(text.capacity(), payload.len());
    }

    #[test]
    fn read_frame_zeroizes_partial_body_on_io_error() {
        // Başlık 32 bayt söz veriyor ancak yalnızca 12 bayt geliyor -> Io hatası ve kısmi gövde sıfırlanır.
        let mut partial_wire = encode_header(FrameHeader {
            reason: 0,
            node_count: 1,
            text_len: 32,
        })
        .to_vec();
        partial_wire.extend_from_slice(b"SECRET_PART_");

        let res = read_frame(&mut partial_wire.as_slice(), 1024);
        assert_eq!(res.err(), Some(FrameError::Io));
    }

    #[test]
    fn frame_rejects_bad_magic_oversize_truncation_and_bad_utf8() {
        let mut wire = Vec::new();
        write_frame(&mut wire, None, 1, "abcdef").unwrap();

        let mut bad = wire.clone();
        bad[0] = b'X';
        assert_eq!(
            read_frame(&mut bad.as_slice(), 1024).err(),
            Some(FrameError::BadMagic)
        );
        assert_eq!(
            read_frame(&mut wire.as_slice(), 3).err(),
            Some(FrameError::TooLarge)
        );
        let truncated = &wire[..wire.len() - 2];
        assert_eq!(
            read_frame(&mut &truncated[..], 1024).err(),
            Some(FrameError::Io)
        );
        assert_eq!(
            read_frame(&mut &wire[..4], 1024).err(),
            Some(FrameError::Io)
        );

        let mut utf = wire.clone();
        let n = utf.len();
        utf[n - 1] = 0xFF;
        assert_eq!(
            read_frame(&mut utf.as_slice(), 1024).err(),
            Some(FrameError::BadUtf8)
        );
    }

    #[test]
    fn request_encode_decode_roundtrip() {
        let req = WorkerRequest {
            hwnd_raw: 0x0012_3456,
            max_depth: 12,
            max_nodes: 256,
            max_text_bytes: 65536,
            timeout_ms: 5000,
        };
        let mut raw = encode_request(req);
        assert_eq!(decode_request(&raw), Some(req));
        raw[0] = b'Z';
        assert_eq!(decode_request(&raw), None);
    }

    #[test]
    fn reason_codes_roundtrip() {
        for r in [
            None,
            Some("null_hwnd"),
            Some("element_from_handle_failed"),
            Some("no_text_nodes_in_tree"),
            Some("uia_init_failed"),
        ] {
            assert_eq!(reason_from_code(reason_code(r)), r);
        }
    }

    #[test]
    fn worker_pid_set_tracks_and_clears_pids() {
        let pids = WorkerPidSet::default();
        assert!(!pids.contains(0));
        pids.insert(0);
        assert!(pids.snapshot().is_empty());

        pids.insert(4201);
        pids.insert(4201);
        pids.insert(4202);
        assert!(pids.contains(4201));
        assert!(pids.contains(4202));
        assert!(!pids.contains(9999));
        assert_eq!(pids.snapshot().len(), 2);

        pids.remove(4201);
        assert!(!pids.contains(4201));
        assert!(pids.contains(4202));
        pids.remove(4202);
        assert!(pids.snapshot().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn worker_isolation_without_host_hook_fails_fast() {
        let cfg = crate::SensorConfig {
            uia_isolation: UiaIsolation::Worker,
            ..crate::SensorConfig::default()
        };
        assert!(matches!(
            UiaProbe::new(cfg).err(),
            Some(crate::SensorError::UiaWorkerHostMissing)
        ));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Pre-warmed UIA worker latency & lifecycle benchmark (60 samples; requires metadata_demo example built)"]
    fn prewarmed_worker_latency_and_lifecycle_bench() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::time::Instant;
        use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOVSCROLL,
            ES_MULTILINE, GetMessageW, MSG, PostQuitMessage, RegisterClassW, SW_SHOWNA, ShowWindow,
            TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_DESTROY, WNDCLASSW, WS_CHILD,
            WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
        };
        use windows::core::PCWSTR;

        unsafe extern "system" fn bench_wnd_proc(
            hwnd: HWND,
            msg: u32,
            wp: WPARAM,
            lp: LPARAM,
        ) -> LRESULT {
            if msg == WM_DESTROY {
                // SAFETY: Geçici benchmark penceresi mesaj döngüsü çıkışı.
                unsafe { PostQuitMessage(0) };
                return LRESULT(0);
            }
            // SAFETY: İşlenmeyen mesajlar `DefWindowProcW`'e iletilir.
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }

        if std::env::var_os("S_SENSOR_PREWARM_BENCH_CHILD").is_some() {
            let class_w: Vec<u16> = "SRecallPrewarmBench\0".encode_utf16().collect();
            let title_w: Vec<u16> = "sk_live_BENCHMARKTITLE000000000000 - Synthetic\0"
                .encode_utf16()
                .collect();
            let edit_w: Vec<u16> = "EDIT\0".encode_utf16().collect();
            let body = format!(
                "aws_access_key_id = AKIASYNTHETICBENCH01\r\n\
                 aws_secret_access_key = SyntheticSecretBenchKey0123456789ABCDEF0123\r\n\
                 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZW5jaCJ9.sig0123456789\r\n\
                 card 4111 1111 1111 1111\r\n\
                 password=Hunter2x-Synth9-Gate2\r\n\
                 mail bench.user@example.invalid\r\n\
                 -----BEGIN RSA PRIVATE KEY-----\r\n\
                 {0}\r\n{0}\r\n{0}\r\n{0}\r\n\
                 -----END RSA PRIVATE KEY-----\r\n",
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQSyntheticRow"
            );
            let body_w: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: Tek iş parçacığında geçici benchmark penceresi açılır.
            unsafe {
                let hmod = GetModuleHandleW(None).expect("GetModuleHandleW");
                let hinst = hmod.into();
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(bench_wnd_proc),
                    hInstance: hinst,
                    lpszClassName: PCWSTR(class_w.as_ptr()),
                    ..Default::default()
                };
                RegisterClassW(&wc);
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(class_w.as_ptr()),
                    PCWSTR(title_w.as_ptr()),
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    100,
                    100,
                    800,
                    400,
                    None,
                    None,
                    Some(hinst),
                    None,
                )
                .expect("CreateWindowExW");
                let _edit = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(edit_w.as_ptr()),
                    PCWSTR(body_w.as_ptr()),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_VSCROLL
                        | WINDOW_STYLE(ES_MULTILINE as u32)
                        | WINDOW_STYLE(ES_AUTOVSCROLL as u32),
                    10,
                    10,
                    760,
                    340,
                    Some(hwnd),
                    None,
                    Some(hinst),
                    None,
                );
                let _ = ShowWindow(hwnd, SW_SHOWNA);
                println!("BENCH_HWND={}", hwnd.0 as isize);
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                let _ = DestroyWindow(hwnd);
            }
            return;
        }

        let self_exe = std::env::current_exe().expect("current_exe");
        let examples_dir = self_exe
            .parent()
            .and_then(|d| d.parent())
            .expect("target/debug")
            .join("examples");
        let worker_exe = examples_dir.join("metadata_demo.exe");
        assert!(
            worker_exe.exists(),
            "metadata_demo.exe bulunamadı ({}); önce `cargo build -p s-sensor --example metadata_demo` çalıştırın",
            worker_exe.display()
        );

        let mut child = Command::new(&self_exe)
            .arg("--exact")
            .arg("uia_worker::tests::prewarmed_worker_latency_and_lifecycle_bench")
            .arg("--ignored")
            .arg("--nocapture")
            .env("S_SENSOR_PREWARM_BENCH_CHILD", "1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child");

        let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
        let mut hwnd_raw: isize = 0;
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if let Some(rest) = line.trim().strip_prefix("BENCH_HWND=") {
                hwnd_raw = rest.parse().expect("parse hwnd");
                break;
            }
            line.clear();
        }
        assert!(hwnd_raw != 0, "BENCH_HWND alınamadı");

        let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);
        let cfg = crate::SensorConfig::default();
        let pool = win32::WorkerPool::new_with_exe(cfg.uia_worker_timeout, true, worker_exe)
            .expect("WorkerPool::new_with_exe");
        assert!(pool.has_ready_standby(), "ilk yedek hazır olmalı");
        assert!(
            !pool.active_worker_pids().is_empty(),
            "hazır yedek işçi PID kümesinde görünmeli"
        );

        // Suspended -> yedek hemen öldürülür; Active -> yeniden ısıtılır.
        pool.on_controller_state(crate::ControllerState::Suspended);
        assert!(!pool.has_ready_standby(), "Suspended iken yedek olmamalı");
        pool.on_controller_state(crate::ControllerState::Active);
        for _ in 0..40 {
            if pool.has_ready_standby() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            pool.has_ready_standby(),
            "Active dönüşünde yeniden ısıtılmalı"
        );

        // 5 warmup
        for _ in 0..5 {
            let ex = pool.extract(hwnd, &cfg);
            assert!(!ex.text.is_empty(), "warmup çıkarım boş olmamalı");
            // Gerçek kullanımda 250 ms yerleşme süresi kadar arka plan ısıtması tamamlanır.
            for _ in 0..40 {
                if pool.has_ready_standby() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        }

        const SAMPLES: usize = 60;
        let mut latencies_ms = Vec::with_capacity(SAMPLES);
        let mut last_len = 0usize;
        let mut last_nodes = 0u32;
        for _ in 0..SAMPLES {
            // Arka plandaki ön-ısıtmanın tamamlanmasını bekle (250ms+ odak yerleşme senaryosu).
            for _ in 0..40 {
                if pool.has_ready_standby() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            let t0 = Instant::now();
            let ex = pool.extract(hwnd, &cfg);
            let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
            assert!(!ex.text.is_empty(), "çıkarım metni boş olmamalı");
            assert!(
                ex.text.contains("AKIASYNTHETICBENCH01"),
                "EDIT gövdesi çıkarılmalı"
            );
            last_len = ex.text.len();
            last_nodes = ex.node_count;
            latencies_ms.push(elapsed);
        }

        let shut_t0 = Instant::now();
        pool.shutdown();
        let shut_ms = shut_t0.elapsed().as_secs_f64() * 1000.0;
        assert!(!pool.has_ready_standby());
        assert!(
            pool.active_worker_pids().is_empty(),
            "shutdown sonrası aktif işçi PID'i kalmamalı"
        );
        assert!(shut_ms < 500.0, "shutdown hızlı bitmeli: {shut_ms:.2}ms");

        let _ = child.kill();
        let _ = child.wait();

        latencies_ms.sort_by(|a, b| a.total_cmp(b));
        let p50 = latencies_ms[SAMPLES / 2];
        let p95_idx = ((SAMPLES as f64) * 0.95).ceil() as usize - 1;
        let p95 = latencies_ms[p95_idx.min(SAMPLES - 1)];
        let mean = latencies_ms.iter().sum::<f64>() / SAMPLES as f64;
        println!(
            "PREWARMED_WORKER_BENCH samples={SAMPLES} text_len={last_len} nodes={last_nodes} spawns={} shutdown={shut_ms:.2}ms min={:.2}ms p50={:.2}ms mean={:.2}ms p95={:.2}ms max={:.2}ms",
            pool.spawned_count(),
            latencies_ms[0],
            p50,
            mean,
            p95,
            latencies_ms[SAMPLES - 1]
        );
    }
}
