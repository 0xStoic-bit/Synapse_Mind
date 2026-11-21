//! Resmi Gate 2 harness'i için Windows yardımcıları (yalnızca test amaçlı): sentetik pano içeriği, sentetik
//! pencere (başlık + metin), klavye girdisi, süreç ağacı ve pid ile bellek dökümü.
//! TÜM VERİLER SENTETİKTİR. Her `unsafe` bloğunda `// SAFETY:` gerekçesi vardır.

use std::io;
use std::path::Path;
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Diagnostics::Debug::{
    MINIDUMP_TYPE, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo, MiniDumpWithThreadInfo,
    MiniDumpWriteDump,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_KEYUP,
    KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, SendInput, VIRTUAL_KEY, VK_MENU, VK_RETURN, VK_SPACE,
    keybd_event,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOVSCROLL, ES_MULTILINE,
    GetMessageW, MSG, PostMessageW, PostQuitMessage, RegisterClassW, SW_SHOW, SetForegroundWindow,
    ShowWindow, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_DESTROY, WNDCLASSW,
    WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};
use windows::core::PCWSTR;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ------------------------------------------------------------------------ pano

/// Panoya Unicode metin koyar (sensörün pano kancasını tetikler). Başarısızsa hata.
pub fn set_clipboard_text(text: &str) -> io::Result<()> {
    let w = wide(text);
    let bytes = w.len() * 2;
    // SAFETY: Pano bu iş parçacığı tarafından açılır/kapatılır. `GlobalAlloc` taşınabilir bir blok ayırır;
    // `GlobalLock` ile elde edilen işaretçiye tam `bytes` bayt yazılır (blok en az o kadardır) ve
    // `GlobalUnlock` ile bırakılır. `SetClipboardData` başarılı olursa blok sahipliği panoya geçer
    // (serbest bırakılmaz); başarısızsa blok sızar (yalnızca test sürecinde, bilinçli ve önemsiz).
    unsafe {
        OpenClipboard(None).map_err(io::Error::other)?;
        let result = (|| -> io::Result<()> {
            EmptyClipboard().map_err(io::Error::other)?;
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(io::Error::other)?;
            let p = GlobalLock(h) as *mut u16;
            if p.is_null() {
                return Err(io::Error::other("GlobalLock"));
            }
            std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
            let _ = GlobalUnlock(h);
            SetClipboardData(13, Some(HANDLE(h.0))).map_err(io::Error::other)?; // CF_UNICODETEXT
            Ok(())
        })();
        let _ = CloseClipboard();
        result
    }
}

pub fn clear_clipboard() {
    // SAFETY: Pano açılıp boşaltılıp kapatılır; başka işaretçi kullanılmaz.
    unsafe {
        if OpenClipboard(None).is_ok() {
            let _ = EmptyClipboard();
            let _ = CloseClipboard();
        }
    }
}

// --------------------------------------------------------------------- pencere

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_DESTROY {
        // SAFETY: Mesaj döngüsünü bitirmek için standart çağrı.
        unsafe { PostQuitMessage(0) };
        return LRESULT(0);
    }
    // SAFETY: Aynı parametrelerle varsayılan işleyiciye devredilir.
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

/// Başlığı ve (UIA ile okunabilen) çok satırlı EDIT içeriği sentetik olan üst düzey bir pencere.
/// Kendi iş parçacığında mesaj döngüsü çalıştırır; `Drop`'ta kapatılır.
pub struct SyntheticWindow {
    hwnd: isize,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SyntheticWindow {
    pub fn open(title: &str, body: &str) -> io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<isize, String>>();
        let title = title.to_string();
        let body = body.to_string();
        let thread = std::thread::spawn(move || {
            // SAFETY: Pencere sınıfı kaydı, pencere oluşturma ve mesaj döngüsü TEK iş parçacığında yapılır;
            // `hwnd` yalnızca bu iş parçacığında geçerli olduğu sürece kullanılır, dışarıya `isize` olarak verilir
            // ve yalnızca `PostMessageW` (iş parçacığı güvenli) ile kullanılır.
            unsafe {
                let hmod = match GetModuleHandleW(None) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let hinst = HINSTANCE(hmod.0);
                let class = wide("S_Recall_Gate2_Synthetic");
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(wndproc),
                    hInstance: hinst,
                    lpszClassName: PCWSTR(class.as_ptr()),
                    ..Default::default()
                };
                RegisterClassW(&wc);
                let wtitle = wide(&title);
                let hwnd = match CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(class.as_ptr()),
                    PCWSTR(wtitle.as_ptr()),
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    200,
                    200,
                    900,
                    500,
                    None,
                    None,
                    Some(hinst),
                    None,
                ) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let wbody = wide(&body);
                let edit = wide("EDIT");
                let _ = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(edit.as_ptr()),
                    PCWSTR(wbody.as_ptr()),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_VSCROLL
                        | WINDOW_STYLE(ES_MULTILINE as u32)
                        | WINDOW_STYLE(ES_AUTOVSCROLL as u32),
                    10,
                    10,
                    860,
                    440,
                    Some(hwnd),
                    None,
                    Some(hinst),
                    None,
                );
                let _ = ShowWindow(hwnd, SW_SHOW);
                // Ön plan kilidini aşmak için Alt tuşu vur-bırak.
                keybd_event(VK_MENU.0 as u8, 0, KEYBD_EVENT_FLAGS(0), 0);
                let _ = SetForegroundWindow(hwnd);
                keybd_event(VK_MENU.0 as u8, 0, KEYEVENTF_KEYUP, 0);
                let _ = tx.send(Ok(hwnd.0 as isize));
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        });
        let hwnd = rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::other("pencere olusturulamadi (zaman asimi)"))?
            .map_err(io::Error::other)?;
        Ok(Self {
            hwnd,
            thread: Some(thread),
        })
    }

    /// Üst düzey pencere tutamacı (ölçüm araçları için).
    pub fn hwnd(&self) -> isize {
        self.hwnd
    }

    /// Pencereyi yeniden ön plana getirir (odak olayı üretir).
    pub fn focus(&self) {
        // SAFETY: Geçerli (bu nesne yaşadığı sürece) bir üst düzey pencere tutamacı; çağrılar yalnızca
        // ön plan isteğidir.
        unsafe {
            let hwnd = HWND(self.hwnd as *mut core::ffi::c_void);
            keybd_event(VK_MENU.0 as u8, 0, KEYBD_EVENT_FLAGS(0), 0);
            let _ = SetForegroundWindow(hwnd);
            keybd_event(VK_MENU.0 as u8, 0, KEYEVENTF_KEYUP, 0);
        }
    }
}

impl Drop for SyntheticWindow {
    fn drop(&mut self) {
        // SAFETY: `PostMessageW` herhangi bir iş parçacığından çağrılabilir; pencere zaten kapanmışsa hata döner (yok sayılır).
        unsafe {
            let hwnd = HWND(self.hwnd as *mut core::ffi::c_void);
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            let _ = DestroyWindow(hwnd);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------- klavye

fn send(inputs: &[INPUT]) {
    // SAFETY: `inputs` tam başlatılmış INPUT yapıları içerir ve `size_of::<INPUT>()` doğru boyuttur.
    unsafe {
        SendInput(inputs, std::mem::size_of::<INPUT>() as i32);
    }
}

fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: if up {
                    KEYEVENTF_KEYUP
                } else {
                    KEYBD_EVENT_FLAGS(0)
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Alt+Space (Synapse Mind kısayolu).
pub fn press_alt_space() {
    send(&[
        key(VK_MENU, false),
        key(VK_SPACE, false),
        key(VK_SPACE, true),
        key(VK_MENU, true),
    ]);
}

/// Tarama kodu (scan code) tabanlı tuş olayı: Chromium/WebView2 yalnızca VK içeren olayları keydown olarak işlemeyebilir.
fn key_sc(scan: u16, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: scan,
                dwFlags: if up {
                    KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP
                } else {
                    KEYEVENTF_SCANCODE
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Ctrl+M (Hafıza Paneli kısayolu; overlay açıkken), tarama koduyla (sol Ctrl 0x1D, M 0x32).
pub fn press_ctrl_m() {
    send(&[key_sc(0x1D, false)]);
    std::thread::sleep(Duration::from_millis(80));
    send(&[key_sc(0x32, false)]);
    std::thread::sleep(Duration::from_millis(60));
    send(&[key_sc(0x32, true)]);
    std::thread::sleep(Duration::from_millis(80));
    send(&[key_sc(0x1D, true)]);
}

/// Tab ve Boşluk (odak gezintisi ile düğmeyi etkinleştirmek için).
pub fn press_tab() {
    send(&[key_sc(0x0F, false), key_sc(0x0F, true)]);
}

pub fn press_space() {
    send(&[key_sc(0x39, false), key_sc(0x39, true)]);
}

pub fn press_escape() {
    send(&[key_sc(0x01, false), key_sc(0x01, true)]);
}

pub fn press_enter() {
    send(&[key(VK_RETURN, false), key(VK_RETURN, true)]);
}

/// Odaktaki pencereye Unicode karakter karakter metin yazar.
pub fn type_text(text: &str) {
    for u in text.encode_utf16() {
        let mk = |up: bool| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: u,
                    dwFlags: if up {
                        KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
                    } else {
                        KEYEVENTF_UNICODE
                    },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        send(&[mk(false), mk(true)]);
        std::thread::sleep(Duration::from_millis(15));
    }
}

// ---------------------------------------------------------------- süreç / döküm

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent: u32,
    pub exe: String,
}

pub fn list_processes() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    // SAFETY: Anlık görüntü tutamacı bu işlevde açılıp kapatılır; PROCESSENTRY32W `dwSize` ile başlatılır.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let len = e
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(e.szExeFile.len());
                out.push(ProcInfo {
                    pid: e.th32ProcessID,
                    parent: e.th32ParentProcessID,
                    exe: String::from_utf16_lossy(&e.szExeFile[..len]),
                });
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// `root` ve tüm torunları (WebView2 alt süreçleri dahil).
pub fn process_tree(root: u32) -> Vec<ProcInfo> {
    let all = list_processes();
    let mut result: Vec<ProcInfo> = all.iter().filter(|p| p.pid == root).cloned().collect();
    let mut frontier = vec![root];
    while let Some(pid) = frontier.pop() {
        for p in all.iter().filter(|p| p.parent == pid && p.pid != pid) {
            if !result.iter().any(|r| r.pid == p.pid) {
                result.push(p.clone());
                frontier.push(p.pid);
            }
        }
    }
    result
}

/// Verilen pid'in tam bellek dökümünü `out` dosyasına yazar.
pub fn write_full_dump_pid(pid: u32, out: &Path) -> io::Result<u64> {
    use std::os::windows::io::AsRawHandle;
    let file = std::fs::File::create(out)?;
    let dump_type = MINIDUMP_TYPE(
        MiniDumpWithFullMemory.0 | MiniDumpWithFullMemoryInfo.0 | MiniDumpWithThreadInfo.0,
    );
    // SAFETY: `OpenProcess` süreç için sorgu + bellek okuma hakkı ister; dönen tutamaç bu işlevde kapatılır.
    // `file` yaşadığı sürece yazılabilir geçerli dosya tutamacıdır. İsteğe bağlı üç işaretçi `None` (null).
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| io::Error::other(format!("OpenProcess({pid}): {e}")))?;
        let r = MiniDumpWriteDump(
            h,
            pid,
            HANDLE(file.as_raw_handle()),
            dump_type,
            None,
            None,
            None,
        );
        let _ = CloseHandle(h);
        r.map_err(|e| io::Error::other(format!("MiniDumpWriteDump({pid}): {e}")))?;
    }
    file.sync_all()?;
    Ok(file.metadata()?.len())
}

/// Verilen süreçlere ait GÖRÜNÜR üst düzey pencerelerin başlıkları (panel pencere varlığı kanıtı için).
pub fn visible_window_titles(pids: &[u32]) -> Vec<String> {
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };
    use windows::core::BOOL;
    struct Ctx<'a> {
        pids: &'a [u32],
        out: Vec<String>,
    }
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
        // SAFETY: `lp`, `EnumWindows` çağrısı süresince yaşayan `Ctx`'e işaret eder (aşağıda `&mut ctx`).
        let ctx = unsafe { &mut *(lp.0 as *mut Ctx) };
        let mut pid = 0u32;
        // SAFETY: Geçerli pencere tutamacı ve geçerli `pid` işaretçisi.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        // SAFETY: Salt sorgu.
        if ctx.pids.contains(&pid) && unsafe { IsWindowVisible(hwnd) }.as_bool() {
            let mut buf = [0u16; 256];
            // SAFETY: `buf` yazılabilir 256 elemanlı tampon.
            let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
            if n > 0 {
                ctx.out.push(String::from_utf16_lossy(&buf[..n as usize]));
            }
        }
        BOOL(1)
    }
    let mut ctx = Ctx {
        pids,
        out: Vec::new(),
    };
    // SAFETY: `cb` imzası doğru; `ctx` çağrı bitene dek yaşar ve yalnızca bu iş parçacığında kullanılır.
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(&mut ctx as *mut Ctx as isize));
    }
    ctx.out
}

/// Verilen süreçlerin görünür üst düzey penceresini (başlığı `needle` içeren) ön plana getirir. Bulunursa `true`.
pub fn activate_window_titled(pids: &[u32], needle: &str) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };
    use windows::core::BOOL;
    struct Ctx<'a> {
        pids: &'a [u32],
        needle: &'a str,
        found: Option<isize>,
    }
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
        // SAFETY: `lp`, `EnumWindows` süresince yaşayan `Ctx`'e işaret eder.
        let ctx = unsafe { &mut *(lp.0 as *mut Ctx) };
        let mut pid = 0u32;
        // SAFETY: Geçerli tutamaç ve işaretçi.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        // SAFETY: Salt sorgu.
        if ctx.pids.contains(&pid) && unsafe { IsWindowVisible(hwnd) }.as_bool() {
            let mut buf = [0u16; 256];
            // SAFETY: `buf` yazılabilir tampon.
            let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
            if n > 0 && String::from_utf16_lossy(&buf[..n as usize]).contains(ctx.needle) {
                ctx.found = Some(hwnd.0 as isize);
                return BOOL(0);
            }
        }
        BOOL(1)
    }
    let mut ctx = Ctx {
        pids,
        needle,
        found: None,
    };
    // SAFETY: `cb` imzası doğru; `ctx` çağrı bitene dek yaşar.
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(&mut ctx as *mut Ctx as isize));
    }
    let Some(h) = ctx.found else { return false };
    // SAFETY: Bulunan geçerli pencere tutamacı; yalnızca ön plan isteği (Alt hilesi + AllowSetForegroundWindow +
    // geçici AttachThreadInput; bağlama her zaman geri alınır).
    unsafe {
        use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
        use windows::Win32::UI::WindowsAndMessaging::{
            ASFW_ANY, AllowSetForegroundWindow, BringWindowToTop, GetForegroundWindow,
            GetWindowThreadProcessId,
        };
        let hwnd = HWND(h as *mut core::ffi::c_void);
        let _ = AllowSetForegroundWindow(ASFW_ANY);
        let fg = GetForegroundWindow();
        let fg_thread = if fg.0.is_null() {
            0
        } else {
            GetWindowThreadProcessId(fg, None)
        };
        let me = GetCurrentThreadId();
        let attached =
            fg_thread != 0 && fg_thread != me && AttachThreadInput(me, fg_thread, true).as_bool();
        keybd_event(VK_MENU.0 as u8, 0, KEYBD_EVENT_FLAGS(0), 0);
        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);
        keybd_event(VK_MENU.0 as u8, 0, KEYEVENTF_KEYUP, 0);
        if attached {
            let _ = AttachThreadInput(me, fg_thread, false);
        }
    }
    true
}

/// Tanı: ön plandaki pencerenin (pid, süreç adı, başlık) özeti. Girdi enjekte edilmez.
pub fn foreground_info() -> String {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
    };
    // SAFETY: Salt sorgular; tutamaç yalnızca bu çağrıda kullanılır, `buf` yazılabilir 256 elemanlı tampon.
    let (pid, title) = unsafe {
        let h = GetForegroundWindow();
        if h.0.is_null() {
            return "on plan yok".to_owned();
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, Some(&mut pid));
        let mut buf = [0u16; 256];
        let n = GetWindowTextW(h, &mut buf);
        (pid, String::from_utf16_lossy(&buf[..n.max(0) as usize]))
    };
    let exe = list_processes()
        .into_iter()
        .find(|p| p.pid == pid)
        .map(|p| p.exe)
        .unwrap_or_else(|| "?".to_owned());
    format!("pid={pid} exe={exe} baslik={title:?}")
}

/// Overlay'i ön plana getirmeye çalışır; yalnızca doğrulanmış ön plan için `true` döner. Gizliyse
/// Alt+Space basılır ve görünür olması beklenir, arkadaysa odak zorlanır. Girdi enjekte edilmez.
pub fn ensure_overlay_foreground(
    pids_of: &mut dyn FnMut() -> Vec<u32>,
    needle: &str,
    attempts: u32,
    show_wait: Duration,
    log: &mut dyn FnMut(String),
) -> bool {
    for attempt in 1..=attempts {
        let mut visible = find_window_titled(&pids_of(), needle).is_some();
        log(format!(
            "overlay deneme {attempt}/{attempts}: gorunur={visible} on_plan=[{}]",
            foreground_info()
        ));
        if !visible {
            press_alt_space();
            let start = std::time::Instant::now();
            while start.elapsed() < show_wait {
                std::thread::sleep(Duration::from_millis(150));
                if find_window_titled(&pids_of(), needle).is_some() {
                    visible = true;
                    break;
                }
            }
            log(format!(
                "   Alt+Space sonrasi {} ms: gorunur={visible} on_plan=[{}]",
                start.elapsed().as_millis(),
                foreground_info()
            ));
            if !visible {
                continue;
            }
        }
        // Görünür: ön planı yokla; değilse odak ver.
        for _ in 0..4 {
            let pids = pids_of();
            if foreground_belongs_to(&pids) && find_window_titled(&pids, needle).is_some() {
                // Kısa kararlılık beklemesi: odak hemen geri çalınmamalı (ör. kullanıcı etkinliği).
                std::thread::sleep(Duration::from_millis(300));
                let pids = pids_of();
                if foreground_belongs_to(&pids) && find_window_titled(&pids, needle).is_some() {
                    log(format!("   on plan DOGRULANDI: [{}]", foreground_info()));
                    return true;
                }
            }
            let _ = activate_window_titled(&pids, needle);
            std::thread::sleep(Duration::from_millis(500));
        }
        log(format!(
            "   deneme {attempt}: overlay gorunur ama on planda degil: [{}]",
            foreground_info()
        ));
    }
    false
}

/// Tanı: verilen süreçlerin TÜM üst düzey pencereleri (görünür mü, başlık).
pub fn all_window_titles(pids: &[u32]) -> Vec<(bool, String)> {
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };
    use windows::core::BOOL;
    struct Ctx<'a> {
        pids: &'a [u32],
        out: Vec<(bool, String)>,
    }
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
        // SAFETY: `lp`, `EnumWindows` süresince yaşayan `Ctx`'e işaret eder.
        let ctx = unsafe { &mut *(lp.0 as *mut Ctx) };
        let mut pid = 0u32;
        // SAFETY: Geçerli tutamaç ve işaretçi.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if ctx.pids.contains(&pid) {
            let mut buf = [0u16; 256];
            // SAFETY: `buf` yazılabilir tampon.
            let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
            // SAFETY: Salt sorgu.
            let vis = unsafe { IsWindowVisible(hwnd) }.as_bool();
            if n > 0 {
                ctx.out
                    .push((vis, String::from_utf16_lossy(&buf[..n as usize])));
            }
        }
        BOOL(1)
    }
    let mut ctx = Ctx {
        pids,
        out: Vec::new(),
    };
    // SAFETY: `cb` imzası doğru; `ctx` çağrı bitene dek yaşar.
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(&mut ctx as *mut Ctx as isize));
    }
    ctx.out
}

/// UI Automation ile `hwnd` altında adı `name` olan öğeyi bulup `Invoke` eder (WebView2 içeriğindeki düğme için).
/// Bulunup çağrılırsa `true`. Yalnızca test aracıdır.
pub fn uia_invoke_by_name(hwnd: isize, name: &str) -> bool {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationInvokePattern, TreeScope_Descendants,
        UIA_InvokePatternId, UIA_NamePropertyId,
    };
    use windows::core::{BSTR, Interface};
    // SAFETY: COM bu iş parçacığında başlatılır; tüm arayüz işaretçileri `windows` crate'inin akıllı sarmalayıcılarıdır
    // (Drop'ta Release); `hwnd` yalnızca `ElementFromHandle`a verilen sayısal tutamaçtır.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let Ok(auto) =
            CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
        else {
            return false;
        };
        let Ok(root) = auto.ElementFromHandle(HWND(hwnd as *mut core::ffi::c_void)) else {
            return false;
        };
        let Ok(cond) =
            auto.CreatePropertyCondition(UIA_NamePropertyId, &VARIANT::from(BSTR::from(name)))
        else {
            return false;
        };
        let Ok(el) = root.FindFirst(TreeScope_Descendants, &cond) else {
            return false;
        };
        let Ok(pat) = el.GetCurrentPattern(UIA_InvokePatternId) else {
            return false;
        };
        let Ok(inv) = pat.cast::<IUIAutomationInvokePattern>() else {
            return false;
        };
        inv.Invoke().is_ok()
    }
}

/// Verilen süreçlerin görünür penceresini (başlığı `needle` içeren) bulur: `hwnd` (isize).
pub fn find_window_titled(pids: &[u32], needle: &str) -> Option<isize> {
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    };
    use windows::core::BOOL;
    struct Ctx<'a> {
        pids: &'a [u32],
        needle: &'a str,
        found: Option<isize>,
    }
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
        // SAFETY: `lp`, `EnumWindows` süresince yaşayan `Ctx`'e işaret eder.
        let ctx = unsafe { &mut *(lp.0 as *mut Ctx) };
        let mut pid = 0u32;
        // SAFETY: Geçerli tutamaç ve işaretçi.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        // SAFETY: Salt sorgu.
        if ctx.pids.contains(&pid) && unsafe { IsWindowVisible(hwnd) }.as_bool() {
            let mut buf = [0u16; 256];
            // SAFETY: `buf` yazılabilir tampon.
            let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
            if n > 0 && String::from_utf16_lossy(&buf[..n as usize]).contains(ctx.needle) {
                ctx.found = Some(hwnd.0 as isize);
                return BOOL(0);
            }
        }
        BOOL(1)
    }
    let mut ctx = Ctx {
        pids,
        needle,
        found: None,
    };
    // SAFETY: `cb` imzası doğru; `ctx` çağrı bitene dek yaşar.
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(&mut ctx as *mut Ctx as isize));
    }
    ctx.found
}

/// Pencere dikdörtgeni (sol, üst, sağ, alt).
pub fn window_rect(hwnd: isize) -> Option<(i32, i32, i32, i32)> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::WindowsAndMessaging::GetWindowRect;
    let mut r = RECT::default();
    // SAFETY: Geçerli (sorgu anında) pencere tutamacı ve yazılabilir RECT.
    unsafe { GetWindowRect(HWND(hwnd as *mut core::ffi::c_void), &mut r).ok()? };
    Some((r.left, r.top, r.right, r.bottom))
}

/// Ekran koordinatına sol tıklama (imleç taşınır).
pub fn click_at(x: i32, y: i32) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        INPUT_MOUSE, MOUSE_EVENT_FLAGS, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEINPUT,
    };
    use windows::Win32::UI::WindowsAndMessaging::SetCursorPos;
    // SAFETY: Koordinatlar tamsayı; SetCursorPos yalnızca imleci taşır.
    unsafe {
        let _ = SetCursorPos(x, y);
    }
    std::thread::sleep(Duration::from_millis(120));
    let mk = |flags: MOUSE_EVENT_FLAGS| INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    send(&[mk(MOUSEEVENTF_LEFTDOWN)]);
    std::thread::sleep(Duration::from_millis(60));
    send(&[mk(MOUSEEVENTF_LEFTUP)]);
}

/// Ön plandaki pencere verilen süreçlerden birine mi ait? (Girdi enjekte etmeden önce yanlış uygulamaya yazmayı önler.)
pub fn foreground_belongs_to(pids: &[u32]) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
    // SAFETY: Salt sorgu; dönen tutamaç yalnızca pid almak için kullanılır.
    unsafe {
        let h = GetForegroundWindow();
        if h.0.is_null() {
            return false;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, Some(&mut pid));
        pids.contains(&pid)
    }
}
