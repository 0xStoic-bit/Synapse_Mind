//! Windows UI Automation metin çıkarıcı.
//!
//! Öncelik kuralı: Sıfır OCR. Odaktaki pencerenin erişilebilirlik ağacından
//! (`IUIAutomation`) metin düğümleri (`TextPattern`, `ValuePattern`, `Name`)
//! sınırlı derinlik ve düğüm bütçesiyle toplanır.

use std::collections::HashSet;
use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher, RandomState};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

/// Odaktaki pencerenin `AccessibilityTreeChanged` metin akışı eşikleri.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccessibilityStreamConfig {
    /// Odaktaki pencerede `AccessibilityTreeChanged` takibini etkinleştirir.
    pub enabled: bool,
    /// Ardışık UIA değişikliklerini birleştiren sessizlik bekleme süresi (debounce).
    pub debounce: Duration,
    /// Sürekli akışta (ör. terminal çıktısı) beklemenin üst sınırı.
    /// `Duration::ZERO` ise yalnızca sessizlik debounce uygulanır.
    pub max_wait: Duration,
    /// Yeni metnin anlamlı değişim sayılması için gereken en az değişen bayt miktarı.
    pub min_changed_bytes: usize,
    /// Önceki metne göre gereken en az oransal değişim (`0.0..=1.0`).
    pub min_change_ratio: f64,
    /// Büyük belgelerde oransal eşik beklenmeden tetiklenecek mutlak değişim eşiği (bayt).
    pub unconditional_changed_bytes: usize,
}

impl Default for AccessibilityStreamConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            debounce: Duration::from_millis(750),
            max_wait: Duration::from_millis(3000),
            min_changed_bytes: 32,
            min_change_ratio: 0.10,
            unconditional_changed_bytes: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTreeDebounce {
    hwnd_raw: isize,
    first_event_at: Instant,
    last_event_at: Instant,
    latest_timestamp_ms: u64,
}

/// Odaktaki pencere için saf (OS çağrısız) UIA olay birleştirici / debounce durum makinesi.
#[derive(Debug, Default)]
pub struct TreeChangeDebouncer {
    pending: Option<PendingTreeDebounce>,
}

impl TreeChangeDebouncer {
    pub fn new() -> Self {
        Self { pending: None }
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn clear(&mut self) {
        self.pending = None;
    }

    /// Odaktaki pencere için yeni bir UIA değişim sinyali kaydeder.
    pub fn note_activity(&mut self, hwnd_raw: isize, now: Instant, timestamp_ms: u64) {
        if hwnd_raw == 0 {
            return;
        }
        match &mut self.pending {
            Some(p) if p.hwnd_raw == hwnd_raw => {
                p.last_event_at = now;
                p.latest_timestamp_ms = timestamp_ms;
            }
            slot => {
                *slot = Some(PendingTreeDebounce {
                    hwnd_raw,
                    first_event_at: now,
                    last_event_at: now,
                    latest_timestamp_ms: timestamp_ms,
                });
            }
        }
    }

    /// Bekleyen debounce zaman aşımını hesaplar (`enabled == false` ise `None`).
    pub fn next_deadline(&self, cfg: &AccessibilityStreamConfig) -> Option<Instant> {
        if !cfg.enabled {
            return None;
        }
        let p = self.pending?;
        let quiet_deadline = p.last_event_at + cfg.debounce;
        if !cfg.max_wait.is_zero() {
            let max_deadline = p.first_event_at + cfg.max_wait.max(cfg.debounce);
            Some(quiet_deadline.min(max_deadline))
        } else {
            Some(quiet_deadline)
        }
    }

    /// Zaman aşımı dolduysa bekleyen `(hwnd_raw, latest_timestamp_ms)` çiftini tüketip döndürür.
    pub fn poll_ready(
        &mut self,
        now: Instant,
        cfg: &AccessibilityStreamConfig,
    ) -> Option<(isize, u64)> {
        let deadline = self.next_deadline(cfg)?;
        if now >= deadline {
            let p = self.pending.take()?;
            Some((p.hwnd_raw, p.latest_timestamp_ms))
        } else {
            None
        }
    }
}

/// İki UIA metin anlık görüntüsü arasındaki değişim ölçümü (ham metin içermez).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TextDelta {
    pub changed_bytes: usize,
    pub change_ratio: f64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TokenDigest {
    hash: u64,
    byte_len: u32,
    count: u32,
}

impl Zeroize for TokenDigest {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.byte_len.zeroize();
        self.count.zeroize();
    }
}

#[derive(Default)]
struct TextFingerprint {
    tokens: Vec<TokenDigest>,
    total_bytes: usize,
}

impl Zeroize for TextFingerprint {
    fn zeroize(&mut self) {
        self.tokens.zeroize();
        self.tokens.clear();
        self.total_bytes.zeroize();
    }
}

impl Drop for TextFingerprint {
    fn drop(&mut self) {
        self.zeroize();
    }
}

const MAX_CHUNK_BYTES: usize = 32;

fn split_long_token<'a>(mut token: &'a str, out: &mut Vec<&'a str>) {
    while token.len() > MAX_CHUNK_BYTES {
        let mut cut = MAX_CHUNK_BYTES;
        while cut > 0 && !token.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            break;
        }
        out.push(&token[..cut]);
        token = &token[cut..];
    }
    if !token.is_empty() {
        out.push(token);
    }
}

fn build_fingerprint(hasher: &RandomState, text: &str) -> TextFingerprint {
    let mut chunks = Vec::new();
    for word in text.split_whitespace() {
        if word.len() <= MAX_CHUNK_BYTES {
            chunks.push(word);
        } else {
            split_long_token(word, &mut chunks);
        }
    }

    if chunks.is_empty() {
        return TextFingerprint::default();
    }

    let mut tokens = Vec::with_capacity(chunks.len());
    let mut total_bytes = 0usize;
    for chunk in chunks {
        let byte_len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        total_bytes = total_bytes.saturating_add(chunk.len());
        tokens.push(TokenDigest {
            hash: hasher.hash_one(chunk.as_bytes()),
            byte_len,
            count: 1,
        });
    }

    tokens.sort_unstable_by(|a, b| a.hash.cmp(&b.hash).then(a.byte_len.cmp(&b.byte_len)));

    let mut write_idx = 0usize;
    for read_idx in 1..tokens.len() {
        if tokens[write_idx].hash == tokens[read_idx].hash
            && tokens[write_idx].byte_len == tokens[read_idx].byte_len
        {
            tokens[write_idx].count = tokens[write_idx].count.saturating_add(1);
        } else {
            write_idx += 1;
            tokens[write_idx] = tokens[read_idx];
        }
    }
    tokens.truncate(write_idx + 1);

    TextFingerprint {
        tokens,
        total_bytes,
    }
}

fn compare_fingerprints(prev: &TextFingerprint, next: &TextFingerprint) -> TextDelta {
    let mut added_bytes = 0usize;
    let mut removed_bytes = 0usize;

    let mut i = 0usize;
    let mut j = 0usize;
    let a = &prev.tokens;
    let b = &next.tokens;

    while i < a.len() && j < b.len() {
        match a[i]
            .hash
            .cmp(&b[j].hash)
            .then(a[i].byte_len.cmp(&b[j].byte_len))
        {
            std::cmp::Ordering::Less => {
                removed_bytes = removed_bytes
                    .saturating_add((a[i].count as usize).saturating_mul(a[i].byte_len as usize));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                added_bytes = added_bytes
                    .saturating_add((b[j].count as usize).saturating_mul(b[j].byte_len as usize));
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if b[j].count > a[i].count {
                    added_bytes = added_bytes.saturating_add(
                        ((b[j].count - a[i].count) as usize).saturating_mul(b[j].byte_len as usize),
                    );
                } else if a[i].count > b[j].count {
                    removed_bytes = removed_bytes.saturating_add(
                        ((a[i].count - b[j].count) as usize).saturating_mul(a[i].byte_len as usize),
                    );
                }
                i += 1;
                j += 1;
            }
        }
    }

    while i < a.len() {
        removed_bytes = removed_bytes
            .saturating_add((a[i].count as usize).saturating_mul(a[i].byte_len as usize));
        i += 1;
    }
    while j < b.len() {
        added_bytes = added_bytes
            .saturating_add((b[j].count as usize).saturating_mul(b[j].byte_len as usize));
        j += 1;
    }

    let changed_bytes = added_bytes.max(removed_bytes);
    let denom = prev.total_bytes.max(next.total_bytes);
    let change_ratio = if denom == 0 {
        0.0
    } else {
        (changed_bytes as f64 / denom as f64).min(1.0)
    };

    TextDelta {
        changed_bytes,
        change_ratio,
    }
}

/// Değişim ölçümünün `AccessibilityStreamConfig` eşiğini geçip geçmediğini sınar.
pub fn meets_change_threshold(
    delta: TextDelta,
    prev_total_bytes: usize,
    cfg: &AccessibilityStreamConfig,
) -> bool {
    if delta.changed_bytes < cfg.min_changed_bytes || delta.changed_bytes == 0 {
        return false;
    }
    if prev_total_bytes == 0 {
        return true;
    }
    if delta.changed_bytes >= cfg.unconditional_changed_bytes {
        return true;
    }
    let min_ratio = if cfg.min_change_ratio.is_finite() {
        cfg.min_change_ratio.clamp(0.0, 1.0)
    } else {
        1.0
    };
    delta.change_ratio >= min_ratio
}

/// Odaktaki pencere metin değişimini RAM'de ham metin tutmadan izler.
///
/// Önceki anlık görüntü yalnızca süreç içi rastgele anahtarlı SipHash özetleri
/// (`TokenDigest`) olarak saklanır ve sıfırlama/drop sırasında `zeroize` edilir.
pub struct TextDeltaTracker {
    hasher: RandomState,
    last_hwnd: isize,
    last_fp: TextFingerprint,
}

impl Default for TextDeltaTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TextDeltaTracker {
    pub fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            last_hwnd: 0,
            last_fp: TextFingerprint::default(),
        }
    }

    pub fn clear(&mut self) {
        self.last_hwnd = 0;
        self.last_fp.zeroize();
    }

    /// `WindowFocusChanged` gibi bir olay sonrası pencerenin taban özetini günceller.
    pub fn record_snapshot(&mut self, hwnd_raw: isize, text: &str) {
        if hwnd_raw == 0 {
            self.clear();
            return;
        }
        let next_fp = build_fingerprint(&self.hasher, text);
        self.last_hwnd = hwnd_raw;
        self.last_fp.zeroize();
        self.last_fp = next_fp;
    }

    /// Metnin `AccessibilityStreamConfig` eşiğini aşıp aşmadığını ölçer; aşarsa
    /// anlık özeti günceller ve `true` döndürür.
    pub fn should_emit_and_update(
        &mut self,
        hwnd_raw: isize,
        text: &str,
        cfg: &AccessibilityStreamConfig,
    ) -> bool {
        if !cfg.enabled || hwnd_raw == 0 || text.trim().is_empty() {
            return false;
        }

        let next_fp = build_fingerprint(&self.hasher, text);
        if next_fp.total_bytes == 0 {
            return false;
        }

        let empty_fp = TextFingerprint::default();
        let prev_fp = if self.last_hwnd == hwnd_raw {
            &self.last_fp
        } else {
            &empty_fp
        };

        let delta = compare_fingerprints(prev_fp, &next_fp);
        let emit = meets_change_threshold(delta, prev_fp.total_bytes, cfg);
        if emit {
            self.last_hwnd = hwnd_raw;
            self.last_fp.zeroize();
            self.last_fp = next_fp;
        }
        emit
    }
}

/// UTF-16 dilimini yeniden tahsis (realloc) yapmadan tek seferde ayrılmış
/// `Zeroizing<String>` tamponuna dönüştürür.
pub(crate) fn decode_utf16_no_realloc(wide: &[u16], max_bytes: usize) -> Zeroizing<String> {
    if wide.is_empty() || max_bytes == 0 {
        return Zeroizing::new(String::new());
    }
    let cap = wide.len().saturating_mul(3).min(max_bytes);
    let mut out = Zeroizing::new(String::with_capacity(cap));
    for ch in char::decode_utf16(wide.iter().copied()) {
        let c = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
        if out.len() + c.len_utf8() > cap {
            break;
        }
        out.push(c);
    }
    out
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Toplanan UIA metin parçalarını tekilleştirir, boşlukları temizler ve
/// `String` yeniden tahsisi (realloc) yapmadan tek seferde ayrılmış
/// `Zeroizing<String>` tamponda birleştirir.
pub(crate) fn join_unique_text_nodes_zeroizing<I>(nodes: I, max_bytes: usize) -> Zeroizing<String>
where
    I: IntoIterator<Item = Zeroizing<String>>,
{
    if max_bytes == 0 {
        return Zeroizing::new(String::new());
    }

    let mut seen_hashes: HashSet<u64> = HashSet::new();
    let mut slices: Vec<(Zeroizing<String>, usize, usize)> = Vec::new();
    let mut planned_bytes = 0usize;

    for raw in nodes {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        let start = trimmed.as_ptr() as usize - raw.as_ptr() as usize;
        let len = trimmed.len();
        let h = hash_str(trimmed);
        if !seen_hashes.insert(h) {
            continue;
        }

        let sep_len = usize::from(!slices.is_empty());
        if planned_bytes + sep_len >= max_bytes {
            break;
        }

        let available = max_bytes - planned_bytes - sep_len;
        let take_len = if len <= available {
            len
        } else {
            let mut cut = available;
            while cut > 0 && !trimmed.is_char_boundary(cut) {
                cut -= 1;
            }
            cut
        };

        if take_len == 0 {
            break;
        }

        planned_bytes += sep_len + take_len;
        slices.push((raw, start, take_len));

        if planned_bytes >= max_bytes {
            break;
        }
    }

    if planned_bytes == 0 {
        return Zeroizing::new(String::new());
    }

    // Tam kapasiteyle tek seferde ayır: `push_str` sırasında realloc olmaz.
    let mut out = Zeroizing::new(String::with_capacity(planned_bytes));
    for (idx, (buf, start, take_len)) in slices.into_iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&buf[start..start + take_len]);
        // `buf` (`Zeroizing<String>`) kapsam sonunda otomatik zeroize edilir.
    }
    out
}

/// Toplanan UIA metin parçalarını tekilleştirir, boşlukları temizler ve
/// `String` yeniden tahsisi (realloc) yapmadan tek seferde ayrılmış tamponda birleştirir.
pub fn join_unique_text_nodes<I>(nodes: I, max_bytes: usize) -> String
where
    I: IntoIterator<Item = Zeroizing<String>>,
{
    let mut out = join_unique_text_nodes_zeroizing(nodes, max_bytes);
    core::mem::take(&mut *out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFocusSettle {
    hwnd_raw: isize,
    timestamp_ms: u64,
    deadline: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TitleDigest {
    hash: u64,
    len: usize,
}

#[derive(Clone, Copy)]
struct RecentFocusEmission {
    hwnd_raw: isize,
    title: TitleDigest,
    emitted_at: Instant,
}

const FOCUS_COOLDOWN_HISTORY: usize = 8;

/// Odak yerleşme (250 ms) ve aynı `(hwnd, başlık)` soğuma (2 s) kapısı.
///
/// Ham pencere başlığını bellekte tutmaz; yalnızca süreç içi rastgele anahtarlı
/// SipHash özeti (`TitleDigest`) saklar.
pub struct FocusGate {
    hasher: RandomState,
    pending: Option<PendingFocusSettle>,
    recent: Vec<RecentFocusEmission>,
}

impl Default for FocusGate {
    fn default() -> Self {
        Self::new()
    }
}

impl FocusGate {
    pub fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            pending: None,
            recent: Vec::with_capacity(FOCUS_COOLDOWN_HISTORY),
        }
    }

    pub fn clear_pending(&mut self) {
        self.pending = None;
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Odak değişimini kaydeder; `settle_delay` dolmadan önceki ara pencereler üzerine yazılır.
    pub fn note_focus(
        &mut self,
        hwnd_raw: isize,
        now: Instant,
        timestamp_ms: u64,
        settle_delay: Duration,
    ) {
        if hwnd_raw == 0 {
            self.pending = None;
            return;
        }
        self.pending = Some(PendingFocusSettle {
            hwnd_raw,
            timestamp_ms,
            deadline: now + settle_delay,
        });
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.map(|p| p.deadline)
    }

    /// Yerleşme süresi dolduysa bekleyen `(hwnd_raw, timestamp_ms)` çiftini tüketir.
    pub fn poll_ready(&mut self, now: Instant) -> Option<(isize, u64)> {
        let p = self.pending?;
        if now >= p.deadline {
            self.pending = None;
            Some((p.hwnd_raw, p.timestamp_ms))
        } else {
            None
        }
    }

    /// Aynı `(hwnd_raw, title)` için `cooldown` süresi dolmadıysa `false` döndürür;
    /// aksi halde zaman damgasını günceller ve `true` döndürür.
    pub fn should_emit_focus(
        &mut self,
        hwnd_raw: isize,
        title: &str,
        now: Instant,
        cooldown: Duration,
    ) -> bool {
        if hwnd_raw == 0 {
            return false;
        }
        let digest = TitleDigest {
            hash: self.hasher.hash_one(title.as_bytes()),
            len: title.len(),
        };
        if !cooldown.is_zero() {
            self.recent
                .retain(|r| now.saturating_duration_since(r.emitted_at) < cooldown);
            if self
                .recent
                .iter()
                .any(|r| r.hwnd_raw == hwnd_raw && r.title == digest)
            {
                return false;
            }
        } else {
            self.recent.clear();
        }

        if let Some(slot) = self.recent.iter_mut().find(|r| r.hwnd_raw == hwnd_raw) {
            slot.title = digest;
            slot.emitted_at = now;
        } else {
            if self.recent.len() >= FOCUS_COOLDOWN_HISTORY {
                self.recent.remove(0);
            }
            self.recent.push(RecentFocusEmission {
                hwnd_raw,
                title: digest,
                emitted_at: now,
            });
        }
        true
    }
}

#[cfg(windows)]
pub(crate) mod win32 {
    use std::mem::ManuallyDrop;
    use std::sync::Once;

    use windows::Win32::Foundation::{HWND, SysFreeString, SysStringLen};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationTextPattern,
        IUIAutomationTreeWalker, IUIAutomationValuePattern, UIA_TextPatternId, UIA_ValuePatternId,
    };
    use windows::core::{BSTR, s, w};
    use zeroize::{Zeroize, Zeroizing};

    use super::{decode_utf16_no_realloc, join_unique_text_nodes_zeroizing};
    use crate::{SensorConfig, SensorError};

    static OA_NO_CACHE_ONCE: Once = Once::new();

    /// YALNIZCA tek kullanımlık UIA işçi sürecinde çağrılır (`SetOaNoCache`).
    /// Ana süreçte çağrılmaz (WebView2/Tauri COM davranışını etkilemez).
    pub(crate) fn disable_oleaut_bstr_cache() {
        OA_NO_CACHE_ONCE.call_once(|| {
            // SAFETY: `oleaut32.dll` `SysFreeString` üzerinden yüklüdür;
            // `SetOaNoCache` parametresiz `extern "system" fn()` imzasına sahiptir.
            unsafe {
                if let Ok(hmod) = GetModuleHandleW(w!("oleaut32.dll"))
                    && let Some(proc_addr) = GetProcAddress(hmod, s!("SetOaNoCache"))
                {
                    let set_no_cache: unsafe extern "system" fn() = core::mem::transmute(proc_addr);
                    set_no_cache();
                }
            }
        });
    }

    /// `windows::core::BSTR` düşüşüne güvenmeden, `SysFreeString` öncesinde
    /// `SysStringLen` uzunluğunca UTF-16 içeriğini sıfırlayan RAII koruyucu.
    struct ZeroizingBstr(ManuallyDrop<BSTR>);

    impl ZeroizingBstr {
        fn new(bstr: BSTR) -> Self {
            Self(ManuallyDrop::new(bstr))
        }

        fn as_slice(&self) -> &[u16] {
            &self.0
        }
    }

    impl Drop for ZeroizingBstr {
        fn drop(&mut self) {
            // SAFETY: `self.0` `ManuallyDrop<BSTR>` içindedir ve `Drop` yalnızca bir kez
            // çalışır; `into_raw` ile `windows::core::BSTR::drop` devre dışı bırakılır.
            let raw = unsafe { ManuallyDrop::take(&mut self.0) }.into_raw();
            if !raw.is_null() {
                // SAFETY: `raw` null olmayan geçerli bir `BSTR` işaretçisidir.
                // `SysFreeString` BSTR önbelleğine belleği iade etmeden önce
                // `SysStringLen` adet `u16` karakter volatile olarak sıfırlanır.
                unsafe {
                    let bstr_ref = ManuallyDrop::new(BSTR::from_raw(raw));
                    let len = SysStringLen(&bstr_ref) as usize;
                    if len > 0 {
                        core::slice::from_raw_parts_mut(raw.cast_mut(), len).zeroize();
                    }
                    SysFreeString(&bstr_ref);
                }
            }
        }
    }

    struct ComGuard {
        should_uninit: bool,
    }

    impl ComGuard {
        fn init_mta() -> Result<Self, SensorError> {
            // SAFETY: İşçi iş parçacığı için COM MTA başlatılır; `S_OK` veya `S_FALSE`
            // döndüğünde `Drop` içinde `CoUninitialize` ile eşleştirilir.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            // `RPC_E_CHANGED_MODE` (0x80010106) bu iş parçacığında COM'un zaten başka modda
            // başlatıldığını gösterir; yine de UIA nesnesi oluşturulabilir ama uninit yapılmaz.
            const RPC_E_CHANGED_MODE_CODE: i32 = -2147417850; // 0x80010106u32 as i32
            if hr.is_ok() {
                Ok(Self {
                    should_uninit: true,
                })
            } else if hr.0 == RPC_E_CHANGED_MODE_CODE {
                Ok(Self {
                    should_uninit: false,
                })
            } else {
                Err(SensorError::ComInitFailed(hr.0))
            }
        }
    }

    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.should_uninit {
                // SAFETY: `ComGuard::init_mta` bu iş parçacığında `CoInitializeEx` ile
                // `S_OK` veya `S_FALSE` aldığında `should_uninit` doğrudur.
                unsafe { CoUninitialize() };
            }
        }
    }

    pub(crate) struct UiaExtraction {
        pub text: Zeroizing<String>,
        pub node_count: u32,
        /// UIA ağacı boşsa yalnızca metadata sebepten ibaret statik etiket (ham başlık/metin içermez).
        pub empty_reason: Option<&'static str>,
    }

    pub(crate) struct UiaExtractor {
        // Drop sırası kritik: önce COM arayüzleri (`walker`, `automation`) serbest
        // bırakılmalı, en son `_com` (`CoUninitialize`) çalışmalıdır.
        walker: IUIAutomationTreeWalker,
        automation: IUIAutomation,
        _com: ComGuard,
    }

    impl UiaExtractor {
        pub(crate) fn new() -> Result<Self, SensorError> {
            let com = ComGuard::init_mta()?;
            // SAFETY: COM başlatılmıştır; `CUIAutomation` sınıf kimliği ile sistem içi
            // `IUIAutomation` örneği oluşturulur.
            let automation: IUIAutomation =
                unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }
                    .map_err(|e| SensorError::UiaInitFailed(e.code().0))?;
            // SAFETY: Geçerli `IUIAutomation` örneğinden `ControlViewWalker` alınır.
            let walker = unsafe { automation.ControlViewWalker() }
                .map_err(|e| SensorError::UiaInitFailed(e.code().0))?;

            Ok(Self {
                walker,
                automation,
                _com: com,
            })
        }

        pub(crate) fn extract_window_text(
            &self,
            hwnd: HWND,
            config: &SensorConfig,
        ) -> UiaExtraction {
            if hwnd.0.is_null() {
                return UiaExtraction {
                    text: Zeroizing::new(String::new()),
                    node_count: 0,
                    empty_reason: Some("null_hwnd"),
                };
            }

            // SAFETY: `hwnd` boş olmayan bir pencere tutamacıdır; pencere kapandıysa UIA hata döner.
            let root = match unsafe { self.automation.ElementFromHandle(hwnd) } {
                Ok(elem) => elem,
                Err(_) => {
                    return UiaExtraction {
                        text: Zeroizing::new(String::new()),
                        node_count: 0,
                        empty_reason: Some("element_from_handle_failed"),
                    };
                }
            };

            let mut collected: Vec<Zeroizing<String>> = Vec::new();
            let mut collected_bytes = 0usize;
            let mut visited: u32 = 0;
            let mut stack: Vec<(IUIAutomationElement, usize)> = vec![(root, 0)];

            while let Some((elem, depth)) = stack.pop() {
                if visited >= config.max_uia_nodes || collected_bytes >= config.max_uia_text_bytes {
                    break;
                }
                visited += 1;

                extract_element_text(
                    &elem,
                    depth,
                    config.max_uia_text_bytes.saturating_sub(collected_bytes),
                    &mut collected,
                    &mut collected_bytes,
                );

                if depth < config.max_uia_depth && visited < config.max_uia_nodes {
                    let mut children = Vec::new();
                    // SAFETY: `elem` geçerli bir UIA COM arayüzüdür; hata durumunda döngü biter.
                    if let Ok(mut child) = unsafe { self.walker.GetFirstChildElement(&elem) } {
                        let remaining_budget =
                            config.max_uia_nodes.saturating_sub(visited) as usize;
                        loop {
                            let next =
                                // SAFETY: `child` geçerli bir UIA COM arayüzüdür.
                                unsafe { self.walker.GetNextSiblingElement(&child) }.ok();
                            children.push(child);
                            if children.len() >= remaining_budget {
                                break;
                            }
                            match next {
                                Some(n) => child = n,
                                None => break,
                            }
                        }
                    }
                    // DFS'nin üstten alta doğal sırayla gezmesi için çocukları ters sırayla it.
                    for c in children.into_iter().rev() {
                        stack.push((c, depth + 1));
                    }
                }
            }

            let text = join_unique_text_nodes_zeroizing(collected, config.max_uia_text_bytes);
            let empty_reason = if text.is_empty() {
                Some("no_text_nodes_in_tree")
            } else {
                None
            };

            UiaExtraction {
                text,
                node_count: visited,
                empty_reason,
            }
        }
    }

    fn push_bstr_text(
        raw_bstr: BSTR,
        remaining_bytes: usize,
        out: &mut Vec<Zeroizing<String>>,
        out_bytes: &mut usize,
    ) -> bool {
        let bstr = ZeroizingBstr::new(raw_bstr);
        let s = decode_utf16_no_realloc(bstr.as_slice(), remaining_bytes);
        drop(bstr);
        if !s.trim().is_empty() {
            *out_bytes = out_bytes.saturating_add(s.len());
            out.push(s);
            true
        } else {
            false
        }
    }

    fn extract_element_text(
        elem: &IUIAutomationElement,
        depth: usize,
        remaining_bytes: usize,
        out: &mut Vec<Zeroizing<String>>,
        out_bytes: &mut usize,
    ) {
        if remaining_bytes == 0 {
            return;
        }

        let mut got_pattern_text = false;

        // 1. TextPattern (belgeler, editörler, tarayıcı içerikleri)
        // SAFETY: `elem` geçerli bir `IUIAutomationElement` COM arayüzüdür.
        if let Ok(text_pattern) =
            unsafe { elem.GetCurrentPatternAs::<IUIAutomationTextPattern>(UIA_TextPatternId) }
        {
            // SAFETY: Geçerli `IUIAutomationTextPattern` arayüzünden `DocumentRange` istenir.
            if let Ok(range) = unsafe { text_pattern.DocumentRange() } {
                let char_cap = remaining_bytes.min(i32::MAX as usize) as i32;
                // SAFETY: `range` geçerli bir `IUIAutomationTextRange` arayüzüdür; `char_cap >= 0`.
                if let Ok(bstr) = unsafe { range.GetText(char_cap) }
                    && push_bstr_text(bstr, remaining_bytes, out, out_bytes)
                {
                    got_pattern_text = true;
                }
            }
        }

        // 2. ValuePattern (metin kutuları, adres çubukları)
        if !got_pattern_text {
            // SAFETY: `elem` geçerli bir `IUIAutomationElement` COM arayüzüdür.
            if let Ok(value_pattern) =
                unsafe { elem.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
            {
                // SAFETY: Geçerli `IUIAutomationValuePattern` arayüzünden `CurrentValue` okunur.
                if let Ok(bstr) = unsafe { value_pattern.CurrentValue() }
                    && push_bstr_text(bstr, remaining_bytes, out, out_bytes)
                {
                    got_pattern_text = true;
                }
            }
        }

        // 3. Name özelliği (etiketler, düğmeler, başlıklar). Kök pencerenin başlığı
        // zaten `window_title`'a alındığı için ikinci kopya oluşmasın diye atlanır.
        if !got_pattern_text && depth > 0 {
            // SAFETY: `elem` geçerli bir `IUIAutomationElement` COM arayüzüdür.
            if let Ok(bstr) = unsafe { elem.CurrentName() } {
                let _ = push_bstr_text(bstr, remaining_bytes, out, out_bytes);
            }
        }
    }
}
