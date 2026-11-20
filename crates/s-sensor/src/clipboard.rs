//! Windows pano dinleme yardımcıları ve format sınıflandırması.
//!
//! Güvenlik kuralı: Pano metni yalnızca `RawCapturePacket` içine taşınır;
//! hiçbir koşulda loglanmaz veya `Debug` ile yazdırılmaz.

use s_types::ClipboardFormat;

// Standart Win32 pano format sabitleri (platform bağımsız test edilebilmesi için).
const CF_TEXT_ID: u32 = 1;
const CF_BITMAP_ID: u32 = 2;
const CF_DIB_ID: u32 = 8;
const CF_UNICODETEXT_ID: u32 = 13;
const CF_HDROP_ID: u32 = 15;
const CF_DIBV5_ID: u32 = 17;

/// Mevcut Win32 pano format ID'lerini `s_types::ClipboardFormat` değerine eşler.
///
/// Öncelik sırası: `RichText` (RTF/HTML) > `PlainText` > `FileDropList` > `ImageBitmap` > `IgnoredFormat`.
pub fn classify_clipboard_formats(
    available_formats: &[u32],
    rtf_format_id: u32,
    html_format_id: u32,
) -> ClipboardFormat {
    let has_rtf = rtf_format_id != 0 && available_formats.contains(&rtf_format_id);
    let has_html = html_format_id != 0 && available_formats.contains(&html_format_id);
    if has_rtf || has_html {
        return ClipboardFormat::RichText;
    }

    if available_formats.contains(&CF_UNICODETEXT_ID) || available_formats.contains(&CF_TEXT_ID) {
        return ClipboardFormat::PlainText;
    }

    if available_formats.contains(&CF_HDROP_ID) {
        return ClipboardFormat::FileDropList;
    }

    if available_formats.contains(&CF_BITMAP_ID)
        || available_formats.contains(&CF_DIB_ID)
        || available_formats.contains(&CF_DIBV5_ID)
    {
        return ClipboardFormat::ImageBitmap;
    }

    ClipboardFormat::IgnoredFormat
}

#[cfg(windows)]
pub(crate) mod win32 {
    use std::time::Duration;

    use s_types::{ClipboardFormat, EventKind, RawCapturePacket, RawPayload};
    use windows::Win32::Foundation::{HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EnumClipboardFormats, GetClipboardData, GetClipboardOwner, OpenClipboard,
        RegisterClipboardFormatW,
    };
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::System::Ole::{CF_TEXT, CF_UNICODETEXT};
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    use windows::core::w;
    use zeroize::{Zeroize, Zeroizing};

    use super::classify_clipboard_formats;
    use crate::win32_hook::query_window_attribution;

    struct ClipboardGuard;

    impl ClipboardGuard {
        fn open() -> Option<Self> {
            // Başka bir uygulama panoyu yeni bıraktıysa kısa süreli kilit çakışması olabilir.
            for attempt in 0..3 {
                // SAFETY: `OpenClipboard(None)` geçerli Win32 API çağrısıdır; başarılı olursa
                // pano kilidi alınır ve `Drop` içinde `CloseClipboard()` ile serbest bırakılır.
                let opened = unsafe { OpenClipboard(None) };
                if opened.is_ok() {
                    return Some(Self);
                }
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            None
        }
    }

    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            // SAFETY: `ClipboardGuard` yalnızca başarılı `OpenClipboard` sonrasında oluşturulur.
            let _ = unsafe { CloseClipboard() };
        }
    }

    struct GlobalLockGuard {
        handle: HGLOBAL,
        ptr: *mut core::ffi::c_void,
    }

    impl GlobalLockGuard {
        fn lock(handle: HGLOBAL) -> Option<Self> {
            // SAFETY: `handle`, açık pano oturumu içinden `GetClipboardData` ile alınan geçerli
            // bir `HGLOBAL` tutamacıdır; `Drop` içinde `GlobalUnlock` ile eşleştirilir.
            let ptr = unsafe { GlobalLock(handle) };
            if ptr.is_null() {
                None
            } else {
                Some(Self { handle, ptr })
            }
        }
    }

    impl Drop for GlobalLockGuard {
        fn drop(&mut self) {
            // SAFETY: `self.handle`, `GlobalLock` ile kilitlenmiş geçerli bir `HGLOBAL` tutamacıdır.
            let _ = unsafe { GlobalUnlock(self.handle) };
        }
    }

    /// Pano değişikliği sonrası formatı sınıflandırır ve metin varsa `RawCapturePacket` üretir.
    ///
    /// Pano sahibi (`GetClipboardOwner`, yoksa `GetForegroundWindow`) Synapse Mind öz süreçlerinden
    /// birine aitse panoyu açıp metin okumadan `None` döndürür.
    pub(crate) fn capture_clipboard_packet(
        timestamp_ms: u64,
        max_text_bytes: usize,
        is_excluded_hwnd: impl Fn(HWND) -> bool,
    ) -> Option<RawCapturePacket> {
        // Pano sahibi pencere yoksa güncel odak penceresinden süreç bilgisi alınır.
        // SAFETY: `GetClipboardOwner` salt-okunur pencere tutamacı döndürür.
        let owner_hwnd = unsafe { GetClipboardOwner() }
            .ok()
            .filter(|h| !h.0.is_null())
            .unwrap_or_else(|| {
                // SAFETY: `GetForegroundWindow` salt-okunur pencere tutamacı döndürür.
                unsafe { GetForegroundWindow() }
            });

        capture_clipboard_packet_for_owner(
            owner_hwnd,
            timestamp_ms,
            max_text_bytes,
            is_excluded_hwnd,
        )
    }

    pub(crate) fn capture_clipboard_packet_for_owner(
        owner_hwnd: HWND,
        timestamp_ms: u64,
        max_text_bytes: usize,
        is_excluded_hwnd: impl Fn(HWND) -> bool,
    ) -> Option<RawCapturePacket> {
        if is_excluded_hwnd(owner_hwnd) {
            return None;
        }

        let _guard = ClipboardGuard::open()?;

        // SAFETY: Sabit null-sonlandırılmış UTF-16 format adları Win32 `RegisterClipboardFormatW`'a verilir.
        let rtf_id = unsafe { RegisterClipboardFormatW(w!("Rich Text Format")) };
        // SAFETY: Sabit null-sonlandırılmış UTF-16 format adı Win32 `RegisterClipboardFormatW`'a verilir.
        let html_id = unsafe { RegisterClipboardFormatW(w!("HTML Format")) };

        let mut available = Vec::with_capacity(16);
        let mut fmt = 0u32;
        loop {
            // SAFETY: Pano `_guard` tarafından açık tutulduğu sürece `EnumClipboardFormats` güvenlidir.
            fmt = unsafe { EnumClipboardFormats(fmt) };
            if fmt == 0 {
                break;
            }
            available.push(fmt);
        }

        let format = classify_clipboard_formats(&available, rtf_id, html_id);
        let mut text = match format {
            ClipboardFormat::PlainText | ClipboardFormat::RichText => {
                read_clipboard_text(max_text_bytes).unwrap_or_else(|| Zeroizing::new(String::new()))
            }
            ClipboardFormat::ImageBitmap
            | ClipboardFormat::FileDropList
            | ClipboardFormat::IgnoredFormat => Zeroizing::new(String::new()),
        };

        let (process_id, mut process_name, mut window_title) = query_window_attribution(owner_hwnd);

        Some(RawCapturePacket {
            timestamp_ms,
            process_id,
            process_name: core::mem::take(&mut *process_name),
            window_title: core::mem::take(&mut *window_title),
            event_kind: EventKind::ClipboardCopied { format },
            raw_payload: RawPayload::ClipboardText(core::mem::take(&mut *text)),
        })
    }

    fn read_clipboard_text(max_text_bytes: usize) -> Option<Zeroizing<String>> {
        // Önce UTF-16 Unicode metin denenir.
        // SAFETY: Pano `ClipboardGuard` tarafından açık tutulmaktadır.
        if let Ok(handle) = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT.0)) } {
            let hglobal = HGLOBAL(handle.0);
            if let Some(lock) = GlobalLockGuard::lock(hglobal) {
                // SAFETY: `hglobal` geçerli bir global bellek bloğudur; `GlobalSize` bayt boyutunu döndürür.
                let byte_size = unsafe { GlobalSize(hglobal) };
                let u16_len = byte_size / core::mem::size_of::<u16>();
                if u16_len > 0 {
                    // SAFETY: `lock.ptr`, en az `u16_len` adet `u16` (`byte_size` bayt) için
                    // `GlobalLock` ile sabitlenmiş süreç-yerel `HGLOBAL` tamponudur; okuma
                    // tamamlandıktan hemen sonra `GlobalUnlock`/`CloseClipboard` serbest
                    // bırakmadan önce `zeroize()` ile temizlenir.
                    let out = unsafe {
                        let slice = core::slice::from_raw_parts(lock.ptr.cast::<u16>(), u16_len);
                        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                        let decoded = decode_utf16_no_realloc_owned(&slice[..end], max_text_bytes);
                        core::slice::from_raw_parts_mut(lock.ptr.cast::<u8>(), byte_size).zeroize();
                        decoded
                    };
                    return Some(out);
                }
            }
        }

        // Fallback: ANSI `CF_TEXT`.
        // SAFETY: Pano `ClipboardGuard` tarafından açık tutulmaktadır.
        if let Ok(handle) = unsafe { GetClipboardData(u32::from(CF_TEXT.0)) } {
            let hglobal = HGLOBAL(handle.0);
            if let Some(lock) = GlobalLockGuard::lock(hglobal) {
                // SAFETY: `hglobal` geçerli bir global bellek bloğudur; `GlobalSize` bayt boyutunu döndürür.
                let byte_size = unsafe { GlobalSize(hglobal) };
                if byte_size > 0 {
                    // SAFETY: `lock.ptr`, `byte_size` bayt boyunca `GlobalLock` ile sabitlenmiş
                    // süreç-yerel `HGLOBAL` tamponudur; okuma sonrası sıfırlanır.
                    let out = unsafe {
                        let slice = core::slice::from_raw_parts(lock.ptr.cast::<u8>(), byte_size);
                        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                        let decoded = decode_bytes_no_realloc_owned(&slice[..end], max_text_bytes);
                        core::slice::from_raw_parts_mut(lock.ptr.cast::<u8>(), byte_size).zeroize();
                        decoded
                    };
                    return Some(out);
                }
            }
        }

        None
    }

    fn decode_utf16_no_realloc_owned(wide: &[u16], max_bytes: usize) -> Zeroizing<String> {
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

    fn decode_bytes_no_realloc_owned(bytes: &[u8], max_bytes: usize) -> Zeroizing<String> {
        if bytes.is_empty() || max_bytes == 0 {
            return Zeroizing::new(String::new());
        }
        let cap = bytes.len().saturating_mul(3).min(max_bytes);
        let mut out = Zeroizing::new(String::with_capacity(cap));
        for chunk in bytes.utf8_chunks() {
            for ch in chunk.valid().chars() {
                if out.len() + ch.len_utf8() > cap {
                    return out;
                }
                out.push(ch);
            }
            if !chunk.invalid().is_empty() {
                let rep = char::REPLACEMENT_CHARACTER;
                if out.len() + rep.len_utf8() > cap {
                    return out;
                }
                out.push(rep);
            }
        }
        out
    }
}
