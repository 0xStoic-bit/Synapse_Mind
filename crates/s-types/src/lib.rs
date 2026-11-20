//! # s-types — Kilitli Tip ve Veri Devir Sözleşmesi (v0.2-ContractSpec)
//!
//! Sahibi: `s-architect`. Faz 0'da dondurulur; değişiklik yalnızca
//! `s-orchestrator` onayı ve `.agents/BOARD.md` kaydıyla yapılır.
//!
//! Derleme zamanı güvencesi: `RawCapturePacket` loglanamaz.
//!
//! ```compile_fail
//! fn leak(p: &s_types::RawCapturePacket) { println!("{:?}", p); }
//! ```
//!
//! Ham yük de loglanamaz:
//!
//! ```compile_fail,E0277
//! fn leak(p: &s_types::RawPayload) { println!("{:?}", p); }
//! ```
//!
//! Ham paket kopyalanamaz (bellekte zeroize edilmeyen ikinci kopya oluşmaz):
//!
//! ```compile_fail,E0277
//! fn dup(p: &s_types::RawCapturePacket) -> s_types::RawCapturePacket {
//!     <s_types::RawCapturePacket as Clone>::clone(p)
//! }
//! ```
//!
//! ```compile_fail,E0277
//! fn dup(p: &s_types::RawPayload) -> s_types::RawPayload {
//!     <s_types::RawPayload as Clone>::clone(p)
//! }
//! ```
//!
//! Ham alanlar paketten taşınarak (move) zeroize'dan kaçırılamaz:
//!
//! ```compile_fail,E0509
//! fn steal(p: s_types::RawCapturePacket) -> String { p.window_title }
//! ```
//!
//! Doğru kullanım: alanları ödünç alarak (`&`) okumak; paket düştüğünde
//! tüm ham içerik sıfırlanır.
//!
//! ```
//! use s_types::{EventKind, ClipboardFormat, RawCapturePacket, RawPayload};
//!
//! let packet = RawCapturePacket {
//!     timestamp_ms: 1,
//!     process_id: 42,
//!     process_name: "notepad.exe".to_owned(),
//!     window_title: "notlar.txt".to_owned(),
//!     event_kind: EventKind::ClipboardCopied { format: ClipboardFormat::PlainText },
//!     raw_payload: RawPayload::ClipboardText("merhaba".to_owned()),
//! };
//! // Yalnızca metadata loglanabilir:
//! let _meta = format!("{:?} pid={}", packet.event_kind, packet.process_id);
//! if let RawPayload::ClipboardText(text) = &packet.raw_payload {
//!     assert_eq!(text.len(), 7);
//! }
//! drop(packet); // process_name, window_title ve yük burada zeroize edilir.
//! ```
//!
//! ## Kalan (tip seviyesinde kapatılamayan) sızıntı yolları
//! Tüketiciler (`s-sensor`, `s-guard`) için bağlayıcı kurallar:
//! 1. Ham `String`/`Vec` alanlarını `.clone()`, `.to_string()`, `.to_owned()`,
//!    `std::mem::take`/`replace` ile kopyalamayın. Ara kopya kaçınılmazsa
//!    `zeroize::Zeroizing<String>` içine sarın.
//! 2. Ham `String`/`Vec`'i paketlemeden önce `push` ile büyütmeyin; her
//!    yeniden tahsis (realloc) eski tamponu sıfırlanmadan serbest bırakır.
//!    Kapasiteyi önceden ayırın (`with_capacity`) veya tek seferde oluşturun.
//! 3. `EventKind`, `ClipboardFormat`, `timestamp_ms`, `process_id`,
//!    `ScreenFrame { width, height }` metadata'dır (içerik değildir);
//!    `EventKind` drop'ta zeroize edilmez, loglanabilir.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 1. SENSÖR ÇIKTISI (os-sensor-agent üretir)
///
/// GÜVENLİK KRİTERİ: Debug, Serialize ve Clone türetilemez!
/// Asla doğrudan loglanamaz, diske yazılamaz veya kopyalanamaz.
/// Drop anında tüm alanlar (`process_name` ve `window_title` dahil)
/// zeroize edilir.
pub struct RawCapturePacket {
    pub timestamp_ms: u64,
    pub process_id: u32,
    pub process_name: String,
    pub window_title: String,
    pub event_kind: EventKind,
    pub raw_payload: RawPayload,
}

/// Olay türü. Yalnızca metadata taşır; içerik taşımaz, bu yüzden `Debug`
/// türetir ve loglanabilir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    WindowFocusChanged,
    ClipboardCopied { format: ClipboardFormat },
    AccessibilityTreeChanged { node_count: u32 },
    VisualDifferenceDetected { phash_distance: u8 },
}

/// Pano biçimi. Yalnızca metadata; loglanabilir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardFormat {
    PlainText,
    RichText,
    ImageBitmap,
    FileDropList,
    IgnoredFormat,
}

/// Ham içerik. Debug/Serialize/Clone YOK; paketten bağımsız olarak da
/// (ör. sensör paketi kurmadan önce hata verip yükü düşürürse) drop'ta
/// zeroize edilir.
pub enum RawPayload {
    /// UI Automation ağacından çekilen metin düğümleri (Sıfır OCR)
    AccessibilityText(String),
    /// Yalnızca UI ağacı boş olduğunda fallback görsel kare
    ScreenFrame {
        width: u32,
        height: u32,
        pixels_rgba: Vec<u8>,
    },
    /// Pano metin içeriği
    ClipboardText(String),
}

impl Zeroize for RawPayload {
    fn zeroize(&mut self) {
        match self {
            RawPayload::AccessibilityText(s) | RawPayload::ClipboardText(s) => s.zeroize(),
            RawPayload::ScreenFrame {
                width,
                height,
                pixels_rgba,
            } => {
                pixels_rgba.zeroize();
                width.zeroize();
                height.zeroize();
            }
        }
    }
}

// Ham bellek düşürüldüğü (drop) an fiziksel olarak RAM'den sıfırlanır
impl Drop for RawPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RawPayload {}

impl Zeroize for RawCapturePacket {
    fn zeroize(&mut self) {
        self.timestamp_ms.zeroize();
        self.process_id.zeroize();
        self.process_name.zeroize();
        self.window_title.zeroize();
        self.raw_payload.zeroize();
    }
}

// Ham bellek düşürüldüğü (drop) an fiziksel olarak RAM'den sıfırlanır.
// `raw_payload` ayrıca kendi Drop'unda da sıfırlanır (savunma derinliği).
impl Drop for RawCapturePacket {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RawCapturePacket {}

/// 2. GÜVENLİK KAPISI ÇIKTISI (zero-trust-guard üretir)
///
/// Yalnızca PII & Secret Scrubber ve Kara Liste onayından geçen verilerdir.
#[derive(Debug, Clone)]
pub struct MaskedMemoryBlock {
    pub event_id: u64,
    pub timestamp_ms: u64,
    pub app_context: AppContext,
    pub clean_text: String,
    pub text_hash: [u8; 32],
    pub redactions_count: u16,
    pub has_embedding_payload: bool,
    /// Kaynak olay türü (ADR-003). Alansız enum: içerik taşıyamaz.
    pub source: EventSource,
}

/// Kaynak olay türü (ADR-003). `EventKind`'in kaba taneli, ALANSIZ özeti.
///
/// Yapısı gereği hiçbir ham içerik veya sayısal metadata taşıyamaz
/// (boyutu 1 bayttır; testte doğrulanır). DB'de `as_str` kodlarıyla saklanır;
/// discriminant sırasına güvenilmez.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// `EventKind::WindowFocusChanged`
    Focus,
    /// `EventKind::ClipboardCopied { .. }` (tüm biçimler)
    Clipboard,
    /// `EventKind::AccessibilityTreeChanged { .. }`
    Accessibility,
    /// `EventKind::VisualDifferenceDetected { .. }`
    Visual,
}

impl EventSource {
    /// Tüm varyantlar (şema `CHECK` kısıtı ve testler için).
    pub const ALL: [EventSource; 4] = [
        EventSource::Focus,
        EventSource::Clipboard,
        EventSource::Accessibility,
        EventSource::Visual,
    ];

    /// Kararlı, kalıcı DB kodu. Değiştirilemez (kalıcı veriyi bozar).
    pub const fn as_str(self) -> &'static str {
        match self {
            EventSource::Focus => "focus",
            EventSource::Clipboard => "clipboard",
            EventSource::Accessibility => "accessibility",
            EventSource::Visual => "visual",
        }
    }

    /// `as_str`'ın tersi. Bilinmeyen kodda `None`.
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "focus" => Some(EventSource::Focus),
            "clipboard" => Some(EventSource::Clipboard),
            "accessibility" => Some(EventSource::Accessibility),
            "visual" => Some(EventSource::Visual),
            _ => None,
        }
    }
}

impl From<&EventKind> for EventSource {
    fn from(kind: &EventKind) -> Self {
        match kind {
            EventKind::WindowFocusChanged => EventSource::Focus,
            EventKind::ClipboardCopied { .. } => EventSource::Clipboard,
            EventKind::AccessibilityTreeChanged { .. } => EventSource::Accessibility,
            EventKind::VisualDifferenceDetected { .. } => EventSource::Visual,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppContext {
    pub process_name: String,
    pub sanitized_title: String,
    pub is_browser: bool,
}

/// 3. SORGULAMA ÇIKTISI (graph-vector-core üretir, Tauri UI tüketir)
#[derive(Debug, Clone)]
pub struct CausalityQueryHit {
    pub event_id: u64,
    pub timestamp_ms: u64,
    pub score: f32,
    pub summary_snippet: String,
    pub matched_app: String,
    /// Nedensellik Grafiği Zinciri (Örn: Hata -> Arama -> Kopyalama -> Kod)
    pub causality_chain: Vec<CausalityEdge>,
}

#[derive(Debug, Clone)]
pub struct CausalityEdge {
    pub source_event_id: u64,
    pub target_event_id: u64,
    pub relationship: String, // "searched_after_error", "pasted_from_clipboard" vb.
    pub time_delta_seconds: u32,
}

/// Sensör → Muhafız kuyruğunun sabit kapasitesi (Iron Rule 5).
pub const SENSOR_CHANNEL_CAPACITY: usize = 128;

// Not: Drop sonrası serbest bırakılmış belleği okumak `unsafe` ve tanımsız
// davranış (UB) gerektirir; bu yüzden testler drop'un kendisini değil, Drop'un
// tek satırda çağırdığı `Zeroize` uygulamasını doğrular. Kapasitenin korunması,
// silmenin yeni tahsis yapılmadan aynı tampon üzerinde (yerinde) yapıldığını
// gösterir; tamponun baytlarının sıfır olduğunu doğrudan okumak yine `unsafe`
// gerektirdiğinden zeroize crate'inin kendi garantisine (volatile yazma) dayanılır.
#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    fn packet(payload: RawPayload) -> RawCapturePacket {
        RawCapturePacket {
            timestamp_ms: 1_700_000_000_000,
            process_id: 4242,
            process_name: String::from("KeePassXC.exe"),
            window_title: String::from("Banka - Gizli"),
            event_kind: EventKind::ClipboardCopied {
                format: ClipboardFormat::PlainText,
            },
            raw_payload: payload,
        }
    }

    #[test]
    fn raw_types_are_zeroize_on_drop() {
        assert_zeroize_on_drop::<RawCapturePacket>();
        assert_zeroize_on_drop::<RawPayload>();
    }

    #[test]
    fn packet_zeroize_wipes_all_fields_in_place() {
        let mut p = packet(RawPayload::ClipboardText(String::from(
            "sk-live-0123456789abcdef",
        )));
        let name_cap = p.process_name.capacity();
        let title_cap = p.window_title.capacity();

        p.zeroize();

        assert_eq!(p.timestamp_ms, 0);
        assert_eq!(p.process_id, 0);
        assert!(p.process_name.is_empty());
        assert!(p.window_title.is_empty());
        assert_eq!(p.process_name.capacity(), name_cap);
        assert_eq!(p.window_title.capacity(), title_cap);
        match &p.raw_payload {
            RawPayload::ClipboardText(s) => assert!(s.is_empty()),
            _ => panic!("payload variant changed"),
        }
    }

    #[test]
    fn text_payload_zeroize_is_in_place() {
        for mut payload in [
            RawPayload::AccessibilityText(String::from("parola: hunter2")),
            RawPayload::ClipboardText(String::from("4111 1111 1111 1111")),
        ] {
            let cap = match &payload {
                RawPayload::AccessibilityText(s) | RawPayload::ClipboardText(s) => s.capacity(),
                RawPayload::ScreenFrame { .. } => unreachable!(),
            };
            payload.zeroize();
            match &payload {
                RawPayload::AccessibilityText(s) | RawPayload::ClipboardText(s) => {
                    assert!(s.is_empty());
                    assert_eq!(s.capacity(), cap);
                }
                RawPayload::ScreenFrame { .. } => unreachable!(),
            }
        }
    }

    #[test]
    fn screen_frame_zeroize_wipes_pixels_and_dimensions() {
        let mut payload = RawPayload::ScreenFrame {
            width: 2,
            height: 2,
            pixels_rgba: vec![0xAB; 16],
        };
        payload.zeroize();
        match &payload {
            RawPayload::ScreenFrame {
                width,
                height,
                pixels_rgba,
            } => {
                assert_eq!((*width, *height), (0, 0));
                assert!(pixels_rgba.is_empty());
                assert_eq!(pixels_rgba.capacity(), 16);
            }
            _ => panic!("payload variant changed"),
        }
    }

    #[test]
    fn drop_runs_without_panic_for_every_variant() {
        drop(packet(RawPayload::AccessibilityText(String::from("a"))));
        drop(packet(RawPayload::ClipboardText(String::from("b"))));
        drop(packet(RawPayload::ScreenFrame {
            width: 1,
            height: 1,
            pixels_rgba: vec![1, 2, 3, 4],
        }));
        // Paketten bağımsız yük de kendi Drop'uyla silinir.
        drop(RawPayload::ClipboardText(String::from("c")));
    }

    #[test]
    fn event_source_is_fieldless_one_byte() {
        // Alan eklenirse (ör. içerik taşıyan bir varyant) boyut büyür ve test kırılır.
        assert_eq!(std::mem::size_of::<EventSource>(), 1);
        assert_eq!(std::mem::size_of::<Option<EventSource>>(), 1);
    }

    #[test]
    fn event_source_db_code_round_trips_and_is_stable() {
        let codes: Vec<&str> = EventSource::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(codes, ["focus", "clipboard", "accessibility", "visual"]);
        for s in EventSource::ALL {
            assert_eq!(EventSource::parse(s.as_str()), Some(s));
        }
        assert_eq!(EventSource::parse(""), None);
        assert_eq!(EventSource::parse("Clipboard"), None);
    }

    #[test]
    fn event_source_from_event_kind_covers_every_variant() {
        let cases = [
            (EventKind::WindowFocusChanged, EventSource::Focus),
            (
                EventKind::AccessibilityTreeChanged { node_count: 7 },
                EventSource::Accessibility,
            ),
            (
                EventKind::VisualDifferenceDetected { phash_distance: 9 },
                EventSource::Visual,
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(EventSource::from(&kind), expected);
        }
        for format in [
            ClipboardFormat::PlainText,
            ClipboardFormat::RichText,
            ClipboardFormat::ImageBitmap,
            ClipboardFormat::FileDropList,
            ClipboardFormat::IgnoredFormat,
        ] {
            let kind = EventKind::ClipboardCopied { format };
            assert_eq!(EventSource::from(&kind), EventSource::Clipboard);
        }
    }

    #[test]
    fn event_kind_metadata_is_loggable() {
        let k = EventKind::ClipboardCopied {
            format: ClipboardFormat::IgnoredFormat,
        };
        assert_eq!(
            format!("{k:?}"),
            "ClipboardCopied { format: IgnoredFormat }"
        );
    }
}
