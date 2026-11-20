//! # s-guard — Zero-Trust In-Memory Security Gate (Katman 2)
//!
//! Sahibi: `zero-trust-guard`.
//! Girdi: `Receiver<RawCapturePacket>` · Çıktı: `Sender<MaskedMemoryBlock>`.
//!
//! Akış (`process`):
//! 1. Kara liste (süreç adı, parola yöneticisi başlığı, gizli pencere, hassas dosya,
//!    yok sayılan pano biçimi) -> `Verdict::Dropped`.
//! 2. Pencere başlığı ve metin payload'ı scrubber'dan geçer (`[REDACTED_<TÜR>]`).
//! 3. `ScreenFrame`: Sprint 1'de OCR yok; metin boş, pikseller `zeroize`.
//! 4. Ham kopyalar (başlık, süreç adı, payload, katlanmış geçici stringler) her
//!    çıkış yolunda `zeroize` edilir.
//!
//! Hiçbir log/panic mesajı ham içerik taşımaz; bu crate hiçbir şey loglamaz.
//!
//! # Veritabanı anahtarı kullanım kılavuzu
//!
//! 256-bit DB anahtarı bellekte mümkün olduğunca az kopyalanmalıdır. `Zeroizing<[u8; 32]>`
//! DEĞERLE taşınırsa (fonksiyon dönüşü, `Option`/`Result` sarmalama) çağrı çerçevelerinde
//! bayat yığın kopyaları kalabilir (Gate 2 bulgusu). Önerilen akış:
//!
//! ```no_run
//! use s_guard::DbKey;
//!
//! # fn run(blob_on_disk: Option<Vec<u8>>) -> s_guard::Result<()> {
//! // İlk çalıştırma: yeni anahtar üret, DPAPI ile sar, blob'u (anahtarı değil) diske yaz.
//! // Sonraki çalıştırmalar: blob'dan yükle. Anahtar heap'te tek kutuda yerinde yazılır.
//! let key = match blob_on_disk {
//!     Some(blob) => DbKey::load(&blob)?,
//!     None => {
//!         let key = DbKey::generate();
//!         let _blob_to_persist = key.protect()?; // dosya I/O çağıranın işi
//!         key
//!     }
//! };
//! // Yalnızca ödünç erişim: `&[u8; 32]` ver (örn. SQLCipher raw key hex'i `Zeroizing`
//! // bir String'e yazılır). `*key.expose()` ile `[u8; 32]` değerine KOPYALAMAYIN.
//! let _borrowed: &[u8; 32] = key.expose();
//! # Ok(()) }
//! ```
//!
//! Kutu kullanılamıyorsa çağıranın kendi (tercihen `Zeroizing`, tek yerde yaşayan)
//! tamponuna yazan [`generate_db_key_into`] / [`unprotect_key_into`] kullanılır.
//! Değerle dönen `generate_db_key` / `unprotect_key` `#[deprecated]` durumdadır.
//! `DbKey` ve DPAPI tamponu (`LocalFree` öncesi) Drop'ta sıfırlanır; `DbKey` bilinçli
//! olarak `Clone`/`Copy`/`Debug` değildir. Dosya I/O `s-guard`'da değil, çağıranda.

mod blacklist;
mod dpapi;
mod normalize;
mod scrub;
mod stats;
mod typeparse;
mod wipe;

use s_types::{AppContext, ClipboardFormat, EventKind, EventSource, RawPayload};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub use dpapi::{DbKey, GuardError, Result, generate_db_key_into, protect_key, unprotect_key_into};
#[allow(deprecated)]
pub use dpapi::{generate_db_key, unprotect_key};
pub use s_types::{MaskedMemoryBlock, RawCapturePacket};
pub use stats::{GuardStats, GuardStatsSnapshot, UserBlocklist};

use stats::Outcome;
use std::sync::Arc;

/// Paket neden düşürüldü (ham içerik taşımaz).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    BlacklistedProcess,
    PrivateWindow,
    SensitiveFile,
    IgnoredFormat,
}

/// Güvenlik kapısı kararı.
#[derive(Debug)]
pub enum Verdict {
    Dropped(DropReason),
    Masked(MaskedMemoryBlock),
}

/// Paketten sökülen ham kopyalar; her çıkış yolunda (panik dahil) sıfırlanır.
struct Held {
    process_name: String,
    window_title: String,
    payload: RawPayload,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.process_name.zeroize();
        self.window_title.zeroize();
        match &mut self.payload {
            RawPayload::AccessibilityText(s) | RawPayload::ClipboardText(s) => s.zeroize(),
            RawPayload::ScreenFrame { pixels_rgba, .. } => pixels_rgba.zeroize(),
        }
    }
}

/// Senkron, saf, test edilebilir. Paketi tüketir; drop'ta zeroize olur.
pub fn process(packet: RawCapturePacket, event_id: u64) -> Verdict {
    evaluate(packet, event_id, None, &mut Outcome::default())
}

/// Kullanıcı kara listesiyle `process`: listedeki bir süreçten gelen paket
/// `DropReason::BlacklistedProcess` ile düşer (redteam sözleşmesi `DropReason`'ı
/// kapalı eşlediğinden yeni varyant eklenmedi; ayrım için [`GuardStats::user_blocked`]).
pub fn process_with_blocklist(
    packet: RawCapturePacket,
    event_id: u64,
    blocklist: &UserBlocklist,
) -> Verdict {
    evaluate(packet, event_id, Some(blocklist), &mut Outcome::default())
}

/// Ham paketi değerlendirir; ham içerik işleyen çağrı zinciri döndükten sonra yığın
/// kalıntısı ezilir (bkz. `wipe`).
fn evaluate(
    packet: RawCapturePacket,
    event_id: u64,
    blocklist: Option<&UserBlocklist>,
    outcome: &mut Outcome,
) -> Verdict {
    scrub::warm_up_thread();
    let verdict = evaluate_inner(packet, event_id, blocklist, outcome);
    wipe::wipe_stack();
    verdict
}

fn evaluate_inner(
    mut packet: RawCapturePacket,
    event_id: u64,
    blocklist: Option<&UserBlocklist>,
    outcome: &mut Outcome,
) -> Verdict {
    // `RawCapturePacket: Drop` olduğundan alanlar taşınamaz; `take`/`replace` ile alınır,
    // geride kalan boş paket drop'ta zaten sıfırlanır.
    let timestamp_ms = packet.timestamp_ms;
    let source = EventSource::from(&packet.event_kind);
    let ignored_format = matches!(
        &packet.event_kind,
        EventKind::ClipboardCopied {
            format: ClipboardFormat::IgnoredFormat
        }
    );
    let file_drop_list = matches!(
        &packet.event_kind,
        EventKind::ClipboardCopied {
            format: ClipboardFormat::FileDropList
        }
    );
    let held = Held {
        process_name: std::mem::take(&mut packet.process_name),
        window_title: std::mem::take(&mut packet.window_title),
        payload: std::mem::replace(
            &mut packet.raw_payload,
            RawPayload::AccessibilityText(String::new()),
        ),
    };
    drop(packet);

    if blacklist::is_blacklisted_process(&held.process_name)
        || blacklist::title_names_password_manager(&held.window_title)
    {
        return Verdict::Dropped(DropReason::BlacklistedProcess);
    }
    if blocklist.is_some_and(|bl| bl.is_blocked(&held.process_name)) {
        outcome.user_blocked = true;
        return Verdict::Dropped(DropReason::BlacklistedProcess);
    }
    if blacklist::is_private_window(&held.window_title) {
        return Verdict::Dropped(DropReason::PrivateWindow);
    }
    let payload_names_sensitive_file = file_drop_list
        && matches!(&held.payload, RawPayload::ClipboardText(t) if blacklist::mentions_sensitive_file(t));
    if blacklist::mentions_sensitive_file(&held.window_title) || payload_names_sensitive_file {
        return Verdict::Dropped(DropReason::SensitiveFile);
    }
    if ignored_format {
        return Verdict::Dropped(DropReason::IgnoredFormat);
    }

    let (sanitized_title, title_kinds) = scrub::scrub_kinds(&held.window_title);
    let (process_name, name_kinds) = scrub::scrub_kinds(&held.process_name);
    let is_browser = blacklist::is_browser(&held.process_name);

    let (clean_text, text_kinds) = match &held.payload {
        RawPayload::AccessibilityText(t) | RawPayload::ClipboardText(t) => scrub::scrub_kinds(t),
        // Sprint 1: OCR yok. Pikseller `Held::drop` ile sıfırlanır.
        RawPayload::ScreenFrame { .. } => (String::new(), Vec::new()),
    };

    let total = title_kinds.len() + name_kinds.len() + text_kinds.len();
    outcome.kinds.extend(title_kinds);
    outcome.kinds.extend(name_kinds);
    outcome.kinds.extend(text_kinds);
    let text_hash: [u8; 32] = Sha256::digest(clean_text.as_bytes()).into();
    let has_embedding_payload = !clean_text.trim().is_empty();

    Verdict::Masked(MaskedMemoryBlock {
        event_id,
        timestamp_ms,
        app_context: AppContext {
            process_name,
            sanitized_title,
            is_browser,
        },
        clean_text,
        text_hash,
        redactions_count: u16::try_from(total).unwrap_or(u16::MAX),
        has_embedding_payload,
        source,
    })
}

/// Asenkron hat: rx'ten okur, Masked olanları tx'e yollar. `event_id` 0'dan başlar.
///
/// Ayrıntı ve sonlanma koşulları için [`run_with_start_id`].
pub async fn run(
    rx: tokio::sync::mpsc::Receiver<RawCapturePacket>,
    tx: tokio::sync::mpsc::Sender<MaskedMemoryBlock>,
) {
    run_with_start_id(rx, tx, 0).await;
}

/// `run` ile aynı; `event_id` sayacı `start_id`'den başlar (ör. `store.next_event_id()`).
///
/// Regex taraması CPU-bound olduğundan `spawn_blocking` ile yürütülür; sıra korunur.
/// Her paket (düşürülenler dahil) bir `event_id` tüketir. Düşürülen paketler ve işleme
/// paniği yaşayan paketler (fail-closed) sessizce atılır.
///
/// Hat şu durumlarda sonlanır: `rx` kapanıp boşalırsa, `tx` kapanırsa veya `event_id`
/// sayacı taşarsa (`u64::MAX` kullanıldıktan sonra yeni paket okunmaz, paket üretilmez,
/// panik yoktur; `event_id` asla yinelenmez/sarılmaz).
pub async fn run_with_start_id(
    rx: tokio::sync::mpsc::Receiver<RawCapturePacket>,
    tx: tokio::sync::mpsc::Sender<MaskedMemoryBlock>,
    start_id: u64,
) {
    pipeline(rx, tx, start_id, None, None).await;
}

/// `run_with_start_id` + sayaçlar: her paket için [`GuardStats`] güncellenir (yalnızca
/// sayı; içerik, süreç adı veya başlık tutulmaz). İşleme paniği yaşayan paket sayılmaz.
pub async fn run_with_stats(
    rx: tokio::sync::mpsc::Receiver<RawCapturePacket>,
    tx: tokio::sync::mpsc::Sender<MaskedMemoryBlock>,
    start_id: u64,
    stats: Arc<GuardStats>,
) {
    pipeline(rx, tx, start_id, Some(stats), None).await;
}

/// `run_with_stats` + çalışma anında değişebilen [`UserBlocklist`]: listedeki süreçlerden
/// gelen paketler (`DropReason::BlacklistedProcess` ile) düşer, hiçbir içerik taranmaz.
/// Liste her pakette okunur; `add`/`remove` bir sonraki pakette etkili olur.
pub async fn run_with_options(
    rx: tokio::sync::mpsc::Receiver<RawCapturePacket>,
    tx: tokio::sync::mpsc::Sender<MaskedMemoryBlock>,
    start_id: u64,
    stats: Arc<GuardStats>,
    blocklist: Arc<UserBlocklist>,
) {
    pipeline(rx, tx, start_id, Some(stats), Some(blocklist)).await;
}

async fn pipeline(
    mut rx: tokio::sync::mpsc::Receiver<RawCapturePacket>,
    tx: tokio::sync::mpsc::Sender<MaskedMemoryBlock>,
    start_id: u64,
    stats: Option<Arc<GuardStats>>,
    blocklist: Option<Arc<UserBlocklist>>,
) {
    let mut next_event_id = Some(start_id);
    while let Some(event_id) = next_event_id {
        let Some(packet) = rx.recv().await else {
            break;
        };
        next_event_id = event_id.checked_add(1);
        let stats = stats.clone();
        let blocklist = blocklist.clone();
        let verdict = tokio::task::spawn_blocking(move || {
            let mut outcome = Outcome::default();
            let verdict = evaluate(packet, event_id, blocklist.as_deref(), &mut outcome);
            if let Some(stats) = &stats {
                stats.record(&verdict, &outcome);
            }
            verdict
        })
        .await;
        if let Ok(Verdict::Masked(block)) = verdict
            && tx.send(block).await.is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn pkt(process: &str, title: &str, payload: RawPayload, kind: EventKind) -> RawCapturePacket {
        RawCapturePacket {
            timestamp_ms: 42,
            process_id: 7,
            process_name: process.to_owned(),
            window_title: title.to_owned(),
            event_kind: kind,
            raw_payload: payload,
        }
    }

    fn text_pkt(process: &str, title: &str, text: &str) -> RawCapturePacket {
        pkt(
            process,
            title,
            RawPayload::AccessibilityText(text.to_owned()),
            EventKind::AccessibilityTreeChanged { node_count: 3 },
        )
    }

    fn clip_pkt(format: ClipboardFormat, text: &str) -> RawCapturePacket {
        pkt(
            "notepad.exe",
            "Untitled",
            RawPayload::ClipboardText(text.to_owned()),
            EventKind::ClipboardCopied { format },
        )
    }

    fn masked(v: Verdict) -> MaskedMemoryBlock {
        match v {
            Verdict::Masked(b) => b,
            Verdict::Dropped(r) => panic!("beklenmeyen drop: {r:?}"),
        }
    }

    fn dropped(v: Verdict) -> DropReason {
        match v {
            Verdict::Dropped(r) => r,
            Verdict::Masked(_) => panic!("drop bekleniyordu"),
        }
    }

    #[test]
    fn blacklisted_processes_dropped() {
        for p in [
            "1Password.exe",
            "bitwarden.exe",
            "KeePassXC.exe",
            "LASTPASS.EXE",
        ] {
            let v = process(text_pkt(p, "x", "hello"), 1);
            assert_eq!(dropped(v), DropReason::BlacklistedProcess, "{p}");
        }
    }

    #[test]
    fn password_manager_title_dropped() {
        let v = process(
            text_pkt("chrome.exe", "Vault | Bitwarden - Google Chrome", "x"),
            1,
        );
        assert_eq!(dropped(v), DropReason::BlacklistedProcess);
    }

    #[test]
    fn evasion_resistant_blacklist() {
        let cases: [(&str, &str, DropReason); 5] = [
            (
                "chrome.exe",
                "New Tab - Incog\u{200B}nito",
                DropReason::PrivateWindow,
            ),
            (
                "1Pass\u{200B}word.exe",
                "Vault",
                DropReason::BlacklistedProcess,
            ),
            (
                "msedge.exe",
                "Bank - \u{0406}nPr\u{0456}vate",
                DropReason::PrivateWindow,
            ),
            (
                "notepad.exe",
                "\u{FF0E}env - Notepad",
                DropReason::SensitiveFile,
            ),
            (
                "notepad.exe",
                "\u{FF49}\u{FF44}_rsa",
                DropReason::SensitiveFile,
            ),
        ];
        for (p, t, want) in cases {
            assert_eq!(dropped(process(text_pkt(p, t, "x"), 1)), want, "{p} / {t}");
        }
    }

    #[test]
    fn private_windows_dropped() {
        for t in [
            "New Tab - Google Chrome (Incognito)",
            "Microsoft Edge - InPrivate",
            "Mozilla Firefox Private Browsing",
            "gizli sekme",
        ] {
            let v = process(text_pkt("msedge.exe", t, "hello"), 1);
            assert_eq!(dropped(v), DropReason::PrivateWindow, "{t}");
        }
    }

    #[test]
    fn sensitive_file_titles_dropped() {
        for t in [".env - Notepad", "server.pem", "my.key", "id_rsa - VS Code"] {
            let v = process(text_pkt("code.exe", t, "hello"), 1);
            assert_eq!(dropped(v), DropReason::SensitiveFile, "{t}");
        }
    }

    #[test]
    fn file_drop_list_with_sensitive_file_dropped() {
        let v = process(
            clip_pkt(
                ClipboardFormat::FileDropList,
                "C:\\proj\\.env\r\nC:\\proj\\a.txt",
            ),
            1,
        );
        assert_eq!(dropped(v), DropReason::SensitiveFile);
        // Düz metin panoda ".env" geçmesi tek başına DROP nedeni değildir.
        let b = masked(process(
            clip_pkt(ClipboardFormat::PlainText, "dotfile .env docs"),
            1,
        ));
        assert!(b.clean_text.contains(".env"));
    }

    #[test]
    fn ignored_format_dropped() {
        let v = process(clip_pkt(ClipboardFormat::IgnoredFormat, "anything"), 1);
        assert_eq!(dropped(v), DropReason::IgnoredFormat);
    }

    #[test]
    fn blacklist_takes_precedence_over_payload() {
        // Parola yöneticisi + kredi kartı içeren payload: Masked değil Dropped.
        let v = process(text_pkt("1password.exe", "t", "4111111111111111"), 1);
        assert!(matches!(v, Verdict::Dropped(_)));
    }

    #[test]
    fn masks_text_payload_and_sets_metadata() {
        let p = text_pkt(
            "Chrome.exe",
            "Checkout - a@b.com",
            "kart 4111 1111 1111 1111 mail user@example.com tc 10000000146",
        );
        let b = masked(process(p, 99));
        assert_eq!(b.event_id, 99);
        assert_eq!(b.timestamp_ms, 42);
        assert_eq!(
            b.clean_text,
            "kart [REDACTED_CREDIT_CARD] mail [REDACTED_EMAIL] tc [REDACTED_TC_KIMLIK]"
        );
        assert_eq!(b.app_context.sanitized_title, "Checkout - [REDACTED_EMAIL]");
        assert_eq!(b.app_context.process_name, "Chrome.exe");
        assert!(b.app_context.is_browser);
        assert_eq!(b.redactions_count, 4);
        assert!(b.has_embedding_payload);
    }

    #[test]
    fn non_browser_and_clean_text() {
        let b = masked(process(text_pkt("code.exe", "main.rs", "fn main() {}"), 1));
        assert!(!b.app_context.is_browser);
        assert_eq!(b.clean_text, "fn main() {}");
        assert_eq!(b.redactions_count, 0);
    }

    #[test]
    fn text_hash_is_hash_of_masked_text_not_raw() {
        let raw = "card 4111111111111111";
        let b = masked(process(text_pkt("code.exe", "t", raw), 1));
        let expected: [u8; 32] = Sha256::digest(b"card [REDACTED_CREDIT_CARD]").into();
        assert_eq!(b.text_hash, expected);
        let raw_hash: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        assert_ne!(b.text_hash, raw_hash);
    }

    #[test]
    fn identical_masked_text_gives_identical_hash() {
        let a = masked(process(text_pkt("a.exe", "t", "x 4111111111111111"), 1));
        let b = masked(process(text_pkt("a.exe", "t", "x 5555555555554444"), 2));
        assert_eq!(a.text_hash, b.text_hash);
    }

    #[test]
    fn screen_frame_has_no_text_and_no_embedding() {
        let p = pkt(
            "game.exe",
            "Canvas",
            RawPayload::ScreenFrame {
                width: 2,
                height: 2,
                pixels_rgba: vec![255; 16],
            },
            EventKind::VisualDifferenceDetected { phash_distance: 9 },
        );
        let b = masked(process(p, 5));
        assert!(b.clean_text.is_empty());
        assert!(!b.has_embedding_payload);
        assert_eq!(b.redactions_count, 0);
        let empty_hash: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(b.text_hash, empty_hash);
    }

    #[test]
    fn screen_frame_from_blacklisted_process_dropped() {
        let p = pkt(
            "keepass.exe",
            "t",
            RawPayload::ScreenFrame {
                width: 1,
                height: 1,
                pixels_rgba: vec![1, 2, 3, 4],
            },
            EventKind::VisualDifferenceDetected { phash_distance: 1 },
        );
        assert!(matches!(process(p, 1), Verdict::Dropped(_)));
    }

    #[test]
    fn output_contains_no_raw_secret() {
        let secrets = [
            "4111111111111111",
            "10000000146",
            "123-45-6789",
            "user@example.com",
            "hunter2",
        ];
        let text = format!(
            "{} {} {} {} password={}",
            secrets[0], secrets[1], secrets[2], secrets[3], secrets[4]
        );
        let b = masked(process(
            text_pkt("x.exe", &format!("t {}", secrets[3]), &text),
            1,
        ));
        for s in secrets {
            assert!(!b.clean_text.contains(s), "{s}");
            assert!(!b.app_context.sanitized_title.contains(s), "{s}");
        }
        // Debug çıktısı da ham sır taşımaz.
        let dbg = format!("{b:?}");
        for s in secrets {
            assert!(!dbg.contains(s), "{s}");
        }
    }

    #[test]
    fn redactions_count_saturates() {
        let text = "a@b.com ".repeat(70_000);
        let b = masked(process(text_pkt("x.exe", "t", &text), 1));
        assert_eq!(b.redactions_count, u16::MAX);
    }

    #[test]
    fn drop_verdict_debug_has_no_content() {
        let v = process(text_pkt("1password.exe", "secret-title", "secret-body"), 1);
        let dbg = format!("{v:?}");
        assert_eq!(dbg, "Dropped(BlacklistedProcess)");
    }

    #[tokio::test]
    async fn run_pipeline_forwards_masked_and_skips_dropped() {
        let (in_tx, in_rx) = mpsc::channel(s_types::SENSOR_CHANNEL_CAPACITY);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let task = tokio::spawn(run(in_rx, out_tx));

        in_tx
            .send(text_pkt("code.exe", "a", "one 4111111111111111"))
            .await
            .ok();
        in_tx
            .send(text_pkt("1password.exe", "b", "dropped"))
            .await
            .ok();
        in_tx
            .send(text_pkt("msedge.exe", "InPrivate", "dropped"))
            .await
            .ok();
        in_tx.send(text_pkt("code.exe", "c", "two")).await.ok();
        drop(in_tx);

        let first = out_rx.recv().await.expect("first block");
        let second = out_rx.recv().await.expect("second block");
        assert!(out_rx.recv().await.is_none());
        task.await.expect("run joins");

        assert_eq!(first.clean_text, "one [REDACTED_CREDIT_CARD]");
        assert_eq!(second.clean_text, "two");
        assert!(first.event_id < second.event_id);
    }

    #[tokio::test]
    async fn run_stops_when_output_closed() {
        let (in_tx, in_rx) = mpsc::channel(4);
        let (out_tx, out_rx) = mpsc::channel(1);
        drop(out_rx);
        let task = tokio::spawn(run(in_rx, out_tx));
        in_tx.send(text_pkt("code.exe", "a", "x")).await.ok();
        task.await.expect("run terminates after tx closed");
    }

    #[tokio::test]
    async fn run_with_start_id_offsets_event_ids() {
        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let task = tokio::spawn(run_with_start_id(in_rx, out_tx, 1000));
        in_tx.send(text_pkt("code.exe", "a", "one")).await.ok();
        in_tx
            .send(text_pkt("1password.exe", "b", "dropped"))
            .await
            .ok();
        in_tx.send(text_pkt("code.exe", "c", "two")).await.ok();
        drop(in_tx);
        let first = out_rx.recv().await.expect("first");
        let second = out_rx.recv().await.expect("second");
        task.await.expect("joins");
        assert_eq!(first.event_id, 1000);
        // Düşürülen paket de bir id tüketir.
        assert_eq!(second.event_id, 1002);
    }

    #[tokio::test]
    async fn run_with_start_id_stops_on_overflow_without_panic() {
        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let task = tokio::spawn(run_with_start_id(in_rx, out_tx, u64::MAX - 1));
        for _ in 0..4 {
            in_tx.send(text_pkt("code.exe", "a", "x")).await.ok();
        }
        let a = out_rx.recv().await.expect("MAX-1");
        let b = out_rx.recv().await.expect("MAX");
        // Sayaç taştı: hat sonlanır, başka blok üretilmez, görev paniksiz biter.
        task.await.expect("run terminates without panic");
        assert!(out_rx.recv().await.is_none());
        assert_eq!((a.event_id, b.event_id), (u64::MAX - 1, u64::MAX));
    }

    fn drops(snap: &GuardStatsSnapshot, reason: DropReason) -> u64 {
        snap.dropped
            .iter()
            .find(|(r, _)| *r == reason)
            .map_or(0, |&(_, n)| n)
    }

    fn reds(snap: &GuardStatsSnapshot, name: &str) -> u64 {
        snap.redactions
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(0, |&(_, c)| c)
    }

    #[tokio::test]
    async fn stats_count_drops_and_redaction_kinds_without_content() {
        let (in_tx, in_rx) = mpsc::channel(16);
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let stats = GuardStats::new();
        let task = tokio::spawn(run_with_stats(in_rx, out_tx, 5, Arc::clone(&stats)));

        let sends = [
            text_pkt(
                "code.exe",
                "t",
                "mail a@b.com card 4111111111111111 and 5555555555554444",
            ),
            text_pkt("1password.exe", "t", "x"),
            text_pkt("msedge.exe", "InPrivate", "x"),
            text_pkt("code.exe", ".env", "x"),
            clip_pkt(ClipboardFormat::IgnoredFormat, "x"),
            text_pkt("code.exe", "t", "password=hunter2xyz tc 10000000146"),
            text_pkt("code.exe", "t", "plain"),
        ];
        for p in sends {
            in_tx.send(p).await.ok();
        }
        drop(in_tx);
        let mut ids = Vec::new();
        while let Some(b) = out_rx.recv().await {
            ids.push(b.event_id);
        }
        task.await.expect("joins");
        assert_eq!(ids, [5, 10, 11]);

        let snap = stats.snapshot();
        assert_eq!(snap.processed, 7);
        assert_eq!(drops(&snap, DropReason::BlacklistedProcess), 1);
        assert_eq!(drops(&snap, DropReason::PrivateWindow), 1);
        assert_eq!(drops(&snap, DropReason::SensitiveFile), 1);
        assert_eq!(drops(&snap, DropReason::IgnoredFormat), 1);
        assert_eq!(reds(&snap, "EMAIL"), 1);
        assert_eq!(reds(&snap, "CREDIT_CARD"), 2);
        assert_eq!(reds(&snap, "PASSWORD"), 1);
        assert_eq!(reds(&snap, "TC_KIMLIK"), 1);
        assert_eq!(reds(&snap, "JWT"), 0);
        assert_eq!(stats.user_blocked(), 0);
        // Yalnızca sayı: Debug çıktısı içerik/ad taşımaz.
        let dbg = format!("{snap:?}{stats:?}");
        for needle in [
            "hunter2",
            "4111",
            "a@b.com",
            "1password",
            "msedge",
            "InPrivate",
        ] {
            assert!(!dbg.contains(needle), "{needle}");
        }
    }

    #[tokio::test]
    async fn user_blocklist_drops_at_runtime_and_is_counted() {
        let (in_tx, in_rx) = mpsc::channel(16);
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let stats = GuardStats::new();
        let blocklist = UserBlocklist::new();
        let task = tokio::spawn(run_with_options(
            in_rx,
            out_tx,
            0,
            Arc::clone(&stats),
            Arc::clone(&blocklist),
        ));

        in_tx
            .send(text_pkt("Spotify.exe", "song", "lyrics"))
            .await
            .ok();
        let first = out_rx.recv().await.expect("not yet blocked");
        assert_eq!(first.app_context.process_name, "Spotify.exe");

        blocklist.add("spotify.EXE");
        in_tx
            .send(text_pkt("Spotify.exe", "song", "lyrics"))
            .await
            .ok();
        in_tx
            .send(text_pkt("Sp\u{200B}otify.exe", "song", "x"))
            .await
            .ok();
        in_tx.send(text_pkt("code.exe", "t", "kept")).await.ok();
        let kept = out_rx.recv().await.expect("other app kept");
        assert_eq!(kept.clean_text, "kept");
        assert_eq!(kept.event_id, 3);

        blocklist.remove("SPOTIFY");
        in_tx
            .send(text_pkt("Spotify.exe", "song", "again"))
            .await
            .ok();
        let again = out_rx.recv().await.expect("unblocked");
        assert_eq!(again.clean_text, "again");
        drop(in_tx);
        task.await.expect("joins");

        let snap = stats.snapshot();
        assert_eq!(snap.processed, 5);
        assert_eq!(drops(&snap, DropReason::BlacklistedProcess), 2);
        assert_eq!(stats.user_blocked(), 2);
    }

    #[test]
    fn user_blocklist_does_not_affect_plain_process() {
        let bl = UserBlocklist::new();
        bl.add("code.exe");
        let v = process_with_blocklist(text_pkt("code.exe", "t", "4111111111111111"), 1, &bl);
        assert_eq!(dropped(v), DropReason::BlacklistedProcess);
        let v = process(text_pkt("code.exe", "t", "hello"), 1);
        assert!(matches!(v, Verdict::Masked(_)));
    }
}
