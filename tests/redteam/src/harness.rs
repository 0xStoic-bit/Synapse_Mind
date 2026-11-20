//! Sızıntı dedektörü: `MaskedMemoryBlock` alanlarında orijinal sırların alt dizgilerini arar.
//!
//! Bu modül yalnızca `s-types`'a bağlıdır; guard API'sinden bağımsızdır.
//!
//! Yöntem: her iğne (needle) için `min_window` (varsayılan 6, `REDTEAM_MIN_WINDOW` ile
//! değiştirilebilir) uzunluğundaki TÜM kayan pencereler hesaplanır ve iki biçimde aranır:
//!  1. "katlanmış ham": küçük harf + tam genişlik->ASCII (noktalama ve boşluklar korunur),
//!  2. "yalnızca alfanümerik": her şey (boşluk, tire, sıfır genişlik, satır sonu...) atılır;
//!     böylece yeniden biçimlendirilmiş / bölünmüş kalıntılar da yakalanır.

use crate::vectors::Vector;
use s_types::MaskedMemoryBlock;

pub fn min_window() -> usize {
    std::env::var("REDTEAM_MIN_WINDOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n >= 4)
        .unwrap_or(6)
}

#[derive(Debug, Clone)]
pub struct Leak {
    pub vector: String,
    pub field: &'static str,
    /// Sızan ilk pencere (sentetik veri; raporlama için).
    pub window: String,
    /// Eşleşen tüm benzersiz pencereler.
    pub windows: Vec<String>,
    /// Toplam kaç farklı pencere eşleşti (sızıntı hacminin kaba ölçüsü).
    pub windows_hit: usize,
}

impl std::fmt::Display for Leak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LEAK vector={} field={} window={:?} windows={:?} windows_hit={}",
            self.vector, self.field, self.window, self.windows, self.windows_hit
        )
    }
}

fn fold_char(c: char) -> impl Iterator<Item = char> {
    let c = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        char::from_u32(c as u32 - 0xFEE0).unwrap()
    } else {
        c
    };
    c.to_lowercase()
}

/// Maske etiketi (`[REDACTED_<TÜR>]`) yerine geçen bariyer karakteri.
const TAG_BARRIER: char = '\u{E000}';

/// `[REDACTED_<A-Z_>+]` etiketlerini bariyer karakteriyle değiştirir. Etiketler guard'ın
/// ürettiği sabit metindir (içinde sır olamaz). `EMAIL`/`API_KEY` gibi sözcüklerin ve
/// etiketin bitişiğindeki sözcüklerin birleşip sahte pencere üretmesi engellenir.
/// Etiket dışındaki hiçbir karakter dışarıda bırakılmaz.
fn mask_tags_to_barrier(s: &str) -> String {
    const OPEN: &str = "[REDACTED_";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(OPEN) {
        let after = &rest[i + OPEN.len()..];
        let kind_len = after
            .bytes()
            .take_while(|b| b.is_ascii_uppercase() || *b == b'_')
            .count();
        if kind_len > 0 && after.as_bytes().get(kind_len) == Some(&b']') {
            out.push_str(&rest[..i]);
            out.push(TAG_BARRIER);
            rest = &after[kind_len + 1..];
        } else {
            out.push_str(&rest[..i + OPEN.len()]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Küçük harf + tam genişlik katlaması; diğer her karakter korunur.
fn fold(s: &str) -> Vec<char> {
    mask_tags_to_barrier(s)
        .chars()
        .flat_map(fold_char)
        .collect()
}

fn alnum_only(chars: &[char]) -> Vec<char> {
    chars
        .iter()
        .copied()
        .filter(|c| c.is_alphanumeric() || *c == TAG_BARRIER)
        .collect()
}

fn contains(hay: &[char], needle: &[char]) -> bool {
    needle.is_empty()
        || (hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle))
}

/// `field` içinde herhangi bir iğnenin `min` uzunluklu penceresi var mı?
/// Dönüş: (eşleşen benzersiz pencereler, toplam eşleşme sayısı).
pub fn find_leak(field: &str, needles: &[String], min: usize) -> Option<(Vec<String>, usize)> {
    let hay_raw = fold(field);
    let hay_alnum = alnum_only(&hay_raw);
    let mut found: Vec<String> = Vec::new();
    let mut hits = 0usize;
    for n in needles {
        let nraw = fold(n);
        let nalnum = alnum_only(&nraw);
        for (needle, hay) in [(&nraw, &hay_raw), (&nalnum, &hay_alnum)] {
            if needle.len() < min {
                continue;
            }
            for w in needle.windows(min) {
                // Yalnızca boşluk/ayırıcıdan oluşan pencereler anlamsızdır.
                if !w.iter().any(|c| c.is_alphanumeric()) {
                    continue;
                }
                if contains(hay, w) {
                    hits += 1;
                    let ws: String = w.iter().collect();
                    if !found.contains(&ws) {
                        found.push(ws);
                    }
                }
            }
        }
    }
    if found.is_empty() {
        None
    } else {
        Some((found, hits))
    }
}

/// Bloğun TÜM metin alanlarını (clean_text, sanitized_title, process_name) denetler.
pub fn check_block(v: &Vector, block: &MaskedMemoryBlock) -> Vec<Leak> {
    check_block_min(v, block, min_window())
}

/// `check_block` ile aynı, pencere uzunluğu açıkça verilir (çapraz-vektör kontrolü için).
pub fn check_block_min(v: &Vector, block: &MaskedMemoryBlock, min: usize) -> Vec<Leak> {
    let fields: [(&'static str, &str); 3] = [
        ("clean_text", &block.clean_text),
        (
            "app_context.sanitized_title",
            &block.app_context.sanitized_title,
        ),
        ("app_context.process_name", &block.app_context.process_name),
    ];
    fields
        .iter()
        .filter_map(|(name, val)| {
            find_leak(val, &v.needles, min).map(|(windows, windows_hit)| Leak {
                vector: v.id.clone(),
                field: name,
                window: windows[0].clone(),
                windows,
                windows_hit,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::{Tier, Vector};
    use s_types::{AppContext, EventSource};

    fn block(clean: &str, title: &str, proc_name: &str) -> MaskedMemoryBlock {
        MaskedMemoryBlock {
            event_id: 0,
            timestamp_ms: 0,
            app_context: AppContext {
                process_name: proc_name.into(),
                sanitized_title: title.into(),
                is_browser: false,
            },
            clean_text: clean.into(),
            text_hash: [0; 32],
            redactions_count: 0,
            has_embedding_payload: false,
            source: EventSource::Accessibility,
        }
    }

    fn vec_with(needle: &str) -> Vector {
        Vector::new("self-test", Tier::Core, "self").secret(needle)
    }

    // Dedektörün kendisi doğrulanır: kör (her şeyi geçiren) bir dedektör Gate 1'i boş geçerdi.

    #[test]
    fn detects_plain_leak_in_each_field() {
        let v = vec_with("sk_live_AbCdEfGhIjKlMnOp");
        let leaks = check_block(
            &v,
            &block(
                "x sk_live_AbCdEfGhIjKlMnOp",
                "t sk_live_AbCdEf",
                "sk_live_AbCdEfGh.exe",
            ),
        );
        let fields: Vec<_> = leaks.iter().map(|l| l.field).collect();
        assert_eq!(
            fields,
            [
                "clean_text",
                "app_context.sanitized_title",
                "app_context.process_name"
            ]
        );
    }

    #[test]
    fn detects_partial_suffix_leak() {
        // Maske yalnızca önekte uygulanmış, kuyruk açıkta kalmış.
        let v = vec_with("sk_live_AbCdEfGhIjKlMnOp");
        let leaks = check_block(&v, &block("[REDACTED_API_KEY]GhIjKlMnOp", "", ""));
        assert_eq!(leaks.len(), 1);
    }

    #[test]
    fn detects_case_and_reformatting() {
        let v = vec_with("4111111111111111");
        assert!(!check_block(&v, &block("4111 1111 1111 1111", "", "")).is_empty());
        assert!(!check_block(&v, &block("4111-1111\n1111-1111", "", "")).is_empty());
        let v = vec_with("AKIAABCDEFGHIJKLMNOP");
        assert!(!check_block(&v, &block("akiaabcdefghijklmnop", "", "")).is_empty());
        assert!(
            !check_block(&v, &block("AKIA\u{200B}ABCD\u{200B}EFGHIJKLMNOP", "", "")).is_empty()
        );
    }

    #[test]
    fn detects_fullwidth_remnant() {
        let v = vec_with("4111111111111111");
        assert!(!check_block(&v, &block("４１１１１１１１１１１１１１１１", "", "")).is_empty());
    }

    #[test]
    fn clean_masked_output_passes() {
        let v = vec_with("sk_live_AbCdEfGhIjKlMnOp");
        assert!(
            check_block(
                &v,
                &block(
                    "key [REDACTED_API_KEY] end",
                    "Project - Notepad",
                    "notepad.exe"
                )
            )
            .is_empty()
        );
        let v = vec_with("ayse.yilmaz@example.test");
        assert!(check_block(&v, &block("mail [REDACTED_EMAIL]", "", "")).is_empty());
    }

    #[test]
    fn mask_tag_words_do_not_form_false_windows() {
        // "[REDACTED_EMAIL] - Mail" alfanümerik birleşiminde "ilma"/"mail" sahte pencereleri oluşmamalı.
        let v = vec_with("ayse.yilmaz@example.test");
        assert!(find_leak("Inbox - [REDACTED_EMAIL] - Mail", &v.needles, 4).is_none());
    }

    #[test]
    fn mask_tag_does_not_hide_adjacent_leak() {
        // Etiketin bitişiğinde kalan gerçek kalıntı hâlâ yakalanır; etiket taklidi de bir şey gizlemez.
        let v = vec_with("sk_live_AbCdEfGhIjKlMnOp");
        assert!(find_leak("[REDACTED_API_KEY]AbCdEfGhIj", &v.needles, 6).is_some());
        assert!(find_leak("AbCdEf[REDACTED_API_KEY]", &v.needles, 6).is_some());
        assert!(find_leak("[REDACTED_x]sk_live_AbCdEf", &v.needles, 6).is_some());
    }

    #[test]
    fn short_fragments_below_window_are_ignored() {
        // 4 haneli kart sonu pencerenin (6) altında; kasıtlı politika (REDTEAM_MIN_WINDOW ile sıkılaştırılır).
        let v = vec_with("4111111111111111");
        assert!(check_block_min(&v, &block("**** **** **** 1111", "", ""), 6).is_empty());
    }
}
