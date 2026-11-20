#![allow(dead_code)] // ikili ve testler farkli alt kumeleri kullanir
//! Denetçi ikilisi ve testler arasında `#[path]` ile paylaşılan modül (lib'e DEĞİL, çünkü hedef
//! ikili `s-redteam`'e bağlanmamalı). Sentetik fixture üretimi ve rapor biçimlendirme.

use s_gate2::scan::{Enc, MIN_SECRET_CHARS, Part, Secret};
use s_gate2::session::SessionResult;
use s_gate2::spec::{
    KIND_ACCESSIBILITY, KIND_CLIPBOARD, KIND_CLIPBOARD_IGNORED, KIND_FRAME, PacketSpec,
};
use s_redteam::vectors::{PayloadKind, Tier, all_vectors};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Gate 1 vektörlerinden (Core + Evasion + Blacklist + Control + Stretch; yalnızca `accepted-*` ve FP sondaları hariç) tarifler ve aranacak sırlar.
pub fn fixture() -> (Vec<PacketSpec>, Vec<Secret>) {
    fixture_impl(false)
}

/// `fixture()` + guard'ın TAM maskelediği Stretch vektörleri (typeparse, iç içe/UTF-16 base64, çok satırlı kuyruk,
/// diceware...): guard'ın yeni kod yollarını bellek açısından da zorlar (`gate2-audit --wide`).
pub fn fixture_wide() -> (Vec<PacketSpec>, Vec<Secret>) {
    fixture_impl(true)
}

fn fixture_impl(wide: bool) -> (Vec<PacketSpec>, Vec<Secret>) {
    let mut specs = Vec::new();
    let mut secrets: Vec<Secret> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut benign = String::new(); // beslenen ZARARSIZ (korunan) metinler: sizinti sayilmamali
    for v in all_vectors() {
        if v.tier == Tier::Control {
            benign.push_str(&v.text.to_lowercase());
            benign.push('\n');
        }
        if v.tier == Tier::FpProbe || v.id.starts_with("accepted-") {
            continue;
        }
        if v.tier == Tier::Stretch && !wide {
            continue;
        }
        // Stretch vektörleri yalnızca guard onları TAM maskeliyorsa (sızıntı yoksa) fixture'a girer; çıktıda
        // zaten görünen (kabul edilen/açık) bir "sır" bellekte bulunursa bu bir bellek sızıntısı değildir.
        if v.tier == Tier::Stretch {
            let leaks = match s_guard::process(v.to_packet(1), 0) {
                s_guard::Verdict::Masked(b) => !s_redteam::harness::check_block(&v, &b).is_empty(),
                _ => false,
            };
            if leaks {
                continue;
            }
        }
        let kind = match v.payload {
            PayloadKind::Accessibility => KIND_ACCESSIBILITY,
            PayloadKind::Clipboard => KIND_CLIPBOARD,
            PayloadKind::Frame => KIND_FRAME,
            PayloadKind::ClipboardIgnored => KIND_CLIPBOARD_IGNORED,
        };
        for (n, needle) in v.needles.iter().enumerate() {
            if needle.chars().count() >= MIN_SECRET_CHARS && seen.insert(needle.clone()) {
                secrets.push(Secret::new(format!("{}#{n}", v.id), needle.clone()));
            }
        }
        specs.push(PacketSpec {
            kind,
            process_name: v.process_name.clone(),
            title: v.window_title.clone(),
            text: if kind == KIND_FRAME {
                String::new()
            } else {
                v.text.clone()
            },
        });
    }
    // Yanlis pozitif onleme: (1) 12 karakterlik penceresi beslenen zararsiz metinlerde gecen sirlar
    // (ornegin "correct_horse_battery" 3 sozcuklu kontrol metni), (2) hedef ikilinin KENDI imajinda
    // gecen dizgiler (alfabe/klavye dizileri: "abcdefghijklmnop") calisma zamani sizintisi degildir.
    let image = std::fs::read(target_exe()).unwrap_or_default();
    // Hedef imajında geçen parçalar (tam / orta / son 12 karakter) aho-corasick ile bir geçişte bulunur.
    let mut frag_owner: Vec<usize> = Vec::new();
    let mut frags: Vec<Vec<u8>> = Vec::new();
    for (i, sec) in secrets.iter().enumerate() {
        let chars: Vec<char> = sec.text.chars().collect();
        let mut parts = vec![sec.text.clone()];
        if chars.len() >= 24 {
            let mid = chars.len() / 2 - 6;
            parts.push(chars[mid..mid + 12].iter().collect());
            parts.push(chars[chars.len() - 12..].iter().collect());
        }
        for p in parts {
            frags.push(p.into_bytes());
            frag_owner.push(i);
        }
    }
    let mut in_image = BTreeSet::new();
    if !image.is_empty()
        && let Ok(ac) = aho_corasick::AhoCorasick::new(&frags)
    {
        for m in ac.find_overlapping_iter(&image) {
            in_image.insert(frag_owner[m.pattern().as_usize()]);
        }
    }
    let mut idx = 0usize;
    secrets.retain(|sec| {
        let me = idx;
        idx += 1;
        let chars: Vec<char> = sec.text.to_lowercase().chars().collect();
        let overlaps_benign = chars
            .windows(12)
            .any(|w| benign.contains(&w.iter().collect::<String>()));
        !(overlaps_benign || in_image.contains(&me))
    });
    (specs, secrets)
}

/// Deterministik SENTETİK test anahtarı (gerçek anahtar değil).
pub fn test_key() -> [u8; 32] {
    let mut r = s_redteam::synth::Rng::new(0x00D8_4BE7_2026_1119);
    let mut k = [0u8; 32];
    for chunk in k.chunks_mut(8) {
        chunk.copy_from_slice(&r.next_u64().to_le_bytes());
    }
    k
}

pub fn key_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Anahtar materyali: ham 32 bayt (+ hex küçük harf UTF-8/UTF-16LE), büyük harf hex, SQLCipher `x'hex'`.
pub fn key_secrets(key: &[u8; 32]) -> Vec<Secret> {
    let hex = key_hex(key);
    vec![
        Secret::key("db-key", key, hex.clone()),
        Secret::new("db-key-hex-upper", hex.to_uppercase()),
        Secret::new("db-key-pragma", format!("x'{hex}'")),
    ]
}

/// `gate2-target.exe` yolu: bu ikilinin/testin bulunduğu `target/<profil>` dizini (test için `deps`'in üstü).
pub fn target_exe() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_gate2-target") {
        return PathBuf::from(p);
    }
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop();
    if p.file_name().is_some_and(|n| n == "deps") {
        p.pop();
    }
    p.join("gate2-target.exe")
}

fn enc_name(e: Enc) -> &'static str {
    match e {
        Enc::Utf8 => "utf8",
        Enc::Utf16Le => "utf16le",
        Enc::Raw => "raw",
    }
}

fn part_name(p: Part) -> &'static str {
    match p {
        Part::Full => "full",
        Part::Mid => "mid",
        Part::Tail => "tail",
    }
}

/// Okunabilir tek-mod raporu. `baseline_ids`: taban modunda bulunan sır dizinleri (fark hesabı için).
pub fn render(
    r: &SessionResult,
    secrets: &[Secret],
    baseline_ids: Option<&BTreeSet<usize>>,
) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let any: BTreeSet<usize> = r.any_secret_ids().into_iter().collect();
    let full8 = r.full_secret_ids(Some(Enc::Utf8)).len();
    let full16 = r.full_secret_ids(Some(Enc::Utf16Le)).len();
    let _ = writeln!(
        s,
        "== mode={} [{}] dump={:.1} MiB searched_secrets={} hits={} unique_secrets_hit={} (full-utf8={full8} full-utf16le={full16})",
        r.mode,
        r.ready_line,
        r.dump_bytes as f64 / (1024.0 * 1024.0),
        r.secrets_searched,
        r.hits.len(),
        any.len()
    );
    let _ = writeln!(s, "   by_region: {:?}", r.by_region());
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for h in &r.hits {
        *by_kind
            .entry(format!("{}/{}", enc_name(h.enc), part_name(h.part)))
            .or_insert(0) += 1;
    }
    let _ = writeln!(s, "   by_enc/part: {by_kind:?}");
    if let Some(b) = baseline_ids {
        let extra: Vec<_> = any.difference(b).collect();
        let _ = writeln!(
            s,
            "   not_in_baseline={} (baseline_hit={})",
            extra.len(),
            b.len()
        );
        for &&i in extra.iter().take(12) {
            let _ = writeln!(s, "     + {}", secrets[i].id);
        }
    }
    for i in any.iter().take(15) {
        let regions: BTreeSet<String> = r
            .hits
            .iter()
            .filter(|h| h.secret == *i)
            .map(|h| h.region.clone())
            .collect();
        let _ = writeln!(s, "   - {} regions={:?}", secrets[*i].id, regions);
    }
    if any.len() > 15 {
        let _ = writeln!(s, "   ... +{} more", any.len() - 15);
    }
    s
}

/// Hitleri ham-metin sırları (dizin < n_text) ve anahtar materyali (dizin >= n_text) olarak ayırır.
/// Dönüş: (ham sırlardan bulunan benzersiz dizinler, anahtar eşleşmeleri).
pub fn split_hits(
    r: &SessionResult,
    n_text: usize,
) -> (BTreeSet<usize>, Vec<&s_gate2::session::LocatedHit>) {
    let text: BTreeSet<usize> = r
        .hits
        .iter()
        .filter(|h| s_gate2::session::is_owned_region(&h.region))
        .map(|h| h.secret)
        .filter(|&i| i < n_text)
        .collect();
    let key = r
        .hits
        .iter()
        .filter(|h| h.secret >= n_text && s_gate2::session::is_owned_region(&h.region))
        .collect();
    (text, key)
}
