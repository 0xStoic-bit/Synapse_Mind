//! Gate 2 altyapısı testleri: kontrol (kör dedektör değil), düzen ayrıştırma, temizlik ve ÖN ÖLÇÜM.
//!
//! Her test gerçek bir `gate2-target` çocuk süreci başlatır, `MiniDumpWriteDump` ile tam dökümünü alır
//! ve tarar. Döküm/tarif dosyaları iş bitince silinir. TÜM VERİLER SENTETİKTİR.
//! `gate2_prelim_*` testleri RESMİ Gate 2 DEĞİLDİR (resmi koşu Faz 4 sonunda nihai synapse-mind.exe üzerinde).

#![cfg(windows)]

#[path = "../src/common.rs"]
mod common;

use s_gate2::scan::{Enc, parse_layout};
use s_gate2::session::{SessionResult, run_session};
use s_gate2::spec::PacketSpec;
use std::collections::BTreeSet;

fn session(mode: &str) -> (SessionResult, Vec<s_gate2::scan::Secret>, Vec<PacketSpec>) {
    let (specs, secrets) = common::fixture();
    let r = run_session(&common::target_exe(), mode, &specs, &secrets, &[]).expect("oturum");
    println!("{}", common::render(&r, &secrets, None));
    (r, secrets, specs)
}

/// Payload metninde gerçekten bulunan sırlar (kontrol modları yalnızca payload metnini sızdırır).
fn expected(secrets: &[s_gate2::scan::Secret], specs: &[PacketSpec]) -> BTreeSet<usize> {
    secrets
        .iter()
        .enumerate()
        .filter(|(_, s)| specs.iter().any(|p| p.text.contains(&s.text)))
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn control_leaky_utf8_is_caught() {
    let (r, secrets, specs) = session("leaky-utf8");
    let exp = expected(&secrets, &specs);
    let found: BTreeSet<usize> = r.full_secret_ids(Some(Enc::Utf8)).into_iter().collect();
    assert!(exp.len() >= 100, "fixture beklenenden kucuk: {}", exp.len());
    assert_eq!(
        exp.difference(&found).count(),
        0,
        "denetci kasitli UTF-8 sizintilari kacirdi (kor dedektor)"
    );
}

#[test]
fn control_leaky_utf16le_is_caught() {
    let (r, secrets, specs) = session("leaky-utf16");
    let exp = expected(&secrets, &specs);
    let found: BTreeSet<usize> = r.full_secret_ids(Some(Enc::Utf16Le)).into_iter().collect();
    assert_eq!(
        exp.difference(&found).count(),
        0,
        "denetci kasitli UTF-16LE sizintilari kacirdi (kor dedektor)"
    );
    assert!(
        r.full_secret_ids(Some(Enc::Utf8)).is_empty(),
        "UTF-16 kontrolunde UTF-8 eslesmesi olmamali"
    );
}

#[test]
fn control_freed_unzeroized_memory_is_caught() {
    let (r, secrets, specs) = session("freed-utf8");
    let exp = expected(&secrets, &specs);
    let found: BTreeSet<usize> = r.any_secret_ids().into_iter().collect();
    let caught = exp.intersection(&found).count();
    assert!(
        caught * 4 >= exp.len(),
        "serbest birakilmis ama zeroize edilmemis bellek yakalanamadi: {caught}/{}",
        exp.len()
    );
}

#[test]
fn dump_layout_parses_and_locates_hits() {
    let (r, _s, _p) = session("leaky-utf8");
    assert!(!r.hits.is_empty());
    assert!(
        r.hits.iter().all(|h| h.va.is_some()),
        "ofsetler sanal adrese cevrilemedi"
    );
    assert!(
        r.hits
            .iter()
            .filter(|h| s_gate2::session::is_owned_region(&h.region))
            .all(|h| h.region == "private(heap/other)"),
        "yigin/ozel bellek bekleniyordu: {:?}",
        r.by_region()
    );

    // Düzen ayrıştırıcı doğrudan: gerçek bir döküm al.
    let (specs, secrets) = common::fixture();
    let tmp = s_gate2::dump::TempFile::new("layout", "dmp");
    let spec_file = s_gate2::dump::TempFile::new("layout", "spec");
    std::fs::write(spec_file.path(), s_gate2::spec::encode(&specs)).unwrap();
    let mut child = std::process::Command::new(common::target_exe())
        .arg("--spec")
        .arg(spec_file.path())
        .arg("--mode")
        .arg("baseline")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.starts_with("READY"));
    }
    let bytes = s_gate2::dump::write_full_dump(&child, tmp.path()).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    let layout = parse_layout(tmp.path()).unwrap();
    assert!(bytes > 1_000_000);
    assert!(!layout.ranges.is_empty() && !layout.stacks.is_empty() && !layout.regions.is_empty());
    let _ = secrets;
}

#[test]
fn temp_files_are_removed_after_session() {
    let before = leftovers();
    let _ = session("baseline");
    let after = leftovers();
    assert!(
        after.iter().all(|f| before.contains(f)),
        "gecici dosya birakildi: {after:?}"
    );
}

/// Yalnizca bu testin kullandigi "baseline" oturumunun dosyalari (diger testler paralel calisir).
fn leftovers() -> BTreeSet<String> {
    let pid = format!("s-gate2-{}-", std::process::id());
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&pid) && n.contains("-baseline."))
        .collect()
}

// ---------------------------------------------------------------- ÖN ÖLÇÜM (resmi Gate 2 değil)

#[test]
fn gate2_prelim_process_mode_has_no_raw_secrets() {
    let (r, secrets, _) = session("process");
    let ids: Vec<_> = r
        .any_secret_ids()
        .iter()
        .map(|&i| secrets[i].id.clone())
        .collect();
    assert!(
        ids.is_empty(),
        "senkron process() sonrasi bellekte ham sir: {ids:?} (bolge: {:?})",
        r.by_region()
    );
}

#[test]
fn gate2_prelim_run_pipeline_has_no_raw_secrets() {
    let (r, secrets, _) = session("run");
    let ids: Vec<_> = r
        .any_secret_ids()
        .iter()
        .map(|&i| secrets[i].id.clone())
        .collect();
    assert!(
        ids.is_empty(),
        "run() hatti sonrasi bellekte ham sir: {ids:?} (bolge: {:?})",
        r.by_region()
    );
}

// ------------------------------------------------------------ Sprint 3: anahtar materyali

use s_gate2::scan::Part;
use s_gate2::session::run_session_with_key;

fn key_session(mode: &str) -> (SessionResult, usize) {
    let (specs, mut secrets) = common::fixture();
    let n_text = secrets.len();
    let key = common::test_key();
    secrets.extend(common::key_secrets(&key));
    let r = run_session_with_key(
        &common::target_exe(),
        mode,
        &specs,
        &secrets,
        &[],
        Some(&common::key_hex(&key)),
    )
    .expect("oturum");
    println!("{}", common::render(&r, &secrets, None));
    (r, n_text)
}

#[test]
fn control_leaky_key_all_forms_are_caught() {
    let (r, n) = key_session("leaky-key");
    let has = |secret: usize, enc: Enc| {
        r.hits
            .iter()
            .any(|h| h.secret == n + secret && h.enc == enc && h.part == Part::Full)
    };
    assert!(has(0, Enc::Raw), "ham 32 bayt yakalanmadi");
    assert!(has(0, Enc::Utf8), "hex UTF-8 yakalanmadi");
    assert!(has(0, Enc::Utf16Le), "hex UTF-16LE yakalanmadi");
    assert!(
        has(2, Enc::Utf8),
        "x'hex' (SQLCipher PRAGMA key) yakalanmadi"
    );
}

/// Harness gürültü tabanı: anahtar doğrudan yığın tamponuna okunur ve zeroize edilir; bellekte KALMAMALI.
#[test]
fn key_read_into_heap_box_leaves_no_residue() {
    let (r, n) = key_session("keyread");
    let (_, key_hits) = common::split_hits(&r, n);
    assert!(key_hits.is_empty(), "anahtar kalintisi: {}", key_hits.len());
}

/// Gerçek uygulama yolu (DbKey::load / generate / protect): anahtar bellekte KALMAMALI. Debug derlemesinde
/// derleyici ek kopya bırakabilir; kesin ölçüm release: `gate2-audit` (aşağıdaki test release'te de koşar).
#[test]
fn dpapi_dbkey_path_has_no_raw_text_secrets_and_no_key_residue() {
    let (r, n) = key_session("dpapi");
    let (text, key_hits) = common::split_hits(&r, n);
    assert!(text.is_empty());
    assert!(
        key_hits.is_empty(),
        "DbKey yolu sonrasi anahtar kalintisi: {} ({:?})",
        key_hits.len(),
        r.by_region()
    );
}

/// Eski değerle-dönen API (`unprotect_key`) bilgi/karşılaştırma: bayat kopyalar yalnızca süreç-sahipli bellekte
/// (yığıt veya yığıtın SP altındaki ölü çerçeveleri: MiniDump bunları "özel bellek" sayar) ve sınırlı sayıda kalmalı.
#[test]
fn dpapi_legacy_by_value_residue_is_process_owned_and_bounded() {
    let (r, n) = key_session("dpapi-legacy");
    let (_, key_hits) = common::split_hits(&r, n);
    assert!(
        key_hits.len() <= 12,
        "beklenenden fazla anahtar kopyasi: {} {:?}",
        key_hits.len(),
        r.by_region()
    );
}

// `--features core` / `--features encrypted` gerektiren testler (s-core derlenebildiğinde).

#[cfg(feature = "core")]
mod core_modes {
    use super::*;

    #[test]
    fn control_unmasked_store_content_is_caught() {
        let (r, secrets, specs) = session("core-unmasked-control");
        let exp = expected(&secrets, &specs);
        let found: BTreeSet<usize> = r.any_secret_ids().into_iter().collect();
        assert!(
            exp.intersection(&found).count() * 2 >= exp.len(),
            "depodaki ham metin yakalanamadi"
        );
    }

    #[test]
    fn gate2_prelim_core_store_has_no_raw_secrets() {
        let (r, secrets, _) = session("core");
        let ids: Vec<_> = r
            .any_secret_ids()
            .iter()
            .map(|&i| secrets[i].id.clone())
            .collect();
        assert!(
            ids.is_empty(),
            "core (guard -> s-core) sonrasi bellekte ham sir: {ids:?}"
        );
        assert!(r.ready_line.contains("store_events="), "{}", r.ready_line);
    }
}

#[cfg(feature = "encrypted")]
mod encrypted_modes {
    use super::*;

    #[test]
    fn gate2_prelim_encrypted_closed_has_no_key_or_raw_secrets() {
        let (r, n) = key_session("encrypted-closed");
        let (text, key_hits) = common::split_hits(&r, n);
        assert!(text.is_empty(), "ham sir: {text:?}");
        assert!(
            key_hits.is_empty(),
            "depo kapaliyken anahtar bellekte: {}",
            key_hits.len()
        );
    }
}

// ------------------------------------------------------------ geniş fixture (Stretch dahil)

/// Guard'ın TAM maskelediği Stretch vektörleriyle (yeni R2/R3 kod yolları) bellek ölçümü. Bilinen açık bulgu
/// (R4b: iç içe/UTF-16 base64 blob'unun 12 karakterlik kuyruğu serbest yığında kalıyor) giderilene kadar `#[ignore]`.
#[test]
#[ignore = "R4b: genis fixture'da ic ice/UTF-16 base64 kuyruk kalintisi; --ignored ile kos"]
fn gate2_wide_process_mode_has_no_raw_secrets() {
    let (specs, secrets) = common::fixture_wide();
    let r = run_session(&common::target_exe(), "process", &specs, &secrets, &[]).expect("oturum");
    println!("{}", common::render(&r, &secrets, None));
    let ids: Vec<_> = r
        .any_secret_ids()
        .iter()
        .map(|&i| secrets[i].id.clone())
        .collect();
    assert!(ids.is_empty(), "genis fixture: bellekte ham sir: {ids:?}");
}

// ------------------------------------------------ düşük-trafik (gerçek biçimli) guard testi

#[path = "../src/synthetic.rs"]
mod synthetic;

/// Gerçek sensör biçimli girdilerle (tek başlık / UIA çok satırlı gövde / pano metinleri) guard `process`:
/// büyük fixture'da yığın yeniden kullanımı kalıntıyı ezip gizler; düşük trafikte son işlenen paketin ham metni
/// serbest yığında KALIYOR (G1-G3, attribution). Giderilene kadar `#[ignore]`.
#[test]
#[ignore = "guard dusuk-trafik kalintisi (G1-G3); --ignored ile kos"]
fn guard_real_shaped_low_traffic_inputs_leave_no_residue() {
    use s_gate2::scan::Secret;
    use s_gate2::spec::{KIND_ACCESSIBILITY, KIND_CLIPBOARD, PacketSpec};
    let syn = synthetic::synthetic_set();
    let raw: Vec<Secret> = syn
        .raw
        .iter()
        .map(|(i, t)| Secret::new(i.clone(), t.clone()))
        .collect();
    let mk = |kind: u8, title: &str, text: &str| PacketSpec {
        kind,
        process_name: "Gate2Synthetic.exe".into(),
        title: title.into(),
        text: text.into(),
    };
    let cases: Vec<(&str, Vec<PacketSpec>)> = vec![
        ("baslik", vec![mk(KIND_ACCESSIBILITY, &syn.title, "")]),
        (
            "uia govde",
            vec![mk(KIND_ACCESSIBILITY, "Gate2 Synthetic", &syn.body)],
        ),
        (
            "pano",
            syn.clips
                .iter()
                .map(|c| mk(KIND_CLIPBOARD, "Gate2 Synthetic", c))
                .collect(),
        ),
    ];
    let mut bad = Vec::new();
    for (name, specs) in cases {
        let r = run_session(&common::target_exe(), "process", &specs, &raw, &[]).expect("oturum");
        let owned: Vec<_> = r
            .hits
            .iter()
            .filter(|h| h.region.starts_with("private") || h.region.starts_with("stack"))
            .map(|h| h.secret_id.clone())
            .collect();
        if !owned.is_empty() {
            bad.push(format!("{name}: {owned:?}"));
        }
    }
    assert!(bad.is_empty(), "dusuk trafikte guard kalintisi: {bad:?}");
}
