//! Gate 1: PII / sır sızma testi (`s_guard::process` ve `s_guard::run` karşısında).
//!
//! Rapor: `cargo test -p s-redteam --test gate1_pii -- --nocapture`.
//! Daha sıkı pencere: `REDTEAM_MIN_WINDOW=4`.

use s_guard::{DropReason, Verdict, process};
use s_redteam::harness::{Leak, check_block, check_block_min, min_window};
use s_redteam::vectors::{DropKind, Expect, Tier, Vector, all_vectors};
use s_types::MaskedMemoryBlock;

enum Out {
    Masked(MaskedMemoryBlock),
    Dropped(&'static str, Option<DropKind>),
}

fn map_drop(r: &DropReason) -> (&'static str, Option<DropKind>) {
    match r {
        DropReason::BlacklistedProcess => {
            ("BlacklistedProcess", Some(DropKind::BlacklistedProcess))
        }
        DropReason::PrivateWindow => ("PrivateWindow", Some(DropKind::PrivateWindow)),
        DropReason::SensitiveFile => ("SensitiveFile", Some(DropKind::SensitiveFile)),
        DropReason::IgnoredFormat => ("IgnoredFormat", Some(DropKind::IgnoredFormat)),
        #[allow(unreachable_patterns)]
        _ => ("Other", None),
    }
}

const TS: u64 = 1_763_424_000_000;

fn exec(v: &Vector, event_id: u64) -> Out {
    match process(v.to_packet(TS), event_id) {
        Verdict::Masked(b) => Out::Masked(b),
        Verdict::Dropped(r) => {
            let (n, k) = map_drop(&r);
            Out::Dropped(n, k)
        }
        #[allow(unreachable_patterns)]
        _ => Out::Dropped("Other", None),
    }
}

#[derive(Default)]
struct Summary {
    rows: Vec<String>,
    leaks: Vec<Leak>,
    problems: Vec<String>,
}

fn audit(tiers: &[Tier]) -> Summary {
    audit_by(|v| tiers.contains(&v.tier))
}

fn audit_by(pred: impl Fn(&Vector) -> bool) -> Summary {
    let mut s = Summary::default();
    for (i, v) in all_vectors().iter().enumerate() {
        if !pred(v) {
            continue;
        }
        let id = i as u64;
        match (exec(v, id), v.expect) {
            (Out::Masked(b), Expect::Masked) => {
                let l = check_block(v, &b);
                if l.is_empty() {
                    s.rows.push(format!(
                        "PASS      {:<48} masked, redactions={}",
                        v.id, b.redactions_count
                    ));
                } else {
                    for x in &l {
                        s.rows.push(format!(
                            "LEAK      {:<48} field={} windows_hit={}",
                            v.id, x.field, x.windows_hit
                        ));
                    }
                    s.leaks.extend(l);
                }
            }
            (Out::Masked(b), Expect::Dropped(d)) => {
                // Düşürülmeliydi: hem uyum hatası hem de sızıntı kontrolü.
                let l = check_block(v, &b);
                s.rows.push(format!(
                    "NOT-DROP  {:<48} expected {:?}, got Masked (leaks={})",
                    v.id,
                    d,
                    l.len()
                ));
                s.problems.push(format!(
                    "{}: expected Dropped({:?}) but got Masked",
                    v.id, d
                ));
                s.leaks.extend(l);
            }
            (Out::Dropped(n, k), Expect::Dropped(d)) => {
                if k == Some(d) {
                    s.rows.push(format!("PASS      {:<48} dropped {n}", v.id));
                } else {
                    s.rows
                        .push(format!("WRONG-WHY {:<48} expected {:?}, got {n}", v.id, d));
                    s.problems.push(format!(
                        "{}: expected Dropped({:?}) but got Dropped({n})",
                        v.id, d
                    ));
                }
            }
            (Out::Dropped(n, _), Expect::Masked) => {
                if v.tier == Tier::Control {
                    s.rows
                        .push(format!("OVER-DROP {:<48} benign input dropped ({n})", v.id));
                    s.problems
                        .push(format!("{}: benign control was dropped ({n})", v.id));
                } else {
                    s.rows.push(format!(
                        "SAFE-DROP {:<48} dropped {n} (no leak; informational)",
                        v.id
                    ));
                }
            }
        }
    }
    s
}

fn report(title: &str, s: &Summary) {
    println!("==== {title} (min_window={}) ====", min_window());
    for r in &s.rows {
        println!("{r}");
    }
    println!(
        "---- leaks={} problems={} rows={}",
        s.leaks.len(),
        s.problems.len(),
        s.rows.len()
    );
}

fn assert_no_leaks(title: &str, s: &Summary) {
    report(title, s);
    let mut msg = String::new();
    for l in &s.leaks {
        msg.push_str(&format!("\n  {l}"));
    }
    for p in &s.problems {
        msg.push_str(&format!("\n  PROBLEM {p}"));
    }
    assert!(
        s.leaks.is_empty() && s.problems.is_empty(),
        "Gate 1 ihlali ({title}):{msg}"
    );
}

#[test]
fn gate1_core_vectors_leave_no_residue() {
    assert_no_leaks("core", &audit(&[Tier::Core]));
}

#[test]
fn gate1_evasion_vectors_leave_no_residue() {
    assert_no_leaks("evasion", &audit(&[Tier::Evasion]));
}

#[test]
fn gate1_blacklist_vectors_are_dropped_with_right_reason() {
    assert_no_leaks("blacklist", &audit(&[Tier::Blacklist]));
}

/// Hepsini düşüren "kör" guard'ı yakalar: zararsız girdi Masked ve metni korunmuş olmalı.
#[test]
fn gate1_benign_controls_survive() {
    let s = audit(&[Tier::Control]);
    report("controls", &s);
    for (i, v) in all_vectors().iter().enumerate() {
        if v.tier != Tier::Control {
            continue;
        }
        match exec(v, i as u64) {
            Out::Masked(b) => {
                let keep = v.keep.as_ref().unwrap();
                assert!(
                    b.clean_text.contains(keep.as_str()),
                    "{}: zararsiz metin bozuldu/bos kaldi (clean_text korunmadi)",
                    v.id
                );
                assert_eq!(
                    b.redactions_count, 0,
                    "{}: zararsiz metinde maskeleme yapildi",
                    v.id
                );
            }
            Out::Dropped(n, _) => panic!("{}: zararsiz girdi dusuruldu ({n})", v.id),
        }
    }
}

/// Maske biçimi `[REDACTED_<TÜR>]`, redactions_count, event_id/timestamp aktarımı.
#[test]
fn gate1_mask_format_conformance() {
    let mut problems = Vec::new();
    for (i, v) in all_vectors().iter().enumerate() {
        if v.tier != Tier::Core || v.mask_kinds.is_empty() {
            continue;
        }
        if let Out::Masked(b) = exec(v, i as u64) {
            let hay = format!(
                "{}\n{}\n{}",
                b.clean_text, b.app_context.sanitized_title, b.app_context.process_name
            );
            for k in &v.mask_kinds {
                let tag = format!("[REDACTED_{k}]");
                if !hay.contains(&tag) {
                    problems.push(format!("{}: {tag} yok", v.id));
                }
            }
            if b.redactions_count == 0 {
                problems.push(format!("{}: redactions_count == 0", v.id));
            }
            if b.event_id != i as u64 || b.timestamp_ms != TS {
                problems.push(format!("{}: event_id/timestamp tasinmadi", v.id));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "Maske uyum ihlalleri:\n  {}",
        problems.join("\n  ")
    );
}

/// Asenkron hat (`run`): aynı vektörler mpsc üzerinden. `event_id` gönderim sırasıdır.
/// Her blok kendi sırlarına karşı tam pencereyle, senkron `process()` çıktısıyla eşitlik için
/// ve diğer vektörlerin sırlarına karşı 12 karakterlik pencereyle (çapraz bulaşma) denetlenir.
#[tokio::test]
async fn gate1_async_pipeline_no_leak() {
    let vectors = all_vectors();
    let sent: Vec<Vector> = vectors
        .iter()
        .filter(|v| matches!(v.tier, Tier::Core | Tier::Evasion | Tier::Blacklist))
        .cloned()
        .collect();
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(128);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(128);
    let guard = tokio::spawn(s_guard::run(in_rx, out_tx));

    let sender = {
        let vs = sent.clone();
        tokio::spawn(async move {
            for v in vs.iter() {
                in_tx.send(v.to_packet(TS)).await.unwrap();
            }
            // in_tx burada düşer -> run sonlanmalı.
        })
    };

    let mut blocks = Vec::new();
    while let Some(b) = out_rx.recv().await {
        blocks.push(b);
    }
    sender.await.unwrap();
    guard.await.unwrap();

    let mut problems = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for b in &blocks {
        let idx = b.event_id as usize;
        if idx >= sent.len() || !seen.insert(idx) {
            problems.push(format!("gecersiz/tekrarli event_id {}", b.event_id));
            continue;
        }
        let own = &sent[idx];
        if own.expect != Expect::Masked {
            problems.push(format!(
                "{}: DROP beklenirken async hat blok uretti",
                own.id
            ));
        }
        // (1) kendi iğneleri, tam pencere
        for l in check_block(own, b) {
            problems.push(l.to_string());
        }
        // (2) eşleştirme doğrulaması + senkron/asenkron tutarlılık
        match exec(own, b.event_id) {
            Out::Masked(sync_b) => {
                if sync_b.clean_text != b.clean_text
                    || sync_b.app_context.sanitized_title != b.app_context.sanitized_title
                    || sync_b.app_context.process_name != b.app_context.process_name
                {
                    problems.push(format!(
                        "{}: async cikti sync process() ile ayni degil",
                        own.id
                    ));
                }
            }
            Out::Dropped(..) => problems.push(format!("{}: sync DROP, async blok", own.id)),
        }
        // (3) çapraz bulaşma
        for (j, other) in sent.iter().enumerate() {
            if j != idx {
                for l in check_block_min(other, b, 12) {
                    problems.push(format!("cross-contamination from {}: {l}", other.id));
                }
            }
        }
    }
    // Masked beklenen her vektör için blok gelmeli (sessiz kayıp yok).
    for (i, v) in sent.iter().enumerate() {
        if v.expect == Expect::Masked && !seen.contains(&i) {
            // Guard güvenli biçimde DROP ettiyse (sync de DROP) kabul.
            if let Out::Masked(_) = exec(v, i as u64) {
                problems.push(format!("{}: async blok eksik", v.id));
            }
        }
    }
    println!("async: {} blok, sorun={}", blocks.len(), problems.len());
    assert!(
        problems.is_empty(),
        "async pipeline sorunlari:\n  {}",
        problems.join("\n  ")
    );
}

/// Özet: tüm katmanlar tek raporda (`-- --nocapture`).
#[test]
fn gate1_full_report() {
    let s = audit(&[Tier::Core, Tier::Evasion, Tier::Blacklist, Tier::Control]);
    assert_no_leaks("FULL GATE 1", &s);
}

/// Teşhis: `REDTEAM_DUMP=<vektör-id-öneki> cargo test -p s-redteam --test gate1_pii dump -- --nocapture`
/// eşleşen vektörlerin guard çıktısını (sentetik) yazdırır. Env yoksa hiçbir şey yapmaz.
#[test]
fn dump_vector_outputs() {
    let Ok(prefix) = std::env::var("REDTEAM_DUMP") else {
        return;
    };
    for (i, v) in all_vectors().iter().enumerate() {
        if !v.id.starts_with(&prefix) {
            continue;
        }
        println!(
            "--- {} input.text={:?} title={:?} proc={:?}",
            v.id, v.text, v.window_title, v.process_name
        );
        match exec(v, i as u64) {
            Out::Masked(b) => println!(
                "    clean_text={:?}\n    sanitized_title={:?} process_name={:?} redactions={}",
                b.clean_text,
                b.app_context.sanitized_title,
                b.app_context.process_name,
                b.redactions_count
            ),
            Out::Dropped(n, _) => println!("    Dropped({n})"),
        }
    }
}

/// Benign 4-5 karakterlik pencere eşleşmeleri (sınıflandırılmış yanlış pozitifler).
/// Her satır: (vektör-id, alan, pencere, gerekçe). Gerçek sır gövdesinden gelen pencere BURAYA EKLENMEZ.
const WINDOW4_BENIGN: &[(&str, &str, &str, &str)] = &[
    (
        "core-stripe-json-clipboard",
        "clean_text",
        "live",
        "girdideki ayri `\"mode\":\"live\"` sozcugu; anahtar gövdesi degil, sk_live_ oneki",
    ),
    (
        "core-openai-sk-proj",
        "app_context.sanitized_title",
        "proj",
        "harness varsayilan basligi 'Project notes' ile sk-proj- on eki; baslik girdide zaten vardi, sir govdesi degil",
    ),
    (
        "core-openai-in-code",
        "app_context.sanitized_title",
        "proj",
        "ayni: 'Project' sozcugu",
    ),
    (
        "core-env-dump-export-quoted",
        "app_context.sanitized_title",
        "proj",
        "ayni: 'Project' sozcugu",
    ),
    (
        "evade-markdown-codespan-openai",
        "app_context.sanitized_title",
        "proj",
        "ayni: 'Project' sozcugu",
    ),
    (
        "core-pw-turkish-label",
        "clean_text",
        "sifr",
        "etiket 'sifre:' (girdide aynen var); parola metni 'Gizli-Sifre-4471!' de bu sozcugu iceriyor, deger [REDACTED_PASSWORD]",
    ),
    (
        "core-pw-turkish-label",
        "clean_text",
        "ifre",
        "ayni: etiket sozcugu",
    ),
    (
        "evade-url-email-at",
        "clean_text",
        ".tes",
        "ayri 'app.test' ana makinesi; e-posta alan adi .test herkese acik TLD, yerel kisim/alan govdesi maskeli",
    ),
    (
        "evade-url-email-at",
        "clean_text",
        "test",
        "ayni: 'app.test' ana makinesi",
    ),
];

fn window4_report() -> (Vec<String>, Vec<String>) {
    let mut unclassified = Vec::new();
    let mut benign = Vec::new();
    for (i, v) in all_vectors().iter().enumerate() {
        if !matches!(v.tier, Tier::Core | Tier::Evasion | Tier::Blacklist) {
            continue;
        }
        if let Out::Masked(b) = exec(v, i as u64) {
            for l in check_block_min(v, &b, 4) {
                for w in &l.windows {
                    let line = format!("vector={} field={} window={:?}", l.vector, l.field, w);
                    if WINDOW4_BENIGN
                        .iter()
                        .any(|(id, f, win, _)| *id == l.vector && *f == l.field && *win == w)
                    {
                        benign.push(line);
                    } else {
                        unclassified.push(line);
                    }
                }
            }
        }
    }
    (unclassified, benign)
}

/// Pencere=4 ile sıkı koşu: sınıflandırılmamış her eşleşme başarısızlıktır.
/// (Sınıflandırma listesi `WINDOW4_BENIGN`; her giriş için gerekçe yazılıdır.)
#[test]
fn gate1_window4_every_hit_is_classified_benign() {
    let (unclassified, benign) = window4_report();
    println!(
        "window=4: benign-classified={} unclassified={}",
        benign.len(),
        unclassified.len()
    );
    for b in &benign {
        println!("  benign       {b}");
    }
    for u in &unclassified {
        println!("  UNCLASSIFIED {u}");
    }
    assert!(
        unclassified.is_empty(),
        "pencere=4 siniflandirilmamis eslesmeler:\n  {}",
        unclassified.join("\n  ")
    );
}

/// İleri kaçırma (bilinen sınırlama) vektörleri: yalnızca rapor, testi başarısız etmez.
#[test]
fn gate1_stretch_report() {
    let s = audit_by(|v| v.id.starts_with("stretch-"));
    report("stretch (informational)", &s);
}

/// İleri kaçırma vektörlerini katı doğrular (`--ignored`).
#[test]
#[ignore = "bilinen sinirlamalar (stretch); --ignored ile kos"]
fn gate1_stretch_vectors_leave_no_residue() {
    assert_no_leaks("stretch", &audit_by(|v| v.id.starts_with("stretch-")));
}

/// Ek kaçırma varyantları: yalnızca rapor.
#[test]
fn gate1_stretch2_report() {
    let s = audit_by(|v| v.id.starts_with("stretch2-"));
    report("stretch2 (informational)", &s);
}

/// Ek kaçırma varyantlarını katı doğrular (`--ignored`).
#[test]
#[ignore = "bilinen sinirlamalar (stretch2); --ignored ile kos"]
fn gate1_stretch2_vectors_leave_no_residue() {
    assert_no_leaks("stretch2", &audit_by(|v| v.id.starts_with("stretch2-")));
}

/// Yanlış pozitif sondaları (bilinçli fail-closed olabilir): yalnızca RAPOR; kaç tanesi gereksiz maskelendi.
#[test]
fn gate1_fp_probe_report() {
    let mut over = 0usize;
    let mut total = 0usize;
    for (i, v) in all_vectors().iter().enumerate() {
        if v.tier != Tier::FpProbe {
            continue;
        }
        total += 1;
        let keep = v.keep.as_ref().unwrap();
        match exec(v, i as u64) {
            Out::Masked(b) if b.clean_text.contains(keep.as_str()) && b.redactions_count == 0 => {
                println!("FP-OK     {:<34} korundu", v.id);
            }
            Out::Masked(b) => {
                over += 1;
                println!(
                    "FP-MASKED {:<34} redactions={} clean_text={:?}",
                    v.id, b.redactions_count, b.clean_text
                );
            }
            Out::Dropped(n, _) => {
                over += 1;
                println!("FP-DROPPED {:<33} {n}", v.id);
            }
        }
    }
    println!("---- fp_probe: over-masked={over}/{total}");
}

/// r1 bypass sondaları: yalnızca rapor.
#[test]
fn gate1_r1_probe_report() {
    let s = audit_by(|v| v.id.starts_with("r1-"));
    report("r1 exception probes (informational)", &s);
}

/// r1 sondalarını katı doğrular (`--ignored`).
#[test]
#[ignore = "R1 istisna sondalari; --ignored ile kos"]
fn gate1_r1_probes_leave_no_residue() {
    assert_no_leaks("r1", &audit_by(|v| v.id.starts_with("r1-")));
}

/// Guard'ın KABUL ETTİĞİ riskler (`accepted-*`): ayrı kategori, yalnızca RAPOR (başarısız etmez).
#[test]
fn gate1_accepted_risk_report() {
    let s = audit_by(|v| v.id.starts_with("accepted-"));
    report("accepted risks (informational)", &s);
}

/// r2 sondaları: yalnızca rapor.
#[test]
fn gate1_r2_probe_report() {
    let s = audit_by(|v| v.id.starts_with("r2-"));
    report("r2 probes (informational)", &s);
}

/// r2 sondalarını katı doğrular (`--ignored`).
#[test]
#[ignore = "R2 sondalari; --ignored ile kos"]
fn gate1_r2_probes_leave_no_residue() {
    assert_no_leaks("r2", &audit_by(|v| v.id.starts_with("r2-")));
}

/// r3 sondaları: yalnızca rapor.
#[test]
fn gate1_r3_probe_report() {
    let s = audit_by(|v| v.id.starts_with("r3-"));
    report("r3 probes (informational)", &s);
}

/// 19.11.2026'da yazılı olarak kabul edilen `r3-*` sızıntıları (vektör, sınıf). Bu listenin
/// dışındaki her sızıntı testi kırmızı bırakır.
const ACCEPTED_R3: &[(&str, &str)] = &[
    ("r3-type-space-before-angle", "R5-b"),
    ("r3-type-concat-plus", "R5-b"),
    ("r3-type-array-concat", "R5-b"),
    ("r3-type-camel-ident-lookalike-value", "R5-b"),
    ("r3-datauri-base64-x7", "R5-b"),
    ("r3-datauri-base64-x8", "R5-b"),
    ("r3-datauri-base64-of-hex", "R5-b"),
    ("r3-tail-4-words-line", "R5-a"),
    ("r3-tail-9-lines", "R5-a"),
    ("r3-tail-2char-words", "R5-a"),
    ("r3-tail-assignment-like", "R5-a"),
    ("r3-tail-colon-inside", "R5-a"),
    ("r3-tail-keyword-line-continues", "R5-a"),
    ("r3-word-2letter-words", "R5-c"),
    ("r3-word-11-letter-words", "R5-c"),
    ("r3-word-leet-digits-in-words", "R5-c"),
    ("r3-word-dot-separated", "R5-c"),
    ("r3-word-plus-separated", "R5-c"),
    ("r3-word-with-extension-suffix", "R5-c"),
    ("r3-word-preceded-by-code-keyword", "R5-c"),
    ("r3-word-followed-by-equals", "R5-c"),
    ("r3-word-camelcase-3-words", "R5-c"),
];

/// r3 sondaları: kabul edilmemiş her sızıntı kırmızı; kabul edilenler sınıfıyla raporlanır.
#[test]
fn gate1_r3_probes_leave_no_unaccepted_residue() {
    let s = audit_by(|v| v.id.starts_with("r3-"));
    report("r3 probes (accepted classes split)", &s);
    let leaking: std::collections::BTreeSet<&str> =
        s.leaks.iter().map(|l| l.vector.as_str()).collect();
    let mut by_class: std::collections::BTreeMap<&str, usize> = Default::default();
    for (id, class) in ACCEPTED_R3 {
        if leaking.contains(id) {
            *by_class.entry(class).or_insert(0) += 1;
        } else {
            println!("FIXED-SINCE-ACCEPTANCE {id} ({class}) artik sizdirmiyor");
        }
    }
    println!(
        "accepted_leaks_by_class={by_class:?} total={}",
        leaking.len()
    );
    let unaccepted: Vec<String> = s
        .leaks
        .iter()
        .filter(|l| !ACCEPTED_R3.iter().any(|(id, _)| *id == l.vector))
        .map(|l| l.to_string())
        .collect();
    assert!(
        unaccepted.is_empty() && s.problems.is_empty(),
        "KABUL EDILMEMIS r3 sizintisi:
  {}
{:?}",
        unaccepted.join(
            "
  "
        ),
        s.problems
    );
}
