//! Gate 2 denetçisi: hedef süreci başlatır, canlı tam döküm alır, ham sırları ve DB anahtar
//! materyalini (ham, hex, UTF-16, `x'hex'`) arar. Maskeli metin sızıntı sayılmaz.
//!
//! `gate2-audit [--modes ...] [--skip-control] [--wide]`
//!
//! Çıkış: 0 = kontroller yakalandı, koşullar sağlandı; 1 = bulgu; 2 = kontrol yakalanamadı.

#[cfg(windows)]
#[path = "../common.rs"]
mod common;

#[cfg(windows)]
fn main() {
    use s_gate2::scan::{Enc, Part};
    use s_gate2::session::{SessionResult, run_session, run_session_with_key};
    use std::collections::BTreeSet;
    use std::io::ErrorKind;

    let args: Vec<String> = std::env::args().collect();
    let modes: Vec<String> = args
        .iter()
        .position(|a| a == "--modes")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_else(|| {
            [
                "baseline",
                "process",
                "run",
                "core",
                "keyread",
                "keyread-byvalue",
                "dpapi",
                "dpapi-legacy",
                "encrypted",
                "encrypted-closed",
            ]
            .map(str::to_string)
            .to_vec()
        });
    let skip_control = args.iter().any(|a| a == "--skip-control");

    let exe = common::target_exe();
    let wide = args.iter().any(|a| a == "--wide");
    let (specs, text_secrets) = if wide {
        common::fixture_wide()
    } else {
        common::fixture()
    };
    let n_text = text_secrets.len();
    let key = common::test_key();
    let key_hex = common::key_hex(&key);
    let mut secrets = text_secrets.clone();
    secrets.extend(common::key_secrets(&key));
    println!(
        "Gate 2 on-olcum: hedef={} paket={} aranan_ham_sir={} + anahtar_materyali={} (UTF-8 + UTF-16LE + ham bayt; sentetik veri)",
        exe.display(),
        specs.len(),
        n_text,
        secrets.len() - n_text
    );

    let mut control_ok = true;
    if !skip_control {
        for (mode, enc) in [
            ("leaky-utf8", Enc::Utf8),
            ("leaky-utf16", Enc::Utf16Le),
            ("freed-utf8", Enc::Utf8),
        ] {
            let r = run_session(&exe, mode, &specs, &secrets, &[]).expect("kontrol oturumu");
            print!("{}", common::render(&r, &secrets, None));
            let expected: BTreeSet<usize> = text_secrets
                .iter()
                .enumerate()
                .filter(|(_, s)| specs.iter().any(|p| p.text.contains(&s.text)))
                .map(|(i, _)| i)
                .collect();
            if mode == "freed-utf8" {
                // Serbest bırakılmış kopyalar yığın yeniden kullanımıyla kısmen ezilir: herhangi bir
                // parçası (full/mid/tail) bulunan sırların en az %25'i beklenir.
                let found: BTreeSet<usize> = r.any_secret_ids().into_iter().collect();
                let caught = expected.intersection(&found).count();
                println!(
                    "   KONTROL {mode}: beklenen={} yakalanan(herhangi parca)={caught}",
                    expected.len()
                );
                if caught * 4 < expected.len() {
                    control_ok = false;
                }
                continue;
            }
            let found: BTreeSet<usize> = r.full_secret_ids(Some(enc)).into_iter().collect();
            let missed = expected.difference(&found).count();
            println!(
                "   KONTROL {mode}: beklenen={} yakalanan={} kacan={missed}",
                expected.len(),
                found.len()
            );
            if missed > 0 {
                control_ok = false;
            }
        }
        // Anahtar kontrolü: ham bayt, hex UTF-8, hex UTF-16LE ve x'hex' kopyaları yakalanmalı.
        let r = run_session_with_key(&exe, "leaky-key", &specs, &secrets, &[], Some(&key_hex))
            .expect("anahtar kontrol oturumu");
        print!("{}", common::render(&r, &secrets, None));
        let has = |secret: usize, enc: Enc| {
            r.hits
                .iter()
                .any(|h| h.secret == n_text + secret && h.enc == enc && h.part == Part::Full)
        };
        let checks = [
            ("ham-bayt", has(0, Enc::Raw)),
            ("hex-utf8", has(0, Enc::Utf8)),
            ("hex-utf16le", has(0, Enc::Utf16Le)),
            ("x'hex'-utf8", has(2, Enc::Utf8)),
        ];
        for (name, ok) in checks {
            println!(
                "   KONTROL leaky-key {name}: {}",
                if ok { "yakalandi" } else { "KACTI" }
            );
            control_ok &= ok;
        }
    }

    // s-core kontrolü: HAM metin guard'sız depoya alınırsa denetçi bunu görmeli (`core` modundaki "0" anlamlı olsun).
    if !skip_control && modes.iter().any(|m| m == "core") {
        match run_session(&exe, "core-unmasked-control", &specs, &secrets, &[]) {
            Ok(r) => {
                print!("{}", common::render(&r, &secrets, None));
                let expected: BTreeSet<usize> = text_secrets
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| specs.iter().any(|p| p.text.contains(&s.text)))
                    .map(|(i, _)| i)
                    .collect();
                let found: BTreeSet<usize> = r.any_secret_ids().into_iter().collect();
                let caught = expected.intersection(&found).count();
                println!(
                    "   KONTROL core-unmasked-control: beklenen={} yakalanan(herhangi parca)={caught}",
                    expected.len()
                );
                if caught * 2 < expected.len() {
                    control_ok = false;
                }
            }
            Err(e) if e.kind() == ErrorKind::Unsupported => {
                println!("== mode=core-unmasked-control ATLANDI: {e}")
            }
            Err(e) => panic!("core kontrol: {e}"),
        }
    }

    let mut text_leaks = 0usize;
    let mut key_gate_leaks = 0usize;
    let mut baseline: Option<BTreeSet<usize>> = None;
    for mode in &modes {
        let needs_key = matches!(
            mode.as_str(),
            "dpapi"
                | "dpapi-legacy"
                | "keyread"
                | "keyread-byvalue"
                | "encrypted"
                | "encrypted-closed"
        );
        let res: std::io::Result<SessionResult> = if needs_key {
            run_session_with_key(&exe, mode, &specs, &secrets, &[], Some(&key_hex))
        } else {
            run_session(&exe, mode, &specs, &secrets, &[])
        };
        let r = match res {
            Ok(r) => r,
            Err(e) if e.kind() == ErrorKind::Unsupported => {
                println!("== mode={mode} ATLANDI: {e}");
                continue;
            }
            Err(e) => panic!("oturum {mode}: {e}"),
        };
        print!("{}", common::render(&r, &secrets, baseline.as_ref()));
        let (text_ids, key_hits) = common::split_hits(&r, n_text);
        if mode == "baseline" {
            baseline = Some(text_ids.clone());
        }
        text_leaks += text_ids.len();
        println!(
            "   ham_sir_bulgusu={} anahtar_bulgusu={} {}",
            text_ids.len(),
            key_hits.len(),
            if key_hits.is_empty() {
                String::new()
            } else {
                let mut m = std::collections::BTreeMap::new();
                for h in &key_hits {
                    let k = format!(
                        "{}/{}@{}",
                        match h.enc {
                            Enc::Utf8 => "utf8",
                            Enc::Utf16Le => "utf16le",
                            Enc::Raw => "raw",
                        },
                        match h.part {
                            Part::Full => "full",
                            Part::Mid => "mid",
                            Part::Tail => "tail",
                        },
                        h.region
                    );
                    *m.entry(k).or_insert(0usize) += 1;
                }
                format!("{m:?}")
            }
        );
        match mode.as_str() {
            // Anahtar bu modlarda bellekte KALMAMALI.
            "dpapi" | "keyread" | "encrypted-closed" => key_gate_leaks += key_hits.len(),
            "dpapi-legacy" | "keyread-byvalue" => println!(
                "   (bilgi: anahtar DEGERLE tasiniyor; yigin cercevelerinde bayat kopya kalabilir, eski desen; bkz. dpapi/keyread (DbKey, Box))"
            ),
            "encrypted" => println!(
                "   (acik depo: anahtarin SQLCipher baglaminda bulunmasi tasarim geregi beklenir; bilgi amacli)"
            ),
            _ => {}
        }
    }

    if !control_ok {
        println!(
            "SONUC: KONTROL BASARISIZ (denetci kasitli sizintiyi yakalayamadi; sonuclar guvenilmez)"
        );
        std::process::exit(2);
    }
    if text_leaks > 0 || key_gate_leaks > 0 {
        println!(
            "SONUC (on-olcum, resmi Gate 2 degil): ham_sir={text_leaks} kapali/dpapi_anahtar={key_gate_leaks} -> FAIL"
        );
        std::process::exit(1);
    }
    println!(
        "SONUC (on-olcum, resmi Gate 2 degil): ham sir ve kapali-durum anahtar bulgusu yok -> PASS"
    );
}

#[cfg(not(windows))]
fn main() {
    eprintln!("gate2-audit yalnizca Windows'ta calisir");
    std::process::exit(2);
}
