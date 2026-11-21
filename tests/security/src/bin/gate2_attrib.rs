//! Gate 2 atıf koşuları: bellek kalıntısının kaynağını (sensör, guard, anahtar ömrü) ayırır.
//! Yalnızca uygulamaya ait (APP_OWNED) bulgular sayılır. Veriler sentetiktir.

#[cfg(windows)]
#[path = "../common.rs"]
mod common;
#[cfg(windows)]
#[path = "../synthetic.rs"]
mod synthetic;

#[cfg(windows)]
fn main() {
    use s_gate2::scan::Secret;
    use s_gate2::session::run_session_hook;
    use s_gate2::winutil::{SyntheticWindow, clear_clipboard, set_clipboard_text};
    use std::collections::BTreeMap;
    use std::time::Duration;

    let syn = synthetic::synthetic_set();
    let raw_secrets: Vec<Secret> = syn
        .raw
        .iter()
        .map(|(i, t)| Secret::new(i.clone(), t.clone()))
        .collect();
    let exe = common::target_exe();
    println!("Gate 2 atif kosulari: hedef={}", exe.display());

    // (ad, hedef modu, pencere (baslik, govde), pano icerikleri)
    type Scenario<'a> = (&'a str, &'a str, Option<(String, String)>, Vec<String>);
    let full_win = Some((syn.title.clone(), syn.body.clone()));
    let title_only = Some((syn.title.clone(), String::new()));
    let scenarios: Vec<Scenario> = vec![
        (
            "S1 sensor: pencere(baslik+UIA govde)+pano",
            "sensor",
            full_win.clone(),
            syn.clips.clone(),
        ),
        (
            "S2 sensor: yalniz pencere (baslik+UIA govde)",
            "sensor",
            full_win.clone(),
            vec![],
        ),
        (
            "S3 sensor: yalniz baslik (govde yok)",
            "sensor",
            title_only,
            vec![],
        ),
        ("S4 sensor: yalniz pano", "sensor", None, syn.clips.clone()),
        (
            "S5 sensor+guard: pencere+pano",
            "sensor-guard",
            full_win,
            syn.clips.clone(),
        ),
        (
            "K1 keystore ilk calistirma (generate->protect->open_encrypted->drop)",
            "keystore-first-run",
            None,
            vec![],
        ),
        (
            "K3 yalniz DbKey::generate+protect (DB yok)",
            "keystore-gen-protect",
            None,
            vec![],
        ),
        (
            "K5 yalniz DbKey::generate (protect YOK)",
            "keystore-gen-only",
            None,
            vec![],
        ),
        (
            "K6 DbKey::generate + 1 MiB rastgele bayt cekip atma (ezme deneyi)",
            "keystore-gen-only-flush",
            None,
            vec![],
        ),
        (
            "K7 DbKey::generate + olu yigin cercevesi silme (256 KiB)",
            "keystore-gen-only-stackscrub",
            None,
            vec![],
        ),
        (
            "K8 s-guard OLMADAN getrandom -> Box (kontrol)",
            "keystore-rng-only",
            None,
            vec![],
        ),
        (
            "K4 denetci blobu -> DbKey::load -> open_encrypted -> drop (generate/protect yok)",
            "keystore-load-open",
            None,
            vec![],
        ),
        (
            "K2 keystore yeniden yukleme (DbKey::load->open_encrypted->drop)",
            "keystore-reload",
            None,
            vec![],
        ),
    ];

    let only: Option<String> = std::env::args()
        .position(|x| x == "--only")
        .and_then(|i| std::env::args().nth(i + 1));
    let mut any_owned = false;
    let mut zero_fail = false;
    for (name, mode, window, clips) in scenarios {
        if only.as_ref().is_some_and(|o| !name.contains(o.as_str())) {
            continue;
        }
        let is_key = mode.starts_with("keystore");
        let hook = |db_dir: Option<&std::path::Path>| -> Vec<Secret> {
            if is_key {
                // Hedefin urettigi anahtari denetci blobdan cozer (ayni kullanici) ve arama listesine ekler.
                let dir = db_dir.expect("db-dir");
                let mut key = [0u8; 32];
                if let Ok(plain) = std::fs::read(dir.join("key-plain.bin")) {
                    key.copy_from_slice(&plain);
                } else {
                    let blob = std::fs::read(dir.join("key.bin")).expect("key.bin");
                    let k = s_guard::DbKey::load(&blob).expect("DbKey::load");
                    key.copy_from_slice(k.expose());
                }
                return common::key_secrets(&key);
            }
            let win = window
                .as_ref()
                .map(|(t, b)| SyntheticWindow::open(t, b).expect("pencere"));
            std::thread::sleep(Duration::from_secs(4));
            for c in &clips {
                set_clipboard_text(c).expect("pano");
                std::thread::sleep(Duration::from_millis(2500));
            }
            drop(win);
            std::thread::sleep(Duration::from_secs(3));
            Vec::new()
        };
        let provided = if mode == "keystore-load-open" {
            let k = s_guard::DbKey::generate();
            let blob = k.protect().expect("protect");
            let path =
                std::env::temp_dir().join(format!("s-gate2-attrib-{}.blob", std::process::id()));
            std::fs::write(&path, blob).expect("blob");
            let mut kb = [0u8; 32];
            kb.copy_from_slice(k.expose());
            Some((path, kb))
        } else {
            None
        };
        let blob_arg = provided
            .as_ref()
            .map(|(p, _)| p.to_string_lossy().into_owned());
        let extra: Vec<&str> = match &blob_arg {
            Some(p) => vec!["--key-blob", p.as_str()],
            None => vec![],
        };
        let known_key = provided.as_ref().map(|(_, k)| *k);
        let mut hook2 = |d: Option<&std::path::Path>| -> Vec<Secret> {
            match known_key {
                Some(k) => common::key_secrets(&k),
                None => hook(d),
            }
        };
        let r = run_session_hook(
            &exe,
            mode,
            &[],
            &raw_secrets,
            &extra,
            None,
            Some(&mut hook2),
        );
        if let Some((p, _)) = &provided {
            let _ = std::fs::remove_file(p);
        }
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                println!("== {name}: HATA {e}");
                continue;
            }
        };
        clear_clipboard();
        let mut owned: BTreeMap<String, usize> = BTreeMap::new();
        let mut shared = 0usize;
        for h in &r.hits {
            if h.region.starts_with("private") || h.region.starts_with("stack") {
                *owned
                    .entry(format!("{} {:?}/{:?}", h.secret_id, h.enc, h.part))
                    .or_insert(0) += 1;
            } else {
                shared += 1;
            }
        }
        let n_owned: usize = owned.values().sum();
        any_owned |= n_owned > 0;
        // Arena A sifir tolerans: sensor/guard senaryolarinda (S*, G*) HER APP_OWNED bulgu ve HER alt surec (UIA isci,
        // bosta yedek dahil) bulgusu hatadir; K senaryolarinda yalnizca db-key Raw/Tail (K1, kabul edilmis) serbest.
        let child_owned: Vec<_> = r
            .child_hits
            .iter()
            .filter(|(_, h)| h.region.starts_with("private") || h.region.starts_with("stack"))
            .collect();
        println!(
            "   ALT_SUREC (UIA isci): bosta={} besleme_sonrasi={} APP_OWNED_bulgu={}",
            r.child_counts.0,
            r.child_counts.1,
            child_owned.len()
        );
        for (who, h) in &child_owned {
            println!(
                "   BULGU(ALT_SUREC) {who} {} {:?}/{:?}",
                h.secret_id, h.enc, h.part
            );
        }
        let key_ok = |k: &str| k.starts_with("db-key Raw/Tail");
        let strict_fail = if mode.starts_with("keystore") {
            owned.keys().any(|k| !key_ok(k)) || owned.values().sum::<usize>() > 1
        } else {
            n_owned > 0
        } || !child_owned.is_empty();
        zero_fail |= strict_fail;
        println!(
            "   SIFIR_TOLERANS: {}",
            if strict_fail { "IHLAL" } else { "TEMIZ" }
        );
        println!(
            "== {name} [{}]\n   APP_OWNED={n_owned}  OS_SHARED(mapped/image)={shared}",
            r.ready_line
        );
        let mut by_enc: BTreeMap<String, usize> = BTreeMap::new();
        for (k, n) in &owned {
            let enc = k
                .split(' ')
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            *by_enc.entry(enc).or_insert(0) += n;
        }
        println!("   kodlama_dagilimi={by_enc:?}");
        for (k, n) in owned.iter().filter(|(k, _)| k.contains("Utf8")) {
            println!("   UTF8_BULGU {k} x{n}");
        }
        let ids: std::collections::BTreeSet<&str> = owned
            .keys()
            .map(|k| k.split(' ').next().unwrap_or(""))
            .collect();
        println!("   bulunan_sirlar={ids:?}");
    }
    // ---- G*: guard'ın GERÇEK-BİÇİMLİ girdilerle (aynı başlık/UIA metni/pano) izole sınaması (sensör yok)
    {
        use s_gate2::spec::{KIND_ACCESSIBILITY, KIND_CLIPBOARD, PacketSpec};
        let mk = |kind: u8, title: &str, text: &str| PacketSpec {
            kind,
            process_name: "Gate2Synthetic.exe".into(),
            title: title.into(),
            text: text.into(),
        };
        let guard_cases: Vec<(&str, Vec<PacketSpec>)> = vec![
            (
                "G1 guard: yalniz baslik (stripe, govde bos)",
                vec![mk(KIND_ACCESSIBILITY, &syn.title, "")],
            ),
            (
                "G2 guard: yalniz UIA govde (baslik zararsiz)",
                vec![mk(KIND_ACCESSIBILITY, "Gate2 Synthetic", &syn.body)],
            ),
            (
                "G3 guard: yalniz pano metinleri",
                syn.clips
                    .iter()
                    .map(|c| mk(KIND_CLIPBOARD, "Gate2 Synthetic", c))
                    .collect(),
            ),
            (
                "G0 baslangic (guard YOK, harness tabani): G3 girdileri",
                syn.clips
                    .iter()
                    .map(|c| mk(KIND_CLIPBOARD, "Gate2 Synthetic", c))
                    .collect(),
            ),
        ];
        for (name, specs) in guard_cases {
            if only.as_ref().is_some_and(|o| !name.contains(o.as_str())) {
                continue;
            }
            let gmode = if name.starts_with("G0") {
                "baseline"
            } else {
                "process"
            };
            match s_gate2::session::run_session(&exe, gmode, &specs, &raw_secrets, &[]) {
                Ok(r) => {
                    let mut owned: BTreeMap<String, usize> = BTreeMap::new();
                    for h in &r.hits {
                        if h.region.starts_with("private") || h.region.starts_with("stack") {
                            *owned
                                .entry(format!("{} {:?}/{:?}", h.secret_id, h.enc, h.part))
                                .or_insert(0) += 1;
                        }
                    }
                    println!(
                        "== {name} [{}]
   APP_OWNED={}",
                        r.ready_line,
                        owned.values().sum::<usize>()
                    );
                    for (k, n) in &owned {
                        println!("   BULGU {k} x{n}");
                    }
                    any_owned |= !owned.is_empty();
                }
                Err(e) => println!("== {name}: HATA {e}"),
            }
        }
    }
    if zero_fail {
        println!("SONUC (sifir tolerans): IHLAL VAR");
    } else {
        println!("SONUC (sifir tolerans): TEMIZ");
    }
    println!(
        "SONUC (atif): {}",
        if any_owned {
            "APP_OWNED kalinti VAR"
        } else {
            "APP_OWNED kalinti YOK"
        }
    );
    if zero_fail {
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("gate2-attrib yalnizca Windows'ta calisir");
    std::process::exit(2);
}
