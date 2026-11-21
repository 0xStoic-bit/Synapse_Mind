//! Resmi Gate 2 harness'i: GERÇEK uygulama ikilisi (`synapse-mind.exe`) üzerinde bellek dökümü.
//!
//! `gate2-app [--exe <yol>] [--skip-search] [--keep-going]`
//!
//! PANEL EVRESI OTOMATIKTIR (v0.1.1): Hafıza Paneli, klavye enjeksiyonu (Ctrl+M) yerine uygulamanın test-only
//! `gate2-hooks` kancasıyla açılır. Bu yüzden `--exe` ile verilen ikili MUTLAKA
//! `cargo build --manifest-path src-tauri/Cargo.toml --features gate2-hooks` ile derlenmiş olmalıdır (varsayılan yol
//! `src-tauri/target/debug/synapse-mind.exe`; yayın/`cargo tauri build` ikilisi kancayı İÇERMEZ). Kanca yoksa harness
//! panel evresini ÇALIŞTIRMAZ ve uygulamayı başlatmadan çıkış kodu 2 ile açıkça bildirir (`--skip-search` yalnız
//! arama + panel evrelerini birlikte atlar). Kanca: ikinci çağrı `synapse-mind.exe --gate2-open-panel`
//! (adlı olay `Local\SynapseMind-Gate2-OpenPanel`).
//!
//! Akış: (1) uygulama izole `LOCALAPPDATA` ile başlatılır (kullanıcının gerçek Synapse Mind verisine DOKUNULMAZ),
//! (2) gerçek sensör yoluyla SENTETİK sırlar beslenir: sentetik bir üst düzey pencere (başlık + UIA ile okunan
//! çok satırlı metin) ve üç sentetik pano içeriği, (3) boşta DÖKÜM (uygulama + tüm WebView2 alt süreçleri),
//! (4) Alt+Space + yazılan sentetik arama (WebView içeriği için pozitif kontrol işareti) sonrası ikinci DÖKÜM,
//! (5) her döküm: HAM sırlar + DbKey (ham/hex/UTF-16/`x'hex'`) + SQLCipher türetilmiş HMAC anahtarı aranır,
//! (6) canlılık: uygulama kapatıldıktan sonra şifreli DB gerçek anahtarla açılıp olayların maskeli geldiği ve ham
//! sırrın bulunmadığı doğrulanır (aksi halde "0 bulgu" anlamsız olabilirdi).
//! Pozitif kontroller: denetçinin kendi süreci (ham sırlar bellekte) ve WebView'e yazılan işaret.
//!
//! Çıkış: 0 = PASS; 1 = bulgu (VETO); 2 = kontrol/canlılık başarısız (sonuç GÜVENİLMEZ).
//! TÜM VERİLER SENTETİKTİR. Pano ve odak etkilenir (iş bitince pano temizlenir).

#[cfg(windows)]
#[path = "../common.rs"]
mod common;
#[cfg(windows)]
#[path = "../synthetic.rs"]
mod synthetic;

#[cfg(windows)]
fn main() {
    use s_gate2::dump::TempDir;
    use s_gate2::scan::{Secret, parse_layout, scan_file};
    use s_gate2::sqlcipher::{derive_hmac_key, verify_page1};
    use s_gate2::winutil::{
        SyntheticWindow, clear_clipboard, press_alt_space, press_ctrl_m, press_enter, process_tree,
        set_clipboard_text, type_text, write_full_dump_pid,
    };
    use std::collections::BTreeMap;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let args: Vec<String> = std::env::args().collect();
    let skip_search = args.iter().any(|a| a == "--skip-search");
    let exe = args
        .iter()
        .position(|a| a == "--exe")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../src-tauri/target/debug/synapse-mind.exe")
        });
    let exe = exe.canonicalize().unwrap_or(exe);
    println!("Resmi Gate 2: ikili={} ", exe.display());
    if !exe.exists() {
        println!("SONUC: ikili bulunamadi");
        std::process::exit(2);
    }
    // Kanca korumasi: panel evresi (arama ile birlikte) kancasiz ikiliyle calistirilmaz.
    let hook_probe = probe_gate2_hook(&exe);
    println!("Gate2 panel kancasi (ikilide bayrak+olay adi): {hook_probe}");
    if !skip_search && !hook_probe.present() {
        println!(
            "SONUC: panel kancasi YOK ({hook_probe}); ikili `cargo build --manifest-path src-tauri/Cargo.toml --features gate2-hooks` ile derlenmeli (yayin ikilisinde kanca bilincli olarak bulunmaz). Panel evresi calistirilmadi; sonuc GUVENILMEZ"
        );
        std::process::exit(2);
    }

    // ---- sentetik sırlar (Gate 1 üreteçleriyle; `synthetic.rs`, atıf koşularıyla ortak)
    let syn = synthetic::synthetic_set();
    let mut rng = s_redteam::synth::Rng::new(0x6A7E_2026_1119_00FF);
    let marker = format!("g2ctl-{}-marker", rng.string(b"0123456789abcdef", 12));
    let window_title = syn.title.clone();
    let window_body = syn.body.clone();
    let clips = syn.clips.clone();
    let raw_values = syn.raw.clone();
    let raw_secrets: Vec<Secret> = raw_values
        .iter()
        .map(|(id, t)| Secret::new(id.clone(), t.clone()))
        .collect();

    // ---- uygulamayı izole veri dizini ile başlat
    let data_root = TempDir::new("app").expect("temp dir");
    // Özgün ikili KİLİTLENMESİN (başka ajan release derleyebilsin): kopyası çalıştırılır.
    let run_exe = data_root.path().join("bin").join("synapse-mind.exe");
    std::fs::create_dir_all(run_exe.parent().unwrap()).expect("bin dizini");
    std::fs::copy(&exe, &run_exe).expect("ikili kopyalanamadi");
    let mut cmd = Command::new(&run_exe);
    cmd.env("LOCALAPPDATA", data_root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(if std::env::var_os("GATE2_APP_STDERR").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        });
    let mut child = cmd.spawn().expect("uygulama baslatilamadi");
    let root_pid = child.id();
    let db_path = data_root.path().join("SynapseMind").join("memory.db");
    let key_path = data_root.path().join("SynapseMind").join("key.bin");
    for _ in 0..120 {
        if db_path.exists() && key_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !db_path.exists() {
        let _ = child.kill();
        println!("SONUC: uygulama veri dizinini olusturmadi (baska ornek calisiyor olabilir)");
        std::process::exit(2);
    }
    std::thread::sleep(Duration::from_secs(6));
    if args.iter().any(|a| a == "--dry-overlay") {
        // Tanı: yalnızca overlay odak adımı (dökümsüz, işaret YAZILMAZ); resmi koşuyla aynı `ensure_overlay_foreground`.
        let ok = s_gate2::winutil::ensure_overlay_foreground(
            &mut || process_tree(root_pid).iter().map(|p| p.pid).collect(),
            "Synapse Mind",
            5,
            Duration::from_secs(6),
            &mut |l| println!("   {l}"),
        );
        println!("dry-overlay: on_plan_dogrulandi={ok}");
        let _ = Command::new("taskkill")
            .args(["/PID", &root_pid.to_string(), "/T", "/F"])
            .status();
        let _ = child.wait();
        std::process::exit(if ok { 0 } else { 2 });
    }
    if args.iter().any(|a| a == "--dry-panel") {
        // Hızlı kontrol: yalnızca Alt+Space + Ctrl+M ile panelin açıldığını doğrular (döküm yok).
        press_alt_space();
        std::thread::sleep(Duration::from_millis(2000));
        type_text("abc");
        std::thread::sleep(Duration::from_millis(1000));
        if std::env::var_os("GATE2_DRY_ESC").is_some() {
            // Tanı: Escape overlay'i gizlemeli (aynı keydown + invoke yolu).
            s_gate2::winutil::press_escape();
            std::thread::sleep(Duration::from_millis(1500));
            let pids: Vec<u32> = process_tree(root_pid).iter().map(|p| p.pid).collect();
            println!(
                "escape sonrasi gorunur={:?}",
                s_gate2::winutil::visible_window_titles(&pids)
            );
        }
        for i in 0..8 {
            let pids0: Vec<u32> = process_tree(root_pid).iter().map(|p| p.pid).collect();
            if i == 0 {
                press_ctrl_m();
            } else if let Some(h) = s_gate2::winutil::find_window_titled(&pids0, "Synapse Mind") {
                // Fare ile durum çubuğundaki "Hafıza Paneli" düğmesi: sağ alt şeritte yatay tarama.
                if let Some((l, t, r, b)) = s_gate2::winutil::window_rect(h) {
                    let _ = t;
                    let x = r - 40 - (i - 1) * 45 - (r - l) / 6;
                    let y = b - 26;
                    println!("   tikla({x},{y}) pencere=({l},{t},{r},{b})");
                    s_gate2::winutil::click_at(x, y);
                }
            }
            std::thread::sleep(Duration::from_millis(1800));
            let pids: Vec<u32> = process_tree(root_pid).iter().map(|p| p.pid).collect();
            let titles = s_gate2::winutil::visible_window_titles(&pids);
            println!(
                "deneme {i}: gorunur_pencereler={titles:?} tum={:?}",
                s_gate2::winutil::all_window_titles(&pids)
            );
            if titles.iter().any(|t| t.contains("Hafıza")) {
                break;
            }
        }
        let _ = Command::new("taskkill")
            .args(["/PID", &root_pid.to_string(), "/T", "/F"])
            .status();
        let _ = child.wait();
        return;
    }

    // ---- anahtar materyali (kullanıcı hesabıyla DPAPI çözülür; yalnızca denetçi bilir)
    let blob = std::fs::read(&key_path).expect("key.bin");
    let dbkey = s_guard::DbKey::load(&blob).expect("DbKey::load");
    let mut key = [0u8; 32];
    key.copy_from_slice(dbkey.expose());
    let mut header = [0u8; 16];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(&db_path).expect("db");
        f.read_exact(&mut header).expect("db baslik");
    }
    let hmac_key = derive_hmac_key(&key, &header);
    let page1 = std::fs::read(&db_path).unwrap_or_default();
    let hmac_verified = verify_page1(&page1, &hmac_key);
    println!("SQLCipher HMAC turetimi dogrulandi (1. sayfa HMAC eslesmesi): {hmac_verified}");
    let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    let mut key_secrets = common::key_secrets(&key);
    key_secrets.push(Secret::key("hmac-key", &hmac_key, hex(&hmac_key)));
    key_secrets.push(Secret::new(
        "hmac-key-hex-upper",
        hex(&hmac_key).to_uppercase(),
    ));
    let marker_secret = Secret::new("webview-marker", marker.clone());

    let mut all: Vec<Secret> = raw_secrets.clone();
    let n_raw = all.len();
    let n_key = key_secrets.len();
    all.extend(key_secrets);
    all.push(marker_secret);
    let marker_idx = all.len() - 1;
    // Panel açıldı mı kanıtı: panel sayfasının başlığı (yalnız panel.html yüklenince WebView belleğinde bulunur).
    all.push(Secret::new("panel-title", "Synapse Mind · Hafıza Paneli"));
    let panel_idx = all.len() - 1;
    // Gerçek (gömülü) arayüz pozitif kontrolü: hata sayfası ("localhost:1420 reddetti") değil, derlenmiş arayüzün metinleri.
    all.push(Secret::new(
        "ui-overlay-text",
        "Aramak için yazmaya başlayın",
    ));
    let ui_overlay_idx = all.len() - 1;
    all.push(Secret::new("ui-panel-text", "Kara listedeki uygulama"));
    let ui_panel_idx = all.len() - 1;
    let mut ui_overlay_seen: Vec<String> = Vec::new();
    let mut ui_panel_seen: Vec<String> = Vec::new();
    let mut panel_seen: Vec<String> = Vec::new();
    let mut panel_window_stages: Vec<String> = Vec::new();
    let describe = |idx: usize| -> &'static str {
        if idx < n_raw {
            "HAM_SIR"
        } else if idx < n_raw + n_key {
            "ANAHTAR"
        } else {
            "ISARET"
        }
    };

    // ---- döküm + tarama
    let mut findings: Vec<String> = Vec::new();
    let mut marker_seen_in: Vec<String> = Vec::new();
    let mut dumped = 0usize;
    let mut dump_errors: Vec<String> = Vec::new();
    // APP_OWNED: sürecin kendi özel bellek/yığını. OS_SHARED: `mapped`/`image`/`unknown` (masaüstü yığını gibi
    // oturum-genel paylaşımlı bölümler; aynı sırların ilgisiz bir süreçte (explorer) de görülmesiyle doğrulanır).
    let owned = |region: &str| region.starts_with("private") || region.starts_with("stack");
    let mut os_shared: Vec<String> = Vec::new();
    let role_of = |p: &s_gate2::winutil::ProcInfo, root: u32| -> &'static str {
        if p.pid == root {
            "APP"
        } else if p.exe.eq_ignore_ascii_case("synapse-mind.exe") {
            "UIA_ISCI" // tek kullanımlık UIA işçi alt süreci (boşta yedek dahil)
        } else if p.exe.eq_ignore_ascii_case("msedgewebview2.exe") {
            "WEBVIEW2"
        } else {
            "DIGER"
        }
    };
    let mut k1_accepted: Vec<String> = Vec::new();
    let uia_cnt = std::cell::Cell::new(0usize);
    let mut roles_seen: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let oz_only = args.iter().any(|a| a == "--oz-only");
    let mut stage_dump = |stage: &str, root: u32, only_workers: bool| {
        if oz_only {
            return; // hızlı OZ_KAYIT tekrar koşusu: döküm yok
        }
        let mut tree = process_tree(root);
        {
            let pids: Vec<u32> = tree.iter().map(|p| p.pid).collect();
            let titles = s_gate2::winutil::visible_window_titles(&pids);
            println!("   gorunur_pencereler={titles:?}");
            if titles.iter().any(|t| t.contains("Hafıza")) {
                panel_window_stages.push(stage.to_string());
            }
        }
        // UIA işçileri (kısa ömürlü; her odak çıkarımında yenilenir) EN ÖNCE dökülür: yavaş WebView dökümleri sırasında yok olmasınlar.
        tree.sort_by_key(|p| match role_of(p, root) {
            "UIA_ISCI" => 0,
            "APP" => 1,
            _ => 2,
        });
        if only_workers {
            tree.retain(|p| role_of(p, root) == "UIA_ISCI");
        }
        println!("-- evre={stage} surec_agaci={}", tree.len());
        for p in &tree {
            let f = s_gate2::dump::TempFile::new("app", "dmp");
            match write_full_dump_pid(p.pid, f.path()) {
                Ok(bytes) => {
                    dumped += 1;
                    *roles_seen.entry(role_of(p, root)).or_insert(0) += 1;
                    if role_of(p, root) == "UIA_ISCI" {
                        uia_cnt.set(uia_cnt.get() + 1);
                    }
                    let hits = scan_file(f.path(), &all).unwrap_or_default();
                    let layout = parse_layout(f.path()).unwrap_or_default();
                    let mut app_by: BTreeMap<(&'static str, String, String), usize> =
                        BTreeMap::new();
                    let mut shared_by: BTreeMap<String, usize> = BTreeMap::new();
                    for h in &hits {
                        let kind = describe(h.secret);
                        if h.secret == marker_idx {
                            marker_seen_in.push(format!("{}:{}", p.exe, p.pid));
                            continue;
                        }
                        if h.secret == panel_idx {
                            panel_seen.push(format!("{stage}/{}:{}", p.exe, p.pid));
                            continue;
                        }
                        if h.secret == ui_overlay_idx {
                            ui_overlay_seen.push(format!("{stage}/{}:{}", p.exe, p.pid));
                            continue;
                        }
                        if h.secret == ui_panel_idx {
                            ui_panel_seen.push(format!("{stage}/{}:{}", p.exe, p.pid));
                            continue;
                        }
                        let region = layout.locate(h.offset).region;
                        if owned(&region) {
                            let enc = format!("{:?}/{:?}", h.enc, h.part);
                            *app_by
                                .entry((kind, all[h.secret].id.clone(), enc))
                                .or_insert(0) += 1;
                        } else {
                            *shared_by.entry(all[h.secret].id.clone()).or_insert(0) += 1;
                        }
                    }
                    println!(
                        "   [{:<8}] {:<24} pid={:<6} dump={:>7.1} MiB  hits={}  APP_OWNED={}  OS_SHARED(mapped/image)={}",
                        role_of(p, root),
                        p.exe,
                        p.pid,
                        bytes as f64 / 1048576.0,
                        hits.len(),
                        app_by.values().sum::<usize>(),
                        shared_by.values().sum::<usize>()
                    );
                    for ((k, id, enc), n) in &app_by {
                        let role = role_of(p, root);
                        // Sınıflar: K1 = DbKey'in YALNIZCA son 12/32 baytı (OS RNG kalıntısı; tek kabul edilmiş ayrık sınıf).
                        // Diğer her şey SIFIR TOLERANSTIR: UTF8, BSTR/UTF-16 (sensör), WEBVIEW2, tam/hex/UTF-16 DbKey, HMAC,
                        // boşta yedek işçi.
                        let class = if id == "db-key" && enc == "Raw/Tail" {
                            "K1_KABUL"
                        } else if enc.starts_with("Utf8") {
                            "UTF8"
                        } else if k == &"ANAHTAR" {
                            "ANAHTAR"
                        } else if role == "WEBVIEW2" {
                            "WEBVIEW2"
                        } else if role == "UIA_ISCI" {
                            "UIA_ISCI"
                        } else {
                            "UTF16_SENSOR"
                        };
                        let line = format!(
                            "{stage}/{role}:{}:{} [{class}] [{k}] {id} {enc} x{n}",
                            p.exe, p.pid
                        );
                        if class == "K1_KABUL" {
                            println!("      KABUL(K1) {line}");
                            k1_accepted.push(line);
                        } else {
                            println!("      BULGU(APP_OWNED) {line}");
                            findings.push(line);
                        }
                    }
                    for (id, n) in &shared_by {
                        os_shared.push(format!("{stage}/{}:{} {id} x{n}", p.exe, p.pid));
                    }
                }
                Err(e) => {
                    println!("   {:<28} pid={:<6} DOKUM ALINAMADI: {e}", p.exe, p.pid);
                    dump_errors.push(format!("{}:{} {e}", p.exe, p.pid));
                }
            }
        }
    };
    // Evre dökümü; işçi dökümü alınamadıysa (süreç tam o anda yenilendi) yalnızca işçileri 8 kez daha dene.
    macro_rules! stage {
        ($stage:expr) => {{
            let before = uia_cnt.get();
            stage_dump($stage, root_pid, false);
            let mut tries = 0;
            while uia_cnt.get() == before && tries < 8 {
                std::thread::sleep(Duration::from_millis(200));
                stage_dump(&format!("{}-isci-tekrar", $stage), root_pid, true);
                tries += 1;
            }
        }};
    }
    // Arena A: HİÇ pencere beslenmeden önce, boşta bekleyen tek kullanımlık UIA yedek işçisi dahil tüm süreçler.
    stage!("baslangic-yedek-bosta");
    // ---- gerçek sensör yolu: pencere + pano
    let win = SyntheticWindow::open(&window_title, &window_body).expect("sentetik pencere");
    std::thread::sleep(Duration::from_secs(4));
    for c in &clips {
        set_clipboard_text(c).expect("pano");
        std::thread::sleep(Duration::from_millis(2500));
    }
    win.focus();
    std::thread::sleep(Duration::from_secs(3));

    stage!("bosta");
    // Sentetik pencere kapanınca masaüstü yığınındaki başlık/metin serbest kalır: OS_SHARED artığı ayrışır.
    drop(win);
    std::thread::sleep(Duration::from_secs(3));
    stage!("pencere-kapali");

    if !skip_search {
        // Girdi YALNIZCA ön plan overlay'e aitse enjekte edilir (aksi halde kullanıcının başka uygulamasına yazılırdı).
        // Kök neden (v0.1.1): eski adım tek Alt+Space + 2 sn uyku + yalnız ön plan yoklamasıydı; overlay görünür değilse
        // (kısayol gecikti/yutuldu) `activate_window_titled` pencere bulamıyor ve Alt+Space bir daha basılmıyordu.
        // Şimdi: görünürlük beklenir, gizliyse Alt+Space yeniden basılır, görünür-ama-arkadaysa odak zorlanır; her
        // denemenin ön plan süreci/başlığı loglanır. Doğrulanmadıkça işaret yazılmaz.
        let mut fg_ok = s_gate2::winutil::ensure_overlay_foreground(
            &mut || process_tree(root_pid).iter().map(|p| p.pid).collect(),
            "Synapse Mind",
            5,
            Duration::from_secs(6),
            &mut |l| println!("   {l}"),
        );
        if !fg_ok {
            fg_ok = s_gate2::winutil::ensure_overlay_foreground(
                &mut || process_tree(root_pid).iter().map(|p| p.pid).collect(),
                "Synapse Mind",
                3,
                Duration::from_secs(8),
                &mut |l| println!("   {l}"),
            );
        }
        if fg_ok {
            type_text(&marker);
        } else {
            println!(
                "-- UYARI: overlay on planda degil; isaret YAZILMADI (baska uygulamaya yazmamak icin)"
            );
        }
        std::thread::sleep(Duration::from_millis(1500));
        if fg_ok {
            press_enter();
        }
        std::thread::sleep(Duration::from_millis(3500));
        stage!("arama-sonrasi");
        // Hafıza Paneli AÇIKKEN (panel penceresi exclude_from_capture'lı, dökümü engellemez). Panel, klavye enjeksiyonu
        // yerine `gate2-hooks` kancasıyla açılır: çalışan örneğe ikinci çağrı `--gate2-open-panel` (adlı olay sinyali).
        // Panel açılana (görünür "Hafıza" penceresi) kadar en çok 3 deneme; her deneme izole LOCALAPPDATA ile yapılır.
        let mut hook_log: Vec<String> = Vec::new();
        for attempt in 1..=3 {
            let mut helper = match Command::new(&run_exe)
                .arg("--gate2-open-panel")
                .env("LOCALAPPDATA", data_root.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    hook_log.push(format!("deneme {attempt}: yardimci baslatilamadi: {e}"));
                    continue;
                }
            };
            // Yardımcı olayı sinyalleyip hemen çıkar; çıkmazsa (kanca yok / birincil örnek oldu) öldürülür.
            let started = std::time::Instant::now();
            let status = loop {
                match helper.try_wait() {
                    Ok(Some(st)) => break Some(st),
                    Ok(None) if started.elapsed() < Duration::from_secs(15) => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    _ => {
                        let _ = helper.kill();
                        let _ = helper.wait();
                        break None;
                    }
                }
            };
            hook_log.push(format!(
                "deneme {attempt}: yardimci_cikis={}",
                status.map_or("ZAMAN_ASIMI(oldurüldü)".to_string(), |s| s.to_string())
            ));
            std::thread::sleep(Duration::from_millis(2500));
            let pids: Vec<u32> = process_tree(root_pid).iter().map(|p| p.pid).collect();
            if s_gate2::winutil::visible_window_titles(&pids)
                .iter()
                .any(|t| t.contains("Hafıza"))
            {
                hook_log.push("panel penceresi gorundu".to_string());
                break;
            }
        }
        println!("-- PANEL_KANCASI: {hook_log:?}");
        std::thread::sleep(Duration::from_millis(1500));
        stage!("panel-acik");
    }

    // ---- pozitif kontrol: denetçinin kendi süreci (ham sırlar bellekte) bulunmalı
    let self_dump = s_gate2::dump::TempFile::new("self", "dmp");
    let self_ok = write_full_dump_pid(std::process::id(), self_dump.path())
        .ok()
        .map(|_| scan_file(self_dump.path(), &all).unwrap_or_default())
        .map(|h| {
            let raw_found: std::collections::BTreeSet<usize> =
                h.iter().map(|x| x.secret).filter(|&i| i < n_raw).collect();
            println!(
                "-- KONTROL denetci-kendi-sureci: {} / {} ham sir bulundu",
                raw_found.len(),
                n_raw
            );
            raw_found.len() * 2 >= n_raw
        })
        .unwrap_or(false);
    drop(self_dump);

    // ---- OS_SHARED doğrulaması: ilgisiz bir süreçte (explorer) aynı sırlar `mapped` bölgesinde görülüyor mu?
    let mut explorer_note = String::from("explorer dokumu alinamadi");
    if let Some(p) = s_gate2::winutil::list_processes()
        .into_iter()
        .find(|p| p.exe.eq_ignore_ascii_case("explorer.exe"))
    {
        let f = s_gate2::dump::TempFile::new("expl", "dmp");
        if write_full_dump_pid(p.pid, f.path()).is_ok() {
            let hits = scan_file(f.path(), &all[..n_raw]).unwrap_or_default();
            let layout = parse_layout(f.path()).unwrap_or_default();
            let ids: std::collections::BTreeSet<String> = hits
                .iter()
                .filter(|h| !owned(&layout.locate(h.offset).region))
                .map(|h| all[h.secret].id.clone())
                .collect();
            explorer_note = format!(
                "explorer.exe (Synapse Mind ile ilgisiz) `mapped/image` bolgesinde {} ham sir gorundu: {ids:?}",
                ids.len()
            );
        }
    }
    println!("-- KONTROL OS_SHARED: {explorer_note}");
    println!(
        "-- OS_SHARED (mapped/image) toplam eslesme grubu: {} (uygulamanin sorumlulugunda DEGIL)",
        os_shared.len()
    );

    // ---- uygulamayı kapat, veriyi doğrula (canlılık + diskte ham sır yok)
    clear_clipboard();
    let _ = Command::new("taskkill")
        .args(["/PID", &root_pid.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.wait();
    std::thread::sleep(Duration::from_secs(2));

    let disk_hits = scan_file(&db_path, &all[..n_raw]).unwrap_or_default().len();
    println!("-- DISK memory.db icinde ham sir eslesmesi: {disk_hits} (sifreli dosya: 0 beklenir)");
    let (live, oz_kayit) = liveness(&db_path, &key, &raw_values, &marker);
    println!("-- CANLILIK: {live}");
    println!("-- OZ_KAYIT (sifir tolerans): {oz_kayit}");
    if oz_only {
        std::process::exit(if oz_kayit == 0 { 0 } else { 1 });
    }

    // ---- karar
    let marker_ok = !marker_seen_in.is_empty();
    println!(
        "-- KONTROL webview-isareti (arama kutusuna yazilan sentetik isaret, UTF-16LE): {}",
        if skip_search {
            "atlandi".to_string()
        } else if marker_ok {
            format!("gorüldü {:?}", marker_seen_in)
        } else {
            "GORULMEDI".to_string()
        }
    );
    {
        let stages: std::collections::BTreeSet<&str> = panel_seen
            .iter()
            .filter_map(|x| x.split('/').next())
            .collect();
        println!(
            "-- KONTROL panel-acildi: gorunur 'Hafiza' penceresi evreleri={panel_window_stages:?} (panel.html basligi bellekte: {stages:?}; panel gate2-hooks kancasiyla acilir; acilmadiysa kontrol basarisiz sayilir)"
        );
    }
    println!(
        "-- dokum_alinan_surec={dumped} dokum_hatasi={}",
        dump_errors.len()
    );
    // Gömülü arayüz kanıtı: overlay arayüz metni WebView belleğinde; panel penceresi (görünür "Hafıza") ve panel arayüz metni.
    let stages_of = |v: &Vec<String>| -> std::collections::BTreeSet<String> {
        v.iter()
            .filter_map(|x| x.split('/').next().map(str::to_string))
            .collect()
    };
    let ui_overlay_ok = !ui_overlay_seen.is_empty();
    let panel_window_ok = panel_window_stages.iter().any(|x| x == "panel-acik");
    let ui_panel_ok = ui_panel_seen.iter().any(|x| x.starts_with("panel-acik/"));
    println!(
        "-- KONTROL gomulu-arayuz: overlay_metni_webview_bellegi={ui_overlay_ok} evreler={:?}; panel_penceresi_panel-acik={panel_window_ok}; panel_metni_panel-acik={ui_panel_ok} evreler={:?}",
        stages_of(&ui_overlay_seen),
        stages_of(&ui_panel_seen)
    );
    let controls_ok = self_ok
        && (skip_search || (marker_ok && ui_overlay_ok && panel_window_ok && ui_panel_ok))
        && live.starts_with("OK")
        && dumped > 0
        && hmac_verified;
    if !controls_ok {
        println!(
            "SONUC: KONTROL/CANLILIK BASARISIZ (kendi-surec={self_ok}, isaret={marker_ok}, overlay_arayuz={ui_overlay_ok}, panel_penceresi(kanca ile acilmasi gerekir; ikili --features gate2-hooks ile derlenmis olmali)={panel_window_ok}, panel_arayuz={ui_panel_ok}, hmac_dogrulandi={hmac_verified}); sonuc guvenilmez"
        );
        std::process::exit(2);
    }
    // Sıfır tolerans sınıfları (Arena A): UTF8, UTF16_SENSOR (BSTR / s-sensor Vec<u16>), UIA_ISCI (boşta yedek dahil),
    // WEBVIEW2, ANAHTAR (tam/hex/HMAC), DISK. Tek kabul edilmiş ayrık sınıf: K1_KABUL (DbKey son 12/32 bayt, OS RNG).
    let mut by_class: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in &findings {
        let class = f
            .split('[')
            .nth(1)
            .and_then(|x| x.split(']').next())
            .unwrap_or("?");
        *by_class.entry(class.to_string()).or_insert(0) += 1;
    }
    println!(
        "-- SINIF OZETI: sifir_tolerans_bulgulari={by_class:?} DISK={disk_hits} OZ_KAYIT={oz_kayit} K1_KABUL(DbKey son 12/32 bayt, OS RNG)={} surec_rolleri={roles_seen:?}",
        k1_accepted.len()
    );
    if !roles_seen.contains_key("UIA_ISCI") {
        println!(
            "-- NOT: UIA_ISCI sureci gorulmedi (yedek isci bu ikilide yok ya da henuz baslamadi)"
        );
    }
    if !findings.is_empty() || disk_hits > 0 || oz_kayit > 0 {
        println!(
            "SONUC: {} sifir-tolerans bulgu (+disk {disk_hits}, +OZ_KAYIT {oz_kayit}) -> VETO",
            findings.len()
        );
        std::process::exit(1);
    }
    println!(
        "SONUC: uygulama + alt surec dokumlerinde ham sir / anahtar / HMAC anahtari bulunamadi -> PASS"
    );
}

/// `gate2-hooks` kancasının ikilide bulunup bulunmadığı: adlı olay (belirleyici) ve `--gate2-open-panel`
/// bayrağı (bilgi amaçlı) ASCII/UTF-16LE. Yayın ikilisinde ikisi de bulunmaz (overlay-ui-dev doğrulaması);
/// olay adı yoksa panel evresi çalıştırılmaz.
#[cfg(windows)]
struct HookProbe {
    flag: bool,
    event: bool,
}

#[cfg(windows)]
impl HookProbe {
    /// Adlı olay dizesi kancanın kesin işaretidir. 18 baytlık bayrak dizesi optimize yayın
    /// derlemesinde karşılaştırma için anlık değerlere (immediate) gömülebildiğinden ikilide düz
    /// metin olarak bulunmayabilir (v0.1.1 doğrulaması, 21.11.2026); bu yüzden tek başına
    /// belirleyici değildir. Kancanın gerçekten çalıştığı, panel penceresinin açılmasıyla ayrıca
    /// doğrulanır (`panel_window_ok`).
    fn present(&self) -> bool {
        self.event
    }
}

#[cfg(windows)]
impl std::fmt::Display for HookProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "bayrak(--gate2-open-panel)={} olay(Local\\SynapseMind-Gate2-OpenPanel)={}",
            self.flag, self.event
        )
    }
}

#[cfg(windows)]
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true;
    };
    let mut from = 0;
    while let Some(pos) = hay[from..].iter().position(|&b| b == first) {
        let at = from + pos;
        if hay.len() - at >= needle.len() && &hay[at + 1..at + needle.len()] == rest {
            return true;
        }
        from = at + 1;
    }
    false
}

#[cfg(windows)]
fn probe_gate2_hook(exe: &std::path::Path) -> HookProbe {
    let Ok(bytes) = std::fs::read(exe) else {
        return HookProbe {
            flag: false,
            event: false,
        };
    };
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let flag = "--gate2-open-panel";
    let event = "Local\\SynapseMind-Gate2-OpenPanel";
    HookProbe {
        flag: contains_bytes(&bytes, flag.as_bytes()) || contains_bytes(&bytes, &utf16(flag)),
        event: contains_bytes(&bytes, event.as_bytes()) || contains_bytes(&bytes, &utf16(event)),
    }
}

/// Uygulama kapandıktan sonra şifreli DB'yi gerçek anahtarla açıp olayların maskeli geldiğini doğrular.
#[cfg(all(windows, feature = "encrypted"))]
fn liveness(
    db: &std::path::Path,
    key: &[u8; 32],
    raw: &[(String, String)],
    marker: &str,
) -> (String, usize) {
    struct E;
    impl s_core::Embedder for E {
        fn embed_batch(&self, texts: &[&str]) -> s_core::Result<Vec<Vec<f32>>> {
            Ok(texts
                .iter()
                .map(|_| {
                    let mut v = vec![0.0_f32; s_core::EMBEDDING_DIM];
                    v[0] = 1.0;
                    v
                })
                .collect())
        }
    }
    // DB'nin kopyası üzerinde çalışılır (özgün dosya değişmesin).
    let copy = db.with_file_name("memory-liveness.db");
    if std::fs::copy(db, &copy).is_err() {
        return ("HATA: db kopyalanamadi".into(), 0);
    }
    let store = match s_core::MemoryStore::open_encrypted(&copy, key, E) {
        Ok(s) => s,
        Err(e) => return (format!("HATA: open_encrypted: {e}"), 0),
    };
    let conn = store.connection();
    let full: Vec<(String, String, String)> =
        match conn.prepare("SELECT process_name, sanitized_title, clean_text FROM events") {
            Ok(mut st) => st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map(|it| it.filter_map(Result::ok).collect())
                .unwrap_or_default(),
            Err(e) => return (format!("HATA: sorgu: {e}"), 0),
        };
    let rows: Vec<(String, String)> = full
        .iter()
        .map(|(_, t, c)| (t.clone(), c.clone()))
        .collect();
    // OZ_KAYIT: Synapse Mind'ın kendi süreçlerinden (overlay / WebView2 / UIA işçisi) kaynaklı olay VEYA overlay'e yazılan
    // sentetik arama işaretinin DB'ye düşmesi. İkisi de 0 olmalı.
    let own_events = full
        .iter()
        .filter(|(p, _, _)| {
            let p = p.to_ascii_lowercase();
            (p.contains("synapse-mind") || p.contains("s-recall")) || p.contains("msedgewebview2")
        })
        .count();
    let is_own = |p: &str| {
        let p = p.to_ascii_lowercase();
        (p.contains("synapse-mind") || p.contains("s-recall")) || p.contains("msedgewebview2")
    };
    // OZ_KAYIT yalnızca Synapse Mind'ın KENDİ süreç adıyla kaydedilen işaret sayılır; başka bir uygulamanın penceresine
    // yazılan işaret HARNESS yazımıdır (ayrı raporlanır; ön plan doğrulaması bunu önlemelidir).
    let marker_in_db = full
        .iter()
        .filter(|(p, t, c)| is_own(p) && (t.contains(marker) || c.contains(marker)))
        .count();
    let marker_foreign = full
        .iter()
        .filter(|(p, t, c)| !is_own(p) && (t.contains(marker) || c.contains(marker)))
        .count();
    if marker_foreign > 0 {
        println!(
            "   UYARI HARNESS_YAZIMI: isaret baska uygulama olaylarinda ({marker_foreign}); OZ_KAYIT degil"
        );
    }
    // Tanı (içerik YAZDIRILMAZ; yalnızca süreç adı ve alan adı): işaretin hangi olaylarda/alanlarda düştüğü.
    for (p, t, c) in full
        .iter()
        .filter(|(_, t, c)| t.contains(marker) || c.contains(marker))
    {
        println!(
            "   OZ_KAYIT_TANI: process_name={p} baslikta={} metinde={} metin_uzunlugu={}",
            t.contains(marker),
            c.contains(marker),
            c.len()
        );
    }
    let oz = own_events + marker_in_db;
    let total = rows.len();
    let redacted = rows
        .iter()
        .filter(|(t, c)| t.contains("[REDACTED_") || c.contains("[REDACTED_"))
        .count();
    let synthetic_title = rows
        .iter()
        .filter(|(t, _)| t.contains("Gate2 Synthetic"))
        .count();
    let leaked: Vec<&str> = raw
        .iter()
        .filter(|(_, v)| {
            v.len() >= 11
                && rows
                    .iter()
                    .any(|(t, c)| t.contains(v.as_str()) || c.contains(v.as_str()))
        })
        .map(|(id, _)| id.as_str())
        .collect();
    let ok = total > 0 && redacted > 0 && leaked.is_empty();
    (
        format!(
            "{} olay={total} maskeli_olay={redacted} sentetik_baslikli={synthetic_title} DB_metninde_ham_sir={leaked:?} OZ_KAYIT: kendi_surec_olayi={own_events} isaret_DBde={marker_in_db}",
            if ok { "OK" } else { "BASARISIZ" }
        ),
        oz,
    )
}

#[cfg(all(windows, not(feature = "encrypted")))]
fn liveness(
    _db: &std::path::Path,
    _key: &[u8; 32],
    _raw: &[(String, String)],
    _marker: &str,
) -> (String, usize) {
    (
        "BASARISIZ: canlilik dogrulamasi icin `--features encrypted` gerekir".into(),
        0,
    )
}

#[cfg(not(windows))]
fn main() {
    eprintln!("gate2-app yalnizca Windows'ta calisir");
    std::process::exit(2);
}
