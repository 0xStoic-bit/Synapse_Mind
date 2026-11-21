//! UIA işçi yaşam döngüsü izleyicisi: sentetik besleme sırasında alt süreçler 2 ms aralıkla
//! örneklenir; doğuş/ölüm, en yüksek eşzamanlılık ve yetim işçi sayısı raporlanır.

#[cfg(windows)]
#[path = "../synthetic.rs"]
mod synthetic;

#[cfg(windows)]
fn main() {
    use s_gate2::dump::TempDir;
    use s_gate2::winutil::{SyntheticWindow, clear_clipboard, list_processes, set_clipboard_text};
    use std::collections::BTreeMap;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../src-tauri/target/release/synapse-mind.exe");
    let exe = exe.canonicalize().expect("ikili yok");
    let syn = synthetic::synthetic_set();
    let root = TempDir::new("workers").expect("temp");
    let run_exe = root.path().join("bin").join("synapse-mind.exe");
    std::fs::create_dir_all(run_exe.parent().unwrap()).unwrap();
    std::fs::copy(&exe, &run_exe).unwrap();
    let mut child = Command::new(&run_exe)
        .env("LOCALAPPDATA", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("baslat");
    let app = child.id();
    let t0 = Instant::now();

    // pid -> (dogus_ms, olum_ms)
    type Book = Arc<Mutex<BTreeMap<u32, (u128, Option<u128>)>>>;
    let book: Book = Arc::new(Mutex::new(BTreeMap::new()));
    let timeline: Arc<Mutex<Vec<(u128, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let poller = {
        let (book, timeline, stop) = (book.clone(), timeline.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut last_n = usize::MAX;
            while !stop.load(Ordering::Relaxed) {
                let now = t0.elapsed().as_millis();
                let ps = list_processes();
                let live: Vec<u32> = ps
                    .iter()
                    .filter(|p| p.parent == app && p.exe.eq_ignore_ascii_case("synapse-mind.exe"))
                    .map(|p| p.pid)
                    .collect();
                {
                    let mut b = book.lock().unwrap();
                    for &pid in &live {
                        b.entry(pid).or_insert((now, None));
                    }
                    for (pid, v) in b.iter_mut() {
                        if v.1.is_none() && !live.contains(pid) {
                            v.1 = Some(now);
                        }
                    }
                }
                if live.len() != last_n {
                    timeline.lock().unwrap().push((now, live.len()));
                    last_n = live.len();
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };

    std::thread::sleep(Duration::from_secs(10)); // başlangıç + ısınma
    let win = SyntheticWindow::open(&syn.title, &syn.body).expect("pencere");
    for i in 0..4 {
        std::thread::sleep(Duration::from_secs(3));
        win.focus(); // her odak değişimi bir UIA çıkarımı => işçi tüketilir, yenisi ısınır
        let _ = i;
    }
    for c in &syn.clips {
        set_clipboard_text(c).expect("pano");
        std::thread::sleep(Duration::from_secs(2));
    }
    drop(win);
    std::thread::sleep(Duration::from_secs(8));
    clear_clipboard();

    stop.store(true, Ordering::Relaxed);
    let _ = poller.join();
    let end_ms = t0.elapsed().as_millis();
    println!("-- zaman cizelgesi (ms, eszamanli UIA isci sayisi):");
    for (t, n) in timeline.lock().unwrap().iter() {
        println!("   t={t:>6}  n={n}");
    }
    let book = book.lock().unwrap();
    println!("-- isciler (pid: dogus -> olum, omur ms):");
    let mut max_life = 0u128;
    for (pid, (born, died)) in book.iter() {
        let life = died.unwrap_or(end_ms).saturating_sub(*born);
        max_life = max_life.max(life);
        println!(
            "   pid={pid:<7} dogus={born:>6} olum={:>8} omur={life} ms",
            died.map(|d| d.to_string()).unwrap_or("YASIYOR".into())
        );
    }
    let max_conc = timeline
        .lock()
        .unwrap()
        .iter()
        .map(|x| x.1)
        .max()
        .unwrap_or(0);
    // 2 iscinin ust uste bindigi toplam sure (>=2 oldugu araliklarin toplami)
    let tl = timeline.lock().unwrap().clone();
    let mut overlap_ms = 0u128;
    let mut longest_overlap = 0u128;
    for w in tl.windows(2) {
        if w[0].1 >= 2 {
            let d = w[1].0 - w[0].0;
            overlap_ms += d;
            longest_overlap = longest_overlap.max(d);
        }
    }
    println!(
        "-- OZET: toplam_isci={} en_yuksek_eszamanli={max_conc} >=2_suresi_toplam={overlap_ms} ms en_uzun_kesintisiz_>=2={longest_overlap} ms en_uzun_omur={max_life} ms",
        book.len()
    );
    // Kapanış: uygulamayı öldür, yetim işçi kalıyor mu?
    let _ = Command::new("taskkill")
        .args(["/PID", &app.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.wait();
    std::thread::sleep(Duration::from_secs(3));
    let orphans = list_processes()
        .iter()
        .filter(|p| p.exe.eq_ignore_ascii_case("synapse-mind.exe") && p.parent == app)
        .count();
    let by_path_orphans = list_processes()
        .iter()
        .filter(|p| {
            p.exe.eq_ignore_ascii_case("synapse-mind.exe")
                && p.pid != app
                && book.contains_key(&p.pid)
        })
        .count();
    println!("-- KAPANIS: yetim_isci(parent=app)={orphans} yetim_isci(eski pid)={by_path_orphans}");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("yalnizca Windows");
    std::process::exit(2);
}
