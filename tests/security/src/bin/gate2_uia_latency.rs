//! UIA çıkarım gecikmesi: süreç içi UIA ile tek kullanımlık işçi süreç (aynı `s_sensor::UiaProbe`
//! yolu), hedef pencere ayrı süreçte. `gate2-uia-latency [--samples N]` → p50/p95/p99 (ms).

#[cfg(windows)]
#[path = "../synthetic.rs"]
#[allow(dead_code)] // yalnizca baslik/govde kullanilir
mod synthetic;

#[cfg(windows)]
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(windows)]
fn report(label: &str, mut v: Vec<f64>) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    println!(
        "{label:<34} n={:<4} p50={:>8.2} ms  p95={:>8.2} ms  p99={:>8.2} ms  mean={:>8.2} ms  min={:>7.2}  max={:>8.2}",
        v.len(),
        percentile(&v, 50.0),
        percentile(&v, 95.0),
        percentile(&v, 99.0),
        mean,
        v[0],
        v[v.len() - 1]
    );
}

#[cfg(windows)]
fn main() {
    // İşçi kipi (bu ikili kendi UIA işçisidir).
    s_sensor::run_uia_worker_if_requested();
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "--host-window") {
        let syn = synthetic::synthetic_set();
        let w = s_gate2::winutil::SyntheticWindow::open(&syn.title, &syn.body).expect("pencere");
        println!("HWND {}", w.hwnd());
        // stdin kapanana kadar pencereyi yaşat.
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        drop(w);
        return;
    }
    let samples: usize = args
        .iter()
        .position(|a| a == "--samples")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let mut host = Command::new(std::env::current_exe().unwrap())
        .arg("--host-window")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("pencere sureci");
    let mut line = String::new();
    BufReader::new(host.stdout.take().unwrap())
        .read_line(&mut line)
        .expect("HWND satiri");
    let hwnd: isize = line
        .trim()
        .strip_prefix("HWND ")
        .and_then(|s| s.parse().ok())
        .expect("HWND");
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("hedef pencere (ayri surec) hwnd=0x{hwnd:x}, ornek={samples}");

    for (label, iso) in [
        ("InProcess (eski yol)", s_sensor::UiaIsolation::InProcess),
        ("Worker (tek atimlik surec)", s_sensor::UiaIsolation::Worker),
    ] {
        let cfg = s_sensor::SensorConfig {
            uia_isolation: iso,
            ..s_sensor::SensorConfig::default()
        };
        let t = Instant::now();
        let probe = s_sensor::UiaProbe::new(cfg).expect("probe");
        println!("{label}: kurulum {:.2} ms", t.elapsed().as_secs_f64() * 1e3);
        for _ in 0..3 {
            let _ = probe.extract_stats(hwnd);
        }
        let mut v = Vec::with_capacity(samples);
        let mut last = None;
        for _ in 0..samples {
            let t = Instant::now();
            let s = probe.extract_stats(hwnd);
            v.push(t.elapsed().as_secs_f64() * 1e3);
            last = Some(s);
        }
        let s = last.unwrap();
        println!(
            "{label}: son ornek text_len={} node_count={} empty_reason={:?}",
            s.text_len, s.node_count, s.empty_reason
        );
        report(label, v);
        if iso == s_sensor::UiaIsolation::Worker {
            let mut v = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t = Instant::now();
                let s = probe.extract_stats(0);
                v.push(t.elapsed().as_secs_f64() * 1e3);
                assert_eq!(s.empty_reason, Some("null_hwnd"));
            }
            report("Worker el sikisma (null HWND)", v);
        }
    }
    drop(host.stdin.take());
    let _ = host.wait();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("yalnizca Windows");
    std::process::exit(2);
}
