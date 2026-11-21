//! Gate 2 hedef süreci: sahte sensör + `s_guard` hattı (+ isteğe bağlı s-core) + bekleme.
//!
//! `gate2-target --spec <dosya> --mode <mod> [--close] [--test-key-file <dosya>] [--db-dir <dizin>]`
//!
//! Modlar: `baseline` (guard yok), `process`, `run`, `core` (+ `MemoryStore`), `dpapi`,
//! `encrypted` / `encrypted-closed` (`--features encrypted`). Kontrol modları (`leaky-*`, `freed-utf8`)
//! kasıtlı sızıntı üretir; denetçi yakalamalıdır.
//!
//! Anahtar `--test-key-file` ile verilir (komut satırı PEB'de kalırdı). Sırlar tarif dosyasından
//! okunur. Yalnızca sentetik veri işlenir.

use s_gate2::spec::decode_to_packets;
use s_guard::Verdict;
use s_types::{EventKind, RawCapturePacket, RawPayload};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const SENTINEL: &str = "GATE2-SENTINEL-BENIGN";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn payload_text(p: &RawCapturePacket) -> Option<&str> {
    match &p.raw_payload {
        RawPayload::AccessibilityText(s) | RawPayload::ClipboardText(s) => Some(s.as_str()),
        RawPayload::ScreenFrame { .. } => None,
    }
}

/// Sızdırılan kopyaların adresleri. Göstericiyi global duruma kaçırmak, optimize edicinin (release)
/// kullanılmayan `Box::leak` tahsisini silmesini engeller; aksi halde kontrol KÖR olurdu.
static LEAKED: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// KASITLI sızıntı (yalnızca kontrol modu): ham metnin zeroize edilmeyen kopyası.
fn leak_copy(text: &str, utf16: bool) {
    let addr = if utf16 {
        let v: Vec<u16> = text.encode_utf16().collect();
        std::hint::black_box(Box::leak(v.into_boxed_slice())).as_ptr() as usize
    } else {
        std::hint::black_box(Box::leak(text.to_owned().into_boxed_str())).as_ptr() as usize
    };
    LEAKED.lock().unwrap().push(addr);
}

fn leak_bytes(b: Vec<u8>) {
    let addr = std::hint::black_box(Box::leak(b.into_boxed_slice())).as_ptr() as usize;
    LEAKED.lock().unwrap().push(addr);
}

/// 64 hex karakterlik dosyadan 32 baytlık test anahtarı okur (ara String kopyası bırakmaz).
fn read_key(path: &str) -> Zeroizing<[u8; 32]> {
    let mut buf = std::fs::read(path).expect("anahtar dosyasi okunamadi");
    assert_eq!(buf.len(), 64, "anahtar dosyasi 64 hex karakter olmali");
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("hex degil"),
        }
    };
    let mut key = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        key[i] = (nib(buf[2 * i]) << 4) | nib(buf[2 * i + 1]);
    }
    buf.zeroize();
    key
}

/// Yığına kopyalanmadan dolaşan, Drop'ta zeroize edilen anahtar kutusu.
struct KeyBox(Box<[u8; 32]>);

impl KeyBox {
    fn read(path: &str) -> Self {
        let mut b = Box::new([0u8; 32]);
        read_key_into(path, &mut b);
        Self(b)
    }
}

impl Drop for KeyBox {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `read_key` ile aynı, ama sonucu çağıranın tamponuna yazar (değerle taşıma yok).
fn read_key_into(path: &str, out: &mut [u8; 32]) {
    let mut buf = std::fs::read(path).expect("anahtar dosyasi okunamadi");
    assert_eq!(buf.len(), 64);
    let nib = |c: u8| -> u8 { (c as char).to_digit(16).expect("hex") as u8 };
    for i in 0..32 {
        out[i] = (nib(buf[2 * i]) << 4) | nib(buf[2 * i + 1]);
    }
    buf.zeroize();
}

fn hex_lower(key: &[u8; 32]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    key.iter()
        .flat_map(|b| [H[(b >> 4) as usize], H[(b & 15) as usize]])
        .collect()
}

/// DPAPI turu: `protect_key` -> `unprotect_key`; sonuç anahtarı döner, ara blob düşer.
#[allow(deprecated)] // KASITLI: eski değerle-dönen API karşılaştırması
fn dpapi_roundtrip(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let blob = s_guard::protect_key(key).expect("protect_key");
    let key2 = s_guard::unprotect_key(&blob).expect("unprotect_key");
    assert_eq!(*key2, *key, "DPAPI turu anahtari degistirdi");
    // generate_db_key yolu da calissin (bu anahtar arama listesinde yok).
    let g = s_guard::generate_db_key();
    let gb = s_guard::protect_key(&g).expect("protect_key(generated)");
    let g2 = s_guard::unprotect_key(&gb).expect("unprotect_key(generated)");
    assert_eq!(*g, *g2);
    key2
}

/// SP'nin altındaki ölü yığın çerçevelerini üzerine yazar (yalnızca atıf deneyi; üretimde de aynı teknik önerilir).
#[inline(never)]
fn scrub_stack() {
    let mut buf = [0u8; 256 * 1024];
    for b in buf.iter_mut() {
        // SAFETY: `b` geçerli, hizalı ve yazılabilir bir u8 referansıdır; volatile yazma optimizasyonu engeller.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::hint::black_box(&mut buf);
}

fn skipped(why: &str) -> ! {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "SKIPPED {why}");
    let _ = out.flush();
    std::process::exit(3);
}

// ----------------------------------------------------------------- s-core modları
// `--features core` (s-core derlenebiliyorsa) ve `--features encrypted` (open_encrypted API'si varsa).

#[cfg(feature = "core")]
mod store_modes {
    use super::*;

    /// Çevrimdışı, belirleyici gömme (modelsiz). Yalnızca MASKELİ metin görür.
    struct TestEmbedder;

    impl s_core::Embedder for TestEmbedder {
        fn embed_batch(&self, texts: &[&str]) -> s_core::Result<Vec<Vec<f32>>> {
            Ok(texts
                .iter()
                .map(|t| {
                    let mut v = vec![0.0_f32; s_core::EMBEDDING_DIM];
                    for tok in t
                        .to_ascii_lowercase()
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|s| !s.is_empty())
                    {
                        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                        for &b in tok.as_bytes() {
                            h ^= u64::from(b);
                            h = h.wrapping_mul(0x0100_0000_01b3);
                        }
                        v[(h % s_core::EMBEDDING_DIM as u64) as usize] += 1.0;
                    }
                    let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                    if n == 0.0 {
                        v[0] = 1.0;
                    } else {
                        for x in &mut v {
                            *x /= n;
                        }
                    }
                    v
                })
                .collect())
        }
    }

    type Store = s_core::MemoryStore<TestEmbedder>;

    #[cfg(feature = "encrypted")]
    fn open_encrypted(key: &[u8; 32], db_dir: &str) -> Store {
        let path = std::path::Path::new(db_dir).join("gate2.db");
        s_core::MemoryStore::open_encrypted(&path, key, TestEmbedder).expect("open_encrypted")
    }

    #[cfg(not(feature = "encrypted"))]
    fn open_encrypted(_key: &[u8; 32], _db_dir: &str) -> Store {
        skipped(
            "encrypted: bu derleme `--features encrypted` olmadan yapildi (s-core open_encrypted API'si gerekir)",
        )
    }

    const QUERIES: &[&str] = &[
        "checkout payment",
        "meeting notes",
        "stripe key",
        "project notes",
        "token",
        "password reset",
    ];

    pub fn run_load_open(blob_path: &str, db_dir: &str) -> (Box<dyn std::any::Any>, String) {
        let blob = std::fs::read(blob_path).expect("blob oku");
        let key = s_guard::DbKey::load(&blob).expect("DbKey::load");
        drop(blob);
        let store = open_encrypted(key.expose(), db_dir);
        drop(key);
        (Box::new(store), " keystore_load_open=true".to_string())
    }

    /// src-tauri `keystore.rs` akışının birebir kopyası (bkz. mod açıklaması).
    pub fn run_keystore(mode: &str, db_dir: &str) -> (Box<dyn std::any::Any>, String) {
        let dir = std::path::Path::new(db_dir);
        let key_path = dir.join("key.bin");
        let first_run = mode == "keystore-first-run";
        if !first_run {
            // önceki "çalıştırma": anahtar üret, blobu yaz, anahtarı DÜŞÜR (bu süreçte ayrı kapsam)
            let k = s_guard::DbKey::generate();
            let blob = k.protect().expect("protect");
            std::fs::write(&key_path, blob).expect("blob yaz");
        }
        let key = if first_run {
            let key = s_guard::DbKey::generate();
            let blob = key.protect().expect("protect");
            std::fs::write(&key_path, &blob).expect("blob yaz");
            key
        } else {
            let blob = std::fs::read(&key_path).expect("blob oku");
            s_guard::DbKey::load(&blob).expect("DbKey::load")
        };
        let store = open_encrypted(key.expose(), db_dir);
        drop(key);
        (Box::new(store), " keystore_store_open=true".to_string())
    }

    /// KONTROL: guard ATLANIR; HAM metin doğrudan `MaskedMemoryBlock.clean_text` olarak depoya alınır.
    /// Denetçi bunun (SQLite sayfaları / FTS / gömme girdisi) bellekte bulunduğunu YAKALAMALI;
    /// aksi halde `core` modundaki "0 bulgu" anlamsız olurdu.
    pub fn run_unmasked_control(
        packets: Vec<RawCapturePacket>,
    ) -> (Box<dyn std::any::Any>, String) {
        let mut store = s_core::MemoryStore::open_in_memory(TestEmbedder).expect("open_in_memory");
        let mut n = 0u64;
        for (i, p) in packets.into_iter().enumerate() {
            let Some(text) = payload_text(&p).map(str::to_owned) else {
                continue;
            };
            let block = s_core::MaskedMemoryBlock {
                event_id: i as u64,
                timestamp_ms: 1_763_424_000_000 + i as u64,
                app_context: s_core::AppContext {
                    process_name: "notepad.exe".into(),
                    sanitized_title: "Project notes - Notepad".into(),
                    is_browser: false,
                },
                clean_text: text,
                text_hash: [7u8; 32],
                redactions_count: 0,
                has_embedding_payload: true,
                source: s_core::EventSource::Accessibility,
            };
            store.ingest_block(&block).expect("ingest_block");
            n += 1;
        }
        for q in QUERIES {
            let _ = store.hybrid_search(q, 5);
        }
        (
            Box::new(store),
            format!(" store_events={n} UNMASKED_CONTROL=true"),
        )
    }

    /// Guard -> relay -> `run_ingestion` -> depo hattı; ardından aramalar.
    /// Dönüş: (hayatta tutulacaklar, READY satırına eklenecek bilgi).
    pub fn run_store_mode(
        mode: &str,
        packets: Vec<RawCapturePacket>,
        key: Option<KeyBox>,
        db_dir: Option<String>,
    ) -> (Box<dyn std::any::Any>, String) {
        let encrypted = mode.starts_with("encrypted");
        let mut info = String::new();

        let store: Store = if encrypted {
            let key = key.expect("encrypted modu --test-key-file ister");
            let db_dir = db_dir.expect("encrypted modu --db-dir ister");
            // Gerçek uygulama yolu: test anahtarı Box'ta -> `protect_key` -> blob -> `DbKey::load` (yerinde
            // doldurulan Box; değerle taşıma yok) -> `open_encrypted(.., key.expose(), ..)` -> DbKey düşer.
            let blob = s_guard::protect_key(&key.0).expect("protect_key");
            drop(key); // hedefin kendi kopyası (zeroize)
            // DbKey::generate + protect + load yolu da çalışsın (bu anahtar arama listesinde yok).
            {
                let g = s_guard::DbKey::generate();
                let gb = g.protect().expect("protect(generated)");
                let g2 = s_guard::DbKey::load(&gb).expect("load(generated)");
                assert!(g.expose() == g2.expose());
            }
            let k2 = s_guard::DbKey::load(&blob).expect("DbKey::load");
            drop(blob);
            let s = open_encrypted(k2.expose(), &db_dir);
            drop(k2); // zeroize
            s
        } else {
            s_core::MemoryStore::open_in_memory(TestEmbedder).expect("open_in_memory")
        };
        let store = Arc::new(std::sync::Mutex::new(store));

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .expect("runtime");
        let (in_tx, in_rx) =
            tokio::sync::mpsc::channel::<RawCapturePacket>(s_types::SENSOR_CHANNEL_CAPACITY);
        let (g_tx, mut g_rx) = tokio::sync::mpsc::channel(128);
        let (c_tx, c_rx) = tokio::sync::mpsc::channel(128);
        let sentinel_id = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        rt.spawn(s_guard::run(in_rx, g_tx));
        let ingest = rt.spawn(s_core::run_ingestion(Arc::clone(&store), c_rx));
        let sid = Arc::clone(&sentinel_id);
        rt.spawn(async move {
            while let Some(b) = g_rx.recv().await {
                if b.clean_text.contains(SENTINEL) {
                    sid.store(b.event_id, Ordering::SeqCst);
                }
                if c_tx.send(b).await.is_err() {
                    break;
                }
            }
        });

        rt.block_on(async {
            for p in packets {
                in_tx.send(p).await.expect("guard hatti kapandi");
            }
            let sentinel = RawCapturePacket {
                timestamp_ms: 1_763_424_999_000,
                process_id: 1,
                process_name: "notepad.exe".into(),
                window_title: "Project notes - Notepad".into(),
                event_kind: EventKind::AccessibilityTreeChanged { node_count: 1 },
                raw_payload: RawPayload::AccessibilityText(SENTINEL.into()),
            };
            in_tx.send(sentinel).await.expect("guard hatti kapandi");
            // Sentinel depoya yazılana kadar bekle (event_id'ler 0..; her paket bir id tüketir).
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                let sid = sentinel_id.load(Ordering::SeqCst);
                if sid != u64::MAX {
                    let next = store.lock().unwrap().next_event_id().unwrap_or(0);
                    if next > sid {
                        break;
                    }
                }
                assert!(std::time::Instant::now() < deadline, "ingest zaman asimi");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        // Aramalar (yalnızca zararsız sorgular; ham sır içermez).
        let mut hits = 0usize;
        {
            let s = store.lock().unwrap();
            for _ in 0..3 {
                for q in QUERIES {
                    hits += s.hybrid_search(q, 5).map(|h| h.len()).unwrap_or(0);
                }
            }
            let events: i64 = s
                .connection()
                .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                .unwrap_or(-1);
            info.push_str(&format!(" store_events={events} search_hits={hits}"));
            if encrypted {
                for pragma in ["cipher_version", "cipher_memory_security"] {
                    let v = s
                        .connection()
                        .query_row(&format!("PRAGMA {pragma}"), [], |r| {
                            let v = r.get_ref(0)?;
                            Ok(v.as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|_| format!("{v:?}")))
                        })
                        .unwrap_or_else(|e| format!("err({e})"));
                    info.push_str(&format!(" {pragma}={}", v.replace(' ', "_")));
                }
            }
        }

        if mode == "encrypted-closed" {
            // Zinciri kapat: in_tx düşer -> guard biter -> relay biter -> run_ingestion biter (Arc düşer).
            drop(in_tx);
            let _ =
                rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), ingest).await });
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while Arc::strong_count(&store) > 1 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "depo referanslari kapanmadi"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            drop(store); // bağlantı kapanır (SQLCipher anahtar tamponlarını silmeli)
            rt.shutdown_timeout(Duration::from_secs(2));
            info.push_str(" store_closed=true");
            (Box::new(()), info)
        } else {
            (Box::new((rt, in_tx, store)), info)
        }
    }
}

#[cfg(not(feature = "core"))]
mod store_modes {
    use super::*;

    pub fn run_unmasked_control(
        _packets: Vec<RawCapturePacket>,
    ) -> (Box<dyn std::any::Any>, String) {
        skipped("core: bu derleme `--features core` olmadan yapildi (s-core bagimliligi kapali)")
    }

    pub fn run_store_mode(
        _mode: &str,
        _packets: Vec<RawCapturePacket>,
        _key: Option<KeyBox>,
        _db_dir: Option<String>,
    ) -> (Box<dyn std::any::Any>, String) {
        skipped("core: bu derleme `--features core` olmadan yapildi (s-core bagimliligi kapali)")
    }

    pub fn run_load_open(_blob: &str, _db_dir: &str) -> (Box<dyn std::any::Any>, String) {
        skipped("keystore: `--features encrypted` gerekir")
    }

    pub fn run_keystore(_mode: &str, _db_dir: &str) -> (Box<dyn std::any::Any>, String) {
        skipped("keystore: `--features encrypted` gerekir")
    }
}

fn main() {
    // Üretim ikilisiyle aynı: UIA işçi alt komutu (sensör modları varsayılan `UiaIsolation::Worker` ile her UIA
    // çıkarımını bu ikilinin tek atımlık işçi kopyasında yapar). İşçi kipindeyse dönmez.
    #[cfg(feature = "uia-worker")]
    s_sensor::run_uia_worker_if_requested();
    let args: Vec<String> = std::env::args().collect();
    let spec_path = arg(&args, "--spec").expect("--spec gerekli");
    let mode = arg(&args, "--mode").expect("--mode gerekli");
    let close = args.iter().any(|a| a == "--close");
    let key_file = arg(&args, "--test-key-file");
    let db_dir = arg(&args, "--db-dir");

    if mode.starts_with("encrypted") && !cfg!(feature = "encrypted") {
        skipped(
            "encrypted: bu derleme `--features encrypted` olmadan yapildi (s-core open_encrypted API'si gerekir)",
        );
    }

    // Tarifi oku: tam boyutlu tek tampon (yeniden tahsis/kopya yok), paketlere tek kopya, sonra zeroize.
    let packets = {
        let mut f = std::fs::File::open(&spec_path).expect("spec acilamadi");
        let len = f.metadata().expect("meta").len() as usize;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).expect("spec okunamadi");
        let p = decode_to_packets(&buf).expect("spec cozulemedi");
        buf.zeroize();
        p
    };

    let blocks = Arc::new(AtomicUsize::new(0));
    let mut info = String::new();
    // Boşta bekleyen hattın tutamaçları (süreç boyunca yaşar).
    let mut _keep: Option<Box<dyn std::any::Any>> = None;
    let mut _keep_rt: Option<(
        tokio::runtime::Runtime,
        tokio::sync::mpsc::Sender<RawCapturePacket>,
    )> = None;

    match mode.as_str() {
        "baseline" => drop(packets),
        "process" => {
            for (i, p) in packets.into_iter().enumerate() {
                if let Verdict::Masked(b) = s_guard::process(p, i as u64) {
                    blocks.fetch_add(1, Ordering::Relaxed);
                    drop(b);
                }
            }
        }
        // `dpapi`: gerçek uygulama yolu (DbKey): test anahtarı Box'ta -> protect -> blob -> `DbKey::load`
        // (yerinde doldurma) -> `DbKey::generate().protect()` turu -> hepsi düşer. Değerle taşıma YOK.
        "dpapi" => {
            drop(packets);
            let kb = KeyBox::read(&key_file.expect("--test-key-file gerekli"));
            let blob = s_guard::protect_key(&kb.0).expect("protect_key");
            drop(kb);
            {
                let k = s_guard::DbKey::load(&blob).expect("DbKey::load");
                std::hint::black_box(k.expose().iter().fold(0u8, |a, x| a ^ x));
                let g = s_guard::DbKey::generate();
                let gb = g.protect().expect("protect(generated)");
                let g2 = s_guard::DbKey::load(&gb).expect("load(generated)");
                assert!(g.expose() == g2.expose());
            }
            drop(blob);
            info.push_str(" dpapi_ok=true");
        }
        // `dpapi-legacy`: ESKİ API (`unprotect_key` -> `Zeroizing<[u8;32]>` DEĞERLE döner); karşılaştırma içindir.
        "dpapi-legacy" => {
            drop(packets);
            let key = read_key(&key_file.expect("--test-key-file gerekli"));
            let k2 = dpapi_roundtrip(&key);
            drop(k2);
            drop(key);
            info.push_str(" dpapi_ok=true");
        }
        // Ayrıştırma modları (sızıntı yeri tahmini): DPAPI olmadan yalnızca anahtar okuma.
        // `keyread`: anahtar doğrudan yığın tamponuna (KeyBox) okunur, yığına KOPYALANMAZ.
        "keyread" => {
            drop(packets);
            let kb = KeyBox::read(&key_file.expect("--test-key-file gerekli"));
            drop(kb);
        }
        // `keyread-byvalue`: eski desen (`read_key` Zeroizing'i değerle döndürür); bayat yığın kopyası karşılaştırması.
        "keyread-byvalue" => {
            drop(packets);
            let key = read_key(&key_file.expect("--test-key-file gerekli"));
            drop(key);
        }
        "leaky-key" => {
            drop(packets);
            let key = read_key(&key_file.expect("--test-key-file gerekli"));
            let hex = hex_lower(&key);
            let hex_str = String::from_utf8(hex.clone()).unwrap();
            leak_bytes(key.to_vec()); // ham 32 bayt
            leak_bytes(hex.clone()); // hex UTF-8
            leak_copy(&hex_str, true); // hex UTF-16LE
            leak_copy(&format!("x'{hex_str}'"), false); // SQLCipher PRAGMA key biçimi
        }
        // Sensör atıfı: yalnızca sensör hattı (paketler tüketilip düşürülür). `sensor-guard`: + `s_guard::process`.
        // Besleme denetçi tarafından READY SONRASI yapılır (sentetik pencere/pano).
        "sensor" | "sensor-guard" => {
            drop(packets);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .expect("runtime");
            let guard_on = mode == "sensor-guard";
            let (handle, mut rx) = {
                let _g = rt.enter();
                s_sensor::start_sensor_pipeline(s_sensor::SensorConfig::default()).expect("sensor")
            };
            let counter = Arc::clone(&blocks);
            // Canlılık kanıtı (isteğe bağlı, varsayılan KAPALI): `GATE2_SENSOR_TRACE=1` ise her paketin YALNIZCA
            // metadata'sı (olay türü, pid, ts, metin uzunluğu; ham içerik yok) stderr'e yazılır.
            let trace = std::env::var_os("GATE2_SENSOR_TRACE").is_some();
            rt.spawn(async move {
                let mut id = 0u64;
                while let Some(p) = rx.recv().await {
                    counter.fetch_add(1, Ordering::Relaxed);
                    if trace {
                        eprintln!("TRACE {}", s_sensor::extract_metadata(&p));
                    }
                    if guard_on {
                        if let Verdict::Masked(b) = s_guard::process(p, id) {
                            drop(b);
                        }
                    } else {
                        drop(p);
                    }
                    id += 1;
                }
            });
            _keep = Some(Box::new((rt, handle)));
        }
        // Anahtar ömrü modları src-tauri `keystore` akışını taklit eder: üret/yükle → protect →
        // `key.bin` → open_encrypted → anahtar düşer. Denetçi blobu çözüp anahtarı arar.
        "keystore-gen-protect" => {
            drop(packets);
            let db_dir = db_dir.expect("--db-dir gerekli");
            let k = s_guard::DbKey::generate();
            let blob = k.protect().expect("protect");
            std::fs::write(std::path::Path::new(&db_dir).join("key.bin"), &blob).expect("blob yaz");
            drop(k);
            drop(blob);
            info.push_str(" keystore_gen_protect=true");
        }
        // `keystore-gen-only`: yalnızca DbKey::generate (protect YOK); anahtar denetçi için `--db-dir/key-plain.bin`e
        // doğrudan Box'tan yazılır (ara kopya yok). Kalıntı varsa `generate` yolu, yoksa `protect` yolu sorumludur.
        "keystore-gen-only" | "keystore-gen-only-flush" | "keystore-gen-only-stackscrub" => {
            drop(packets);
            let db_dir = db_dir.expect("--db-dir gerekli");
            let k = s_guard::DbKey::generate();
            {
                use std::io::Write as _;
                let mut f =
                    std::fs::File::create(std::path::Path::new(&db_dir).join("key-plain.bin"))
                        .expect("anahtar dosyasi");
                f.write_all(k.expose()).expect("yaz");
            }
            drop(k);
            if mode == "keystore-gen-only-flush" {
                // Hipotez: kalıntı OS CSPRNG/yığın tamponunda. Ardından çok sayıda rastgele bayt çekip atarak ezmeyi dene.
                let mut scratch = vec![0u8; 4096];
                for _ in 0..256 {
                    getrandom::fill(&mut scratch).expect("rng");
                }
                scratch.iter_mut().for_each(|b| *b = 0);
            }
            if mode == "keystore-gen-only-stackscrub" {
                // Hipotez: kalıntı ÖLÜ YIĞIN ÇERÇEVESİNDE (SP'nin altı; MiniDump bunu "yığın" değil özel bellek sayar).
                scrub_stack();
            }
            info.push_str(" keystore_gen_only=true");
        }
        // `keystore-rng-only`: DbKey/s-guard OLMADAN doğrudan getrandom -> Box; dosyaya doğrudan Box'tan yazılır.
        "keystore-rng-only" => {
            drop(packets);
            let db_dir = db_dir.expect("--db-dir gerekli");
            let mut b: Box<[u8; 32]> = Box::new([0u8; 32]);
            getrandom::fill(&mut b[..]).expect("rng");
            {
                use std::io::Write as _;
                let mut f =
                    std::fs::File::create(std::path::Path::new(&db_dir).join("key-plain.bin"))
                        .expect("dosya");
                f.write_all(&b[..]).expect("yaz");
            }
            b.zeroize();
            drop(b);
            info.push_str(" keystore_rng_only=true");
        }
        "keystore-load-open" => {
            drop(packets);
            let db_dir = db_dir.expect("--db-dir gerekli");
            let blob_path = arg(&args, "--key-blob").expect("--key-blob gerekli");
            let (keep, i) = store_modes::run_load_open(&blob_path, &db_dir);
            _keep = Some(keep);
            info.push_str(&i);
        }
        "keystore-first-run" | "keystore-reload" => {
            drop(packets);
            let db_dir = db_dir.expect("--db-dir gerekli");
            let (keep, i) = store_modes::run_keystore(&mode, &db_dir);
            _keep = Some(keep);
            info.push_str(&i);
        }
        "core-unmasked-control" => {
            let (keep, i) = store_modes::run_unmasked_control(packets);
            _keep = Some(keep);
            info.push_str(&i);
        }
        "core" | "encrypted" | "encrypted-closed" => {
            let key = key_file.as_deref().map(KeyBox::read);
            let (keep, i) = store_modes::run_store_mode(&mode, packets, key, db_dir);
            _keep = Some(keep);
            info.push_str(&i);
        }
        "run" | "leaky-utf8" | "leaky-utf16" | "freed-utf8" => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .build()
                .expect("runtime");
            let (in_tx, in_rx) =
                tokio::sync::mpsc::channel::<RawCapturePacket>(s_types::SENSOR_CHANNEL_CAPACITY);
            let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(128);
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            rt.spawn(s_guard::run(in_rx, out_tx));
            let counter = Arc::clone(&blocks);
            rt.spawn(async move {
                let mut done_tx = Some(done_tx);
                // Tüketici hat boyunca canlı kalır (aksi halde guard `tx` kapanınca biter).
                while let Some(b) = out_rx.recv().await {
                    counter.fetch_add(1, Ordering::Relaxed);
                    if b.clean_text.contains(SENTINEL)
                        && let Some(d) = done_tx.take()
                    {
                        let _ = d.send(());
                    }
                }
            });
            let leak = match mode.as_str() {
                "leaky-utf8" => Some(false),
                "leaky-utf16" => Some(true),
                "freed-utf8" => Some(false),
                _ => None,
            };
            let mut copies: Vec<String> = Vec::new();
            rt.block_on(async {
                for p in packets {
                    if let (Some(utf16), Some(t)) = (leak, payload_text(&p)) {
                        if mode == "freed-utf8" {
                            copies.push(t.to_owned()); // KASITLI: zeroize edilmeden, toplu serbest birakilacak kopya
                        } else {
                            leak_copy(t, utf16);
                        }
                    }
                    in_tx.send(p).await.expect("guard hatti kapandi");
                }
                let sentinel = RawCapturePacket {
                    timestamp_ms: 1,
                    process_id: 1,
                    process_name: "notepad.exe".into(),
                    window_title: "Project notes - Notepad".into(),
                    event_kind: EventKind::AccessibilityTreeChanged { node_count: 1 },
                    raw_payload: RawPayload::AccessibilityText(SENTINEL.into()),
                };
                in_tx.send(sentinel).await.expect("guard hatti kapandi");
                done_rx.await.expect("sentinel gelmedi");
            });
            drop(copies); // freed-utf8 kontrolu: zeroize edilmemis kopyalar burada toplu serbest kalir
            if close {
                drop(in_tx);
                std::thread::sleep(Duration::from_millis(300));
            } else {
                _keep_rt = Some((rt, in_tx));
            }
        }
        other => panic!("bilinmeyen mod: {other}"),
    }

    // Dökümü alınacak durum: işlem bitti, hat (varsa) boşta.
    std::thread::sleep(Duration::from_millis(500));
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "READY {} blocks={}{info}",
        std::process::id(),
        blocks.load(Ordering::Relaxed)
    );
    let _ = out.flush();
    loop {
        std::thread::park_timeout(Duration::from_secs(600));
    }
}
