//! Bir hedef sürecin başlatılması, hazır olana kadar beklenmesi, dökümünün alınması ve taranması.

use crate::dump::{TempDir, TempFile, write_full_dump};
use crate::scan::{Enc, Hit, Part, Secret, parse_layout, scan_file};
use crate::spec::{PacketSpec, encode};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Hedef çocuk süreç; Drop'ta öldürülür.
struct Target(Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, Clone)]
pub struct LocatedHit {
    pub secret: usize,
    pub secret_id: String,
    pub enc: Enc,
    pub part: Part,
    pub offset: u64,
    pub va: Option<u64>,
    pub region: String,
}

#[derive(Debug, Clone)]
pub struct SessionResult {
    pub mode: String,
    pub dump_bytes: u64,
    pub secrets_searched: usize,
    /// Hedefin READY satırı (ör. "READY 1234 blocks=100").
    pub ready_line: String,
    pub hits: Vec<LocatedHit>,
    /// Hedefin ALT süreçleri (UIA işçi süreçleri): (kaynak "exe:pid", eşleşme). Besleme ÖNCESİ (boşta yedek işçi) ve
    /// besleme SONRASI ayrı etiketlenir ("idle:" / "after:" öneki).
    pub child_hits: Vec<(String, LocatedHit)>,
    /// Dökümü alınan alt süreç sayısı (idle, after).
    pub child_counts: (usize, usize),
}

/// Süreç-sahipli bellek (özel yığın / yığıt). `mapped`/`image` oturum-genel paylaşımlı bölümlerdir (masaüstü yığını,
/// konsol arabelleği vb.: başka süreçlerin metni de görünür); hedef sürecin kalıntısı sayılmaz.
pub fn is_owned_region(region: &str) -> bool {
    region.starts_with("private") || region.starts_with("stack")
}

impl SessionResult {
    /// Tam sır (Full) bulunan benzersiz sır sayısı.
    pub fn full_secret_ids(&self, enc: Option<Enc>) -> Vec<usize> {
        let mut v: Vec<usize> = self
            .hits
            .iter()
            .filter(|h| {
                is_owned_region(&h.region) && h.part == Part::Full && enc.is_none_or(|e| e == h.enc)
            })
            .map(|h| h.secret)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Herhangi bir parçası (Full/Mid/Tail) bulunan benzersiz sır sayısı.
    pub fn any_secret_ids(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self
            .hits
            .iter()
            .filter(|h| is_owned_region(&h.region))
            .map(|h| h.secret)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// bölge -> eşleşme sayısı
    pub fn by_region(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for h in &self.hits {
            let key = if h.region.starts_with("stack") {
                "stack".to_string()
            } else {
                h.region.clone()
            };
            *m.entry(key).or_insert(0) += 1;
        }
        m
    }
}

/// Hedefi `mode` ile başlatır, "READY" satırını bekler, tam dökümü alır, tarar, süreci öldürür,
/// döküm ve tarif dosyalarını siler.
pub fn run_session(
    target_exe: &Path,
    mode: &str,
    specs: &[PacketSpec],
    secrets: &[Secret],
    extra_args: &[&str],
) -> io::Result<SessionResult> {
    run_session_with_key(target_exe, mode, specs, secrets, extra_args, None)
}

/// `run_session` + deterministik test anahtarı. Anahtar komut satırıyla geçirilmez (PEB'de kalır),
/// geçici dosyayla verilir ve döküm öncesinde silinir. Desteklenmeyen modda `Unsupported` döner.
pub fn run_session_with_key(
    target_exe: &Path,
    mode: &str,
    specs: &[PacketSpec],
    secrets: &[Secret],
    extra_args: &[&str],
    key_hex: Option<&str>,
) -> io::Result<SessionResult> {
    run_session_hook(target_exe, mode, specs, secrets, extra_args, key_hex, None)
}

/// `after_ready` kancası: `--db-dir` yolunu alır, ek sırlar döndürür.
pub type AfterReady<'a> = &'a mut dyn FnMut(Option<&Path>) -> Vec<Secret>;

/// `after_ready`: hedef READY dedikten SONRA, dökümden ÖNCE çağrılır; hedefe sentetik olay besleyebilir
/// (ör. sentetik pencere/pano) ve dökümde ayrıca aranacak ek sırlar döndürebilir (`--db-dir` yolunu alır;
/// hedefin kendi ürettiği anahtarı bloblandan çözmek için). `encrypted*` ve `keystore*` modlarında `--db-dir` verilir.
pub fn run_session_hook(
    target_exe: &Path,
    mode: &str,
    specs: &[PacketSpec],
    secrets: &[Secret],
    extra_args: &[&str],
    key_hex: Option<&str>,
    mut after_ready: Option<AfterReady<'_>>,
) -> io::Result<SessionResult> {
    let spec_file = TempFile::new(mode, "spec");
    std::fs::write(spec_file.path(), encode(specs))?;
    let dump_file = TempFile::new(mode, "dmp");
    let key_file = TempFile::new(mode, "key");
    // `child`'dan ÖNCE bildirilir: süreç öldürüldükten SONRA silinir.
    let db_dir = if mode.starts_with("encrypted") || mode.starts_with("keystore") {
        Some(TempDir::new(mode)?)
    } else {
        None
    };
    if let Some(k) = key_hex {
        std::fs::write(key_file.path(), k)?;
    }

    let mut cmd = Command::new(target_exe);
    cmd.arg("--spec")
        .arg(spec_file.path())
        .arg("--mode")
        .arg(mode)
        .args(extra_args);
    if key_hex.is_some() {
        cmd.arg("--test-key-file").arg(key_file.path());
    }
    if let Some(d) = &db_dir {
        cmd.arg("--db-dir").arg(d.path());
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null());
    let mut child = Target(cmd.spawn()?);

    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let ready_line;
    loop {
        match rx.recv_timeout(Duration::from_secs(180)) {
            Ok(l) if l.starts_with("READY") => {
                ready_line = l;
                break;
            }
            Ok(l) if l.starts_with("SKIPPED") => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, l));
            }
            Ok(_) => continue,
            Err(_) => {
                return Err(io::Error::other(
                    "hedef READY demedi (zaman asimi veya erken cikis)",
                ));
            }
        }
    }
    // Hedef READY sonrası sessiz kalır; tarif dosyasını döküm öncesi silmek disk artığını azaltır.
    let _ = std::fs::remove_file(spec_file.path());
    let _ = std::fs::remove_file(key_file.path());

    // Alt süreçler (tek kullanımlık UIA işçileri; boşta yedek dahil) BESLEMEDEN ÖNCE.
    let mut child_hits: Vec<(String, LocatedHit)> = Vec::new();
    let idle_children = if after_ready.is_some() {
        scan_children("idle", child.0.id(), secrets, &mut child_hits)
    } else {
        0
    };
    let extra: Vec<Secret> = match after_ready.as_mut() {
        Some(h) => h(db_dir.as_ref().map(|d| d.path())),
        None => Vec::new(),
    };
    let all: Vec<Secret> = secrets.iter().cloned().chain(extra).collect();
    let secrets: &[Secret] = &all;

    let after_children = if after_ready.is_some() {
        scan_children("after", child.0.id(), secrets, &mut child_hits)
    } else {
        0
    };
    let dump_bytes = write_full_dump(&child.0, dump_file.path())?;
    let layout = parse_layout(dump_file.path())?;
    let raw: Vec<Hit> = scan_file(dump_file.path(), secrets)?;
    let hits = raw
        .into_iter()
        .map(|h| {
            let loc = layout.locate(h.offset);
            LocatedHit {
                secret: h.secret,
                secret_id: secrets[h.secret].id.clone(),
                enc: h.enc,
                part: h.part,
                offset: h.offset,
                va: loc.va,
                region: loc.region,
            }
        })
        .collect();
    Ok(SessionResult {
        mode: mode.to_string(),
        ready_line,
        dump_bytes,
        secrets_searched: secrets
            .iter()
            .filter(|s| s.text.chars().count() >= crate::scan::MIN_SECRET_CHARS)
            .count(),
        hits,
        child_hits,
        child_counts: (idle_children, after_children),
    })
    // `child` (Target) ve `dump_file` burada düşer: süreç öldürülür, döküm silinir.
}

/// `root`un ALT süreçlerini (kendisi hariç) döker ve tarar; sonuçları `out`a "etiket:exe:pid" ile ekler.
fn scan_children(
    label: &str,
    root: u32,
    secrets: &[Secret],
    out: &mut Vec<(String, LocatedHit)>,
) -> usize {
    let mut n = 0;
    for p in crate::winutil::process_tree(root)
        .into_iter()
        .filter(|p| p.pid != root)
    {
        let f = TempFile::new("child", "dmp");
        if crate::winutil::write_full_dump_pid(p.pid, f.path()).is_err() {
            continue;
        }
        n += 1;
        if std::env::var_os("GATE2_VERBOSE").is_some() {
            println!(
                "   [alt surec {label}] {} pid={} parent={}",
                p.exe, p.pid, p.parent
            );
        }
        let layout = parse_layout(f.path()).unwrap_or_default();
        for h in scan_file(f.path(), secrets).unwrap_or_default() {
            let loc = layout.locate(h.offset);
            out.push((
                format!("{label}:{}:{}", p.exe, p.pid),
                LocatedHit {
                    secret: h.secret,
                    secret_id: secrets[h.secret].id.clone(),
                    enc: h.enc,
                    part: h.part,
                    offset: h.offset,
                    va: loc.va,
                    region: loc.region,
                },
            ));
        }
    }
    n
}
