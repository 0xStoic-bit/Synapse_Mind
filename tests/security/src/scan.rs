//! Döküm dosyasında sır arama (UTF-8 + UTF-16LE) ve döküm düzeninden (thread yığınları,
//! bellek bölgesi türü) sızıntı yeri tahmini. Platformdan bağımsız saf kod (dosya okuma).

use aho_corasick::AhoCorasick;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Aranan sır (sentetik). `id` raporlama içindir.
#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub text: String,
    /// Ham bayt dizisi olan sırlar (ör. 32 baytlık anahtar): bayt deseni (Enc::Raw) ayrıca aranır.
    pub raw: Option<Vec<u8>>,
}

impl Secret {
    pub fn new(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            raw: None,
        }
    }

    /// Anahtar materyali: ham baytlar + `text` (genellikle hex) için metin kodlamaları.
    pub fn key(id: impl Into<String>, raw: &[u8], text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            raw: Some(raw.to_vec()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Enc {
    Utf8,
    Utf16Le,
    /// Ham bayt deseni (metin değil; anahtar baytları).
    Raw,
}

/// `Full`: sırrın tamamı. `Mid`/`Tail`: 12 karakterlik orta/son parça; serbest bırakılmış
/// yığın bloklarında baş baytlar free-list işaretçisiyle ezilebildiği için ek olarak aranır.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Part {
    Full,
    Mid,
    Tail,
}

/// Bundan kısa sırlar aranmaz (rastgele eşleşme riski).
pub const MIN_SECRET_CHARS: usize = 11;
/// Bu uzunluktan itibaren orta/son parça da aranır.
pub const FRAGMENT_MIN_CHARS: usize = 24;
pub const FRAGMENT_CHARS: usize = 12;

#[derive(Debug, Clone, Copy)]
struct PatternMeta {
    secret: usize,
    enc: Enc,
    part: Part,
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn patterns(secrets: &[Secret]) -> (Vec<Vec<u8>>, Vec<PatternMeta>) {
    let mut pats = Vec::new();
    let mut metas = Vec::new();
    for (i, s) in secrets.iter().enumerate() {
        if let Some(raw) = &s.raw
            && raw.len() >= 16
        {
            let mut rparts: Vec<(Part, Vec<u8>)> = vec![(Part::Full, raw.clone())];
            if raw.len() >= FRAGMENT_MIN_CHARS {
                let mid = raw.len() / 2 - FRAGMENT_CHARS / 2;
                rparts.push((Part::Mid, raw[mid..mid + FRAGMENT_CHARS].to_vec()));
                rparts.push((Part::Tail, raw[raw.len() - FRAGMENT_CHARS..].to_vec()));
            }
            for (part, bytes) in rparts {
                pats.push(bytes);
                metas.push(PatternMeta {
                    secret: i,
                    enc: Enc::Raw,
                    part,
                });
            }
        }
        let chars: Vec<char> = s.text.chars().collect();
        if chars.len() < MIN_SECRET_CHARS {
            continue;
        }
        let mut parts: Vec<(Part, String)> = vec![(Part::Full, s.text.clone())];
        if chars.len() >= FRAGMENT_MIN_CHARS {
            let mid = chars.len() / 2 - FRAGMENT_CHARS / 2;
            parts.push((Part::Mid, chars[mid..mid + FRAGMENT_CHARS].iter().collect()));
            parts.push((
                Part::Tail,
                chars[chars.len() - FRAGMENT_CHARS..].iter().collect(),
            ));
        }
        for (part, text) in parts {
            pats.push(text.as_bytes().to_vec());
            metas.push(PatternMeta {
                secret: i,
                enc: Enc::Utf8,
                part,
            });
            pats.push(utf16le(&text));
            metas.push(PatternMeta {
                secret: i,
                enc: Enc::Utf16Le,
                part,
            });
        }
    }
    (pats, metas)
}

#[derive(Debug, Clone, Copy)]
pub struct Hit {
    pub secret: usize,
    pub enc: Enc,
    pub part: Part,
    /// Döküm dosyasındaki bayt ofseti.
    pub offset: u64,
}

/// Döküm dosyasını parça parça tarar (bellekte tamamını tutmaz). ÇAKIŞAN eşleşmeler de raporlanır
/// (Full + Mid + Tail aynı yerde); parça sınırlarını aşan eşleşmeler için en uzun desen boyunca
/// bindirme (carry) tutulur ve yalnızca bindirmeyi aşan eşleşmeler yeni sayılır.
pub fn scan_file(path: &Path, secrets: &[Secret]) -> io::Result<Vec<Hit>> {
    const CHUNK: usize = 4 * 1024 * 1024;
    let (pats, metas) = patterns(secrets);
    if pats.is_empty() {
        return Ok(Vec::new());
    }
    let ac = AhoCorasick::new(&pats).map_err(io::Error::other)?;
    let carry_len = pats
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let mut f = File::open(path)?;
    let mut hits = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + carry_len);
    let mut buf_base: u64 = 0; // buf[0]'ın dosyadaki ofseti
    let mut carry = 0usize; // buf başındaki önceki parçadan kalan bayt sayısı
    loop {
        let old = buf.len();
        buf.resize(old + CHUNK, 0);
        let n = f.read(&mut buf[old..])?;
        buf.truncate(old + n);
        if n == 0 {
            break;
        }
        for m in ac.find_overlapping_iter(&buf) {
            if m.end() > carry {
                let meta = metas[m.pattern().as_usize()];
                hits.push(Hit {
                    secret: meta.secret,
                    enc: meta.enc,
                    part: meta.part,
                    offset: buf_base + m.start() as u64,
                });
            }
        }
        let keep = carry_len.min(buf.len());
        let drop_n = buf.len() - keep;
        buf.drain(..drop_n);
        buf_base += drop_n as u64;
        carry = keep;
    }
    Ok(hits)
}

// ------------------------------------------------------------------ döküm düzeni

#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// (sanal adres, boyut, dosya ofseti) — Memory64List.
    pub ranges: Vec<(u64, u64, u64)>,
    /// (thread id, yığın başlangıç VA, boyut)
    pub stacks: Vec<(u32, u64, u64)>,
    /// (taban VA, bölge boyutu, tür) — MemoryInfoList.
    pub regions: Vec<(u64, u64, u32)>,
}

const MEM_IMAGE: u32 = 0x0100_0000;
const MEM_MAPPED: u32 = 0x0004_0000;
const MEM_PRIVATE: u32 = 0x0002_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub va: Option<u64>,
    /// "stack(tid=N)", "private(heap/other)", "image", "mapped", "unknown".
    pub region: String,
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn read_at(f: &mut File, off: u64, len: usize) -> io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut v = vec![0u8; len];
    f.read_exact(&mut v)?;
    Ok(v)
}

/// Minidump başlığını/akış dizinini okur; ThreadList(3), Memory64List(9), MemoryInfoList(16).
pub fn parse_layout(path: &Path) -> io::Result<Layout> {
    let mut f = File::open(path)?;
    let hdr = read_at(&mut f, 0, 32)?;
    if &hdr[0..4] != b"MDMP" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a minidump"));
    }
    let n = rd_u32(&hdr, 8) as usize;
    let dir_rva = rd_u32(&hdr, 12) as u64;
    let dir = read_at(&mut f, dir_rva, n * 12)?;
    let mut layout = Layout::default();
    for i in 0..n {
        let ty = rd_u32(&dir, i * 12);
        let size = rd_u32(&dir, i * 12 + 4) as usize;
        let rva = rd_u32(&dir, i * 12 + 8) as u64;
        match ty {
            3 => {
                let d = read_at(&mut f, rva, size)?;
                let cnt = rd_u32(&d, 0) as usize;
                for t in 0..cnt {
                    let o = 4 + t * 48;
                    if o + 48 > d.len() {
                        break;
                    }
                    // THREAD: id u32, suspend u32, prio class u32, prio u32, teb u64, stack{start u64, size u32, rva u32}
                    layout.stacks.push((
                        rd_u32(&d, o),
                        rd_u64(&d, o + 24),
                        rd_u32(&d, o + 32) as u64,
                    ));
                }
            }
            9 => {
                let d = read_at(&mut f, rva, 16)?;
                let cnt = rd_u64(&d, 0) as usize;
                let mut file_off = rd_u64(&d, 8);
                let descs = read_at(&mut f, rva + 16, cnt * 16)?;
                for k in 0..cnt {
                    let va = rd_u64(&descs, k * 16);
                    let sz = rd_u64(&descs, k * 16 + 8);
                    layout.ranges.push((va, sz, file_off));
                    file_off += sz;
                }
            }
            16 => {
                let d = read_at(&mut f, rva, size)?;
                let hsz = rd_u32(&d, 0) as usize;
                let esz = rd_u32(&d, 4) as usize;
                let cnt = rd_u64(&d, 8) as usize;
                for k in 0..cnt {
                    let o = hsz + k * esz;
                    if o + 48 > d.len() {
                        break;
                    }
                    // INFO: base u64, alloc_base u64, alloc_prot u32, pad u32, size u64, state u32, protect u32, type u32
                    layout
                        .regions
                        .push((rd_u64(&d, o), rd_u64(&d, o + 24), rd_u32(&d, o + 40)));
                }
            }
            _ => {}
        }
    }
    Ok(layout)
}

impl Layout {
    pub fn locate(&self, file_offset: u64) -> Location {
        let Some(&(va0, _sz, off0)) = self
            .ranges
            .iter()
            .find(|&&(_, sz, off)| file_offset >= off && file_offset < off + sz)
        else {
            return Location {
                va: None,
                region: "unknown".into(),
            };
        };
        let va = va0 + (file_offset - off0);
        if let Some(&(tid, _, _)) = self.stacks.iter().find(|&&(_, s, z)| va >= s && va < s + z) {
            return Location {
                va: Some(va),
                region: format!("stack(tid={tid})"),
            };
        }
        let region = match self
            .regions
            .iter()
            .find(|&&(b, z, _)| va >= b && va < b + z)
        {
            Some(&(_, _, ty)) if ty == MEM_IMAGE => "image",
            Some(&(_, _, ty)) if ty == MEM_MAPPED => "mapped",
            Some(&(_, _, ty)) if ty == MEM_PRIVATE => "private(heap/other)",
            _ => "unknown",
        };
        Location {
            va: Some(va),
            region: region.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("s-gate2-unit-{}-{name}", std::process::id()));
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn finds_utf8_and_utf16_and_fragments() {
        let secret = Secret::new("s", "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX");
        let mut data = vec![0u8; 5000];
        data.extend_from_slice(secret.text.as_bytes());
        data.extend(vec![1u8; 9000]);
        data.extend(utf16le(&secret.text));
        // baş baytları ezilmiş kopya: yalnızca kuyruk/orta parça kalır
        data.extend(vec![2u8; 100]);
        data.extend_from_slice(&secret.text.as_bytes()[10..]);
        let p = tmp("scan.bin", &data);
        let hits = scan_file(&p, std::slice::from_ref(&secret)).unwrap();
        std::fs::remove_file(&p).ok();
        assert!(
            hits.iter()
                .any(|h| h.enc == Enc::Utf8 && h.part == Part::Full)
        );
        assert!(
            hits.iter()
                .any(|h| h.enc == Enc::Utf16Le && h.part == Part::Full)
        );
        assert!(
            hits.iter()
                .any(|h| h.part == Part::Tail && h.offset > 14_000)
        );
    }

    #[test]
    fn short_secrets_are_not_searched() {
        let s = Secret::new("s", "short");
        let p = tmp("short.bin", b"xxshortxx");
        assert!(scan_file(&p, &[s]).unwrap().is_empty());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn detects_across_buffer_boundaries() {
        let secret = Secret::new("s", "ghp_0123456789abcdefABCDEF0123456789abcd");
        let mut data = vec![0u8; 8 * 1024 * 1024 - 7];
        data.extend_from_slice(secret.text.as_bytes());
        let p = tmp("boundary.bin", &data);
        let hits = scan_file(&p, std::slice::from_ref(&secret)).unwrap();
        std::fs::remove_file(&p).ok();
        assert!(
            hits.iter()
                .any(|h| h.part == Part::Full && h.enc == Enc::Utf8)
        );
    }
}
