//! Gölge metin üretimi: görünmez karakterleri atar, NFKC uygular, homogliflerle
//! farklı yazı sistemlerinin rakamlarını ASCII'ye katlar, tek seviye kaçış
//! (`%XX`, `\uXXXX`, `&#NN;`) çözer. Her gölge bayt, ORİJİNAL metindeki karakter
//! aralığına geri eşlenir; böylece tarama gölgede, maskeleme orijinalde yapılır.
//!
//! Gölge metinler ham veri kopyasıdır; `View` drop edilirken `zeroize` edilir.

use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// Metnin bir görünümü: gölge metin + her baytın orijinaldeki `(başlangıç, bitiş)` aralığı.
pub(crate) struct View {
    pub text: String,
    map: Vec<(u32, u32)>,
}

impl Drop for View {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

/// `String::push`, ancak kapasite yetmezse büyütmeden ÖNCE eski tamponu sıfırlar
/// (`realloc` eski kopyayı serbest bırakırken silmez). Ham/ham-türevi tamponlar için.
pub(crate) fn push_grow(s: &mut String, c: char) {
    if s.capacity() - s.len() < c.len_utf8() {
        let mut bigger = String::with_capacity(s.capacity() * 2 + 16);
        bigger.push_str(s);
        s.zeroize();
        *s = bigger;
    }
    s.push(c);
}

fn to_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

impl View {
    fn with_capacity(n: usize) -> Self {
        View {
            text: String::with_capacity(n),
            map: Vec::with_capacity(n),
        }
    }

    fn push(&mut self, c: char, range: (u32, u32)) {
        push_grow(&mut self.text, c);
        for _ in 0..c.len_utf8() {
            self.map.push(range);
        }
    }

    /// Orijinal metnin kendisi (özdeşlik eşlemesi).
    pub fn identity(text: &str) -> View {
        let mut v = View::with_capacity(text.len());
        for (i, c) in text.char_indices() {
            v.push(c, (to_u32(i), to_u32(i + c.len_utf8())));
        }
        v
    }

    /// Gölge metindeki `[s, e)` aralığının orijinaldeki karşılığı.
    pub fn orig_range(&self, s: usize, e: usize) -> (usize, usize) {
        (self.map[s].0 as usize, self.map[e - 1].1 as usize)
    }

    fn char_range(&self, i: usize, c: char) -> (u32, u32) {
        (self.map[i].0, self.map[i + c.len_utf8() - 1].1)
    }

    /// Görünmezleri atar, NFKC + homoglif + rakam katlaması uygular.
    pub fn normalized(&self) -> View {
        let mut out = View::with_capacity(self.text.len());
        for (i, c) in self.text.char_indices() {
            let range = self.char_range(i, c);
            norm_char(c, |n| out.push(n, range));
        }
        out
    }

    /// Tüm boşluk/satır sonlarını atar (bölünmüş anahtarlar için).
    pub fn compacted(&self) -> View {
        let mut out = View::with_capacity(self.text.len());
        for (i, c) in self.text.char_indices() {
            if !c.is_whitespace() {
                out.push(c, self.char_range(i, c));
            }
        }
        out
    }
}

/// Katlama (kara liste ve tarayıcı için ortak): `f` her çıktı karakteri için çağrılır.
pub(crate) fn norm_char(c: char, mut f: impl FnMut(char)) {
    if is_invisible(c) {
        return;
    }
    for n in std::iter::once(c).nfkc() {
        if is_invisible(n) {
            continue;
        }
        f(fold_homoglyph(fold_digit(n)));
    }
}

/// Yalnızca metni normalleştirir (eşleme gerekmez). Çağıran `zeroize` etmelidir.
pub(crate) fn normalize_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        norm_char(c, |n| push_grow(&mut out, n));
    }
    out
}

fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5
        | 0x180B..=0x180E
        | 0x200B..=0x200F
        | 0x202A..=0x202E
        | 0x2060..=0x206F
        | 0x3164
        | 0xFE00..=0xFE0F
        | 0xFEFF | 0xFFA0
        | 0xFFF9..=0xFFFB
        | 0xE0000..=0xE007F
        | 0xE0100..=0xE01EF)
}

fn fold_digit(c: char) -> char {
    const ZEROS: [u32; 18] = [
        0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
        0x0D66, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x17E0, 0x1810,
    ];
    let cp = c as u32;
    if cp < 0x0660 {
        return c;
    }
    for z in ZEROS {
        if (z..z + 10).contains(&cp) {
            return char::from_u32(u32::from(b'0') + (cp - z)).unwrap_or(c);
        }
    }
    c
}

/// Yaygın Kiril/Yunan görsel benzerlerini Latin karşılıklarına katlar.
fn fold_homoglyph(c: char) -> char {
    match c {
        // Kiril küçük
        'а' => 'a',
        'в' => 'b',
        'с' => 'c',
        'ԁ' => 'd',
        'е' => 'e',
        'һ' => 'h',
        'і' => 'i',
        'ј' => 'j',
        'к' => 'k',
        'ӏ' => 'l',
        'м' => 'm',
        'н' => 'h',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'т' => 't',
        'у' => 'y',
        'х' => 'x',
        'ԝ' => 'w',
        // Kiril büyük
        'А' => 'A',
        'В' => 'B',
        'С' => 'C',
        'Ԁ' => 'D',
        'Е' => 'E',
        'Н' => 'H',
        'І' => 'I',
        'Ј' => 'J',
        'К' => 'K',
        'М' => 'M',
        'О' => 'O',
        'Р' => 'P',
        'Ѕ' => 'S',
        'Т' => 'T',
        'Х' => 'X',
        'Ү' => 'Y',
        'Ԛ' => 'Q',
        'Ԝ' => 'W',
        // Yunan
        'α' => 'a',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'ι' => 'i',
        'κ' => 'k',
        'υ' => 'u',
        'χ' => 'x',
        'τ' => 't',
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        other => other,
    }
}

// ---------------------------------------------------------------- kaçış çözme

fn hex_val(b: u8) -> Option<u32> {
    char::from(b).to_digit(16)
}

fn parse_hex(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    bytes
        .iter()
        .try_fold(0u32, |acc, &b| Some(acc.checked_mul(16)? + hex_val(b)?))
}

/// `%XX` baytı (3 bayt) varsa değerini döndürür.
fn percent_byte(b: &[u8], i: usize) -> Option<u8> {
    if b.get(i) == Some(&b'%') && i + 2 < b.len() {
        let v = hex_val(b[i + 1])? * 16 + hex_val(b[i + 2])?;
        u8::try_from(v).ok()
    } else {
        None
    }
}

/// `\uXXXX` kod birimi.
fn unicode_unit(b: &[u8], i: usize) -> Option<u32> {
    if b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'u') && i + 5 < b.len() {
        parse_hex(&b[i + 2..i + 6])
    } else {
        None
    }
}

fn named_entity(name: &[u8]) -> Option<char> {
    let c = match name {
        b"amp" => '&',
        b"lt" => '<',
        b"gt" => '>',
        b"quot" => '"',
        b"apos" => '\'',
        b"nbsp" => ' ',
        b"commat" => '@',
        b"period" => '.',
        b"lowbar" | b"UnderBar" => '_',
        b"hyphen" | b"dash" | b"minus" => '-',
        b"colon" => ':',
        b"semi" => ';',
        b"comma" => ',',
        b"num" => '#',
        b"equals" => '=',
        b"plus" => '+',
        b"percnt" => '%',
        b"excl" => '!',
        b"sol" => '/',
        b"bsol" => '\\',
        b"ast" | b"midast" => '*',
        b"quest" => '?',
        b"dollar" => '$',
        b"lpar" => '(',
        b"rpar" => ')',
        b"lsqb" | b"lbrack" => '[',
        b"rsqb" | b"rbrack" => ']',
        b"lcub" | b"lbrace" => '{',
        b"rcub" | b"rbrace" => '}',
        b"vert" | b"verbar" => '|',
        b"Tab" => '\t',
        b"NewLine" => '\n',
        _ => return None,
    };
    Some(c)
}

/// `&#NN;`, `&#xNN;` ve birkaç adlandırılmış varlık: `(karakter, tüketilen bayt)`.
fn html_entity(b: &[u8], i: usize) -> Option<(char, usize)> {
    if b.get(i) != Some(&b'&') {
        return None;
    }
    let semi = b[i + 1..].iter().take(10).position(|&x| x == b';')? + i + 1;
    let body = &b[i + 1..semi];
    let c = if let Some(rest) = body.strip_prefix(b"#") {
        let code = match rest.first() {
            Some(b'x' | b'X') => parse_hex(&rest[1..])?,
            _ => std::str::from_utf8(rest).ok()?.parse::<u32>().ok()?,
        };
        char::from_u32(code)?
    } else {
        named_entity(body)?
    };
    Some((c, semi + 1 - i))
}

/// `\xNN` (4 bayt) kaçışı.
fn hex_escape(b: &[u8], i: usize) -> Option<u8> {
    if b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'x') && i + 3 < b.len() {
        u8::try_from(parse_hex(&b[i + 2..i + 4])?).ok()
    } else {
        None
    }
}

/// Tek seviye çözme. Hiçbir şey çözülmediyse `None`.
pub(crate) fn decode_escapes(view: &View) -> Option<View> {
    let text = view.text.as_str();
    let b = text.as_bytes();
    let m = |s: usize, e: usize| {
        let (x, y) = view.orig_range(s, e);
        (to_u32(x), to_u32(y))
    };
    let mut out = View::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        // %XX koşusu
        if percent_byte(b, i).is_some() {
            let start = i;
            // Tam kapasiteli, sıfırlanan tampon: büyütme (realloc) eski kopya bırakmasın.
            let mut run = 0;
            while percent_byte(b, i + 3 * run).is_some() {
                run += 1;
            }
            let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(run));
            while let Some(v) = percent_byte(b, i) {
                buf.push(v);
                i += 3;
            }
            match std::str::from_utf8(&buf) {
                Ok(s) => {
                    // Her karakterin kaynağı, kendi %XX dizileridir.
                    let mut off = start;
                    for c in s.chars() {
                        let end = off + 3 * c.len_utf8();
                        out.push(c, m(off, end));
                        off = end;
                    }
                    changed = true;
                }
                Err(_) => {
                    // Geçersiz UTF-8: ASCII baytları çöz, kalanını olduğu gibi bırak.
                    for (k, &v) in buf.iter().enumerate() {
                        let off = start + 3 * k;
                        if v.is_ascii() {
                            out.push(char::from(v), m(off, off + 3));
                            changed = true;
                        } else {
                            for (j, ch) in text[off..off + 3].char_indices() {
                                out.push(ch, m(off + j, off + j + 1));
                            }
                        }
                    }
                }
            }
            continue;
        }
        // \uXXXX (vekil çiftleri dahil)
        if let Some(u) = unicode_unit(b, i) {
            let (code, len) = if (0xD800..0xDC00).contains(&u) {
                match unicode_unit(b, i + 6) {
                    Some(lo) if (0xDC00..0xE000).contains(&lo) => {
                        (0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00), 12)
                    }
                    _ => (u, 6),
                }
            } else {
                (u, 6)
            };
            if let Some(c) = char::from_u32(code) {
                out.push(c, m(i, i + len));
                changed = true;
                i += len;
                continue;
            }
        }
        // \xNN
        if let Some(v) = hex_escape(b, i) {
            out.push(char::from(v), m(i, i + 4));
            changed = true;
            i += 4;
            continue;
        }
        // &#NN; / &#xNN; / adlandırılmış varlıklar
        if let Some((c, len)) = html_entity(b, i) {
            out.push(c, m(i, i + len));
            changed = true;
            i += len;
            continue;
        }
        let Some(c) = text[i..].chars().next() else {
            break;
        };
        out.push(c, m(i, i + c.len_utf8()));
        i += c.len_utf8();
    }
    if changed { Some(out) } else { None }
}

// ---------------------------------------------------------------- base64

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn is_b64_char(b: u8) -> bool {
    b64_val(b).is_some()
}

/// Standart ve URL-güvenli base64 (dolgusuz da olur). Çağıran sonucu zeroize eder.
fn base64_decode(s: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(s.len() * 3 / 4 + 1));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in s {
        acc = (acc << 6) | u32::from(b64_val(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn printable_text(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| (0x20..0x7F).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
}

/// Baytlar UTF-16 (LE veya BE) kodlu ASCII metne benziyorsa (karakter başına bir sıfır
/// bayt) yalnızca ASCII baytları döndürür.
fn utf16_ascii(bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if bytes.len() < 32 {
        return None;
    }
    let pairs = bytes.len() / 2;
    let zero_odd = bytes.chunks_exact(2).filter(|p| p[1] == 0).count();
    let zero_even = bytes.chunks_exact(2).filter(|p| p[0] == 0).count();
    let keep = if zero_odd * 10 >= pairs * 9 {
        0
    } else if zero_even * 10 >= pairs * 9 {
        1
    } else {
        return None;
    };
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(pairs));
    for p in bytes.chunks_exact(2) {
        if p[keep] != 0 {
            out.push(p[keep]);
        }
    }
    Some(out)
}

/// Çözülmüş baytlarda >= `min` uzunlukta yazdırılabilir ASCII koşusu var mı?
fn has_printable_run(bytes: &[u8], min: usize) -> bool {
    let mut run = 0;
    for &b in bytes {
        if (0x20..0x7F).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r') {
            run += 1;
            if run >= min {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// En az 16 karakterlik base64/base64url sözcüklerini çözer. Satır sarmalı (MIME: 4'ün
/// katı uzunlukta satırlar arası `\r\n`) tek sözcük sayılır. Çözülmüş içerik tamamen
/// yazdırılabilir ASCII ise ya da >= 16 baytlık yazdırılabilir bir koşu içeriyorsa
/// (mime'a/başlığa güvenilmez: `\x89PNG...` + metin) görünüme alınır; yazdırılamayan baytlar
/// satır sonuna çevrilir. Çözülen her karakter, sözcüğün tüm orijinal aralığına eşlenir.
/// Hiçbir şey çözülmediyse `None`.
pub(crate) fn decode_base64_tokens(view: &View) -> Option<View> {
    let text = view.text.as_str();
    let b = text.as_bytes();
    let mut out = View::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if is_b64_char(b[i]) {
            let start = i;
            // 1. geçiş: yalnızca sınırlar (içerik kopyalanmaz); 2. geçişte tam kapasiteli,
            // sıfırlanan tampon kullanılır (büyütme/realloc eski ham kopya bırakmasın).
            let mut pieces: Vec<(usize, usize)> = Vec::new();
            let mut total = 0usize;
            loop {
                let piece_start = i;
                while i < b.len() && is_b64_char(b[i]) {
                    i += 1;
                }
                pieces.push((piece_start, i));
                total += i - piece_start;
                let piece = i - piece_start;
                if piece >= 16 && piece % 4 == 0 {
                    let mut k = i;
                    if b.get(k) == Some(&b'\r') {
                        k += 1;
                    }
                    if b.get(k) == Some(&b'\n') {
                        k += 1;
                        if k < b.len() && is_b64_char(b[k]) {
                            i = k;
                            continue;
                        }
                    }
                }
                break;
            }
            let mut end = i;
            while i < b.len() && i < end + 2 && b[i] == b'=' {
                i += 1;
            }
            end = i;
            let bytes: Zeroizing<Vec<u8>> = if total >= 16 {
                let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(total));
                for &(ps, pe) in &pieces {
                    chars.extend_from_slice(&b[ps..pe]);
                }
                let decoded = base64_decode(&chars).unwrap_or_default();
                // UTF-16 (LE/BE) ASCII metni: sıfır baytları atılır.
                utf16_ascii(&decoded).unwrap_or(decoded)
            } else {
                Zeroizing::new(Vec::new())
            };
            if printable_text(&bytes) || has_printable_run(&bytes, 16) {
                let (x, y) = view.orig_range(start, end);
                for &c in bytes.iter() {
                    let ch = if (0x20..0x7F).contains(&c) || matches!(c, b'\t' | b'\n' | b'\r') {
                        char::from(c)
                    } else {
                        '\n'
                    };
                    out.push(ch, (to_u32(x), to_u32(y)));
                }
                changed = true;
            } else {
                for (j, ch) in text[start..end].char_indices() {
                    let (x, y) = view.orig_range(start + j, start + j + ch.len_utf8());
                    out.push(ch, (to_u32(x), to_u32(y)));
                }
            }
            continue;
        }
        let Some(c) = text[i..].chars().next() else {
            break;
        };
        let (x, y) = view.orig_range(i, i + c.len_utf8());
        out.push(c, (to_u32(x), to_u32(y)));
        i += c.len_utf8();
    }
    if changed { Some(out) } else { None }
}

/// En az 16 karakterlik (çift uzunluklu) hex sözcüklerini çözer; yalnızca çıktısı tamamen
/// yazdırılabilir ASCII olanlar değiştirilir. Çözülen her karakter sözcüğün tüm
/// orijinal aralığına eşlenir. SHA-256/commit gibi ikili özetler çözülmeden kalır.
pub(crate) fn decode_hex_tokens(view: &View) -> Option<View> {
    let text = view.text.as_str();
    let b = text.as_bytes();
    let mut out = View::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_hexdigit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_hexdigit() {
                i += 1;
            }
            let run = i - start;
            let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(run / 2 + 1));
            if run >= 16 && run % 2 == 0 {
                for pair in b[start..i].chunks(2) {
                    if let Some(v) = parse_hex(pair).and_then(|v| u8::try_from(v).ok()) {
                        bytes.push(v);
                    }
                }
            }
            if printable_text(&bytes) {
                let (x, y) = view.orig_range(start, i);
                for &c in bytes.iter() {
                    out.push(char::from(c), (to_u32(x), to_u32(y)));
                }
                changed = true;
            } else {
                for (j, ch) in text[start..i].char_indices() {
                    let (x, y) = view.orig_range(start + j, start + j + ch.len_utf8());
                    out.push(ch, (to_u32(x), to_u32(y)));
                }
            }
            continue;
        }
        let Some(c) = text[i..].chars().next() else {
            break;
        };
        let (x, y) = view.orig_range(i, i + c.len_utf8());
        out.push(c, (to_u32(x), to_u32(y)));
        i += c.len_utf8();
    }
    if changed { Some(out) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_invisibles_fullwidth_homoglyph_digits() {
        assert_eq!(normalize_str("Incog\u{200B}nito"), "Incognito");
        assert_eq!(normalize_str("1Pass\u{FEFF}word"), "1Password");
        assert_eq!(normalize_str("ｓｋ＿ｌｉｖｅ"), "sk_live");
        assert_eq!(normalize_str("\u{0661}\u{0662}\u{06F3}"), "123");
        assert_eq!(normalize_str("\u{0406}nPr\u{0456}vate"), "InPrivate");
        assert_eq!(normalize_str("\u{FF0E}env"), ".env");
        assert_eq!(normalize_str("soft\u{00AD}hyphen"), "softhyphen");
    }

    #[test]
    fn identity_and_normalized_ranges_map_back() {
        let t = "a\u{200B}b\u{FF11}c";
        let v = View::identity(t).normalized();
        assert_eq!(v.text, "ab1c");
        let (s, e) = v.orig_range(0, 3);
        assert_eq!(&t[s..e], "a\u{200B}b\u{FF11}");
        let (s, e) = v.orig_range(2, 3);
        assert_eq!(&t[s..e], "\u{FF11}");
    }

    #[test]
    fn compact_drops_whitespace() {
        let v = View::identity("a b\r\nc").compacted();
        assert_eq!(v.text, "abc");
        let (s, e) = v.orig_range(0, 3);
        assert_eq!((s, e), (0, 6));
    }

    #[test]
    fn decodes_percent_unicode_html() {
        let t = "x%40y \\u0041\\ud83d\\ude00 &#52;&#x31;&amp;";
        let v = decode_escapes(&View::identity(t)).expect("changed");
        assert_eq!(v.text, "x@y A\u{1F600} 41&");
        // `%40` orijinalde 3 bayt
        let (s, e) = v.orig_range(1, 2);
        assert_eq!(&t[s..e], "%40");
        assert!(decode_escapes(&View::identity("plain text 100% sure & done")).is_none());
        // Geçersiz/eksik kaçışlar bozulmaz
        assert!(decode_escapes(&View::identity("%4 \\u12 &#;")).is_none());
    }

    #[test]
    fn decodes_hex_and_named_entities() {
        let t = "\\x73\\x6b&commat;&period;&lowbar;";
        let v = decode_escapes(&View::identity(t)).expect("changed");
        assert_eq!(v.text, "sk@._");
        assert_eq!(v.orig_range(0, 1), (0, 4));
    }

    #[test]
    fn two_level_decode_maps_to_original() {
        let t = "a%2540b";
        let d1 = decode_escapes(&View::identity(t)).expect("level 1");
        assert_eq!(d1.text, "a%40b");
        let d2 = decode_escapes(&d1).expect("level 2");
        assert_eq!(d2.text, "a@b");
        let (s, e) = d2.orig_range(1, 2);
        assert_eq!(&t[s..e], "%2540");
    }

    #[test]
    fn base64_tokens_decode_printable_only() {
        // "tc=50625767390 ok" (url-safe, dolgusuz)
        let t = "ref=dGM9NTA2MjU3NjczOTAgb2s";
        let v = decode_base64_tokens(&View::identity(t)).expect("changed");
        assert_eq!(v.text, "ref=tc=50625767390 ok");
        let (s, e) = v.orig_range(4, 5);
        assert_eq!(&t[s..e], "dGM9NTA2MjU3NjczOTAgb2s");
        // Sıradan uzun sözcük ve ikili çıktı çözülmez
        assert!(decode_base64_tokens(&View::identity("internationalization-x")).is_none());
        assert!(decode_base64_tokens(&View::identity("short")).is_none());
    }

    #[test]
    fn hex_tokens_decode_printable_only() {
        // "sk_live_abc123" hex
        let t = "blob 736b5f6c6976655f616263313233 end";
        let v = decode_hex_tokens(&View::identity(t)).expect("changed");
        assert_eq!(v.text, "blob sk_live_abc123 end");
        let (s, e) = v.orig_range(5, 6);
        assert_eq!(&t[s..e], "736b5f6c6976655f616263313233");
        // SHA-256 benzeri ikili özet ve kısa hex çözülmez
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(decode_hex_tokens(&View::identity(sha)).is_none());
        assert!(decode_hex_tokens(&View::identity("deadbeef")).is_none());
    }

    #[test]
    fn percent_multibyte_utf8() {
        let v = decode_escapes(&View::identity("%C3%BC")).expect("changed");
        assert_eq!(v.text, "ü");
        assert_eq!(v.orig_range(0, 2), (0, 6));
    }
}
