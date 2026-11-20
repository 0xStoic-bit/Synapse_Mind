//! Sentetik veri üreteçleri ve kodlayıcılar (yalnızca test amaçlı).
//!
//! Tüm değerler deterministik sahte-rastgeledir; gerçek kimlik bilgisi YOKTUR.
//! Stripe/AWS/GitHub vb. anahtarlar yalnızca biçimsel olarak gerçeğe benzer.

/// Deterministik splitmix64 PRNG (harici bağımlılık yok).
pub struct Rng(u64);

pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const B64_STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const B64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len() as u64) as usize] as char)
            .collect()
    }

    pub fn digits(&mut self, len: usize) -> String {
        self.string(b"0123456789", len)
    }
}

// ---------------------------------------------------------------- Luhn / kart

pub fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 12 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// `prefix` ile başlayan, toplam `total` haneli, Luhn-geçerli sahte kart numarası.
pub fn card(rng: &mut Rng, prefix: &str, total: usize) -> String {
    let mut body = String::from(prefix);
    let fill = total - 1 - prefix.len();
    body.push_str(&rng.digits(fill));
    let sum: u32 = body
        .chars()
        .rev()
        .enumerate()
        .map(|(i, c)| {
            let d = c.to_digit(10).unwrap();
            if i % 2 == 0 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    body.push(char::from_digit((10 - sum % 10) % 10, 10).unwrap());
    debug_assert!(luhn_valid(&body));
    body
}

/// Haneleri `sizes` düzeninde `sep` ile gruplar.
pub fn group(s: &str, sizes: &[usize], sep: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    for (n, &sz) in sizes.iter().enumerate() {
        if n > 0 {
            out.push_str(sep);
        }
        out.extend(&chars[i..i + sz]);
        i += sz;
    }
    out
}

// ------------------------------------------------------------ TC kimlik / SSN

pub fn tc_valid(s: &str) -> bool {
    let d: Vec<i32> = s
        .chars()
        .filter_map(|c| c.to_digit(10))
        .map(|x| x as i32)
        .collect();
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let even = d[1] + d[3] + d[5] + d[7];
    let d10 = ((odd * 7 - even) % 10 + 10) % 10;
    let d11 = (d[..10].iter().sum::<i32>()) % 10;
    d[9] == d10 && d[10] == d11
}

/// Checksum-geçerli sahte TC Kimlik No (11 hane).
pub fn tc_kimlik(rng: &mut Rng) -> String {
    let mut d: Vec<i32> = Vec::new();
    d.push(1 + rng.below(9) as i32);
    for _ in 1..9 {
        d.push(rng.below(10) as i32);
    }
    let odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let even = d[1] + d[3] + d[5] + d[7];
    let d10 = ((odd * 7 - even) % 10 + 10) % 10;
    d.push(d10);
    let d11 = d.iter().sum::<i32>() % 10;
    d.push(d11);
    let s: String = d
        .iter()
        .map(|x| char::from_digit(*x as u32, 10).unwrap())
        .collect();
    debug_assert!(tc_valid(&s));
    s
}

/// Geçerli aralıkta (area != 000/666/9xx) sahte SSN: (ham 9 hane, `AAA-GG-SSSS`).
pub fn ssn(rng: &mut Rng) -> (String, String) {
    let mut area = 1 + rng.below(899);
    if area == 666 {
        area = 667;
    }
    let group_n = 1 + rng.below(99);
    let serial = 1 + rng.below(9999);
    let raw = format!("{area:03}{group_n:02}{serial:04}");
    let dashed = format!("{area:03}-{group_n:02}-{serial:04}");
    (raw, dashed)
}

// ------------------------------------------------------------------ kodlayıcı

pub fn base64_std(data: &[u8]) -> String {
    encode_b64(data, B64_STD, true)
}

pub fn base64_url(data: &[u8]) -> String {
    encode_b64(data, B64_URL, false)
}

fn encode_b64(data: &[u8], alpha: &[u8], pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(alpha[(n >> 18) as usize & 63] as char);
        out.push(alpha[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alpha[(n >> 6) as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alpha[n as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// RFC 3986 "unreserved" dışındaki her baytı %XX yapar.
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Tüm baytları (alfanümerik dahil) %XX yapar.
pub fn url_encode_all(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02x}")).collect()
}

pub fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Her karakteri JSON `\uXXXX` kaçışına çevirir.
pub fn json_unicode_escape(s: &str) -> String {
    s.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
}

/// Her karakteri HTML sayısal varlığına (`&#NN;`) çevirir.
pub fn html_entities(s: &str) -> String {
    s.chars().map(|c| format!("&#{};", c as u32)).collect()
}

// ---------------------------------------------------------- kaçırma dönüşümü

/// `every` karakterde bir `ch` ekler.
pub fn interleave(s: &str, ch: char, every: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && i % every == 0 {
            out.push(ch);
        }
        out.push(c);
    }
    out
}

/// Latin harfleri görsel olarak aynı Kiril/Yunan homoglifleriyle değiştirir.
pub fn homoglyph(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a' => '\u{0430}',
            'c' => '\u{0441}',
            'e' => '\u{0435}',
            'i' => '\u{0456}',
            'o' => '\u{043E}',
            'p' => '\u{0440}',
            'x' => '\u{0445}',
            'y' => '\u{0443}',
            'A' => '\u{0410}',
            'B' => '\u{0412}',
            'C' => '\u{0421}',
            'E' => '\u{0415}',
            'H' => '\u{041D}',
            'I' => '\u{0406}',
            'K' => '\u{041A}',
            'M' => '\u{041C}',
            'O' => '\u{041E}',
            'P' => '\u{0420}',
            'T' => '\u{0422}',
            'X' => '\u{0425}',
            other => other,
        })
        .collect()
}

/// ASCII 0x21..0x7E -> tam genişlikli (U+FF01..U+FF5E).
pub fn fullwidth(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('\u{21}'..='\u{7E}').contains(&c) {
                char::from_u32(c as u32 + 0xFEE0).unwrap()
            } else {
                c
            }
        })
        .collect()
}

/// Rakamları Arap-Hint rakamlarına (U+0660..) çevirir.
pub fn arabic_indic_digits(s: &str) -> String {
    s.chars()
        .map(|c| match c.to_digit(10) {
            Some(d) if c.is_ascii_digit() => char::from_u32(0x0660 + d).unwrap(),
            _ => c,
        })
        .collect()
}

/// Büyük/küçük harfi dönüşümlü yapar (aKiA...).
pub fn alt_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn generated_cards_are_luhn_valid() {
        let mut r = Rng::new(1);
        for (p, n) in [("4", 16), ("51", 16), ("37", 15), ("6011", 16), ("36", 14)] {
            for _ in 0..50 {
                assert!(luhn_valid(&card(&mut r, p, n)));
            }
        }
    }

    #[test]
    fn generated_tc_are_valid() {
        let mut r = Rng::new(2);
        for _ in 0..200 {
            assert!(tc_valid(&tc_kimlik(&mut r)));
        }
        assert!(tc_valid("10000000146"));
    }

    #[test]
    fn base64_known() {
        assert_eq!(base64_std(b"Man"), "TWFu");
        assert_eq!(base64_std(b"Ma"), "TWE=");
        assert_eq!(base64_std(b"M"), "TQ==");
        assert_eq!(
            base64_url(br#"{"alg":"HS256","typ":"JWT"}"#),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        );
    }

    #[test]
    fn url_encode_known() {
        assert_eq!(url_encode("a b!"), "a%20b%21");
    }
}
