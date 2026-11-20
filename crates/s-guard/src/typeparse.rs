//! `password: <değer>` eşleşmelerinde değerin gerçek bir parola mı yoksa Rust/TS/Python tip
//! anotasyonu mu olduğunu ayırır.
//!
//! Küçük bir tip dilbilgisi çözer (`&'a mut str`, `[u8; 32]`, `Option<String>`, `<T>`...):
//! * bilinen tip adları tip sayılır (maskelenmez);
//! * `&`, `[`, `<` ya da jenerik argüman İÇİNDE bilinmeyen bir sözcük "tip taklidi"dir:
//!   o sözcük DEĞER sayılır (`Option<Hunter2x>`, `&'a Hunter2x`, `[Secret1!; 3]`);
//! * tip anotasyonundan SONRA gelen gerçek değer de yakalanır (`: &str = "..."`,
//!   `String::from("...")`, `: str Hunter2x-1`, `String, // default Hunter2x-1`).
//!
//! Fonksiyonlar yalnızca bayt aralıkları döndürür; içerik kopyalanmaz/loglanmaz.

const TYPES: &[&str] = &[
    "String",
    "string",
    "str",
    "bytes",
    "bool",
    "boolean",
    "number",
    "int",
    "integer",
    "float",
    "any",
    "unknown",
    "object",
    "char",
    "void",
    "Self",
    "SecretString",
    "SecureString",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "f32",
    "f64",
    "None",
    "null",
    "nil",
    "undefined",
    "true",
    "false",
    "T",
    "Error",
    "Path",
    "PathBuf",
    "OsString",
    "OsStr",
    "CStr",
    "CString",
    "Vec",
    "vec",
    "list",
    "dict",
    "tuple",
    "set",
];

const GENERICS: &[&str] = &[
    "Option",
    "Vec",
    "Box",
    "Arc",
    "Rc",
    "Result",
    "Zeroizing",
    "Secret",
    "Optional",
    "Union",
    "Cow",
    "Mutex",
    "RefCell",
    "Promise",
    "Array",
    "List",
];

/// `Ok(son)`: tip; `Err(Some((a, b)))`: tip taklidi içinde DEĞER; `Err(None)`: tip değil.
type Parsed = Result<usize, Option<(usize, usize)>>;

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t') {
        i += 1;
    }
    i
}

/// `i`'den itibaren bir değer sözcüğü: kapanış/ayraç/boşluğa kadar.
fn value_span(s: &str, i: usize) -> (usize, usize) {
    let b = s.as_bytes();
    let mut j = i;
    while j < b.len() && !matches!(b[j], b'>' | b']' | b',' | b';' | b')' | b' ' | b'\t') {
        j += 1;
    }
    (i, j)
}

fn parse_ty(s: &str, i: usize, nested: bool, depth: u8) -> Parsed {
    if depth > 5 {
        return Err(None);
    }
    let b = s.as_bytes();
    match b.get(i).copied() {
        Some(b'&') => {
            let mut j = i + 1;
            if b.get(j) == Some(&b'\'') {
                j += 1;
                while j < b.len() && is_ident(b[j]) {
                    j += 1;
                }
                j = skip_ws(b, j);
            }
            if s[j..].starts_with("mut") && matches!(b.get(j + 3), Some(b' ' | b'\t')) {
                j = skip_ws(b, j + 3);
            }
            parse_ty(s, j, true, depth + 1)
        }
        Some(b'[') => {
            let mut j = parse_ty(s, i + 1, true, depth + 1)?;
            if b.get(j) == Some(&b';') {
                j = skip_ws(b, j + 1);
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
            }
            if b.get(j) == Some(&b']') {
                j += 1;
            }
            Ok(j)
        }
        Some(b'<') => {
            let j = parse_ty(s, i + 1, true, depth + 1)?;
            if b.get(j) == Some(&b'>') {
                Ok(j + 1)
            } else {
                Err(None)
            }
        }
        Some(c) if is_ident(c) => {
            let mut j = i;
            while j < b.len() && is_ident(b[j]) {
                j += 1;
            }
            let name = &s[i..j];
            let generic_name = GENERICS.contains(&name)
                || (name.as_bytes()[0].is_ascii_uppercase() && name.len() > 1);
            if b.get(j) == Some(&b'<') && generic_name {
                let mut k = j + 1;
                loop {
                    k = skip_ws(b, k);
                    if b.get(k) == Some(&b'\'') {
                        // yaşam süresi argümanı
                        k += 1;
                        while k < b.len() && is_ident(b[k]) {
                            k += 1;
                        }
                    } else {
                        k = parse_ty(s, k, true, depth + 1)?;
                    }
                    k = skip_ws(b, k);
                    match b.get(k) {
                        Some(b',') => k += 1,
                        Some(b'>') => return Ok(k + 1),
                        _ => return Err(None),
                    }
                }
            }
            if TYPES.contains(&name) {
                Ok(j)
            } else if nested {
                Err(Some(value_span(s, i)))
            } else {
                Err(None)
            }
        }
        _ => Err(None),
    }
}

/// Tip anotasyonundan hemen sonra sözcük sınırı temiz mi (`String,` evet; `String!x` hayır)?
fn clean_boundary(s: &str, end: usize) -> bool {
    match s.as_bytes().get(end) {
        None => true,
        Some(c) => matches!(
            c,
            b' ' | b'\t' | b',' | b';' | b')' | b'}' | b']' | b'=' | b'/' | b'#' | b'{'
        ),
    }
}

/// Parola gibi görünen sözcük: >= 8 karakter, harf + rakam, ve büyük harf ya da özel karakter.
fn password_looking(tok: &str) -> bool {
    let t = tok.trim_matches(|c: char| matches!(c, '.' | ',' | ';' | ')' | '"' | '\'' | '`' | '('));
    let (mut lower, mut upper, mut digit, mut special) = (false, false, false, false);
    for c in t.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c != '_' {
            special = true;
        }
    }
    t.chars().count() >= 8 && digit && (lower || upper) && (upper || special)
}

/// `pos`'tan satır sonuna kadar çift tırnaklı, boş olmayan tüm sabitlerin aralıkları
/// (`String::from("x")`, `format!("{}-1", "y")`, `concat!("a", "b")`).
fn call_literals(text: &str, pos: usize, line_end: usize) -> Vec<(usize, usize)> {
    let seg = &text[pos.min(line_end)..line_end];
    let sb = seg.as_bytes();
    let mut spans = Vec::new();
    let mut k = 0;
    while k < sb.len() {
        if sb[k] == b'"' {
            match seg[k + 1..].find('"') {
                Some(c) => {
                    if c > 0 {
                        spans.push((pos + k, pos + k + c + 2));
                    }
                    k += c + 2;
                }
                None => break,
            }
        } else {
            k += 1;
        }
    }
    spans
}

/// `=`/`:=` işlecinden sonraki değer (`op_end`: işlecin bittiği konum).
fn assigned_value(text: &str, op_end: usize, line_end: usize) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let j = skip_ws(b, op_end);
    let r = &text[j.min(line_end)..line_end];
    if let Some(q) = r.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        let close = r[1..].find(q).map(|k| j + 1 + k);
        return match close {
            Some(c) if c > j + 1 => vec![(j, c + 1)],
            _ => Vec::new(),
        };
    }
    let tok_len = r
        .find(|c: char| c.is_whitespace() || matches!(c, ';' | ','))
        .unwrap_or(r.len());
    let tok = &r[..tok_len];
    if tok.is_empty() {
        return Vec::new();
    }
    // Çağrı/makro (`String::from("x")`, `format!(..)`, `String::new()`): değer, tırnaklı
    // sabitlerdir; sabitsiz çağrı (`String::new()`) değer taşımaz.
    if tok.contains('(') {
        return call_literals(text, j, line_end);
    }
    let type_like = matches!(parse_ty(tok, 0, false, 0), Ok(e) if e == tok.len());
    if type_like {
        Vec::new()
    } else {
        vec![(j, j + tok_len)]
    }
}

/// `pos` (satır sonu) sonrasındaki satır `=`/`:=` ile başlıyorsa işleç bitişi ve o satırın sonu.
fn next_line_assignment(text: &str, line_end: usize) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let mut k = line_end;
    if b.get(k) == Some(&b'\r') {
        k += 1;
    }
    if b.get(k) == Some(&b'\n') {
        k += 1;
    } else {
        return None;
    }
    let ns = skip_ws(b, k);
    let rest = &text[ns..];
    let op = if rest.starts_with(":=") {
        2
    } else if rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>") {
        1
    } else {
        return None;
    };
    let end = rest.find(['\n', '\r']).map_or(text.len(), |i| ns + i);
    Some((ns + op, end))
}

/// Tip anotasyonunun ardından gelen gerçek değer(ler).
fn rest_after_type(text: &str, pos: usize, line_end: usize) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut i = skip_ws(b, pos);
    if matches!(b.get(i), Some(b',' | b';' | b')' | b'}')) && i < line_end {
        i = skip_ws(b, i + 1);
    }
    // Atama bir sonraki satırda (`password: &str\n    = "x"`)
    if i >= line_end {
        return next_line_assignment(text, line_end)
            .map(|(op_end, end)| assigned_value(text, op_end, end))
            .unwrap_or_default();
    }
    let rest = &text[i..line_end];
    // `= değer` / `:= değer`
    let op = if rest.starts_with(":=") {
        2
    } else if rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>") {
        1
    } else {
        0
    };
    if op > 0 {
        return assigned_value(text, i + op, line_end);
    }
    // Yorum: içindeki parola benzeri sözcükler
    let comment_prefix = ["//", "/*", "--", "#", "*"]
        .iter()
        .find(|p| rest.starts_with(**p));
    if let Some(p) = comment_prefix {
        let base = i + p.len();
        let seg = &text[base..line_end];
        let mut spans = Vec::new();
        let mut idx = 0;
        while idx < seg.len() {
            let rem = &seg[idx..];
            idx += rem.len() - rem.trim_start().len();
            if idx >= seg.len() {
                break;
            }
            let wl = seg[idx..]
                .find(char::is_whitespace)
                .unwrap_or(seg.len() - idx);
            let word = &seg[idx..idx + wl];
            if password_looking(word) {
                let trimmed = word.trim_end_matches(['.', ',', ';', ')', '"', '\'', '`']);
                spans.push((base + idx, base + idx + trimmed.len()));
            }
            idx += wl;
        }
        return spans;
    }
    // Tipten sonra boşlukla gelen çıplak değer (`password: str Hunter2x-Synth9`)
    let tok_len = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let tok = &rest[..tok_len];
    if password_looking(tok) {
        let trimmed = tok.trim_end_matches(['.', ',', ';', ')', '"', '\'', '`']);
        return vec![(i, i + trimmed.len())];
    }
    Vec::new()
}

/// `${NAME}` (BUYUK harfli ortam degiskeni adi; sondaki `;`/`,` tolere edilir).
fn is_env_reference(value: &str) -> bool {
    let v = value.trim_end_matches([';', ',']);
    v.strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && !name.as_bytes()[0].is_ascii_digit()
        })
}

/// `Ident::new()` / `Ident::default()` (sondaki `;`/`,` tolere edilir): argumansiz kurucu.
fn is_empty_constructor(value: &str) -> bool {
    let v = value.trim_end_matches([';', ',']);
    ["::new()", "::default()"].iter().any(|suffix| {
        v.strip_suffix(suffix).is_some_and(|head| {
            !head.is_empty()
                && head.bytes().all(|b| is_ident(b) || b == b':')
                && head.as_bytes()[0].is_ascii_alphabetic()
        })
    })
}

/// `password`/`pwd` eşleşmesinin (`v_start..v_end` ham değer grubu) maskelenecek aralıkları.
/// Boş dönerse değer yalnızca bir tip anotasyonudur.
pub(crate) fn password_spans(text: &str, v_start: usize, v_end: usize) -> Vec<(usize, usize)> {
    let value = &text[v_start..v_end];
    // Kendi maske etiketimiz (idempotans).
    if value.starts_with("[REDACTED_") {
        return Vec::new();
    }
    if value.starts_with(['"', '\'']) {
        return vec![(v_start, v_end)];
    }
    let line_end = text[v_start..]
        .find(['\n', '\r'])
        .map_or(text.len(), |i| v_start + i);
    // YAML etiketi (`!!str değer`, `!secret değer`): değer etiketten sonra gelir.
    if value.starts_with('!') {
        let j = skip_ws(text.as_bytes(), v_end);
        if j >= line_end {
            return Vec::new();
        }
        // `!secret db_password`: tirnaksiz ad, gizli depodaki bir BASVURUDUR (deger degil).
        // Tirnakli sabit (`!secret "deger"`) hala maskelenir.
        if value == "!secret" && !matches!(text[j..].chars().next(), Some('"' | '\'')) {
            return Vec::new();
        }
        let e = match text[j..].chars().next() {
            Some(q @ ('"' | '\'')) => text[j + 1..line_end]
                .find(q)
                .map_or(line_end, |c| j + 1 + c + 1),
            _ => text[j..line_end]
                .find(char::is_whitespace)
                .map_or(line_end, |c| j + c),
        };
        return password_spans(text, j, e);
    }
    // `${DB_PASSWORD}`: ortam degiskeni basvurusu (deger degil).
    if is_env_reference(value) {
        return Vec::new();
    }
    // `String::new()` / `Default::default()`: argumansiz kurucu deger tasimaz.
    if is_empty_constructor(value) {
        return Vec::new();
    }
    let s = &text[v_start..line_end];
    match parse_ty(s, 0, false, 0) {
        Ok(end) if clean_boundary(s, end) => rest_after_type(text, v_start + end, line_end),
        Err(Some((a, b))) => {
            // Taklit edilen değer sözcüğün geri kalanını (`>x`, `;`) da içerebilir.
            // Jenerik içindeyse eşleşen `>`'e kadar (`Foo<Bar, Hunter2x>`: tüm argümanlar).
            let mut depth = s[..a]
                .matches('<')
                .count()
                .saturating_sub(s[..a].matches('>').count());
            let mut end = None;
            if depth > 0 {
                for (k, ch) in s[b..].char_indices() {
                    match ch {
                        '<' => depth += 1,
                        '>' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(b + k);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            let end =
                end.unwrap_or_else(|| b + s[b..].find(char::is_whitespace).unwrap_or(s.len() - b));
            vec![(v_start + a, v_start + end)]
        }
        _ => {
            // `String::from("x")`: değer, çağrıdaki tırnaklı sabittir.
            if value.ends_with('(')
                && value[..value.len() - 1]
                    .bytes()
                    .all(|c| is_ident(c) || c == b':')
            {
                return call_literals(text, v_end, line_end);
            }
            vec![(v_start, v_end)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(text: &str) -> Vec<String> {
        // `password` etiketinden sonraki ham değeri kabaca bul (testler için).
        let label = text
            .find("password")
            .or_else(|| text.find("pwd"))
            .unwrap_or(0);
        let colon = text[label..]
            .find([':', '='])
            .map(|i| label + i + 1)
            .unwrap_or(0);
        let start = colon + text[colon..].len() - text[colon..].trim_start().len();
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .map_or(text.len(), |i| start + i);
        password_spans(text, start, end)
            .into_iter()
            .map(|(a, b)| text[a..b].to_owned())
            .collect()
    }

    #[test]
    fn plain_types_yield_nothing() {
        for t in [
            "password: &str,",
            "password: &'a str,",
            "password: &mut String)",
            "password: Option<String>,",
            "password: [u8; 32],",
            "password: Vec<u8>",
            "password: Result<String, Error>",
        ] {
            assert!(masked(t).is_empty(), "{t}: {:?}", masked(t));
        }
    }

    #[test]
    fn lookalike_arguments_are_values() {
        assert_eq!(
            masked("password: Option<Hunter2xSynth9>"),
            ["Hunter2xSynth9"]
        );
        assert_eq!(masked("password: &mut Syn7h3ticQ9x"), ["Syn7h3ticQ9x"]);
        assert_eq!(masked("password: &'a Hunter2xSynth9"), ["Hunter2xSynth9"]);
        assert_eq!(masked("password: [Secret1Synth!; 3]"), ["Secret1Synth!;"]);
    }

    #[test]
    fn value_after_type() {
        assert_eq!(
            masked("let password: &str = \"Hunter2x-Synth9\";"),
            ["\"Hunter2x-Synth9\""]
        );
        assert_eq!(masked("password: String::from(\"Zk4nW8\")"), ["\"Zk4nW8\""]);
        assert_eq!(masked("password: str Hunter2x-Synth9"), ["Hunter2x-Synth9"]);
        assert_eq!(
            masked("password: String, // default Hunter2x-Synth9"),
            ["Hunter2x-Synth9"]
        );
        assert!(masked("password: str = \"\"").is_empty());
        assert!(masked("password: String = None").is_empty());
    }
}
