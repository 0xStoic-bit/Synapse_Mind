//! PII & Secret Scrubber.
//!
//! Dedektörler ham metin üzerinde yalnızca bayt aralıkları (span) üretir; eşleşen
//! içerik hiçbir yerde kopyalanmaz, loglanmaz veya hata mesajına konmaz. Aralıklar
//! birleştirilir ve çıktı `[REDACTED_<TÜR>]` etiketleriyle yeniden kurulur.
//! Ham basamak kopyaları tutan geçici tamponlar `zeroize` edilir.

use crate::blacklist::fold_into;
use crate::normalize::{
    View, decode_base64_tokens, decode_escapes, decode_hex_tokens, normalize_str, push_grow,
};
use crate::typeparse::password_spans;
use regex::Regex;
use std::sync::LazyLock;
use zeroize::{Zeroize, Zeroizing};

/// Maske türleri. Varyant sırası çakışma önceliğidir (küçük = baskın).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    PrivateKey,
    Jwt,
    Password,
    ApiKey,
    CreditCard,
    TcKimlik,
    Ssn,
    Email,
}

impl Kind {
    /// Hafıza Paneli sırası: `API_KEY, CREDIT_CARD, TC_KIMLIK, SSN, EMAIL, PRIVATE_KEY, JWT, PASSWORD`.
    pub(crate) const PANEL_ORDER: [Kind; 8] = [
        Kind::ApiKey,
        Kind::CreditCard,
        Kind::TcKimlik,
        Kind::Ssn,
        Kind::Email,
        Kind::PrivateKey,
        Kind::Jwt,
        Kind::Password,
    ];

    pub(crate) fn panel_index(self) -> usize {
        Self::PANEL_ORDER
            .iter()
            .position(|&k| k == self)
            .unwrap_or(0)
    }

    /// Etiket adı (`REDACTED_` öneki ve köşeli parantez olmadan).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::PrivateKey => "PRIVATE_KEY",
            Kind::Jwt => "JWT",
            Kind::Password => "PASSWORD",
            Kind::ApiKey => "API_KEY",
            Kind::CreditCard => "CREDIT_CARD",
            Kind::TcKimlik => "TC_KIMLIK",
            Kind::Ssn => "SSN",
            Kind::Email => "EMAIL",
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Kind::PrivateKey => "[REDACTED_PRIVATE_KEY]",
            Kind::Jwt => "[REDACTED_JWT]",
            Kind::Password => "[REDACTED_PASSWORD]",
            Kind::ApiKey => "[REDACTED_API_KEY]",
            Kind::CreditCard => "[REDACTED_CREDIT_CARD]",
            Kind::TcKimlik => "[REDACTED_TC_KIMLIK]",
            Kind::Ssn => "[REDACTED_SSN]",
            Kind::Email => "[REDACTED_EMAIL]",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    end: usize,
    kind: Kind,
}

struct Detectors {
    private_key: Regex,
    jwt: Regex,
    known_keys: Regex,
    known_keys_loose: Regex,
    bare_prefix: Regex,
    url_userinfo: Regex,
    password_kv: Regex,
    password_sentence: Regex,
    secret_kv: Regex,
    bearer: Regex,
    email: Regex,
    ssn_formatted: Regex,
    ssn_context: Regex,
    digit_chain: Regex,
    dotted_chain: Regex,
    word_chain: Regex,
    camel_phrase: Regex,
    spaced_phrase: Regex,
    password_typed: Regex,
    colon_hex: Regex,
    short_key_before: Regex,
    key_line_end: Regex,
    digit_run: Regex,
    entropy_token: Regex,
}

fn re(pattern: &str) -> Regex {
    // Sabit desenler; hata mesajı yalnızca desen metnini içerir, kullanıcı verisini değil.
    Regex::new(pattern).expect("static regex must compile")
}

static DETECTORS: LazyLock<Detectors> = LazyLock::new(|| Detectors {
    private_key: re(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
    ),
    jwt: re(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?"),
    known_keys: re(concat!(
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b",
        r"|\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}",
        r"|\bwhsec_[A-Za-z0-9]{16,}",
        r"|\bgh[pousr]_[A-Za-z0-9]{30,}",
        r"|\bgithub_pat_[A-Za-z0-9_]{20,}",
        r"|\bsk-[A-Za-z0-9_-]{20,}",
        r"|\bxox[abposr]-[A-Za-z0-9-]{10,}",
        r"|\bxapp-[0-9]-[A-Za-z0-9-]{10,}",
        r"|\bAIza[0-9A-Za-z_-]{35}",
        r"|\bglpat-[A-Za-z0-9_-]{20,}",
        r"|\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
        r"|\bnpm_[A-Za-z0-9]{36}",
        r"|\bhf_[A-Za-z0-9]{30,}",
        r"|\bdop_v1_[a-f0-9]{40,}",
    )),
    // Boşluk/satır sonu atılmış (compact) metinde kullanılır: sözcük sınırı yok.
    known_keys_loose: re(concat!(
        r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}",
        r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}",
        r"|whsec_[A-Za-z0-9]{16,}",
        r"|gh[pousr]_[A-Za-z0-9]{30,}",
        r"|github_pat_[A-Za-z0-9_]{20,}",
        r"|sk-[A-Za-z0-9_-]{20,}",
        r"|xox[abposr]-[A-Za-z0-9-]{10,}",
        r"|xapp-[0-9]-[A-Za-z0-9-]{10,}",
        r"|AIza[0-9A-Za-z_-]{35}",
        r"|glpat-[A-Za-z0-9_-]{20,}",
        r"|npm_[A-Za-z0-9]{36}",
        r"|hf_[A-Za-z0-9]{30,}",
    )),
    // Gövdesi ayrı bir literalde tutulan yalın ön ekler: "sk_live_" + "...".
    bare_prefix: re(r#"\b(?P<v>(?:sk|rk|pk)_(?:live|test)_|gh[pousr]_|github_pat_)(?:["'`]|\z)"#),
    // scheme://user:PAROLA@host
    url_userinfo: re(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<v>[^\s/]+)@[A-Za-z0-9._\[\]-]+"),
    password_kv: re(
        r#"(?i)(?:password|passwd|passphrase|pwd|parola|şifre|sifre)(?:[_-][A-Za-z_-]{0,12}|(?-i:[A-Z])[A-Za-z]{0,12}|s|si|m|im|iniz)?["']?\??[ \t]*(?::=|=>|[:=])[ \t]*(?P<v>"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+)"#,
    ),
    // "my password is Hunter2x" / "şifre ise abc": etiket + is/are/ise/was + sonraki sözcük.
    password_sentence: re(
        r#"(?i)(?:password|passwd|passphrase|pwd|parola|şifre|sifre)(?:s|si|m|im|iniz)?[ \t]+(?:is|are|ise|was)(?:[ \t]*:)?(?:[ \t]+|[ \t]*\r?\n[ \t]*)(?P<v>"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+)"#,
    ),
    secret_kv: re(
        r#"(?i)(?:api[_-]?key|apikey|secret|token|private[_-]?key|credential)(?:[_-][A-Za-z_-]{0,16}|(?-i:[A-Z])[A-Za-z]{0,15})?["']?[ \t]*[:=][ \t]*(?P<v>"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[^\s,;&"']{8,})"#,
    ),
    bearer: re(r"(?i)\bbearer[ \t]+(?P<v>[A-Za-z0-9._~+/=-]{16,})"),
    email: re(r"[\p{L}\p{M}\p{N}._%+-]+@[\p{L}\p{M}\p{N}-]+(?:\.[\p{L}\p{M}\p{N}-]+)+"),
    ssn_formatted: re(r"[0-9]{3}-[0-9]{2}-[0-9]{4}"),
    ssn_context: re(
        r"(?i)\b(?:ssn|social security(?: number| no\.?)?)[^0-9\r\n]{0,15}(?P<v>[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4})",
    ),
    digit_chain: re(r"[0-9]+(?:[ \t\r\n+-]{1,3}[0-9]+)*"),
    // `.`/`_` ayraçlı kısa rakam grupları (kart 4.4.4.4, TC 3.3.3.2); her grup <= 6 hane.
    // Sözcük/sayı parçalarından oluşan `_`/`-` zincirleri (diceware adayı; >= 4 parça).
    word_chain: re(r"\b[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+){3,}\b"),
    // `CorrectHorseBatteryStaple2024`: >= 4 Baş harfli sözcük + 1-4 rakam.
    camel_phrase: re(r"\b(?:[A-Z][a-z]{2,9}){4,}[0-9]{1,4}\b"),
    // Etiketli boşluk ayraçlı parola cümlesi: `passphrase: correct horse battery staple`.
    spaced_phrase: re(
        r"(?i)\b(?P<l>secret words?|secret phrase|passphrase|mnemonic|recovery phrase|seed phrase|phrase)\b[ \t]*[:=]?[ \t]*(?P<v>[a-z]{3,10}(?: [a-z]{3,10}){3,}(?: [0-9]{1,4})?)\b",
    ),
    // Go/C benzeri `password string = "x"` (tip etiketten SONRA, `:` yok).
    password_typed: re(
        r#"(?i)(?:password|passwd|passphrase|pwd|parola|şifre|sifre)[A-Za-z_]{0,12}[ \t]+(?:string|str|\[\]byte|\[\]string|char\*?|bytes)[ \t]*(?::=|=)[ \t]*(?P<v>"[^"\r\n]*"|'[^'\r\n]*'|[^\s"';,]+)"#,
    ),
    // 32 bayt iki nokta ayraçlı hex (`AA:BB:...`).
    colon_hex: re(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31}\b"),
    // `{"k":"` / `'sk'=` gibi kısa JSON anahtarları (yalnızca hex bağlamında etiket sayılır).
    short_key_before: re(r#"(?i)["'](?:k|pk|sk|ak|key)["']\s*[:=]\s*["']?\s*$"#),
    dotted_chain: re(r"[0-9]{2,6}(?:[ \t\r\n+._-][0-9]{2,6}){2,}"),
    // Anahtar öneki/gövdesi satır sonunda biter; sonraki satırların kuyruk olup olmadığına
    // `detect_key_line_end` karar verir.
    key_line_end: re(concat!(
        r"\b(?P<k>(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]*",
        r"|gh[pousr]_[A-Za-z0-9]*|github_pat_[A-Za-z0-9_]*",
        r"|(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]*",
        r"|sk-[A-Za-z0-9_-]*|xox[abposr]-[A-Za-z0-9-]*|xapp-[0-9]-[A-Za-z0-9-]*",
        r"|AIza[0-9A-Za-z_-]*|glpat-[A-Za-z0-9_-]*|npm_[A-Za-z0-9]*|hf_[A-Za-z0-9]*",
        r"|whsec_[A-Za-z0-9]*))[-_]?[ \t]*(?P<nl>\r?\n)",
    )),
    digit_run: re(r"[0-9]+"),
    entropy_token: re(r"[A-Za-z0-9_+/-]{20,}={0,2}"),
});

impl Detectors {
    /// Her desenin arama önbelleğini (regex `Pool` -> `Cache`) bu iş parçacığı için oluşturur.
    fn warm(&self) {
        let probe = "warm-up 0123456789abcdef 0x00";
        for re in [
            &self.private_key,
            &self.jwt,
            &self.known_keys,
            &self.known_keys_loose,
            &self.bare_prefix,
            &self.url_userinfo,
            &self.password_kv,
            &self.password_sentence,
            &self.secret_kv,
            &self.bearer,
            &self.email,
            &self.ssn_formatted,
            &self.ssn_context,
            &self.digit_chain,
            &self.dotted_chain,
            &self.word_chain,
            &self.camel_phrase,
            &self.spaced_phrase,
            &self.password_typed,
            &self.colon_hex,
            &self.short_key_before,
            &self.key_line_end,
            &self.digit_run,
            &self.entropy_token,
        ] {
            std::hint::black_box(re.is_match(probe));
            std::hint::black_box(re.captures(probe).is_some());
        }
    }
}

thread_local! {
    static WARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Regex önbelleklerini iş parçacığı başına bir kez, ham metin işlenmeden ÖNCE kurar.
/// Önbellekler ilk aramada yığından heap'e taşınır; yığın o an temizse içine ham parça kopyalanmaz.
pub(crate) fn warm_up_thread() {
    if WARMED.with(|w| w.replace(true)) {
        return;
    }
    crate::wipe::wipe_stack();
    DETECTORS.warm();
    crate::wipe::wipe_stack();
}

/// Kaçış çözme tur sınırı (kaynak tüketimi sınırlı kalsın).
const MAX_DECODE_ROUNDS: usize = 4;

/// Metni tarar; maskelenmiş yeni metni ve maske sayısını döndürür (testler için kısayol).
/// `text` çağıran tarafından zeroize edilmelidir.
#[cfg(test)]
pub(crate) fn scrub(text: &str) -> (String, usize) {
    let (out, kinds) = scrub_kinds(text);
    (out, kinds.len())
}

/// `scrub` ile aynı; sayı yerine her maskenin türünü döndürür (yalnızca sayaçlar için).
pub(crate) fn scrub_kinds(text: &str) -> (String, Vec<Kind>) {
    let mut spans: Vec<Span> = Vec::new();

    // Gölge görünümler: her biri taranır, eşleşmeler orijinal aralıklara geri eşlenir.
    let plain = View::identity(text);
    let shadow = plain.normalized();
    scan_view(&plain, &mut spans);
    let base = if shadow.text == plain.text {
        &plain
    } else {
        scan_view(&shadow, &mut spans);
        &shadow
    };
    scan_compact(text, base, &mut spans);

    // Sınırlı iteratif kaçış çözme (en çok 4 tur; çözülen metin değişmeyince durur):
    // %XX, \uXXXX, \xNN, &#NN;, adlandırılmış varlıklar. Her tur ayrıca normalize edilip
    // taranır; eşleşmeler orijinal KODLU aralığa geri eşlenir.
    let mut current: Option<View> = None;
    for _ in 0..MAX_DECODE_ROUNDS {
        let source = current.as_ref().unwrap_or(base);
        let Some(decoded) = decode_escapes(source) else {
            break;
        };
        let decoded_shadow = decoded.normalized();
        scan_view(&decoded, &mut spans);
        scan_view(&decoded_shadow, &mut spans);
        scan_compact(text, &decoded_shadow, &mut spans);
        current = Some(decoded_shadow);
    }
    // base64 (satır sarmalı dahil) en çok 6 kat iç içe; mime'a güvenilmez.
    let mut b64 = decode_base64_tokens(base);
    for _ in 0..6 {
        let Some(view) = b64.take() else { break };
        scan_view(&view, &mut spans);
        b64 = decode_base64_tokens(&view);
    }
    if let Some(hex) = decode_hex_tokens(base) {
        scan_view(&hex, &mut spans);
    }

    build(text, spans)
}

/// `view` üzerinde tüm dedektörleri koşar; aralıkları orijinal metne eşler.
fn scan_view(view: &View, spans: &mut Vec<Span>) {
    let mut local: Vec<Span> = Vec::new();
    detect_all(&view.text, &mut local);
    for s in local {
        let (start, end) = view.orig_range(s.start, s.end);
        spans.push(span(start, end, s.kind));
    }
}

/// `s` (boşluklar atılıp normalize edilince) başından itibaren tam bir bilinen anahtar mı?
fn starts_with_complete_key(s: &str) -> bool {
    let mut joined: Zeroizing<String> = Zeroizing::new(String::with_capacity(s.len()));
    for c in s.chars().filter(|c| !c.is_whitespace()) {
        joined.push(c); // kapasite s.len() yeter (yalnızca karakter atılır)
    }
    let norm: Zeroizing<String> = Zeroizing::new(normalize_str(&joined));
    DETECTORS
        .known_keys_loose
        .find(&norm)
        .is_some_and(|f| f.start() == 0)
}

/// Boşluk/satır sonu atılmış metinde bölünmüş anahtarları arar. Yalnızca orijinalde
/// boşluk içeren aralıklar eklenir (bölünmemişler zaten normal taramada yakalanır).
fn scan_compact(original: &str, base: &View, spans: &mut Vec<Span>) {
    let compact = base.compacted();
    for m in DETECTORS.known_keys_loose.find_iter(&compact.text) {
        let (start, end) = compact.orig_range(m.start(), m.end());
        let Some(first_ws) = original[start..end].find(char::is_whitespace) else {
            continue;
        };
        if starts_with_complete_key(&original[start..start + first_ws]) {
            // İlk parça zaten tam anahtar: yalnızca satır sonuyla devam eden, tek başına
            // bir satır olan >= 8 karakterlik alfanümerik kuyruk anahtarın parçası sayılır.
            if let Some(tail_end) = line_continuation_end(original, start + first_ws) {
                spans.push(span(start, tail_end, Kind::ApiKey));
            }
            continue;
        }
        let end = trim_trailing_chunks(original, start, end);
        if original[start..end].chars().any(char::is_whitespace) {
            spans.push(span(start, end, Kind::ApiKey));
        }
    }
}

/// `pos` (boşluk başlangıcı) sonrasında, satır sonu içeren boşlukla ayrılmış ve satırın
/// tamamını kaplayan >= 8 karakterlik ASCII alfanümerik parçanın bitiş konumu.
fn line_continuation_end(original: &str, pos: usize) -> Option<usize> {
    let rest = &original[pos..];
    let after_ws = rest.trim_start();
    let ws_len = rest.len() - after_ws.len();
    if !rest[..ws_len].contains('\n') {
        return None;
    }
    let tok_len = after_ws.find(char::is_whitespace).unwrap_or(after_ws.len());
    let token = &after_ws[..tok_len];
    let line_rest = after_ws[tok_len..].split('\n').next().unwrap_or("");
    let ok = token.len() >= 8
        && token.bytes().all(|b| b.is_ascii_alphanumeric())
        && line_rest.trim().is_empty();
    ok.then_some(pos + ws_len + tok_len)
}

/// Anahtar ilk `chunk`larla zaten tamamlanmışsa, sonda kalan sıradan sözcükleri
/// (>= 4 harf, küçük harf/Baş harfi büyük) veya başka bir tanımlayıcının parçası olan
/// kuyruğu ("AWS" + `_ACCESS_KEY...`) aralıktan çıkarır. Anahtar henüz tamamlanmamışsa
/// kuyruk anahtarın parçasıdır ve korunur.
fn trim_trailing_chunks(original: &str, start: usize, mut end: usize) -> usize {
    fn wordlike(w: &str) -> bool {
        let mut it = w.chars();
        let Some(first) = it.next() else { return false };
        first.is_ascii_alphabetic() && w.chars().count() >= 4 && it.all(|c| c.is_ascii_lowercase())
    }
    loop {
        let seg = &original[start..end];
        let Some(ws) = seg.rfind(char::is_whitespace) else {
            return end;
        };
        let ch_len = seg[ws..].chars().next().map_or(1, char::len_utf8);
        let tail = &seg[ws + ch_len..];
        let before = &seg[..ws];
        if !starts_with_complete_key(before) {
            return end;
        }
        let continues_identifier = original[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
        if wordlike(tail) || continues_identifier {
            end = start + before.trim_end().len();
        } else {
            return end;
        }
    }
}

fn detect_all(text: &str, spans: &mut Vec<Span>) {
    let d = &*DETECTORS;

    for m in d.private_key.find_iter(text) {
        spans.push(span(m.start(), m.end(), Kind::PrivateKey));
    }
    for m in d.jwt.find_iter(text) {
        spans.push(span(m.start(), m.end(), Kind::Jwt));
    }
    for m in d.known_keys.find_iter(text) {
        spans.push(span(m.start(), m.end(), Kind::ApiKey));
    }
    push_group(&d.bare_prefix, text, Kind::ApiKey, spans);
    detect_password_kv(d, text, spans);
    detect_passphrases(d, text, spans);
    detect_key_line_end(d, text, spans);
    detect_password_sentence(d, text, spans);
    push_group(&d.url_userinfo, text, Kind::Password, spans);
    detect_secret_kv(d, text, spans);
    push_group(&d.bearer, text, Kind::ApiKey, spans);
    // `scheme://user:parola@host` içindeki `parola@host` e-posta sayılmaz (PASSWORD baskındır).
    let userinfo: Vec<(usize, usize)> = d
        .url_userinfo
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect();
    for m in d.email.find_iter(text) {
        let inside_url = userinfo.iter().any(|&(s, e)| m.start() < e && s < m.end());
        if !inside_url {
            spans.push(span(m.start(), m.end(), Kind::Email));
        }
    }
    detect_ssn(d, text, spans);
    detect_cards(d, text, spans);
    detect_tc(d, text, spans);
    detect_entropy_tokens(d, text, spans);
}

fn detect_password_kv(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for re in [&d.password_kv, &d.password_typed] {
        for caps in re.captures_iter(text) {
            if let (Some(m), Some(v)) = (caps.get(0), caps.name("v")) {
                // `password_hint = format!(..)`: ipucu etiketi + cagri degeri parola degildir.
                if v.as_str().ends_with('(') && label_has_hint(&text[m.start()..v.start()]) {
                    continue;
                }
                for (a, b) in password_spans(text, v.start(), v.end()) {
                    spans.push(span(a, b, Kind::Password));
                }
            }
        }
    }
}

/// Etiket (`password_hint`) `hint` iceriyor mu? (buyuk/kucuk harf duyarsiz, ara tampon yok)
fn label_has_hint(label: &str) -> bool {
    label
        .as_bytes()
        .windows(4)
        .any(|w| w.eq_ignore_ascii_case(b"hint"))
}

/// `api_key=`/`token=`/`secret:` değerleri; `token: Option<String>` gibi tip
/// anotasyonları değer sayılmaz (parola ile aynı tip dilbilgisi).
fn detect_secret_kv(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for caps in d.secret_kv.captures_iter(text) {
        if let Some(v) = caps.name("v") {
            for (a, b) in password_spans(text, v.start(), v.end()) {
                spans.push(span(a, b, Kind::ApiKey));
            }
        }
    }
}

/// Kod bağlamı: önceki sözcük bildirim anahtar sözcüğü ya da sonraki karakter `=`/`(`.
fn in_code_context(text: &str, start: usize, end: usize) -> bool {
    const KW: &[&str] = &[
        "let", "const", "fn", "var", "def", "mut", "pub", "static", "struct", "enum", "class",
        "use", "mod", "type", "import", "from", "as", "val", "func", "function",
    ];
    let prev = text[..start]
        .trim_end_matches([' ', '\t'])
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or("");
    let mut lower = prev.to_ascii_lowercase();
    let kw = KW.contains(&lower.as_str());
    lower.zeroize();
    let next = text[end..].trim_start_matches([' ', '\t']).chars().next();
    kw || matches!(next, Some('=' | '('))
}

/// `.docx`/`.xlsx` gibi dosya uzantısı hemen ardından geliyor mu?
fn followed_by_extension(text: &str, end: usize) -> bool {
    let rest = &text[end..];
    rest.strip_prefix('.').is_some_and(|r| {
        let n = r.bytes().take_while(u8::is_ascii_alphanumeric).count();
        (1..=5).contains(&n)
    })
}

/// Etiketsiz parola cümleleri (diceware): `_`/`-` zincirli sözcük+sayı, CamelCase ve
/// etiketli boşluk ayraçlı biçimler.
fn detect_passphrases(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for m in d.word_chain.find_iter(text) {
        let mut words = 0;
        let mut upper_words = 0;
        let mut numbers = 0;
        let mut ok = true;
        for part in m.as_str().split(['_', '-']) {
            let numeric = part.strip_prefix(['v', 'V']).unwrap_or(part);
            if (1..=4).contains(&numeric.len()) && numeric.bytes().all(|b| b.is_ascii_digit()) {
                numbers += 1;
                continue;
            }
            let mut c = part.chars();
            let first_ok = c.next().is_some_and(|f| f.is_ascii_alphabetic());
            if first_ok && (3..=10).contains(&part.len()) && c.all(|x| x.is_ascii_lowercase()) {
                words += 1;
            } else if (3..=10).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_uppercase())
            {
                upper_words += 1;
            } else {
                ok = false;
                break;
            }
        }
        // BUYUK harfli zincir (`CORRECT_HORSE_BATTERY_STAPLE_V2`) en az 4 sozcuk ister:
        // 3 sozcuklu `MAX_RETRY_COUNT_V2` gibi sabit adlari korunur.
        let enough = (words >= 3 && upper_words == 0) || (upper_words >= 4 && words == 0);
        if ok
            && enough
            && numbers >= 1
            && !followed_by_extension(text, m.end())
            && !in_code_context(text, m.start(), m.end())
        {
            spans.push(span(m.start(), m.end(), Kind::Password));
        }
    }
    for m in d.camel_phrase.find_iter(text) {
        if !followed_by_extension(text, m.end()) && !in_code_context(text, m.start(), m.end()) {
            spans.push(span(m.start(), m.end(), Kind::Password));
        }
    }
    for caps in d.spaced_phrase.captures_iter(text) {
        let (Some(l), Some(v)) = (caps.name("l"), caps.name("v")) else {
            continue;
        };
        let has_number = v
            .as_str()
            .bytes()
            .next_back()
            .is_some_and(|b| b.is_ascii_digit());
        let strong_label = {
            let mut lab = l.as_str().to_ascii_lowercase();
            let s =
                lab.contains("passphrase") || lab.contains("mnemonic") || lab.contains("secret");
            lab.zeroize();
            s
        };
        if has_number || strong_label {
            spans.push(span(v.start(), v.end(), Kind::Password));
        }
    }
}

/// Anahtar kuyruğu satırı: (yorum/madde işaretli, girintili) en çok 3 ASCII alfanümerik
/// sözcük, her biri >= 3 karakter. `(sözcük sayısı, toplam karakter, ilk sözcük)`.
fn tail_line(line: &str) -> Option<(usize, usize, &str)> {
    let mut body = line.trim_start_matches([' ', '\t']);
    // Satir numarasi oneki (`12: qwertzuiop`).
    let digits = body.bytes().take_while(u8::is_ascii_digit).count();
    if (1..=4).contains(&digits) && body[digits..].starts_with(": ") {
        body = body[digits + 2..].trim_start();
    }
    // Yorum/madde isareti/markdown tablo hucresi oneki; sondaki `,` `;` `|`; cevreleyen tirnaklar.
    let body = body
        .trim_start_matches(['/', '*', '#', '-', ';', '>', '+', '•', '|'])
        .trim_start()
        .trim_end_matches([',', ';', '|', ' ', '\t'])
        .trim_matches(['"', '\'', '`']);
    if body.is_empty() || body.len() > 40 {
        return None;
    }
    let mut count = 0;
    let mut total = 0;
    let mut first = "";
    for tok in body.split(' ').filter(|t| !t.is_empty()) {
        if tok.len() < 3 || !tok.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        if count == 0 {
            first = tok;
        }
        count += 1;
        total += tok.len();
    }
    (1..=3).contains(&count).then_some((count, total, first))
}

/// Anahtar satır sonunda biterse sonraki (en çok 2 boş satır atlanır) en çok 8 kuyruk
/// satırı anahtarla birlikte maskelenir. Kural: tek satırda tek sözcük >= 6 karakter, ya da
/// toplam >= 8 karakter (çok sözcüklü satır veya ardışık kısa satırlar). Yorum/madde işareti
/// ve girinti atlanır; `export FOO=1`, `PORT=8080` gibi atama satırları ve kod sözcüğüyle
/// başlayıp devam eden satırlar (`return value`) kuyruk değildir.
fn detect_key_line_end(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    const CODE_WORDS: &[&str] = &[
        "export", "return", "const", "import", "static", "public", "private", "function", "select",
        "insert", "update", "delete", "where", "from", "class", "struct", "async", "await",
    ];
    for caps in d.key_line_end.captures_iter(text) {
        let (Some(k), Some(nl)) = (caps.name("k"), caps.name("nl")) else {
            continue;
        };
        let mut pos = nl.end();
        let mut blanks = 0;
        let mut lines = 0;
        let mut total = 0;
        let mut first: Option<(usize, usize)> = None; // (sözcük sayısı, ilk sözcük uzunluğu)
        let mut end = 0;
        while pos < text.len() && lines < 8 {
            let line_end = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
            let trimmed = text[pos..line_end].trim_end_matches(['\r', ' ', '\t']);
            if trimmed.trim().is_empty() {
                blanks += 1;
                if blanks > 2 {
                    break;
                }
            } else if let Some((count, chars, tok)) = tail_line(trimmed) {
                if lines == 0 {
                    let mut word = tok.to_ascii_lowercase();
                    let code = CODE_WORDS.contains(&word.as_str());
                    word.zeroize();
                    if code && count > 1 {
                        break;
                    }
                    first = Some((count, tok.len()));
                }
                lines += 1;
                total += chars;
                end = pos + trimmed.len();
            } else {
                break;
            }
            if line_end >= text.len() {
                break;
            }
            pos = line_end + 1;
        }
        let accept = match first {
            Some((1, len)) if lines == 1 => len >= 6,
            Some(_) => total >= 8,
            None => false,
        };
        if accept {
            spans.push(span(k.start(), end, Kind::ApiKey));
        }
    }
}

/// "password is X" düz cümleleri; "is required" gibi sıradan sözcükler maskelenmez.
fn detect_password_sentence(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    const STOPWORDS: &[&str] = &[
        "required",
        "incorrect",
        "wrong",
        "invalid",
        "valid",
        "correct",
        "empty",
        "expired",
        "weak",
        "strong",
        "too",
        "not",
        "set",
        "changed",
        "reset",
        "saved",
        "stored",
        "hashed",
        "encrypted",
        "a",
        "an",
        "the",
        "your",
        "my",
        "same",
        "different",
        "missing",
        "mandatory",
        "long",
        "short",
        "at",
        "in",
        "now",
        "being",
        "sent",
        "updated",
        "ok",
        "case-sensitive",
        "zorunlu",
        "gerekli",
        "yanlış",
        "hatalı",
        "geçersiz",
        "geçerli",
        "doğru",
        "boş",
        "yanlis",
        "hatali",
        "gecersiz",
        "gecerli",
        "dogru",
        "bos",
    ];
    for caps in d.password_sentence.captures_iter(text) {
        let Some(v) = caps.name("v") else { continue };
        let mut word = v
            .as_str()
            .trim_matches(|c: char| matches!(c, '.' | ',' | ';' | '!' | '?'))
            .to_lowercase();
        let stop = STOPWORDS.contains(&word.as_str());
        word.zeroize();
        if !stop {
            spans.push(span(v.start(), v.end(), Kind::Password));
        }
    }
}

fn span(start: usize, end: usize, kind: Kind) -> Span {
    Span { start, end, kind }
}

fn push_group(re: &Regex, text: &str, kind: Kind, spans: &mut Vec<Span>) {
    for caps in re.captures_iter(text) {
        if let Some(v) = caps.name("v") {
            spans.push(span(v.start(), v.end(), kind));
        }
    }
}

/// Çakışan aralıkları birleştirir (baskın tür kazanır) ve çıktıyı kurar.
fn build(text: &str, mut spans: Vec<Span>) -> (String, Vec<Kind>) {
    if spans.is_empty() {
        return (text.to_owned(), Vec::new());
    }
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        match merged.last_mut() {
            Some(cur) if s.start < cur.end => {
                cur.end = cur.end.max(s.end);
                cur.kind = cur.kind.min(s.kind);
            }
            _ => merged.push(s),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for s in &merged {
        out.push_str(&text[last..s.start]);
        out.push_str(s.kind.tag());
        last = s.end;
    }
    out.push_str(&text[last..]);
    (out, merged.iter().map(|s| s.kind).collect())
}

fn is_digit_at(text: &str, idx: usize) -> bool {
    text.as_bytes().get(idx).is_some_and(u8::is_ascii_digit)
}

// ---------------------------------------------------------------- SSN

fn ssn_parts_valid(area: u16, group: u16, serial: u16) -> bool {
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

fn detect_ssn(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for m in d.ssn_formatted.find_iter(text) {
        let before_digit = m.start() > 0 && is_digit_at(text, m.start() - 1);
        if before_digit || is_digit_at(text, m.end()) {
            continue;
        }
        let b = m.as_str().as_bytes();
        let num = |r: std::ops::Range<usize>| {
            b[r].iter()
                .fold(0u16, |acc, c| acc * 10 + u16::from(c - b'0'))
        };
        if ssn_parts_valid(num(0..3), num(4..6), num(7..11)) {
            spans.push(span(m.start(), m.end(), Kind::Ssn));
        }
    }
    for caps in d.ssn_context.captures_iter(text) {
        if let Some(v) = caps.name("v")
            && !is_digit_at(text, v.end())
        {
            spans.push(span(v.start(), v.end(), Kind::Ssn));
        }
    }
}

// ---------------------------------------------------------------- Luhn / kredi kartı

pub(crate) fn luhn_valid(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut v = u32::from(d);
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Pencere aramasında önce en yaygın kart uzunlukları denenir.
const CARD_WINDOW_LENGTHS: [usize; 7] = [16, 15, 19, 18, 17, 14, 13];

fn detect_cards(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for m in d.digit_chain.find_iter(text) {
        scan_chain(m.start(), m.as_str(), spans);
    }
    for m in d.dotted_chain.find_iter(text) {
        // Yalnızca `.`/`_` içerenler (diğerleri genel zincirde taranır) ve rakam dizisinin
        // ortasından başlamayanlar.
        let starts_mid_run = m.start() > 0 && is_digit_at(text, m.start() - 1);
        if !starts_mid_run && m.as_str().contains(['.', '_']) {
            scan_chain(m.start(), m.as_str(), spans);
        }
    }
}

/// Rakam zinciri (`s`, metindeki `start` konumundan): TC pencereleri, bütün-zincir Luhn ve
/// grup sınırına oturan kart pencereleri.
fn scan_chain(start: usize, s: &str, spans: &mut Vec<Span>) {
    {
        let mut digits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(s.len()));
        let mut pos: Vec<usize> = Vec::with_capacity(s.len());
        let mut group_start: Vec<bool> = Vec::with_capacity(s.len());
        let mut prev_digit = false;
        for (i, b) in s.bytes().enumerate() {
            if b.is_ascii_digit() {
                digits.push(b - b'0');
                pos.push(start + i);
                group_start.push(!prev_digit);
                prev_digit = true;
            } else {
                prev_digit = false;
            }
        }
        let n = digits.len();
        // Boşluk/satır sonuyla bölünmüş TC Kimlik: grup sınırına oturan 11 hane.
        for i in (0..n).filter(|&i| group_start[i] && i + 11 <= n) {
            let ends_group = i + 11 == n || group_start[i + 11];
            if ends_group && tc_kimlik_valid(&digits[i..i + 11]) {
                spans.push(span(pos[i], pos[i + 10] + 1, Kind::TcKimlik));
            }
        }
        if n >= 13 {
            if n <= 19 && luhn_valid(&digits) {
                spans.push(span(start, start + s.len(), Kind::CreditCard));
            } else {
                scan_card_windows(&digits, &pos, &group_start, spans);
            }
        }
        digits.zeroize();
    }
}

/// Kart numarası bitişik rakamlarla (son kullanma tarihi, CVV...) uzamış olabilir.
/// Yanlış pozitifleri sınırlamak için pencere, rakam grubu sınırlarına oturmalıdır
/// (tek parça >19 haneli dizilerde başlangıç/bitiş sınırı yeterlidir).
fn scan_card_windows(digits: &[u8], pos: &[usize], group_start: &[bool], spans: &mut Vec<Span>) {
    let n = digits.len();
    let single_group = group_start.iter().filter(|&&g| g).count() == 1;
    let group_end = |idx: usize| idx + 1 == n || group_start[idx + 1];
    let mut i = 0;
    while i + 13 <= n {
        let mut found = false;
        for len in CARD_WINDOW_LENGTHS {
            if i + len > n || !(2..=6).contains(&digits[i]) {
                continue;
            }
            let aligned = (group_start[i] && group_end(i + len - 1))
                || (single_group && n > 19 && (i == 0 || i + len == n));
            if aligned && luhn_valid(&digits[i..i + len]) {
                spans.push(span(pos[i], pos[i + len - 1] + 1, Kind::CreditCard));
                i += len;
                found = true;
                break;
            }
        }
        if !found {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------- TC Kimlik

pub(crate) fn tc_kimlik_valid(d: &[u8]) -> bool {
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let odd: i32 = [0, 2, 4, 6, 8].iter().map(|&i| i32::from(d[i])).sum();
    let even: i32 = [1, 3, 5, 7].iter().map(|&i| i32::from(d[i])).sum();
    let d10 = (odd * 7 - even).rem_euclid(10);
    let d11 = d[..10].iter().map(|&x| i32::from(x)).sum::<i32>() % 10;
    i32::from(d[9]) == d10 && i32::from(d[10]) == d11
}

fn detect_tc(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for m in d.digit_run.find_iter(text) {
        if m.len() == 11 {
            let mut digits: Vec<u8> = m.as_str().bytes().map(|b| b - b'0').collect();
            if tc_kimlik_valid(&digits) {
                spans.push(span(m.start(), m.end(), Kind::TcKimlik));
            }
            digits.zeroize();
        }
    }
}

// ---------------------------------------------------------------- Entropi

/// Bayt başına Shannon entropisi (bit).
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// `RunningD3dFullScreen`, `getUserByIdV2Handler` gibi CamelCase tanımlayıcılar: rakamlar
/// atılınca (isteğe bağlı küçük harf öneki) + `[A-Z][a-z]*` sözcükleri ve sözcük başına
/// ortalama >= 3.5 harf (rastgele belirteçlerde ortalama ~2'dir).
fn is_camel_case_identifier(tok: &str) -> bool {
    if !tok.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    // Ham belirteçten türetilmiş ara tampon (`Vec<u8>`) oluşturulmaz: harfler tek geçişte,
    // yineleyici üzerinden sayılır (serbest bırakılmış, silinmemiş kopya kalmasın).
    let mut letters = tok.bytes().filter(u8::is_ascii_alphabetic).peekable();
    let mut count = 0usize;
    let mut words = 0usize;
    while letters.next_if(u8::is_ascii_lowercase).is_some() {
        count += 1;
        if words == 0 {
            words = 1;
        }
    }
    while let Some(b) = letters.next() {
        if !b.is_ascii_uppercase() {
            return false;
        }
        count += 1;
        while letters.next_if(u8::is_ascii_lowercase).is_some() {
            count += 1;
        }
        words += 1;
    }
    words >= 2 && count * 2 >= words * 7
}

fn looks_like_secret_token(tok: &str) -> bool {
    if is_camel_case_identifier(tok) {
        return false;
    }
    let has_lower = tok.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = tok.bytes().any(|b| b.is_ascii_uppercase());
    let has_digit = tok.bytes().any(|b| b.is_ascii_digit());
    let classes = u8::from(has_lower) + u8::from(has_upper) + u8::from(has_digit);
    if !has_digit || classes < 2 {
        return false;
    }
    let h = shannon_entropy(tok);
    let len = tok.len();

    // Salt hex (karma/anahtar): yalnızca 0-9a-f, uzun.
    if len >= 32 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
        return h >= 3.0;
    }
    if tok.contains('/') {
        // Dosya yolu yanlış pozitiflerini azaltmak için daha sıkı eşik.
        return classes == 3 && h >= 4.0;
    }
    match classes {
        3 => h >= 3.6,
        _ => len >= 32 && h >= 4.0,
    }
}

/// `Quarterly_Report_Final_v3`, `my_snake_case_name_v2` gibi sözcüklerden oluşan, `_`/`-`
/// ile ayrılmış tanımlayıcılar: her parça sözcük (>= 3 harf, küçük harf veya Baş harfi
/// büyük) ya da kısa sürüm/sayı parçasıdır; en az iki sözcük parçası var.
fn is_word_identifier(tok: &str) -> bool {
    if !tok.contains(['_', '-']) {
        return false;
    }
    let mut words = 0;
    for part in tok.split(['_', '-']) {
        let digits_only =
            |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
        let is_version =
            part.strip_prefix(['v', 'V']).is_some_and(digits_only) || digits_only(part);
        let mut chars = part.chars();
        let is_word = part.len() >= 3
            && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_lowercase());
        if is_word {
            words += 1;
        } else if !is_version {
            return false;
        }
    }
    words >= 2
}

/// Yalnızca hex alfabe ve sabit 40 (git/SHA-1) ya da 64 (SHA-256) uzunluk.
fn is_plain_digest(tok: &str) -> bool {
    matches!(tok.len(), 40 | 64) && tok.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Hex özetin çevresinde (aynı satır + önceki satır, <= ~120 bayt önce; aynı satırda <= 80
/// bayt sonra) key/secret/token/parola türü etiket var mı? Etiket Türkçe de olabilir; kısa
/// JSON anahtarları (`"k":`, `"sk":`) yalnızca hemen önünde geçerlidir.
fn has_secret_label_around(d: &Detectors, text: &str, start: usize, end: usize) -> bool {
    const LABELS: &[&str] = &[
        "key",
        "secret",
        "token",
        "passw",
        "pwd",
        "credential",
        "authorization",
        "bearer",
        "private",
        "salt",
        "anahtar",
        "gizli",
        "parola",
        "şifre",
        "sifre",
        "kimlik",
        "mnemonic",
    ];
    let cur_line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let prev_line_start = if cur_line_start > 0 {
        text[..cur_line_start - 1].rfind('\n').map_or(0, |i| i + 1)
    } else {
        0
    };
    let mut from = start.saturating_sub(120).max(prev_line_start);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let mut to = (end + 80).min(text.len());
    while !text.is_char_boundary(to) {
        to -= 1;
    }
    let after_limit = text[end..to].find('\n').map_or(to, |i| end + i);
    // Ham komşu metin: tek, sıfırlanan tampon; ara `String` ve büyütme kopyası yok.
    let mut around: Zeroizing<String> = Zeroizing::new(String::with_capacity(
        (start - from) + (after_limit - end) + 32,
    ));
    fold_into(&mut around, &text[from..start]);
    push_grow(&mut around, ' ');
    fold_into(&mut around, &text[end..after_limit]);
    LABELS.iter().any(|l| around.contains(l))
        || d.short_key_before
            .is_match(&text[cur_line_start.max(from)..start])
}

/// Belirteç `data:<mime>;base64,` yükünün başı mı? (Çözülmüş içerik ayrı görünümde taranır;
/// ikili görüntü/ses yükleri maskelenmeden kalır.)
fn is_data_uri_payload(text: &str, start: usize) -> bool {
    let before = &text[..start];
    before.ends_with(";base64,")
        && before
            .rfind("data:")
            .is_some_and(|i| start - i <= 160 && !before[i..].contains(char::is_whitespace))
}

fn detect_entropy_tokens(d: &Detectors, text: &str, spans: &mut Vec<Span>) {
    for m in d.entropy_token.find_iter(text) {
        let raw = m.as_str();
        let lead = raw.len() - raw.trim_start_matches(['-', '_']).len();
        let trimmed = raw.trim_matches(['-', '_']);
        let start = m.start() + lead;
        let end = start + trimmed.len();
        // `0x` + 40/64 hex: yalnızca etiketliyse maskele (etiketsiz = kabul edilen risk).
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            && is_plain_digest(hex)
        {
            if has_secret_label_around(d, text, start, end) {
                spans.push(span(start, end, Kind::ApiKey));
            }
            continue;
        }
        // Rust/C sayı sabitleri (`0xBF58_476D_1CE4_E5B9`): <= 32 hex hane, `_` ayraçlı.
        if let Some(num) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            && num.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_')
            && num.bytes().filter(u8::is_ascii_hexdigit).count() <= 32
        {
            continue;
        }
        if trimmed.len() < 20 || !looks_like_secret_token(trimmed) {
            continue;
        }
        if is_word_identifier(trimmed)
            || is_data_uri_payload(text, m.start())
            || (is_plain_digest(trimmed) && !has_secret_label_around(d, text, start, end))
        {
            continue;
        }
        spans.push(span(start, end, Kind::ApiKey));
    }
    // `AA:BB:...` (32 bayt) yalnızca etiketliyse.
    for m in d.colon_hex.find_iter(text) {
        if has_secret_label_around(d, text, m.start(), m.end()) {
            spans.push(span(m.start(), m.end(), Kind::ApiKey));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tüm girdiler sentetiktir; gerçek anahtar/kart/kimlik yoktur.

    fn s(t: &str) -> String {
        scrub(t).0
    }

    fn n(t: &str) -> usize {
        scrub(t).1
    }

    #[test]
    fn clean_text_untouched() {
        let t = "Merhaba dünya, fn main() { println!(\"hello\"); } 2026-11-18 10:20";
        assert_eq!(scrub(t), (t.to_owned(), 0));
        assert_eq!(scrub(""), (String::new(), 0));
    }

    #[test]
    fn luhn_known_values() {
        assert!(luhn_valid(&[
            4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ]));
        assert!(!luhn_valid(&[
            4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2
        ]));
        assert!(!luhn_valid(&[]));
    }

    #[test]
    fn credit_cards() {
        for card in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "5555555555554444",
            "378282246310005", // 15 hane (Amex deseni)
            "6011111111111117",
            "4222222222222", // 13 hane
        ] {
            let out = s(&format!("kart: {card} bitti"));
            assert_eq!(out, "kart: [REDACTED_CREDIT_CARD] bitti", "{card}");
        }
    }

    #[test]
    fn credit_card_non_luhn_not_masked() {
        assert_eq!(n("4111111111111112"), 0);
        assert_eq!(n("order 1234 5678 9012 3456 ok"), 0);
    }

    #[test]
    fn credit_card_followed_by_digits_still_masked() {
        let out = s("4111 1111 1111 1111 12/25 123");
        assert!(out.contains("[REDACTED_CREDIT_CARD]"), "{out}");
        assert!(!out.contains("4111"), "{out}");
    }

    #[test]
    fn tc_kimlik() {
        assert!(tc_kimlik_valid(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 4, 6]));
        assert!(!tc_kimlik_valid(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 4, 7]));
        assert!(!tc_kimlik_valid(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(s("TC: 10000000146."), "TC: [REDACTED_TC_KIMLIK].");
        // Checksum tutmayan 11 hane maskelenmez.
        assert_eq!(n("no 10000000147"), 0);
        // Daha uzun rakam dizisinin parçası değil.
        assert_eq!(n("100000001460"), 0);
    }

    #[test]
    fn ssn() {
        assert_eq!(s("ssn 123-45-6789 ok"), "ssn [REDACTED_SSN] ok");
        assert_eq!(s("SSN: 123456789"), "SSN: [REDACTED_SSN]");
        assert_eq!(
            s("Social Security Number is 123 45 6789"),
            "Social Security Number is [REDACTED_SSN]"
        );
        // Geçersiz alan numaraları (000, 666, 9xx) ve sıfır grup/seri.
        for bad in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-00-3456",
            "123-45-0000",
        ] {
            assert_eq!(n(bad), 0, "{bad}");
        }
        // Daha uzun rakam dizisinin parçası.
        assert_eq!(n("9123-45-67890"), 0);
    }

    #[test]
    fn emails() {
        assert_eq!(
            s("yaz: test.user+tag@example.co.uk lütfen"),
            "yaz: [REDACTED_EMAIL] lütfen"
        );
        assert_eq!(n("a@b"), 0);
    }

    #[test]
    fn known_api_keys() {
        let ak = format!("AKIA{}", "ABCDEFGH12345678");
        let stripe = format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc");
        let gh = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        let oai = format!("sk-{}", "proj-Ab12Cd34Ef56Gh78Ij90Kl12");
        let slack = format!("xoxb-{}", "123456789012-abcdefABCDEF1234");
        let aiza = format!("AIza{}", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q");
        for k in [ak, stripe, gh, oai, slack, aiza] {
            let out = s(&format!("key={k}!"));
            // `key=` kalıbı değil, ön ek kuralı yakalar; sonuç tek etiket olmalı.
            assert!(out.contains("[REDACTED_API_KEY]"), "{out}");
            assert!(!out.contains(&k[k.len().saturating_sub(10)..]), "{out}");
            let out2 = s(&format!("anahtar {k} sonu"));
            assert_eq!(out2, "anahtar [REDACTED_API_KEY] sonu");
        }
    }

    #[test]
    fn jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMTIz";
        assert_eq!(
            s(&format!("Authorization {jwt} x")),
            "Authorization [REDACTED_JWT] x"
        );
    }

    #[test]
    fn private_key_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\nMTIzNDU2Nzg5MA==\n-----END RSA PRIVATE KEY-----";
        assert_eq!(s(&format!("a\n{pem}\nb")), "a\n[REDACTED_PRIVATE_KEY]\nb");
        // Kesik (END yok): sona kadar maskelenir.
        let cut = "x -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk";
        assert_eq!(s(cut), "x [REDACTED_PRIVATE_KEY]");
        // Genel anahtar maskelenmez.
        assert_eq!(
            n("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"),
            0
        );
    }

    #[test]
    fn password_patterns() {
        assert_eq!(s("password=hunter2"), "password=[REDACTED_PASSWORD]");
        assert_eq!(s("PWD: s3cret!"), "PWD: [REDACTED_PASSWORD]");
        assert_eq!(
            s("db_password = 'my pass'"),
            "db_password = [REDACTED_PASSWORD]"
        );
        assert_eq!(
            s(r#"{"password": "abc def", "user": "bob"}"#),
            r#"{"password": [REDACTED_PASSWORD], "user": "bob"}"#
        );
        assert_eq!(s("şifre: gizli123"), "şifre: [REDACTED_PASSWORD]");
        assert_eq!(s("passwd=x&next=1"), "passwd=[REDACTED_PASSWORD]");
        assert_eq!(n("password reset link sent"), 0);
    }

    #[test]
    fn secret_kv_and_bearer() {
        assert_eq!(s("api_key=abcd1234efgh"), "api_key=[REDACTED_API_KEY]");
        assert_eq!(
            s("client_secret: 'zzzzzzzzzz'"),
            "client_secret: [REDACTED_API_KEY]"
        );
        assert_eq!(
            s("Authorization: Bearer abc.def-ghi_jkl123456"),
            "Authorization: Bearer [REDACTED_API_KEY]"
        );
        // Kısa değer maskelenmez.
        assert_eq!(n("token=abc"), 0);
    }

    #[test]
    fn entropy_tokens() {
        // Rastgele görünümlü uzun belirteç (sentetik).
        let tok = "q8Zx3LmP0vTt7RkW2yUe9HbN5cAj";
        assert_eq!(s(&format!("t {tok} t")), "t [REDACTED_API_KEY] t");
        // Etiketsiz 64 hex (SHA-256) artık maskelenmez; etiketli (key/secret/token) maskelenir.
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert_eq!(s(hex), hex);
        assert_eq!(s(&format!("aes key: {hex}")), "aes key: [REDACTED_API_KEY]");
        // 32 hex (md5/anahtar benzeri) ve 48 hex sabit 40/64 değil: eskisi gibi maskelenir.
        assert_eq!(n("9f86d081884c7d659a2feaa0c55ad015"), 1);
        assert_eq!(n("9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d65"), 1);
        // urlsafe base64 benzeri (tire/alt çizgi içerir)
        assert_eq!(n("k Zm9vYmFyMTIzNDU2Nzg5MEFCQ-Rk_ZUZH k"), 1);
    }

    #[test]
    fn entropy_low_false_positives() {
        for t in [
            "InternationalizationConfigurationManager",
            "https://doc.rust-lang.org/std/collections/index.html",
            "how-to-fix-the-error-in-rust-2024",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "C:\\Users\\me\\Desktop\\project\\src\\main.rs",
            "snake_case_function_name_with_a_few_words_v2",
            "src/components/forms/validators/emailValidator",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn overlapping_kinds_counted_once() {
        // password değeri aynı zamanda bilinen anahtar ön ekidir: tek maske, baskın tür PASSWORD.
        let k = format!("sk_{}_{}", "test", "4eC39HqLyjWDarjtT1zdp7dc");
        let (out, c) = scrub(&format!("password={k}"));
        assert_eq!(out, "password=[REDACTED_PASSWORD]");
        assert_eq!(c, 1);
    }

    #[test]
    fn multiple_redactions_counted() {
        let (out, c) = scrub("a@b.com 4111111111111111 123-45-6789 10000000146");
        assert_eq!(
            out,
            "[REDACTED_EMAIL] [REDACTED_CREDIT_CARD] [REDACTED_SSN] [REDACTED_TC_KIMLIK]"
        );
        assert_eq!(c, 4);
    }

    #[test]
    fn long_digit_run_with_card_prefix_masked() {
        // 16 haneli kart + bitişik CVV/tarih: tek parça >19 hane.
        let out = s("x 411111111111111112325 y");
        assert!(out.contains("[REDACTED_CREDIT_CARD]"), "{out}");
        assert!(!out.contains("4111111"), "{out}");
    }

    #[test]
    fn small_numbers_and_dates_not_masked() {
        for t in [
            "2026-11-18 10:20:30",
            "port 8080",
            "v1.2.3",
            "+90 532 123 45 67",
            "12345678",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    // --- Gölge metin / kaçış çözme / bölünmüş girdiler (Gate 1 düzeltme turu) ---

    #[test]
    fn invisible_characters_do_not_hide_secrets() {
        let card = "4111\u{200D}1111\u{200D}1111\u{200D}1111";
        assert_eq!(s(&format!("c {card} z")), "c [REDACTED_CREDIT_CARD] z");
        assert_eq!(s("a\u{FEFF}b@exam\u{00AD}ple.com!"), "[REDACTED_EMAIL]!");
        let key = format!("sk_li\u{200B}ve_{}", "4eC39HqLyjWDarjtT1zdp7dc");
        assert_eq!(s(&format!("k {key} e")), "k [REDACTED_API_KEY] e");
    }

    #[test]
    fn fullwidth_arabic_indic_and_homoglyph_inputs() {
        assert_eq!(
            s(
                "\u{FF14}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}\u{FF11}"
            ),
            "[REDACTED_CREDIT_CARD]"
        );
        assert_eq!(
            s(
                "\u{0664}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}"
            ),
            "[REDACTED_CREDIT_CARD]"
        );
        assert_eq!(s("ｕｓｅｒ＠ｅｘａｍｐｌｅ．ｃｏｍ"), "[REDACTED_EMAIL]");
        // Kiril 'р' ve 'о' ile yazılmış ghp_ anahtarı
        let key = format!("gh\u{0440}_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        assert_eq!(s(&format!("tok {key} x")), "tok [REDACTED_API_KEY] x");
    }

    #[test]
    fn split_inputs_are_masked() {
        let k = format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc");
        let (a, b) = k.split_at(12);
        assert_eq!(s(&format!("{a}\n{b}")), "[REDACTED_API_KEY]");
        assert_eq!(s(&format!("key {a} {b}.")), "key [REDACTED_API_KEY].");
        let spaced: String = k.chars().flat_map(|c| [c, ' ']).collect();
        let out = s(&format!("k: {spaced}"));
        assert!(!out.contains("4eC3"), "{out}");
        assert!(out.contains("[REDACTED_API_KEY]"));
        // Bölünmüş kart (satır sonlarıyla)
        assert_eq!(
            s("Card:\n4111\n1111\r\n1111\n1111"),
            "Card:\n[REDACTED_CREDIT_CARD]"
        );
        // Bölünmüş TC Kimlik
        assert_eq!(s("tc 1000 0000 146 ok"), "tc [REDACTED_TC_KIMLIK] ok");
    }

    #[test]
    fn complete_key_does_not_swallow_following_words() {
        let k = format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc");
        assert_eq!(
            s(&format!("anahtar {k}\nAWS sonu")),
            "anahtar [REDACTED_API_KEY]\nAWS sonu"
        );
        // Dört+ sözcüklü sıradan satır kuyruk sayılmaz.
        assert_eq!(
            s(&format!("{k}\nthis line is plain prose")),
            "[REDACTED_API_KEY]\nthis line is plain prose"
        );
    }

    #[test]
    fn encoded_secrets_masked_over_encoded_range() {
        // %XX
        assert_eq!(
            s("mail=us%65r%40example.com&x=1"),
            "mail=[REDACTED_EMAIL]&x=1"
        );
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        let enc: String = k.bytes().map(|b| format!("%{b:02x}")).collect();
        assert_eq!(s(&format!("q={enc}!")), "q=[REDACTED_API_KEY]!");
        // \uXXXX
        let js: String = k.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
        assert_eq!(
            s(&format!("\"k\":\"{js}\"")),
            "\"k\":\"[REDACTED_API_KEY]\""
        );
        // &#NN; ve &#xNN;
        let ent: String = "4111111111111111"
            .chars()
            .map(|c| format!("&#{};", c as u32))
            .collect();
        assert_eq!(
            s(&format!("<td>{ent}</td>")),
            "<td>[REDACTED_CREDIT_CARD]</td>"
        );
        let hex: String = "4111111111111111"
            .chars()
            .map(|c| format!("&#x{:X};", c as u32))
            .collect();
        assert_eq!(s(&hex), "[REDACTED_CREDIT_CARD]");
    }

    #[test]
    fn benign_escapes_survive() {
        for t in [
            "100% sure",
            "a &amp; b",
            "snow\\u2603 man",
            "x%20y",
            "&#65; and %41",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn password_values_run_to_whitespace() {
        assert_eq!(
            s("password=Tr0ub4dor&3-Synth tail"),
            "password=[REDACTED_PASSWORD] tail"
        );
        assert_eq!(
            s("PaSsWoRd = a&b;c,d\nnext"),
            "PaSsWoRd = [REDACTED_PASSWORD]\nnext"
        );
        assert_eq!(s("PASSWORD:x"), "PASSWORD:[REDACTED_PASSWORD]");
        assert_eq!(s("pwd := abc!def"), "pwd := [REDACTED_PASSWORD]");
        assert_eq!(
            s("password=a\u{00AD}&\u{00AD}b"),
            "password=[REDACTED_PASSWORD]"
        );
    }

    #[test]
    fn url_userinfo_password() {
        assert_eq!(
            s("DATABASE_URL=postgres://admin:S3cr3t!pw@db.internal.test:5432/app"),
            "DATABASE_URL=postgres://admin:[REDACTED_PASSWORD]@db.internal.test:5432/app"
        );
        assert_eq!(n("https://example.com:8080/path"), 0);
        assert_eq!(n("see user@example.org"), 1);
    }

    #[test]
    fn bare_key_prefix_literal() {
        assert_eq!(
            s("let key = \"sk_live_\" + body;"),
            "let key = \"[REDACTED_API_KEY]\" + body;"
        );
        assert_eq!(n("use the sk_live_ prefix"), 0);
    }

    // --- Gizleme ve kaçış varyantları ---

    #[test]
    fn password_in_plain_sentence() {
        assert_eq!(
            s("my password is Hunter2x-Synth9 ok"),
            "my password is [REDACTED_PASSWORD] ok"
        );
        assert_eq!(s("Şifre ise abc123XY!"), "Şifre ise [REDACTED_PASSWORD]");
        assert_eq!(
            s("the parola is: s3cr3t."),
            "the parola is: [REDACTED_PASSWORD]"
        );
        assert_eq!(s("şifrem := gizli"), "şifrem := [REDACTED_PASSWORD]");
        // Sıradan cümleler maskelenmez.
        for t in [
            "password is required",
            "Your password is incorrect.",
            "the password is a secret",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn unicode_email_local_part() {
        assert_eq!(
            s("mail ayşe.yılmaz@example.test!"),
            "mail [REDACTED_EMAIL]!"
        );
        assert_eq!(s("müller+tag@bücher.example"), "[REDACTED_EMAIL]");
    }

    #[test]
    fn plus_separated_card_and_tc() {
        assert_eq!(s("cc=4111+1111+1111+1111"), "cc=[REDACTED_CREDIT_CARD]");
        assert_eq!(s("tc 1000+0000+146 ok"), "tc [REDACTED_TC_KIMLIK] ok");
    }

    #[test]
    fn two_level_percent_decoding() {
        assert_eq!(s("e=ayse%2540example.test&x=1"), "e=[REDACTED_EMAIL]&x=1");
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        let twice: String = k.bytes().map(|b| format!("%25{b:02x}")).collect();
        assert_eq!(s(&format!("q={twice}")), "q=[REDACTED_API_KEY]");
    }

    #[test]
    fn hex_escapes_and_named_entities() {
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        let esc: String = k.bytes().map(|b| format!("\\x{b:02x}")).collect();
        assert_eq!(s(&format!("k = \"{esc}\"")), "k = \"[REDACTED_API_KEY]\"");
        assert_eq!(
            s("mail ayse.yilmaz&commat;example.test"),
            "mail [REDACTED_EMAIL]"
        );
    }

    #[test]
    fn base64url_wrapped_identifiers() {
        // "tc=10000000146" url-safe base64
        assert_eq!(s("ref=dGM9MTAwMDAwMDAxNDY"), "ref=[REDACTED_TC_KIMLIK]");
        // "mail ayse@example.test please" std base64
        let out = s("blob bWFpbCBheXNlQGV4YW1wbGUudGVzdCBwbGVhc2U= end");
        assert!(
            out.starts_with("blob [REDACTED_") && out.ends_with("] end"),
            "{out}"
        );
        assert!(!out.contains("bWFpbC"), "{out}");
    }

    #[test]
    fn split_key_with_lowercase_tail() {
        // Anahtar ilk satırda tam; ikinci satırın tamamı 8+ karakterlik alfanümerik kuyruk.
        let out = s("sk_live_AbCd1234EfGh5678\nqwertzuiopasdfgh");
        assert_eq!(out, "[REDACTED_API_KEY]");
        let out = s("ghp_A1b2C3d4E5f6G7h8I9j0\nqwertzuiopasdfgh");
        assert_eq!(out, "[REDACTED_API_KEY]");
        // Kuyruk satırı sıradan metinse (birden çok sözcük / kısa) korunur.
        let k = "sk_live_AbCd1234EfGh5678";
        assert_eq!(s(&format!("{k}\nfoo bar")), "[REDACTED_API_KEY]\nfoo bar");
        assert_eq!(s(&format!("{k}\nAWS sonu")), "[REDACTED_API_KEY]\nAWS sonu");
    }

    #[test]
    fn benign_sentences_with_label_words_survive() {
        for t in [
            "Reset your password at the portal. Contact support.",
            "Passwords must be rotated every 90 days",
            "a b c 1 2 3 4 5 6",
            "call +90 532 123 45 67",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn camel_case_identifiers_are_not_secrets() {
        for t in [
            "Self::RunningD3dFullScreen | x",
            "getUserByIdV2HandlerFactory",
            "Utf8ValidationErrorKind2",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
        // Rastgele karışık harf/rakam belirteci hâlâ maskelenir.
        assert_eq!(n("q8Zx3LmP0vTt7RkW2yUe9HbN5cAj"), 1);
    }

    // --- Çok satırlı sızıntılar ve yanlış pozitif sondaları ---

    #[test]
    fn dot_and_underscore_separated_card_and_tc() {
        assert_eq!(
            s("pan 4111.1111.1111.1111 ok"),
            "pan [REDACTED_CREDIT_CARD] ok"
        );
        assert_eq!(s("pan 5555_5555_5555_4444"), "pan [REDACTED_CREDIT_CARD]");
        assert_eq!(s("TC 100.000.001.46"), "TC [REDACTED_TC_KIMLIK]");
        // Luhn/TC checksum tutmayan veya uzun gruplu zincirler korunur.
        for t in [
            "v 1234.5678.9012.3456",
            "3.14159265358979323",
            "build_20261118_123456789012",
            "192.168.100.200",
            "2026.11.18 10.20.30",
            "1.2.3.4.5.6.7.8.9.10.11.12.13",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn password_is_followed_by_newline_value() {
        assert_eq!(
            s("the password is\nHunter2x-Synth9"),
            "the password is\n[REDACTED_PASSWORD]"
        );
        assert_eq!(
            s("şifre ise:\r\n  gizli-123"),
            "şifre ise:\r\n  [REDACTED_PASSWORD]"
        );
        // Durdurma listesi satır sonunda da geçerli; boş satır değeri ayırır.
        assert_eq!(n("the password is\nrequired"), 0);
        assert_eq!(n("the password is\n\nSection 2"), 0);
    }

    #[test]
    fn iterative_decoding_up_to_four_rounds() {
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        let mut enc = k.to_owned();
        for _ in 0..3 {
            enc = enc.bytes().map(|b| format!("%{b:02x}")).collect::<String>();
            // yeniden kodlama: '%' dahil her bayt
        }
        assert_eq!(s(&format!("q={enc}")), "q=[REDACTED_API_KEY]");
        let e3 = "ayse%252540example.test".to_owned();
        assert_eq!(s(&format!("m={e3}&x=1")), "m=[REDACTED_EMAIL]&x=1");
        // Sınır: 5 kat kodlama maskelenmeyebilir ama panik/sonsuz döngü olmamalı.
        let mut deep = "a@b.com".to_owned();
        for _ in 0..6 {
            deep = deep
                .bytes()
                .map(|b| format!("%{b:02x}"))
                .collect::<String>();
        }
        let _ = s(&deep);
    }

    #[test]
    fn split_tail_of_six_plus_chars_even_with_trailing_text() {
        let head = "AbCd1234EfGh5678IjKl9012";
        for (input, want) in [
            (format!("sk_live_{head}\nqwertzu"), "[REDACTED_API_KEY]"),
            (format!("ghp_{head}\nabcdefg"), "[REDACTED_API_KEY]"),
            (
                format!("sk_live_{head}\nqwertzuiopas and more"),
                "[REDACTED_API_KEY]",
            ),
            (
                format!("sk_live_{head}\n    qwertz.."),
                "[REDACTED_API_KEY]..",
            ),
        ] {
            // son örnekte nokta kuyruğu bitirir: alfanümerik >= 6 ardından boşluk/satır sonu yok
            let out = s(&input);
            if input.ends_with("..") {
                assert!(!out.contains(head), "{out}");
            } else {
                assert_eq!(out, want, "{input}");
            }
        }
        // Kısa kuyruk (< 6), ortam değişkeni adları ve kod sözcükleri korunur.
        let k = format!("sk_live_{head}");
        assert_eq!(s(&format!("{k}\nAWS sonu")), "[REDACTED_API_KEY]\nAWS sonu");
        assert_eq!(
            s(&format!("{k}\nGITHUB_TOKEN=x")),
            "[REDACTED_API_KEY]\nGITHUB_TOKEN=x"
        );
        assert_eq!(
            s(&format!("{k}\nexport FOO=1")),
            "[REDACTED_API_KEY]\nexport FOO=1"
        );
        assert_eq!(
            s(&format!("{k}\nPORT=8080")),
            "[REDACTED_API_KEY]\nPORT=8080"
        );
    }

    #[test]
    fn plain_digests_survive_unless_labelled() {
        let sha1 = "9fceb02d0ae598e95dc970b74767f19372d61af8";
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(n(&format!("commit {sha1} Author: test")), 0);
        assert_eq!(n(&format!("sha256: {sha256}")), 0);
        assert_eq!(n(&format!("sha256sum {sha256}  file.bin")), 0);
        // Etiket varsa (key/secret/token/password) maskelenir.
        assert_eq!(n(&format!("secret: {sha1}")), 1);
        assert_eq!(n(&format!("API_TOKEN {sha256}")), 1);
        assert_eq!(n(&format!("master key = {sha256}")), 1);
        // Etiket önceki satırdaysa (aynı/önceki satır penceresi) maskelenir; iki satır öncesi değil.
        assert_eq!(n(&format!("the key\n{sha256}")), 1);
        assert_eq!(n(&format!("the key\nnothing here\n{sha256}")), 0);
        // Hex kodlu metin (yazdırılabilir) çözülüp taranır.
        let hexed: String = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(s(&format!("blob {hexed}")), "blob [REDACTED_API_KEY]");
    }

    #[test]
    fn type_annotations_are_not_password_values() {
        for t in [
            "fn check(password: &str, salt: &[u8]) -> Hash",
            "password: &'a str,",
            "password: &mut String,",
            "password: String,",
            "pub password: Option<String>,",
            "password: Vec<u8>",
            "password: [u8; 32],",
            "password: string;",
            "password: str = \"\"",
            "password: SecretString,",
            "const f = (password: string, remember: boolean)",
            "fn f<T>(password: <T>)",
            "password=None",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
        // Gerçek parolalar (tip benzeri başlangıçlarla) hâlâ maskelenir.
        for t in [
            "password=&Hunter2x",
            "password: [Secret1!]",
            "password: String123",
            "password=<hunter2>x",
            "password: Strong!Pass9",
            "pwd=&str1ng",
        ] {
            assert_eq!(n(t), 1, "{t}");
        }
    }

    #[test]
    fn word_identifiers_are_not_keys_but_random_tokens_are() {
        for t in [
            r"C:\Users\test\Documents\Quarterly_Report_Final_v3.docx",
            "Quarterly_Report_Final_v3.docx",
            "my_snake_case_function_name_v2",
            "how-to-fix-the-error-in-rust-v2024",
            "Annual-Budget-Review_v12.xlsx",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
        assert_eq!(n("tok a1B2c3D4e5F6_g7H8i9J0k1L2m3N4"), 1);
        assert_eq!(n("tok Zm9vYmFyMTIzNDU2Nzg5MEFCQ-Rk_ZUZH"), 1);
    }

    #[test]
    fn data_uri_payloads() {
        // İkili (PNG) yük maskelenmeden kalır.
        let png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        assert_eq!(n(png), 0);
        assert_eq!(s(png), png);
        // Yazdırılabilir metin yükü çözülüp taranır: kart varsa maskelenir.
        let ok = "data:text/plain;base64,aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBwbGFpbiBub3Rl";
        assert_eq!(n(ok), 0);
        let card =
            "data:text/plain;base64,Y2FyZCBudW1iZXIgNDExMSAxMTExIDExMTEgMTExMSBleHAgMDkvMjk=";
        assert!(s(card).contains("[REDACTED_"), "{}", s(card));
        // data URI olmayan uzun base64 belirteci eskisi gibi maskelenir.
        assert_eq!(
            n(
                "blob iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
            ),
            1
        );
    }

    // --- Ek kaçış ve kodlama varyantları ---

    #[test]
    fn hex_label_window_covers_line_previous_line_and_after() {
        let h = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let filler = "lorem ipsum dolor sit amet ".repeat(4);
        for input in [
            format!("master key {filler}{h}"),
            format!("SECRET KEY\n{h}"),
            format!("private\r\n{h}"),
            format!("{h} (this is the secret)"),
            format!("token{}{h}", " ".repeat(65)),
            format!("gizli anahtar: {h}"),
            format!("şifre: {h}"),
            format!("{{\"k\":\"{h}\"}}"),
            format!("{{'sk': '{h}'}}"),
            format!("eth private key: 0x{h}"),
        ] {
            let out = s(&input);
            assert!(out.contains("[REDACTED_"), "{input}");
            assert!(!out.contains(&h[8..40]), "{out}");
        }
        // 40-hex eski GitHub token da etiketle (uzak) maskelenir
        let h40 = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c";
        assert_eq!(n(&format!("github token {filler}{h40}")), 1);
        // Etiketsiz kalanlar korunur (kabul edilen risk) ve git/özet satırları bozulmaz.
        assert_eq!(n(&format!("value {h} end")), 0);
        assert_eq!(n(&format!("0x{h}")), 0);
        assert_eq!(n(&format!("ref {h40}")), 0);
        assert_eq!(n(&format!("{{\"id\":\"{h}\"}}")), 0);
    }

    #[test]
    fn colon_separated_32_byte_hex_needs_label() {
        let pairs: Vec<String> = (0..32).map(|i| format!("{:02X}", i * 7 + 3)).collect();
        let colon = pairs.join(":");
        let out = s(&format!("private key {colon}"));
        assert!(out.contains("[REDACTED_API_KEY]"), "{out}");
        assert!(!out.contains("0A:11"), "{out}");
        // Etiketsiz sertifika parmak izi / MAC korunur.
        assert_eq!(n(&format!("fingerprint {colon}")), 0);
        assert_eq!(n("mac 00:1A:2B:3C:4D:5E"), 0);
    }

    #[test]
    fn type_lookalikes_and_values_after_types() {
        for (input, secret) in [
            ("password: Option<Hunter2xSynth9>", "Hunter2xSynth9"),
            ("password: Vec<Gizli7788Synth>", "Gizli7788Synth"),
            ("pwd: &mut Syn7h3ticQ9x", "Syn7h3ticQ9x"),
            ("password: &'a Hunter2xSynth9", "Hunter2xSynth9"),
            ("password: Box<Hunter2x-Synth9!>", "Hunter2x-Synth9!"),
            ("password: Zeroizing<Zk4nW8Synth77>", "Zk4nW8Synth77"),
            (
                "let password: &str = \"Hunter2x-Synth9\";",
                "Hunter2x-Synth9",
            ),
            ("password: String = \"Zk4$nW8-Synth\"", "Zk4$nW8-Synth"),
            (
                "password: String::from(\"Hunter2x-Synth9\")",
                "Hunter2x-Synth9",
            ),
            ("password: str Hunter2x-Synth9", "Hunter2x-Synth9"),
            (
                "pub password: String, // default Hunter2x-Synth9",
                "Hunter2x-Synth9",
            ),
            ("let password: &str := 'Gizli-7788'", "Gizli-7788"),
        ] {
            let out = s(input);
            assert!(out.contains("[REDACTED_PASSWORD]"), "{input} -> {out}");
            assert!(!out.contains(secret), "{input} -> {out}");
        }
        // Gerçek tip kullanımları ve boş/None varsayılanlar korunur.
        for t in [
            "password: String = None",
            "password: str = \"\"",
            "fn f(password: &str, salt: &[u8], iterations: u32) -> Hash",
            "pub password: Option<String>, // hashed with argon2id",
            "password: Result<String, Error>,",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn comment_prefixed_and_multi_line_tails() {
        let head = "AbCd1234EfGh5678IjKl9012";
        for input in [
            format!("sk_live_{head}\n// qwertzuiop"),
            format!("sk_live_{head}\n# qwertzuiop"),
            format!("sk_live_{head}\n * qwertzuiop"),
            format!("sk_live_{head}\n-- qwertzuiop"),
            format!("sk_live_{head}\nqwertz\nuiopas"),
            format!("sk_live_{head}\nqwertz\nuiopas\nghjklz"),
            format!("sk_live_{head}\nreturn"),
            format!("sk_live_{head}\nimport"),
        ] {
            let out = s(&input);
            assert_eq!(out, "[REDACTED_API_KEY]", "{input:?} -> {out:?}");
        }
        // Kod devam ediyorsa korunur.
        let k = format!("sk_live_{head}");
        assert_eq!(
            s(&format!("{k}\nexport FOO=1")),
            "[REDACTED_API_KEY]\nexport FOO=1"
        );
        assert_eq!(
            s(&format!("{k}\nreturn value;")),
            "[REDACTED_API_KEY]\nreturn value;"
        );
    }

    #[test]
    fn diceware_passphrases_with_digit_suffix() {
        for t in [
            "my phrase is correct_horse_battery_staple_v2 ok",
            "Winter_Garden_Purple_Lamp_2024",
            "invite code silent-river-golden-moon-7",
            "recovery: tiger-lemon-cobalt-ember-v8",
        ] {
            assert!(s(t).contains("[REDACTED_PASSWORD]"), "{t}");
        }
        // 3 sözcüklü dosya adları, kısa sözcüklü slug'lar ve rakamsız ifadeler korunur.
        for t in [
            "Quarterly_Report_Final_v3.docx",
            "Annual-Budget-Review_v12.xlsx",
            "how-to-fix-the-error-in-rust-2024",
            "correct_horse_battery_staple",
            "my_snake_case_function_name_v2",
            "my-long-slug-of-the-day-7",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn data_uri_payloads_ignore_mime_and_wrapping() {
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        // 1) base64 içinde base64
        let inner = b64_for_test(k.as_bytes());
        let outer = b64_for_test(inner.as_bytes());
        let out = s(&format!("data:image/png;base64,{outer}"));
        assert!(out.contains("[REDACTED_"), "{out}");
        assert!(!out.contains(&outer[..24]), "{out}");
        // 2) ikili başlık + metin
        let mut raw = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
        raw.extend_from_slice(format!("\n{k}\n").as_bytes());
        let b = b64_for_test(&raw);
        let out = s(&format!("data:image/png;base64,{b}"));
        assert!(out.contains("[REDACTED_"), "{out}");
        // 3) 20 sütunlu CRLF sarmalı
        let b = b64_for_test(format!("note {k} end").as_bytes());
        let wrapped: Vec<&str> = b
            .as_bytes()
            .chunks(20)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let out = s(&format!("data:image/png;base64,{}", wrapped.join("\r\n")));
        assert!(out.contains("[REDACTED_"), "{out}");
        assert!(!out.contains(wrapped[1]), "{out}");
        // Gerçek ikili (PNG) yük hâlâ korunur.
        let png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        assert_eq!(n(png), 0);
    }

    fn b64_for_test(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = u32::from(chunk[0]) << 16
                | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn numeric_hex_literals_are_not_secrets() {
        for t in [
            "z.wrapping_mul(0xBF58_476D_1CE4_E5B9);",
            "const M: u64 = 0x94D0_49BB_1331_11EB;",
            "mask = 0xDEADBEEFCAFEBABE1234",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    // --- Ek sızıntı vektörleri ---

    #[test]
    fn r3_type_contexts_and_assignments() {
        for (input, secret) in [
            (
                "password: HashMap<String, Hunter2xSynth9>",
                "Hunter2xSynth9",
            ),
            ("password: Foo<Bar, Hunter2xSynth9>", "Hunter2xSynth9"),
            (
                "password: String = format!(\"{}-Synth9\", \"Hunter2xQ\");",
                "Hunter2xQ",
            ),
            (
                "password: &str\n    = \"Hunter2x-Synth9\";",
                "Hunter2x-Synth9",
            ),
            (
                "password?: string = \"Hunter2x-Synth9\";",
                "Hunter2x-Synth9",
            ),
            (
                "var password string = \"Hunter2x-Synth9\"",
                "Hunter2x-Synth9",
            ),
            ("password: !!str Hunter2x-Synth9", "Hunter2x-Synth9"),
            ("password: !secret \"Hunter2x-Synth9\"", "Hunter2x-Synth9"),
        ] {
            let out = s(input);
            assert!(out.contains("[REDACTED_PASSWORD]"), "{input} -> {out}");
            assert!(!out.contains(secret), "{input} -> {out}");
        }
        // Yeni yanlış pozitifler: tip anotasyonları ve sabitsiz çağrılar maskelenmez.
        for t in [
            "struct Cfg { password: String, token: Option<String>, key: [u8; 32] }",
            "let password: String = String::new(); // empty",
            "token: Option<String>,",
            "secret: Vec<u8>",
            "password: &str\n    = None;",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn r3_tail_variants() {
        let head = "AbCd1234EfGh5678IjKl9012";
        for input in [
            format!("sk_live_{head}\nqwertz\nuiopas\ndfghjk\nlxcvbn\nmqwert"),
            format!("sk_live_{head}\nqwe\nrty\nuio\npas\ndfg"),
            format!("sk_live_{head}\nqwer\ntyui\nopas\ndfgh"),
            format!("sk_live_{head}\nqwert zuiop"),
            format!("sk_live_{head}\n\n# next\nqwertzuiop"),
            format!("- sk_live_{head}\n- qwertzuiop"),
        ] {
            let out = s(&input);
            assert!(!out.contains(head), "{input:?} -> {out:?}");
            assert!(!out.contains("qwe"), "{input:?} -> {out:?}");
            assert!(!out.contains("uio") && !out.contains("tyui"), "{out:?}");
        }
        // Atama satırları, kısa/sıradan satırlar ve kod devamı korunur.
        let k = format!("sk_live_{head}");
        for rest in [
            "PORT=8080",
            "export FOO=1",
            "AWS sonu",
            "return value",
            "this is plain prose",
        ] {
            let out = s(&format!("{k}\n{rest}"));
            assert!(out.ends_with(rest), "{rest} -> {out:?}");
        }
    }

    #[test]
    fn r3_diceware_variants() {
        for t in [
            "phrase red_fox_cat_dog_v2",
            "phrase correct_horse_battery_v2",
            "phrase correct_horse_9_battery_staple",
            "phrase Winter_Garden_Purple_Lamp_V2",
            "phrase winter-garden-purple-lamp-20241119",
            "phrase CorrectHorseBatteryStaple2024",
            "phrase correct horse battery staple 2024",
            "passphrase: correct horse battery staple",
        ] {
            assert!(s(t).contains("[REDACTED_"), "{t}");
        }
        // Dosya adları, kod tanımlayıcıları, düz cümleler ve soneksiz ifadeler korunur.
        for t in [
            "Quarterly_Report_Final_v3.docx",
            "Annual-Budget-Review_v12.xlsx",
            "let max_connection_pool_size_per_host_v2 = 4;",
            "fn correct_horse_battery_staple_v2(x: u8) {}",
            "Meeting about correct_horse_battery planning",
            "Annual Budget Review Draft Final Version",
            "phrase used in the summary report 2024",
            "see the recovery plan from last year",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn r3_nested_base64_and_utf16() {
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        let mut x = k.to_owned();
        for _ in 0..5 {
            x = b64_for_test(x.as_bytes());
        }
        let out = s(&format!("data:image/png;base64,{x}"));
        assert!(out.contains("[REDACTED_"), "{out}");
        let utf16: Vec<u8> = k.bytes().flat_map(|c| [c, 0]).collect();
        let b = b64_for_test(&utf16);
        let out = s(&format!("data:text/plain;charset=utf-16le;base64,{b}"));
        assert!(out.contains("[REDACTED_"), "{out}");
        let be: Vec<u8> = k.bytes().flat_map(|c| [0, c]).collect();
        let out = s(&format!("blob {}", b64_for_test(&be)));
        assert!(out.contains("[REDACTED_"), "{out}");
    }

    #[test]
    fn idempotent() {
        let once = s("mail a@b.com pw password=abc");
        assert_eq!(s(&once), once);
    }

    #[test]
    fn utf8_boundaries_safe() {
        let out = s("öğrenci şifre: çalışkan 4111111111111111 ğ a@b.com ü");
        assert!(out.contains("[REDACTED_CREDIT_CARD]"));
        assert!(out.contains("[REDACTED_EMAIL]"));
        assert!(!out.contains("çalışkan"));
    }

    #[test]
    fn shannon_entropy_sanity() {
        assert!(shannon_entropy("aaaa") < 0.01);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn r5_tail_forms_after_key_line() {
        let k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        for tail in [
            "qwertzuiop,",
            "\"qwertzuiop\"",
            "| qwertzuiop |",
            "12: qwertzuiop",
            "'qwertzuiop';",
        ] {
            let out = s(&format!("{k}\n{tail}"));
            assert!(!out.contains("qwertzuiop"), "{tail}: {out}");
        }
        // Tireyle kirilmis anahtar satiri.
        let out = s(&format!("{k}-\nqwertzuiop"));
        assert!(!out.contains("qwertzuiop"), "{out}");
        // Tablo satiri anahtarla birlikte.
        let out = s(&format!("| {k}\n| qwertzuiop |"));
        assert!(!out.contains("qwertzuiop"), "{out}");
        // Sayisal onek yalnizca `N: ` bicimindedir; madde numarasi (`1.`) kuyruk degildir.
        assert_eq!(n(&format!("{k}\n1. ab")), n(k));
    }

    #[test]
    fn r5_labels_and_uppercase_diceware() {
        for t in [
            "my secret words: alpha bravo charlie delta",
            "phrase CORRECT_HORSE_BATTERY_STAPLE_V2",
            "password: vec = Hunter2x-Synth9",
        ] {
            let out = s(t);
            assert!(out.contains("[REDACTED_"), "{t}: {out}");
        }
        assert!(!s("password: vec = Hunter2x-Synth9").contains("Hunter2x"));
        assert!(!s("my secret words: alpha bravo charlie delta").contains("bravo"));
        // 3 sozcuklu BUYUK harfli sabit adlari ve kod baglami korunur.
        for t in [
            "MAX_RETRY_COUNT_V2 is the limit",
            "const CORRECT_HORSE_BATTERY_STAPLE_V2 = 1;",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
    }

    #[test]
    fn r5_reference_and_constructor_false_positives() {
        for t in [
            "password: !secret db_password",
            "password: ${DB_PASSWORD}",
            "let password_hint = format!(\"{}: {}\", user, \"ok\");",
            "let password = String::new();",
            "let password = Default::default();",
        ] {
            assert_eq!(n(t), 0, "{t}");
        }
        // Bu bicimlerin GERCEK degerleri hala maskelenir.
        for (t, secret) in [
            ("password: !secret \"Hunter2x-Synth9\"", "Hunter2x-Synth9"),
            ("password: ${Hunter2x9}", "Hunter2x9"),
            (
                "let password_hint = \"Hunter2x-Synth9\";",
                "Hunter2x-Synth9",
            ),
            (
                "let password = String::from(\"Hunter2x-Synth9\");",
                "Hunter2x-Synth9",
            ),
        ] {
            let out = s(t);
            assert!(!out.contains(secret), "{t}: {out}");
        }
    }
}
