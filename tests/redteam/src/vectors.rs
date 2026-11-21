//! Gate 1 sentetik saldırı vektörleri.
//!
//! Her vektör: sensörün üretebileceği bir `RawCapturePacket` tarifi + çıktıda
//! ASLA bulunmaması gereken "iğneler" (needles). Tüm değerler sentetiktir.

use crate::synth::*;
use s_types::{ClipboardFormat, EventKind, RawCapturePacket, RawPayload};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Sözleşmedeki açık kategoriler (kart, TC, SSN, API anahtarı, PEM, JWT, parola, e-posta).
    Core,
    /// Kaçırma denemeleri (homoglif, sıfır genişlik, satır bölme, base64, URL, harf oyunları).
    Evasion,
    /// Kara liste: süreç / gizli pencere / hassas dosya başlığı (DROP beklenir).
    Blacklist,
    /// Zararsız kontrol örnekleri (Masked ve metni korunmuş olmalı).
    Control,
    /// Guard'ın "bilinen sınırlama" olarak listelediği ileri kaçırma teknikleri (ayrı raporlanır).
    Stretch,
    /// Yanlış pozitif sondaları: bilinçli fail-closed olabilecek zararsız girdiler (yalnızca RAPOR).
    FpProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropKind {
    BlacklistedProcess,
    PrivateWindow,
    SensitiveFile,
    IgnoredFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// `Verdict::Masked` beklenir (Dropped da güvenli sayılır ama raporlanır; kontrol
    /// örneklerinde Dropped HATA'dır).
    Masked,
    /// Belirli sebeple `Verdict::Dropped` beklenir.
    Dropped(DropKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Accessibility,
    Clipboard,
    /// Yalnızca görsel kare (metin yok; başlık yine de taşınır).
    Frame,
    /// `ClipboardFormat::IgnoredFormat`.
    ClipboardIgnored,
}

#[derive(Debug, Clone)]
pub struct Vector {
    pub id: String,
    pub tier: Tier,
    pub category: &'static str,
    pub process_name: String,
    pub window_title: String,
    pub payload: PayloadKind,
    pub text: String,
    /// Çıktının hiçbir alanında (≥ pencere uzunluğunda parça olarak) kalmaması gereken dizgiler.
    pub needles: Vec<String>,
    pub expect: Expect,
    /// Çıktıda `[REDACTED_<TÜR>]` olarak görünmesi beklenen türler (uyum testi).
    pub mask_kinds: Vec<&'static str>,
    /// Kontrol örneklerinde metinde korunması gereken işaret.
    pub keep: Option<String>,
}

impl Vector {
    pub fn new(id: &str, tier: Tier, category: &'static str) -> Self {
        Self {
            id: id.to_string(),
            tier,
            category,
            process_name: "notepad.exe".into(),
            window_title: "Project notes - Notepad".into(),
            payload: PayloadKind::Accessibility,
            text: String::new(),
            needles: Vec::new(),
            expect: Expect::Masked,
            mask_kinds: Vec::new(),
            keep: None,
        }
    }

    pub fn text(mut self, t: impl Into<String>) -> Self {
        self.text = t.into();
        self
    }
    pub fn secret(mut self, s: impl Into<String>) -> Self {
        self.needles.push(s.into());
        self
    }
    pub fn kinds(mut self, k: &[&'static str]) -> Self {
        self.mask_kinds = k.to_vec();
        self
    }
    pub fn clip(mut self) -> Self {
        self.payload = PayloadKind::Clipboard;
        self
    }
    pub fn payload(mut self, p: PayloadKind) -> Self {
        self.payload = p;
        self
    }
    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.window_title = t.into();
        self
    }
    pub fn proc_name(mut self, p: impl Into<String>) -> Self {
        self.process_name = p.into();
        self
    }
    pub fn drops(mut self, d: DropKind) -> Self {
        self.expect = Expect::Dropped(d);
        self
    }
    pub fn keep(mut self, k: impl Into<String>) -> Self {
        self.keep = Some(k.into());
        self
    }

    /// Her çağrıda taze paket üretir (`RawCapturePacket`'ın Clone'una güvenmez).
    pub fn to_packet(&self, timestamp_ms: u64) -> RawCapturePacket {
        let (event_kind, raw_payload) = match self.payload {
            PayloadKind::Accessibility => (
                EventKind::AccessibilityTreeChanged {
                    node_count: self.text.lines().count() as u32,
                },
                RawPayload::AccessibilityText(self.text.clone()),
            ),
            PayloadKind::Clipboard => (
                EventKind::ClipboardCopied {
                    format: ClipboardFormat::PlainText,
                },
                RawPayload::ClipboardText(self.text.clone()),
            ),
            PayloadKind::ClipboardIgnored => (
                EventKind::ClipboardCopied {
                    format: ClipboardFormat::IgnoredFormat,
                },
                RawPayload::ClipboardText(self.text.clone()),
            ),
            PayloadKind::Frame => (
                EventKind::VisualDifferenceDetected { phash_distance: 9 },
                RawPayload::ScreenFrame {
                    width: 4,
                    height: 4,
                    pixels_rgba: vec![0x7F; 4 * 4 * 4],
                },
            ),
        };
        RawCapturePacket {
            timestamp_ms,
            process_id: 4242,
            process_name: self.process_name.clone(),
            window_title: self.window_title.clone(),
            event_kind,
            raw_payload,
        }
    }
}

// ------------------------------------------------------------------ sentetik sırlar

fn stripe_live(r: &mut Rng) -> String {
    format!("sk_live_{}", r.string(ALNUM, 24))
}
fn stripe_test(r: &mut Rng) -> String {
    format!("sk_test_{}", r.string(ALNUM, 24))
}
fn aws_id(r: &mut Rng) -> String {
    format!("AKIA{}", r.string(UPPER_DIGIT, 16))
}
fn aws_secret(r: &mut Rng) -> String {
    r.string(B64_STD, 40)
}
fn ghp(r: &mut Rng) -> String {
    format!("ghp_{}", r.string(ALNUM, 36))
}
fn openai(r: &mut Rng) -> String {
    format!("sk-proj-{}", r.string(B64_URL, 48))
}
fn slack(r: &mut Rng) -> String {
    format!(
        "xoxb-{}-{}-{}",
        r.digits(12),
        r.digits(13),
        r.string(ALNUM, 24)
    )
}
fn jwt(r: &mut Rng, n: u32) -> String {
    let h = base64_url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let p = base64_url(
        format!(r#"{{"sub":"synthetic-user-{n}","iat":1700000000,"role":"tester"}}"#).as_bytes(),
    );
    let s = r.string(B64_URL, 43);
    format!("{h}.{p}.{s}")
}
fn pem_rows(r: &mut Rng, rows: usize) -> Vec<String> {
    let mut v: Vec<String> = (0..rows).map(|_| r.string(B64_STD, 64)).collect();
    v.push(format!("{}==", r.string(B64_STD, 22)));
    v
}
fn pem(label: &str, rows: &[String]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----",
        rows.join("\n")
    )
}

// ------------------------------------------------------------------------- Core

fn core(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Core;

    // --- Kredi kartları (Luhn-geçerli) ---
    let mut cardv = |id: &str, num: String, shown: String, ctx: &str, clip: bool| {
        let mut x = Vector::new(id, t, "credit_card")
            .text(format!("{ctx} {shown} thanks"))
            .secret(num)
            .secret(shown)
            .kinds(&["CREDIT_CARD"]);
        if clip {
            x = x.clip();
        }
        v.push(x);
    };
    let c = card(r, "4", 16);
    cardv(
        "core-card-visa-space",
        c.clone(),
        group(&c, &[4, 4, 4, 4], " "),
        "Card:",
        false,
    );
    let c = card(r, "4", 16);
    cardv(
        "core-card-visa-dash",
        c.clone(),
        group(&c, &[4, 4, 4, 4], "-"),
        "Card number",
        false,
    );
    let c = card(r, "4", 16);
    cardv(
        "core-card-visa-contiguous",
        c.clone(),
        c.clone(),
        "cc=",
        false,
    );
    let c = card(r, "51", 16);
    cardv(
        "core-card-mc-space",
        c.clone(),
        group(&c, &[4, 4, 4, 4], " "),
        "Mastercard",
        false,
    );
    let c = card(r, "55", 16);
    cardv(
        "core-card-mc-dash",
        c.clone(),
        group(&c, &[4, 4, 4, 4], "-"),
        "MC",
        false,
    );
    let c = card(r, "2221", 16);
    cardv(
        "core-card-mc2-contiguous",
        c.clone(),
        c.clone(),
        "pan:",
        false,
    );
    let c = card(r, "37", 15);
    cardv(
        "core-card-amex-465-space",
        c.clone(),
        group(&c, &[4, 6, 5], " "),
        "AMEX",
        false,
    );
    let c = card(r, "34", 15);
    cardv(
        "core-card-amex-contiguous",
        c.clone(),
        c.clone(),
        "amex",
        false,
    );
    let c = card(r, "6011", 16);
    cardv(
        "core-card-discover-dash",
        c.clone(),
        group(&c, &[4, 4, 4, 4], "-"),
        "Discover",
        false,
    );
    let c = card(r, "3530", 16);
    cardv(
        "core-card-jcb-space",
        c.clone(),
        group(&c, &[4, 4, 4, 4], " "),
        "JCB",
        false,
    );
    let c = card(r, "36", 14);
    cardv(
        "core-card-diners14-space",
        c.clone(),
        group(&c, &[4, 6, 4], " "),
        "Diners",
        false,
    );
    let c = card(r, "4", 16);
    cardv(
        "core-card-clipboard",
        c.clone(),
        group(&c, &[4, 4, 4, 4], " "),
        "",
        true,
    );
    let c = card(r, "4", 16);
    let shown = group(&c, &[4, 4, 4, 4], " ");
    v.push(
        Vector::new("core-card-with-expiry-cvv", t, "credit_card")
            .text(format!(
                "Number {shown}\nExp 09/29\nCVV 417\nName TEST USER"
            ))
            .secret(c)
            .secret(shown)
            .kinds(&["CREDIT_CARD"]),
    );

    // --- TC Kimlik ---
    for (id, ctx, clip) in [
        ("core-tc-plain", "Kimlik: ", false),
        ("core-tc-label", "T.C. Kimlik No: ", false),
        ("core-tc-clipboard", "", true),
    ] {
        let tc = tc_kimlik(r);
        let mut x = Vector::new(id, t, "tc_kimlik")
            .text(format!("Ad Soyad: Test Kisi\n{ctx}{tc}\nDogum: 01.01.1990"))
            .secret(tc)
            .kinds(&["TC_KIMLIK"]);
        if clip {
            x = x.clip();
        }
        v.push(x);
    }
    let tc = tc_kimlik(r);
    v.push(
        Vector::new("core-tc-inline-sentence", t, "tc_kimlik")
            .text(format!(
                "Basvuru sahibinin TC numarasi {tc} olarak kayitlidir."
            ))
            .secret(tc)
            .kinds(&["TC_KIMLIK"]),
    );

    // --- SSN ---
    let (raw, dashed) = ssn(r);
    v.push(
        Vector::new("core-ssn-dashed", t, "ssn")
            .text(format!("SSN: {dashed}"))
            .secret(dashed)
            .kinds(&["SSN"]),
    );
    let (raw2, dashed2) = ssn(r);
    let spaced = format!("{} {} {}", &raw2[..3], &raw2[3..5], &raw2[5..]);
    v.push(
        Vector::new("core-ssn-spaced", t, "ssn")
            .text(format!("Social security number {spaced}"))
            .secret(spaced)
            .secret(dashed2)
            .kinds(&["SSN"]),
    );
    v.push(
        Vector::new("core-ssn-contiguous-clipboard", t, "ssn")
            .text(format!("ssn={raw}"))
            .secret(raw)
            .clip()
            .kinds(&["SSN"]),
    );

    // --- Stripe ---
    let k = stripe_live(r);
    v.push(
        Vector::new("core-stripe-sk-live", t, "api_key")
            .text(format!("STRIPE KEY {k} (prod)"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = stripe_test(r);
    v.push(
        Vector::new("core-stripe-sk-test", t, "api_key")
            .text(format!("use {k} for sandbox"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = format!("rk_live_{}", r.string(ALNUM, 24));
    v.push(
        Vector::new("core-stripe-rk-live", t, "api_key")
            .text(format!("restricted: {k}"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = stripe_live(r);
    v.push(
        Vector::new("core-stripe-json-clipboard", t, "api_key")
            .text(format!(r#"{{"secret":"{k}","mode":"live"}}"#))
            .secret(k)
            .clip()
            .kinds(&["API_KEY"]),
    );

    // --- AWS ---
    let id = aws_id(r);
    v.push(
        Vector::new("core-aws-akia-only", t, "api_key")
            .text(format!("Access key id: {id}"))
            .secret(id)
            .kinds(&["API_KEY"]),
    );
    let s = aws_secret(r);
    v.push(
        Vector::new("core-aws-secret-labelled", t, "api_key")
            .text(format!("aws_secret_access_key = {s}"))
            .secret(s)
            .kinds(&["API_KEY"]),
    );
    let (id, s) = (aws_id(r), aws_secret(r));
    v.push(
        Vector::new("core-aws-credentials-file", t, "api_key")
            .text(format!("[default]\naws_access_key_id = {id}\naws_secret_access_key = {s}\nregion = eu-west-1"))
            .secret(id)
            .secret(s)
            .kinds(&["API_KEY"]),
    );

    // --- GitHub ---
    let k = ghp(r);
    v.push(
        Vector::new("core-github-ghp", t, "api_key")
            .text(format!("export GH_TOKEN={k}"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = format!("gho_{}", r.string(ALNUM, 36));
    v.push(
        Vector::new("core-github-gho", t, "api_key")
            .text(format!("oauth {k}"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = format!("github_pat_{}_{}", r.string(ALNUM, 22), r.string(ALNUM, 59));
    v.push(
        Vector::new("core-github-fine-grained-pat", t, "api_key")
            .text(format!("pat: {k}"))
            .secret(k)
            .clip()
            .kinds(&["API_KEY"]),
    );

    // --- OpenAI / Slack ---
    let k = openai(r);
    v.push(
        Vector::new("core-openai-sk-proj", t, "api_key")
            .text(format!("OPENAI_API_KEY={k}"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = openai(r);
    v.push(
        Vector::new("core-openai-in-code", t, "api_key")
            .text(format!("client = OpenAI(api_key=\"{k}\")"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = slack(r);
    v.push(
        Vector::new("core-slack-xoxb", t, "api_key")
            .text(format!("slack bot token {k}"))
            .secret(k)
            .kinds(&["API_KEY"]),
    );
    let k = slack(r);
    v.push(
        Vector::new("core-slack-xoxb-json", t, "api_key")
            .text(format!(r#"{{"token": "{k}", "ok": true}}"#))
            .secret(k)
            .clip()
            .kinds(&["API_KEY"]),
    );

    // --- JWT ---
    let k = jwt(r, 1);
    v.push(
        Vector::new("core-jwt-bearer", t, "jwt")
            .text(format!("Authorization: Bearer {k}"))
            .secret(k)
            .kinds(&["JWT"]),
    );
    let k = jwt(r, 2);
    v.push(
        Vector::new("core-jwt-cookie", t, "jwt")
            .text(format!("Cookie: session={k}; theme=dark"))
            .secret(k)
            .clip()
            .kinds(&["JWT"]),
    );

    // --- PEM ---
    for (id, label, rows) in [
        ("core-pem-rsa", "RSA PRIVATE KEY", 6),
        ("core-pem-openssh", "OPENSSH PRIVATE KEY", 4),
        ("core-pem-pkcs8", "PRIVATE KEY", 3),
        ("core-pem-ec", "EC PRIVATE KEY", 2),
    ] {
        let body = pem_rows(r, rows);
        let mut x = Vector::new(id, t, "private_key")
            .text(pem(label, &body))
            .kinds(&["PRIVATE_KEY"]);
        for row in &body {
            x = x.secret(row.clone());
        }
        v.push(x);
    }

    // --- .env dökümleri ---
    let (sk, id, s, gh, pw) = (
        stripe_live(r),
        aws_id(r),
        aws_secret(r),
        ghp(r),
        "Zx9!qL2#vB7mRT",
    );
    v.push(
        Vector::new("core-env-dump-app", t, "env_dump")
            .text(format!(
                "NODE_ENV=production\nSTRIPE_SECRET_KEY={sk}\nAWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={s}\nGITHUB_TOKEN={gh}\nDB_PASSWORD={pw}\nPORT=8080"
            ))
            .secret(sk).secret(id).secret(s).secret(gh).secret(pw),
    );
    let (oa, sl, jw) = (openai(r), slack(r), jwt(r, 3));
    v.push(
        Vector::new("core-env-dump-export-quoted", t, "env_dump")
            .text(format!(
                "export OPENAI_API_KEY=\"{oa}\"\nexport SLACK_BOT_TOKEN='{sl}'\nexport JWT_TOKEN=\"{jw}\"\nexport DEBUG=false"
            ))
            .secret(oa).secret(sl).secret(jw).clip(),
    );
    let hexkey = r.string(b"0123456789abcdef", 64);
    let rnd = r.string(ALNUM, 32);
    v.push(
        Vector::new("core-env-dump-high-entropy-generic", t, "env_dump")
            .text(format!(
                "APP_SECRET={hexkey}\nSESSION_KEY={rnd}\nAPP_NAME=demo"
            ))
            .secret(hexkey)
            .secret(rnd),
    );

    // --- password= kalıpları ---
    for (id, tpl, pw) in [
        ("core-pw-equals", "password={}", "Tr0ub4dor&3-Synth"),
        ("core-pw-colon", "passwd: {}", "Hunter2-Synthetic!9"),
        (
            "core-pw-json",
            r#"{{"username":"test","password":"{}"}}"#,
            "P@ssw0rd-RT-2026!x",
        ),
        (
            "core-pw-single-quoted",
            "pwd = '{}'",
            "correct-horse-battery-staple-9",
        ),
        ("core-pw-turkish-label", "sifre: {}", "Gizli-Sifre-4471!"),
        (
            "core-pw-capitalised-login-form",
            "Username: tester\nPassword: {}\n[Login]",
            "Wq8$mN3@zK5pLx",
        ),
    ] {
        v.push(
            Vector::new(id, t, "password")
                .text(tpl.replace("{}", pw))
                .secret(pw)
                .kinds(&["PASSWORD"]),
        );
    }
    let pw = "Syn7h3tic-Pa55!";
    v.push(
        Vector::new("core-pw-db-url", t, "password")
            .text(format!(
                "DATABASE_URL=postgres://admin:{pw}@db.internal.test:5432/app"
            ))
            .secret(pw),
    );

    // --- E-posta ---
    for (id, em) in [
        ("core-email-simple", "ayse.yilmaz@example.test"),
        ("core-email-plus-tag", "john.doe+billing@example.com"),
        ("core-email-uppercase", "SYNTHETIC.USER@EXAMPLE.ORG"),
        ("core-email-subdomain", "k.demir@mail.corp.example.net"),
    ] {
        v.push(
            Vector::new(id, t, "email")
                .text(format!("Contact: {em} for details"))
                .secret(em)
                .kinds(&["EMAIL"]),
        );
    }

    // --- Başlıkta / süreç adında sızıntı ---
    let k = ghp(r);
    v.push(
        Vector::new("core-title-github-token", t, "title_leak")
            .title(format!("Token {k} - Notepad"))
            .text("harmless body")
            .secret(k),
    );
    v.push(
        Vector::new("core-title-email", t, "title_leak")
            .title("Inbox - ayse.yilmaz@example.test - Mail")
            .text("harmless body")
            .secret("ayse.yilmaz@example.test")
            .proc_name("outlook.exe"),
    );
    let c = card(r, "4", 16);
    let shown = group(&c, &[4, 4, 4, 4], " ");
    v.push(
        Vector::new("core-title-card", t, "title_leak")
            .title(format!("Checkout {shown} - Google Chrome"))
            .text("harmless body")
            .secret(c)
            .secret(shown)
            .proc_name("chrome.exe"),
    );
    let k = stripe_live(r);
    v.push(
        Vector::new("core-processname-secret", t, "title_leak")
            .proc_name(format!("tool_{k}.exe"))
            .text("harmless body")
            .secret(k),
    );
    let k = aws_id(r);
    v.push(
        Vector::new("core-frame-title-secret", t, "title_leak")
            .payload(PayloadKind::Frame)
            .title(format!("Console {k} - Browser"))
            .secret(k),
    );

    // --- Bileşik paragraf ---
    let c = card(r, "4", 16);
    let tc = tc_kimlik(r);
    let k = stripe_live(r);
    let shown = group(&c, &[4, 4, 4, 4], " ");
    v.push(
        Vector::new("core-composite-paragraph", t, "composite")
            .text(format!(
                "Musteri ayse@example.test, TC {tc}, kart {shown}, anahtar {k}, password=Kmp0s1t-Synth9"
            ))
            .secret("ayse@example.test").secret(tc).secret(c).secret(shown).secret(k).secret("Kmp0s1t-Synth9"),
    );

    v
}

// ---------------------------------------------------------------------- Evasion

fn evasion(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Evasion;
    const ZWSP: char = '\u{200B}';
    const ZWJ: char = '\u{200D}';
    const WJ: char = '\u{2060}';
    const BOM: char = '\u{FEFF}';
    const SHY: char = '\u{00AD}';

    // --- Homoglif / tam genişlik ---
    let k = stripe_live(r);
    let w = homoglyph(&k);
    v.push(
        Vector::new("evade-homoglyph-stripe-cyrillic", t, "homoglyph")
            .text(format!("key {w}"))
            .secret(k)
            .secret(w),
    );
    let k = aws_id(r);
    let w = homoglyph(&k);
    v.push(
        Vector::new("evade-homoglyph-aws-akia", t, "homoglyph")
            .text(format!("id {w}"))
            .secret(k)
            .secret(w),
    );
    let k = ghp(r);
    let w = homoglyph(&k);
    v.push(
        Vector::new("evade-homoglyph-github", t, "homoglyph")
            .text(format!("tok {w}"))
            .secret(k)
            .secret(w),
    );
    let c = card(r, "4", 16);
    let w = fullwidth(&group(&c, &[4, 4, 4, 4], " "));
    v.push(
        Vector::new("evade-fullwidth-card", t, "homoglyph")
            .text(format!("Card {w}"))
            .secret(c)
            .secret(w),
    );
    let c = card(r, "5", 16);
    let w = arabic_indic_digits(&c);
    v.push(
        Vector::new("evade-arabic-indic-card", t, "homoglyph")
            .text(format!("Card {w}"))
            .secret(c)
            .secret(w),
    );
    let em = "ayse.yilmaz@example.test";
    let w = fullwidth(em);
    v.push(
        Vector::new("evade-fullwidth-email", t, "homoglyph")
            .text(format!("mail {w}"))
            .secret(em)
            .secret(w),
    );

    // --- Sıfır genişlikli / görünmez karakterler ---
    let k = stripe_live(r);
    let w = interleave(&k, ZWSP, 4);
    v.push(
        Vector::new("evade-zwsp-stripe", t, "zero_width")
            .text(format!("key {w}"))
            .secret(k)
            .secret(w),
    );
    let c = card(r, "4", 16);
    let w = interleave(&c, ZWJ, 2);
    v.push(
        Vector::new("evade-zwj-card-digits", t, "zero_width")
            .text(format!("Card {w}"))
            .secret(c)
            .secret(w),
    );
    let w = interleave("ayse.yilmaz@example.test", BOM, 3);
    v.push(
        Vector::new("evade-bom-email", t, "zero_width")
            .text(format!("mail {w}"))
            .secret("ayse.yilmaz@example.test")
            .secret(w),
    );
    let pw = "Tr0ub4dor&3-Synth";
    let w = interleave(pw, SHY, 3);
    v.push(
        Vector::new("evade-softhyphen-password", t, "zero_width")
            .text(format!("password={w}"))
            .secret(pw)
            .secret(w),
    );
    let s = aws_secret(r);
    let w = interleave(&s, WJ, 5);
    v.push(
        Vector::new("evade-wordjoiner-aws-secret", t, "zero_width")
            .text(format!("aws_secret_access_key={w}"))
            .secret(s)
            .secret(w),
    );
    let k = aws_id(r);
    v.push(
        Vector::new("evade-rtl-override-aws", t, "zero_width")
            .text(format!("\u{202E}{k}\u{202C}"))
            .secret(k),
    );
    let body = pem_rows(r, 3);
    let zrows: Vec<String> = body.iter().map(|row| interleave(row, ZWSP, 8)).collect();
    let mut x =
        Vector::new("evade-zwsp-pem-body", t, "zero_width").text(pem("RSA PRIVATE KEY", &zrows));
    for row in body.iter().chain(zrows.iter()) {
        x = x.secret(row.clone());
    }
    v.push(x);

    // --- Satır bölme ---
    let k = stripe_live(r);
    let (a, b) = k.split_at(16);
    v.push(
        Vector::new("evade-split-stripe-2-lines", t, "line_split")
            .text(format!("{a}\n{b}"))
            .secret(k.clone())
            .secret(a)
            .secret(b),
    );
    let s = aws_secret(r);
    let (a, b) = s.split_at(20);
    v.push(
        Vector::new("evade-split-aws-secret-crlf", t, "line_split")
            .text(format!("secret:\r\n{a}\r\n{b}"))
            .secret(s.clone())
            .secret(a)
            .secret(b),
    );
    let c = card(r, "4", 16);
    let shown = group(&c, &[4, 4, 4, 4], "\n");
    v.push(
        Vector::new("evade-split-card-per-line", t, "line_split")
            .text(format!("Card:\n{shown}"))
            .secret(c)
            .secret(shown),
    );
    let c = card(r, "4", 16);
    let shown = format!("{} {}\n{} {}", &c[0..4], &c[4..8], &c[8..12], &c[12..16]);
    v.push(
        Vector::new("evade-split-card-2x2", t, "line_split")
            .text(format!("Card {shown}"))
            .secret(c)
            .secret(shown),
    );
    let j = jwt(r, 4);
    let parts: Vec<&str> = j.split('.').collect();
    v.push(
        Vector::new("evade-split-jwt-at-dots", t, "line_split")
            .text(format!("{}.\n{}.\n{}", parts[0], parts[1], parts[2]))
            .secret(j.clone())
            .secret(parts[1])
            .secret(parts[2]),
    );
    let k = ghp(r);
    let (a, b) = k.split_at(18);
    v.push(
        Vector::new("evade-split-github-mid", t, "line_split")
            .text(format!("{a}\n{b}"))
            .secret(k.clone())
            .secret(a)
            .secret(b),
    );
    let k = stripe_live(r);
    let spaced = interleave(&k, ' ', 4);
    v.push(
        Vector::new("evade-spaced-groups-stripe", t, "line_split")
            .text(format!("key {spaced}"))
            .secret(k)
            .secret(spaced),
    );

    // --- base64 ---
    let k = stripe_live(r);
    let b = base64_std(k.as_bytes());
    v.push(
        Vector::new("evade-base64-stripe-basic-auth", t, "base64")
            .text(format!("Authorization: Basic {b}"))
            .secret(k)
            .secret(b),
    );
    let env = format!("DB_PASSWORD=Zx9!qL2#vB7mRT\nAPI={}", ghp(r));
    let b = base64_std(env.as_bytes());
    v.push(
        Vector::new("evade-base64-env-blob", t, "base64")
            .text(format!("data: {b}"))
            .secret(b)
            .secret("Zx9!qL2#vB7mRT"),
    );
    let pw = "Gizli-Sifre-4471!";
    let b = base64_std(format!("password={pw}").as_bytes());
    v.push(
        Vector::new("evade-base64-password", t, "base64")
            .text(format!("blob {b}"))
            .secret(b),
    );

    // --- URL kodlama ---
    let pw = "Zx9!qL2#vB7mRT";
    let enc = url_encode(pw);
    v.push(
        Vector::new("evade-url-password-value", t, "url_encoding")
            .text(format!("POST /login?user=test&password={enc}"))
            .secret(pw)
            .secret(enc),
    );
    let em = "ayse.yilmaz@example.test";
    let enc = url_encode(em);
    v.push(
        Vector::new("evade-url-email-at", t, "url_encoding")
            .text(format!("https://app.test/invite?email={enc}"))
            .secret(em)
            .secret(enc),
    );
    let k = ghp(r);
    v.push(
        Vector::new("evade-url-token-in-query", t, "url_encoding")
            .text(format!("https://api.test/v1/user?access_token={k}&x=1"))
            .secret(k),
    );
    let k = stripe_live(r);
    let enc = url_encode_all(&k);
    v.push(
        Vector::new("evade-url-full-percent-stripe", t, "url_encoding")
            .text(format!("q={enc}"))
            .secret(k)
            .secret(enc),
    );

    // --- Büyük/küçük harf oyunları ---
    let k = stripe_live(r);
    let up = k.to_uppercase();
    v.push(
        Vector::new("evade-case-stripe-uppercase", t, "case")
            .text(format!("KEY {up}"))
            .secret(k)
            .secret(up),
    );
    let k = aws_id(r);
    let low = alt_case(&k);
    v.push(
        Vector::new("evade-case-akia-altcase", t, "case")
            .text(format!("id {low}"))
            .secret(k)
            .secret(low),
    );
    let k = ghp(r);
    let up = k.to_uppercase();
    v.push(
        Vector::new("evade-case-github-uppercase", t, "case")
            .text(format!("TOK {up}"))
            .secret(k)
            .secret(up),
    );
    let pw = "Tr0ub4dor&3-Synth";
    v.push(
        Vector::new("evade-case-password-label-alt", t, "case")
            .text(format!("PaSsWoRd = {pw}"))
            .secret(pw),
    );
    let k = slack(r);
    let m = format!("Xoxb{}", &k[4..]);
    v.push(
        Vector::new("evade-case-slack-capitalised", t, "case")
            .text(format!("tok {m}"))
            .secret(k)
            .secret(m),
    );

    // --- Diğer kodlama / gömme ---
    let k = stripe_live(r);
    v.push(
        Vector::new("evade-json-unicode-escape-stripe", t, "encoding")
            .text(format!("\"k\":\"{}\"", json_unicode_escape(&k)))
            .secret(k.clone())
            .secret(json_unicode_escape(&k)),
    );
    let c = card(r, "4", 16);
    let ent = html_entities(&c);
    v.push(
        Vector::new("evade-html-entity-card", t, "encoding")
            .text(format!("<td>{ent}</td>"))
            .secret(c)
            .secret(ent),
    );
    let k = stripe_live(r);
    let hx = hex(&k);
    v.push(
        Vector::new("evade-hex-stripe", t, "encoding")
            .text(format!("blob {hx}"))
            .secret(k)
            .secret(hx),
    );
    let k = stripe_live(r);
    let rev: String = k.chars().rev().collect();
    v.push(
        Vector::new("evade-reversed-stripe", t, "encoding")
            .text(format!("rev {rev}"))
            .secret(k)
            .secret(rev),
    );
    let k = stripe_live(r);
    let body = k.trim_start_matches("sk_live_").to_string();
    v.push(
        Vector::new("evade-code-string-concat", t, "encoding")
            .text(format!("let key = \"sk_live_\" + \"{body}\";"))
            .secret(body)
            .secret(k),
    );
    let k = ghp(r);
    v.push(
        Vector::new("evade-adjacent-no-delimiter", t, "encoding")
            .text(format!("tokenis{k}end,next"))
            .secret(k),
    );
    let k = openai(r);
    v.push(
        Vector::new("evade-markdown-codespan-openai", t, "encoding")
            .text(format!("Use `{k}` in **config**"))
            .secret(k)
            .clip(),
    );
    let k = stripe_live(r);
    let letters = interleave(&k, ' ', 1);
    v.push(
        Vector::new("evade-letter-spaced-stripe", t, "encoding")
            .text(format!("k e y: {letters}"))
            .secret(k)
            .secret(letters),
    );

    v
}

// -------------------------------------------------------------------- Blacklist

fn blacklist(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Blacklist;
    let mut mk = |id: &str, cat: &'static str, proc_name: &str, title: &str, d: DropKind| {
        let k = ghp(r);
        v.push(
            Vector::new(id, t, cat)
                .proc_name(proc_name)
                .title(title)
                .text(format!("vault entry token {k}"))
                .secret(k)
                .drops(d),
        );
    };
    use DropKind::*;
    // Parola yöneticisi süreçleri
    mk(
        "bl-proc-1password",
        "blacklist_process",
        "1Password.exe",
        "1Password",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-1password-lower",
        "blacklist_process",
        "1password.exe",
        "Vault",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-1password-upper",
        "blacklist_process",
        "1PASSWORD.EXE",
        "Vault",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-1password-fullpath",
        "blacklist_process",
        "C:\\Program Files\\1Password\\app\\8\\1Password.exe",
        "Vault",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-bitwarden",
        "blacklist_process",
        "Bitwarden.exe",
        "Bitwarden",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-bitwarden-noext",
        "blacklist_process",
        "bitwarden",
        "My Vault",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-keepass",
        "blacklist_process",
        "KeePass.exe",
        "Database.kdbx - KeePass",
        BlacklistedProcess,
    );
    mk(
        "bl-proc-keepassxc",
        "blacklist_process",
        "KeePassXC.exe",
        "Passwords",
        BlacklistedProcess,
    );
    // Gizli pencereler
    mk(
        "bl-win-chrome-incognito",
        "blacklist_private_window",
        "chrome.exe",
        "New Tab - Google Chrome (Incognito)",
        PrivateWindow,
    );
    mk(
        "bl-win-incognito-prefix",
        "blacklist_private_window",
        "chrome.exe",
        "(Incognito) Login - Bank",
        PrivateWindow,
    );
    mk(
        "bl-win-edge-inprivate",
        "blacklist_private_window",
        "msedge.exe",
        "Bank - InPrivate - Microsoft Edge",
        PrivateWindow,
    );
    mk(
        "bl-win-firefox-private",
        "blacklist_private_window",
        "firefox.exe",
        "Mozilla Firefox Private Browsing",
        PrivateWindow,
    );
    mk(
        "bl-win-incognito-uppercase",
        "blacklist_private_window",
        "chrome.exe",
        "INCOGNITO TAB",
        PrivateWindow,
    );
    mk(
        "bl-win-turkish-gizli-sekme",
        "blacklist_private_window",
        "chrome.exe",
        "Yeni Sekme - Gizli Sekme",
        PrivateWindow,
    );
    // Hassas dosya başlıkları
    mk(
        "bl-file-dotenv-vscode",
        "blacklist_sensitive_file",
        "Code.exe",
        ".env - Visual Studio Code",
        SensitiveFile,
    );
    mk(
        "bl-file-dotenv-production",
        "blacklist_sensitive_file",
        "notepad.exe",
        ".env.production - Notepad",
        SensitiveFile,
    );
    mk(
        "bl-file-dotenv-path",
        "blacklist_sensitive_file",
        "notepad++.exe",
        "C:\\app\\.env - Notepad++",
        SensitiveFile,
    );
    mk(
        "bl-file-id-rsa",
        "blacklist_sensitive_file",
        "notepad.exe",
        "id_rsa - Notepad",
        SensitiveFile,
    );
    mk(
        "bl-file-id-rsa-ssh-path",
        "blacklist_sensitive_file",
        "notepad.exe",
        "C:\\Users\\u\\.ssh\\id_rsa - Notepad",
        SensitiveFile,
    );
    mk(
        "bl-file-id-ed25519",
        "blacklist_sensitive_file",
        "Code.exe",
        "id_ed25519 - Visual Studio Code",
        SensitiveFile,
    );
    mk(
        "bl-file-dotenv-uppercase",
        "blacklist_sensitive_file",
        "notepad.exe",
        "CONFIG.ENV - Notepad",
        SensitiveFile,
    );

    // Kaçırma: kara liste bypass denemeleri (hâlâ DROP beklenir)
    let k = ghp(r);
    v.push(
        Vector::new("bl-evade-incognito-zwsp", t, "blacklist_evasion")
            .proc_name("chrome.exe")
            .title("New Tab - Incog\u{200B}nito")
            .text(format!("page token {k}"))
            .secret(k)
            .drops(PrivateWindow),
    );
    let k = ghp(r);
    v.push(
        Vector::new("bl-evade-1password-zwsp-process", t, "blacklist_evasion")
            .proc_name("1Pass\u{200B}word.exe")
            .title("Vault")
            .text(format!("page token {k}"))
            .secret(k)
            .drops(BlacklistedProcess),
    );
    let k = ghp(r);
    v.push(
        Vector::new("bl-evade-inprivate-homoglyph", t, "blacklist_evasion")
            .proc_name("msedge.exe")
            .title(format!("Bank - {}", homoglyph("InPrivate")))
            .text(format!("page token {k}"))
            .secret(k)
            .drops(PrivateWindow),
    );
    let k = ghp(r);
    v.push(
        Vector::new("bl-evade-dotenv-fullwidth-dot", t, "blacklist_evasion")
            .proc_name("notepad.exe")
            .title("\u{FF0E}env - Notepad")
            .text(format!("file token {k}"))
            .secret(k)
            .drops(SensitiveFile),
    );
    // Clipboard IgnoredFormat
    let k = ghp(r);
    v.push(
        Vector::new("bl-clipboard-ignored-format", t, "blacklist_format")
            .payload(PayloadKind::ClipboardIgnored)
            .text(format!("file bytes {k}"))
            .secret(k)
            .drops(IgnoredFormat),
    );
    v
}

// ---------------------------------------------------------------------- Controls

fn controls() -> Vec<Vector> {
    let t = Tier::Control;
    vec![
        Vector::new("ctl-benign-notes", t, "control")
            .text("Meeting notes: ship milestone alpha on Friday afternoon")
            .keep("ship milestone alpha"),
        Vector::new("ctl-benign-code", t, "control")
            .proc_name("Code.exe")
            .title("main.rs - s-recall - Visual Studio Code")
            .text("fn main() { println!(\"hello synthetic world\"); }")
            .keep("hello synthetic world"),
        Vector::new("ctl-benign-clipboard", t, "control")
            .clip()
            .text("Remember to review the quarterly roadmap document")
            .keep("quarterly roadmap document"),
        Vector::new("ctl-benign-turkish", t, "control")
            .text("Toplanti notlari: yarin sabah dokuzda sprint planlamasi yapilacak")
            .keep("sprint planlamasi"),
    ]
}

// ---------------------------------------------------------------------- İleri kaçırma vektörleri

/// Guard'ın bilinen sınırlamaları + ileri kaçırma: çift kodlama, base64 içinde sır,
/// bölünmüş anahtarın küçük harfli son parçası, `+` ayraçlı kart, ayraçlı TC, vb.
fn stretch(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Stretch;

    let em = "ayse.yilmaz@example.test";
    let once = url_encode(em);
    let twice = once.replace('%', "%25");
    v.push(
        Vector::new("stretch-double-url-email", t, "double_encoding")
            .text(format!("https://app.test/invite?email={twice}"))
            .secret(em)
            .secret(twice),
    );
    let k = stripe_live(r);
    let full: String = k.bytes().map(|b| format!("%25{b:02x}")).collect();
    v.push(
        Vector::new("stretch-double-url-full-stripe", t, "double_encoding")
            .text(format!("q={full}"))
            .secret(k)
            .secret(full),
    );
    let pw = "Zx9!qL2#vB7mRT";
    let twice = url_encode(pw).replace('%', "%25");
    v.push(
        Vector::new("stretch-double-url-password", t, "double_encoding")
            .text(format!("POST /login?password={twice}"))
            .secret(pw)
            .secret(twice),
    );

    let b = base64_std(format!("contact {em} please").as_bytes());
    v.push(
        Vector::new("stretch-base64-email-in-json", t, "base64")
            .text(format!(r#"{{"payload":"{b}"}}"#))
            .secret(em)
            .secret(b),
    );
    let c = card(r, "4", 16);
    let b =
        base64_std(format!("card number {} exp 09/29", group(&c, &[4, 4, 4, 4], " ")).as_bytes());
    v.push(
        Vector::new("stretch-base64-card-sentence", t, "base64")
            .text(format!("data:text/plain;base64,{b}"))
            .secret(c)
            .secret(b),
    );
    let k = ghp(r);
    let b = base64_std(format!("token={k}").as_bytes());
    v.push(
        Vector::new("stretch-base64-github-token", t, "base64")
            .text(format!("X-Blob: {b}"))
            .secret(k)
            .secret(b),
    );
    let tc = tc_kimlik(r);
    let b = base64_url(format!("tc={tc}").as_bytes());
    v.push(
        Vector::new("stretch-base64url-tc", t, "base64")
            .text(format!("ref={b}"))
            .secret(tc)
            .secret(b),
    );

    // Bölünmüş anahtarın küçük harfli son parçası (>= 4 harf, saf alfabetik)
    let head = r.string(ALNUM, 16);
    let tail = "qwertzuiopasdfgh";
    let k = format!("sk_live_{head}{tail}");
    v.push(
        Vector::new("stretch-split-lowercase-tail-stripe", t, "split_tail")
            .text(format!("sk_live_{head}\n{tail}"))
            .secret(k)
            .secret(head.clone())
            .secret(tail),
    );
    let head = r.string(ALNUM, 20);
    let tail = "abcdefghijklmnop";
    v.push(
        Vector::new("stretch-split-lowercase-tail-github", t, "split_tail")
            .text(format!("ghp_{head}\n{tail}"))
            .secret(format!("ghp_{head}{tail}"))
            .secret(head)
            .secret(tail),
    );

    // Diğer sınırlamalar
    let c = card(r, "4", 16);
    let plus = group(&c, &[4, 4, 4, 4], "+");
    v.push(
        Vector::new("stretch-card-plus-separated", t, "other")
            .text(format!("cc={plus}"))
            .secret(c)
            .secret(plus),
    );
    let tc = tc_kimlik(r);
    let sp = format!("{} {} {} {}", &tc[0..3], &tc[3..6], &tc[6..9], &tc[9..11]);
    v.push(
        Vector::new("stretch-tc-spaced", t, "other")
            .text(format!("TC: {sp}"))
            .secret(tc)
            .secret(sp),
    );
    let pw = "Hunter2x-Synth9";
    v.push(
        Vector::new("stretch-password-in-sentence", t, "other")
            .text(format!("my password is {pw} ok"))
            .secret(pw),
    );
    let em2 = "ay\u{015F}e.y\u{0131}lmaz@example.test";
    v.push(
        Vector::new("stretch-unicode-email-local", t, "other")
            .text(format!("mail {em2}"))
            .secret(em2),
    );
    let enc = "ayse.yilmaz&commat;example.test";
    v.push(
        Vector::new("stretch-named-html-entity-at", t, "other")
            .text(format!("mail {enc}"))
            .secret(em)
            .secret(enc),
    );
    let k = stripe_live(r);
    let w: String = k
        .chars()
        .map(|c| match c {
            's' => '\u{0455}',
            'l' => '\u{04CF}',
            other => other,
        })
        .collect();
    v.push(
        Vector::new("stretch-homoglyph-dze-palochka", t, "other")
            .text(format!("key {w}"))
            .secret(k)
            .secret(w),
    );
    let k = stripe_live(r);
    let esc: String = k.bytes().map(|b| format!("\\x{b:02x}")).collect();
    v.push(
        Vector::new("stretch-backslash-x-hex", t, "other")
            .text(format!("k = \"{esc}\""))
            .secret(k)
            .secret(esc),
    );
    v
}

// ------------------------------------------------- Ek kontroller ve yanlış pozitif sondaları

/// Ek zararsız kontroller (Masked, metin korunmuş, redactions == 0 ZORUNLU).
fn controls_extra() -> Vec<Vector> {
    let t = Tier::Control;
    let c =
        |id: &str, text: &str, keep: &str| Vector::new(id, t, "control_fp").text(text).keep(keep);
    vec![
        c(
            "ctl2-code-rust",
            "fn verify_len(input: &str) -> bool {\n    input.len() >= 8 && input.chars().any(|c| c.is_ascii_digit())\n}",
            "input.chars().any",
        ),
        c(
            "ctl2-code-js",
            "const total = items.reduce((acc, item) => acc + item.price * item.qty, 0);",
            "acc + item.price",
        ),
        c(
            "ctl2-code-sql",
            "SELECT id, created_at FROM events WHERE kind = 'focus' ORDER BY created_at DESC LIMIT 50;",
            "ORDER BY created_at",
        ),
        c(
            "ctl2-camelcase-1",
            "class RunningD3dFullScreenDetector implements ResourceController",
            "RunningD3dFullScreenDetector",
        ),
        c(
            "ctl2-camelcase-2",
            "HttpClientBuilderFactoryImpl.createDefaultConnectionManager()",
            "HttpClientBuilderFactoryImpl",
        ),
        c(
            "ctl2-camelcase-3",
            "getUserAccountBalanceHistoryForPeriod and computeMonthlyAggregateStatistics",
            "computeMonthlyAggregateStatistics",
        ),
        c(
            "ctl2-snake-case",
            "let pool = max_connection_pool_size_per_host * retry_backoff_multiplier_ms;",
            "retry_backoff_multiplier_ms",
        ),
        c(
            "ctl2-short-git-sha",
            "Merged commit 3f2a9c1 into main (see a1b2c3d4)",
            "Merged commit",
        ),
        c(
            "ctl2-iso-datetime",
            "Logged at 2026-11-19T14:32:07Z and again at 2026-11-19 14:35:42",
            "Logged at",
        ),
        c(
            "ctl2-date-tr",
            "Toplanti 19.11.2026 saat 14:30 salon 4B",
            "Toplanti 19.11.2026",
        ),
        c(
            "ctl2-semver",
            "Upgrade tokio to v1.54.1 and s-guard to 0.1.0-rc.2+build.5",
            "Upgrade tokio",
        ),
        c(
            "ctl2-url",
            "https://docs.rs/tokio/latest/tokio/sync/mpsc/struct.Receiver.html#method.recv",
            "struct.Receiver.html",
        ),
        c(
            "ctl2-password-is-required",
            "The password is required before you can continue to the next step.",
            "before you can continue",
        ),
        c(
            "ctl2-sifreleme",
            "Sifreleme algoritmasi AES-256-GCM kullanilir, anahtar uzunlugu 32 bayttir",
            "AES-256-GCM",
        ),
        c(
            "ctl2-tokenize",
            "We tokenize the input, then the secret santa party starts at noon",
            "secret santa party",
        ),
        c(
            "ctl2-order-numbers",
            "Order #123456 shipped; total 45.67 USD; invoice 2026/0042",
            "total 45.67 USD",
        ),
        c(
            "ctl2-markdown-table",
            "| id | name | qty |\n| 1 | widget | 12 |\n| 2 | gadget | 7 |",
            "widget",
        ),
    ]
}

/// Yanlış pozitif sondaları: guard bunları bilinçli olarak maskeleyebilir (fail-closed); yalnızca
/// raporlanır, testi başarısız etmez.
fn fp_probes() -> Vec<Vector> {
    let t = Tier::FpProbe;
    let c = |id: &str, text: &str, keep: &str| Vector::new(id, t, "fp_probe").text(text).keep(keep);
    vec![
        c(
            "fp-git-commit-40hex",
            "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 Author: test",
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
        ),
        c(
            "fp-sha256-hex",
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        c(
            "fp-uuid",
            "request id 550e8400-e29b-41d4-a716-446655440000 accepted",
            "550e8400-e29b-41d4-a716-446655440000",
        ),
        c(
            "fp-epoch-ms-1",
            "ts=1763424000123 event=focus",
            "ts=1763424000123",
        ),
        c(
            "fp-epoch-ms-2",
            "ts=1763424007391 event=copy",
            "ts=1763424007391",
        ),
        c(
            "fp-epoch-ms-3",
            "ts=1763424015558 event=paste",
            "ts=1763424015558",
        ),
        c(
            "fp-code-password-type",
            "fn check(password: &str, salt: &[u8]) -> Hash { hash(password, salt) }",
            "salt: &[u8]",
        ),
        c(
            "fp-password-is-changeable",
            "The password is changeable from the settings page",
            "changeable from the settings page",
        ),
        c(
            "fp-phone-tr",
            "Ara: +90 532 123 45 67 (cep)",
            "+90 532 123 45 67",
        ),
        c(
            "fp-iban",
            "IBAN TR33 0006 1005 1978 6457 8413 26",
            "TR33 0006 1005",
        ),
        c(
            "fp-long-identifier-hash",
            "cache key v2_8f14e45fceea167a5a36dedd4bea2543 expired",
            "expired",
        ),
        c(
            "fp-windows-path-title-case-underscore",
            r"C:\Users\test\Documents\Quarterly_Report_Final_v3.docx",
            "Quarterly_Report_Final_v3",
        ),
        c(
            "fp-base64-image-ref",
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
            "data:image/png",
        ),
    ]
}

// ------------------------------------------------- r3: genişletilmiş kurallara saldırılar

/// Genişletilmiş guard kurallarına (jenerik tanımlayıcılar, `format!`/`concat!` sabitleri, satır sonu
/// anahtarları, diceware, çok katlı base64) saldıran sondalar.
fn r3_probes(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Stretch;

    // ---- genel Ident<..> jenerik kuralı ve tip-benzeri değerler
    for (id, text, pw) in [
        (
            "r3-type-lowercase-generic",
            "password: vec<Hunter2xSynth9>",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-space-before-angle",
            "password: Option <Hunter2xSynth9>",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-turbofish",
            "password: Option::<Hunter2xSynth9>::None",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-unclosed-generic",
            "password: Option<Hunter2xSynth9",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-secret-after-closed-generic",
            "password: Option<String>Hunter2xSynth9",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-tuple-struct-value",
            "password: Wrapper(Hunter2xSynth9)",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-ctor-call",
            "password: Secret::new(\"Hunter2x-Synth9\")",
            "Hunter2x-Synth9",
        ),
        (
            "r3-type-some-into",
            "password: Some(\"Hunter2x-Synth9\".into())",
            "Hunter2x-Synth9",
        ),
        (
            "r3-type-literal-into-no-type",
            "password: \"Hunter2x-Synth9\".into()",
            "Hunter2x-Synth9",
        ),
        (
            "r3-type-deep-nesting-4",
            "password: Foo<Bar<Baz<Qux<Hunter2xSynth9>>>>",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-map-with-comma",
            "password: Map<String, Vec<Hunter2xSynth9>>",
            "Hunter2xSynth9",
        ),
        (
            "r3-type-lowercase-assignment-generic",
            "password: vec = Hunter2x-Synth9",
            "Hunter2x-Synth9",
        ),
        (
            "r3-type-concat-plus",
            "password: String = \"Hunter\".to_owned() + \"2x-Synth9\";",
            "2x-Synth9",
        ),
        (
            "r3-type-array-concat",
            "password: String = [\"Hunter\", \"2x-Synth9\"].concat();",
            "2x-Synth9",
        ),
        (
            "r3-type-format-with-var",
            "password: String = format!(\"{}{}\", prefix, \"Hunter2xQ9\");",
            "Hunter2xQ9",
        ),
        (
            "r3-type-concat-macro-three",
            "password: &str = concat!(\"Hun\", \"ter2xQ\", \"-Synth9\");",
            "-Synth9",
        ),
        (
            "r3-type-camel-ident-lookalike-value",
            "password: HunterTwoX9<T>",
            "HunterTwoX9",
        ),
        (
            "r3-type-generic-in-comment-then-value",
            "password: String /* Option<X> */ = \"Hunter2x-Synth9\"",
            "Hunter2x-Synth9",
        ),
    ] {
        v.push(Vector::new(id, t, "r3_type").text(text).secret(pw));
    }

    // ---- bölünmüş kuyruk (yeniden yazılan detect_key_line_end)
    let mut tail = |id: &str, mk: &dyn Fn(&str) -> String, secrets: &[&str], r: &mut Rng| {
        let head = r.string(ALNUM, 24);
        let mut x = Vector::new(id, t, "r3_tail")
            .text(mk(&head))
            .secret(head.clone());
        for s in secrets {
            x = x.secret(*s);
        }
        v.push(x);
    };
    tail(
        "r3-tail-4-words-line",
        &|h| format!("sk_live_{h}\nqwe rty uio pas"),
        &["qwe rty uio pas"],
        r,
    );
    tail(
        "r3-tail-3-blank-lines",
        &|h| format!("sk_live_{h}\n\n\n\nqwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-9-lines",
        &|h| {
            format!(
                "sk_live_{h}\nqwerty\nuiopas\ndfghjk\nlxcvbn\nmqwert\nyuiopa\nsdfghj\nklzxcv\nbnmqwe"
            )
        },
        &["qwertyuiopas", "bnmqwe", "klzxcv"],
        r,
    );
    tail(
        "r3-tail-2char-words",
        &|h| format!("sk_live_{h}\nqw er ty ui op"),
        &["qw er ty ui op"],
        r,
    );
    tail(
        "r3-tail-assignment-like",
        &|h| format!("sk_live_{h}\nab=qwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-colon-inside",
        &|h| format!("sk_live_{h}\nqwert:zuiop"),
        &["qwert:zuiop"],
        r,
    );
    tail(
        "r3-tail-markdown-table-cell",
        &|h| format!("| sk_live_{h}\n| qwertzuiop |"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-line-number-prefix",
        &|h| format!("sk_live_{h}\n12: qwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-trailing-punctuation",
        &|h| format!("sk_live_{h}\nqwertzuiop,"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-quoted",
        &|h| format!("sk_live_{h}\n\"qwertzuiop\""),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-tab-indented",
        &|h| format!("sk_live_{h}\n\t\tqwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-trailing-space-after-key",
        &|h| format!("sk_live_{h}   \nqwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-hyphenated-break",
        &|h| format!("sk_live_{h}-\nqwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-two-words-6-and-3",
        &|h| format!("sk_live_{h}\nqwertz uio"),
        &["qwertz uio", "qwertz"],
        r,
    );
    tail(
        "r3-tail-keyword-line-continues",
        &|h| format!("sk_live_{h}\nreturn qwertzuiop"),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-comment-only-two-words",
        &|h| format!("sk_live_{h}\n// qwertz uiop"),
        &["qwertz uiop"],
        r,
    );
    tail(
        "r3-tail-unicode-fullwidth",
        &|h| format!("sk_live_{h}\n{}", fullwidth("qwertzuiop")),
        &["qwertzuiop"],
        r,
    );
    tail(
        "r3-tail-with-zwsp",
        &|h| format!("sk_live_{h}\nqwert\u{200B}zuiop"),
        &["qwertzuiop"],
        r,
    );

    // ---- 3+ sözcüklü diceware
    for (id, text, tok) in [
        (
            "r3-word-2letter-words",
            "phrase to_be_or_not_v2",
            "to_be_or_not_v2",
        ),
        (
            "r3-word-11-letter-words",
            "phrase internationalization_correct_horse_v2",
            "internationalization_correct_horse_v2",
        ),
        (
            "r3-word-leet-digits-in-words",
            "phrase c0rrect_h0rse_b4ttery_st4ple",
            "c0rrect_h0rse_b4ttery_st4ple",
        ),
        (
            "r3-word-dot-separated",
            "phrase correct.horse.battery.staple.2024",
            "correct.horse.battery.staple.2024",
        ),
        (
            "r3-word-plus-separated",
            "phrase correct+horse+battery+staple+2024",
            "correct+horse+battery+staple+2024",
        ),
        (
            "r3-word-uppercase-words",
            "phrase CORRECT_HORSE_BATTERY_STAPLE_V2",
            "CORRECT_HORSE_BATTERY_STAPLE_V2",
        ),
        (
            "r3-word-labeled-secret-words",
            "my secret words: alpha bravo charlie delta",
            "alpha bravo charlie delta",
        ),
        (
            "r3-word-with-extension-suffix",
            "my phrase is correct_horse_battery_staple_v2.txt",
            "correct_horse_battery_staple_v2",
        ),
        (
            "r3-word-preceded-by-code-keyword",
            "let correct_horse_battery_staple_v2 = 1; pass: correct_horse_battery_staple_v2",
            "correct_horse_battery_staple_v2",
        ),
        (
            "r3-word-followed-by-equals",
            "correct_horse_battery_staple_v2 = ok",
            "correct_horse_battery_staple_v2",
        ),
        (
            "r3-word-followed-by-paren",
            "login(correct_horse_battery_staple_v2)",
            "correct_horse_battery_staple_v2",
        ),
        (
            "r3-word-camelcase-3-words",
            "phrase CorrectHorseBattery2024",
            "CorrectHorseBattery2024",
        ),
        (
            "r3-word-space-5-words-labeled",
            "recovery phrase correct horse battery staple lamp 2024",
            "correct horse battery staple lamp",
        ),
        (
            "r3-word-mnemonic-12-words",
            "mnemonic: abandon ability able about above absent absorb abstract absurd abuse access accident",
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
        ),
    ] {
        v.push(Vector::new(id, t, "r3_word").text(text).secret(tok));
    }

    // ---- 6 kat base64 + UTF-16 data URI
    let layered = |s: &[u8], n: usize| {
        let mut x = base64_std(s);
        for _ in 1..n {
            x = base64_std(x.as_bytes());
        }
        x
    };
    for n in [6usize, 7, 8] {
        let k = stripe_live(r);
        let b = layered(k.as_bytes(), n);
        v.push(
            Vector::new(&format!("r3-datauri-base64-x{n}"), t, "r3_datauri")
                .text(format!("data:text/plain;base64,{b}"))
                .secret(k)
                .secret(b),
        );
    }
    let utf16 = |s: &str, le: bool, bom: bool| -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(if le { &[0xFF, 0xFE] } else { &[0xFE, 0xFF] });
        }
        for u in s.encode_utf16() {
            out.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
        }
        out
    };
    let k = stripe_live(r);
    let b = base64_std(&utf16(&k, true, true));
    v.push(
        Vector::new("r3-datauri-utf16le-bom", t, "r3_datauri")
            .text(format!("data:text/plain;charset=utf-16;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(&utf16(&k, false, false));
    v.push(
        Vector::new("r3-datauri-utf16be-nobom", t, "r3_datauri")
            .text(format!("data:text/plain;charset=utf-16be;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(base64_std(&utf16(&k, true, false)).as_bytes());
    v.push(
        Vector::new("r3-datauri-utf16le-inside-base64", t, "r3_datauri")
            .text(format!("data:image/png;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(hex(&k).as_bytes());
    v.push(
        Vector::new("r3-datauri-base64-of-hex", t, "r3_datauri")
            .text(format!("data:text/plain;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let mut utf32 = Vec::new();
    for c in k.chars() {
        utf32.extend_from_slice(&(c as u32).to_le_bytes());
    }
    let b = base64_std(&utf32);
    v.push(
        Vector::new("r3-datauri-utf32le", t, "r3_datauri")
            .text(format!("data:text/plain;charset=utf-32le;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(&utf16(&format!("password={}", &k[8..]), true, false));
    v.push(
        Vector::new("r3-datauri-utf16le-password-label", t, "r3_datauri")
            .text(format!("data:text/plain;charset=utf-16le;base64,{b}"))
            .secret(k[8..].to_string())
            .secret(b),
    );
    v
}

/// r3 turunda guard'ın kabul ettiği yanlış pozitifler (bilgi).
fn fp_probes3() -> Vec<Vector> {
    let t = Tier::FpProbe;
    let c = |id: &str, text: &str, keep: &str| Vector::new(id, t, "fp_probe").text(text).keep(keep);
    vec![
        c(
            "fp3-after-key-short-prose-line",
            "key rotated: sk_live_AAAAAAAAAAAAAAAAAAAAAAAA\nNext steps",
            "Next steps",
        ),
        c(
            "fp3-bare-word-word-v3-no-ext",
            "see Quarterly_Report_Final_v3 for numbers",
            "Quarterly_Report_Final_v3",
        ),
        c(
            "fp3-camelcase-4-words-digit",
            "class UserAccountBalanceHistory2024 {}",
            "UserAccountBalanceHistory2024",
        ),
        c(
            "fp3-snake-3letter-words-number",
            "max_num_val_cap_v2 is the limit",
            "max_num_val_cap_v2",
        ),
        c(
            "fp3-phrase-plain-sentence",
            "The phrase quick brown fox jumps 2024 appears in docs",
            "quick brown fox jumps 2024",
        ),
        c(
            "fp3-yaml-secret-reference",
            "password: !secret db_password",
            "db_password",
        ),
        c(
            "fp3-env-reference",
            "password: ${DB_PASSWORD}",
            "DB_PASSWORD",
        ),
        c(
            "fp3-format-macro-after-label",
            "let password_hint = format!(\"{}: {}\", user, \"ok\");",
            "\"ok\"",
        ),
        c(
            "fp3-let-password-string-new",
            "let password = String::new();",
            "String::new()",
        ),
        c(
            "fp3-token-count-label",
            "token: 4096 tokens used",
            "4096 tokens used",
        ),
        c(
            "fp3-key-value-prose",
            "the key: value pairs are sorted by name",
            "value pairs are sorted",
        ),
    ]
}

/// Korunması ZORUNLU yeni kontroller (guard'ın "korunur" dediği tip/bağlam biçimleri).
fn controls4() -> Vec<Vector> {
    let t = Tier::Control;
    let c =
        |id: &str, text: &str, keep: &str| Vector::new(id, t, "control_fp").text(text).keep(keep);
    vec![
        c(
            "ctl4-secret-string-type",
            "struct S { password: SecretString, token: Option<String>, secret: Vec<u8> }",
            "struct S",
        ),
        c(
            "ctl4-zeroizing-type",
            "fn load() -> Result<Zeroizing<[u8; 32]>, Error> { todo!() }",
            "fn load()",
        ),
        c(
            "ctl4-go-var-no-value",
            "var password string\nvar token string",
            "var token string",
        ),
        c(
            "ctl4-ts-optional-type-only",
            "interface Login { password?: string; remember: boolean }",
            "interface Login",
        ),
        c(
            "ctl4-option-ref-type",
            "pub fn check(password: Option<&str>) -> bool { password.is_some() }",
            "password.is_some()",
        ),
        c(
            "ctl4-hashmap-type-only",
            "let m: HashMap<String, Vec<u8>> = HashMap::new();",
            "HashMap::new()",
        ),
        c(
            "ctl4-extension-filename-4-words",
            "Quarterly_Sales_Report_Final_v3.xlsx exported",
            "exported",
        ),
    ]
}

// ------------------------------------------------- r2: tip ayrıştırma ve iç içe kodlama saldırıları

/// Tip ayrıştırma, iç içe data URI, çok satırlı kuyruk, hex etiket ve diceware kurallarına saldıran
/// sondalar. `r2-*`: kabul edilmemiş yüzey; `accepted-*`: kabul edilmiş risk.
fn r2_probes(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Stretch;

    // ---- typeparse dilbilgisini kandırma
    for (id, text, pw) in [
        (
            "r2-type-nested-option",
            "password: Option<Option<Hunter2xSynth9>>",
            "Hunter2xSynth9",
        ),
        (
            "r2-type-result-generic-value",
            "password: Result<String, Hunter2xSynth9>",
            "Hunter2xSynth9",
        ),
        (
            "r2-type-hashmap-value",
            "password: HashMap<String, Hunter2xSynth9>",
            "Hunter2xSynth9",
        ),
        (
            "r2-type-arc-mutex",
            "password: Arc<Mutex<Hunter2xSynth9>>",
            "Hunter2xSynth9",
        ),
        (
            "r2-type-static-unquoted-value",
            "password: &'static str = Hunter2x-Synth9",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-single-quote-value",
            "password: str = 'Zk4$nW8-Synth'",
            "Zk4$nW8-Synth",
        ),
        (
            "r2-type-raw-string",
            "password: &str = r#\"Hunter2x-Synth9\"#;",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-to-string-call",
            "password: String = \"Hunter2x-Synth9\".to_string();",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-byte-string",
            "password: &[u8] = b\"Hunter2x-Synth9\";",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-format-macro",
            "password: String = format!(\"{}-Synth9\", \"Hunter2xQ\");",
            "Hunter2xQ",
        ),
        (
            "r2-type-concat-macro",
            "password: &str = concat!(\"Hunter2xQ\", \"-Synth9\");",
            "Hunter2xQ",
        ),
        (
            "r2-type-assignment-next-line",
            "password: &str\n    = \"Hunter2x-Synth9\";",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-block-comment-between",
            "password: &str /* c */ = \"Hunter2x-Synth9\";",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-typescript-const",
            "const password: string = 'Hunter2x-Synth9';",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-typescript-optional",
            "password?: string = \"Hunter2x-Synth9\";",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-python-annotation",
            "password: str = \"Hunter2x-Synth9\"",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-go-var",
            "var password string = \"Hunter2x-Synth9\"",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-kotlin-val",
            "val password: String = \"Hunter2x-Synth9\"",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-csharp-decl",
            "private const string Password = \"Hunter2x-Synth9\";",
            "Hunter2x-Synth9",
        ),
        (
            "r2-type-real-password-starting-with-typename",
            "password: Result2024x!",
            "Result2024x!",
        ),
        (
            "r2-type-real-password-boxer",
            "password: Boxer-Synth9x",
            "Boxer-Synth9x",
        ),
        (
            "r2-type-yaml-str-tag",
            "password: !!str Hunter2x-Synth9",
            "Hunter2x-Synth9",
        ),
    ] {
        v.push(Vector::new(id, t, "r2_type").text(text).secret(pw));
    }

    // ---- iç içe data URI / base64 katmanları (guard en çok 3 kat çözer)
    let layered = |s: &str, n: usize| {
        let mut x = s.to_string();
        for _ in 0..n {
            x = base64_std(x.as_bytes());
        }
        x
    };
    for n in [3usize, 4, 5] {
        let k = stripe_live(r);
        let b = layered(&k, n);
        v.push(
            Vector::new(&format!("r2-datauri-nested-base64-x{n}"), t, "r2_datauri")
                .text(format!("data:image/png;base64,{b}"))
                .secret(k)
                .secret(b),
        );
    }
    let k = stripe_live(r);
    let inner = format!("data:text/plain;base64,{}", base64_std(k.as_bytes()));
    let b =
        base64_std(format!("data:image/png;base64,{}", base64_std(inner.as_bytes())).as_bytes());
    v.push(
        Vector::new("r2-datauri-uri-inside-uri-x3", t, "r2_datauri")
            .text(format!("data:text/html;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(url_encode(&base64_std(k.as_bytes())).as_bytes());
    v.push(
        Vector::new("r2-datauri-base64-of-urlencoded-base64", t, "r2_datauri")
            .text(format!("data:image/png;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let mut raw = vec![0u8; 24];
    raw.extend_from_slice(k.as_bytes());
    raw.extend(std::iter::repeat_n(0xA5u8, 24));
    let b = base64_std(&raw);
    v.push(
        Vector::new("r2-datauri-binary-around-text", t, "r2_datauri")
            .text(format!("data:application/octet-stream;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let mut raw = Vec::new();
    for ch in k.bytes() {
        raw.push(ch);
        raw.push(0); // UTF-16LE metni base64 içinde
    }
    let b = base64_std(&raw);
    v.push(
        Vector::new("r2-datauri-utf16le-payload", t, "r2_datauri")
            .text(format!("data:text/plain;charset=utf-16le;base64,{b}"))
            .secret(k)
            .secret(b),
    );

    // ---- bölünmüş kuyruk: satır sayısı / kısa satırlar / etiket
    for (id, parts) in [
        ("r2-tail-3-extra-lines", vec!["qwertz", "uiopas", "dfghjk"]),
        (
            "r2-tail-4-extra-lines",
            vec!["qwertz", "uiopas", "dfghjk", "lxcvbn"],
        ),
        (
            "r2-tail-5-extra-lines",
            vec!["qwertz", "uiopas", "dfghjk", "lxcvbn", "mqwert"],
        ),
        (
            "r2-tail-short-3char-lines",
            vec!["qwe", "rty", "uio", "pas", "dfg"],
        ),
        (
            "r2-tail-4char-lines-x4",
            vec!["qwer", "tyui", "opas", "dfgh"],
        ),
    ] {
        let head = r.string(ALNUM, 24);
        let tail_joined = parts.concat();
        let mut x = Vector::new(id, t, "r2_tail")
            .text(format!("sk_live_{head}\n{}", parts.join("\n")))
            .secret(format!("sk_live_{head}{tail_joined}"))
            .secret(head);
        for p in &parts {
            if p.len() >= 6 {
                x = x.secret(*p);
            }
        }
        x = x.secret(tail_joined);
        v.push(x);
    }
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r2-tail-space-split-in-line", t, "r2_tail")
            .text(format!("sk_live_{head}\nqwert zuiop"))
            .secret("qwertzuiop")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r2-tail-after-trailing-blank-and-comment", t, "r2_tail")
            .text(format!("sk_live_{head}\n\n# next\nqwertzuiop"))
            .secret("qwertzuiop")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r2-tail-markdown-bullet", t, "r2_tail")
            .text(format!("- sk_live_{head}\n- qwertzuiop"))
            .secret("qwertzuiop")
            .secret(head),
    );

    // ---- hex etiket penceresi: etiket iki satır yukarıda / uzakta (guard bu sınırı "kabul" listesinde belirtti)
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("accepted-hex64-label-two-lines-above", t, "accepted_risk")
            .text(format!("secret key\nsomething\n{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("accepted-hex64-label-121-bytes-before", t, "accepted_risk")
            .text(format!("secret {}{h}", "x".repeat(121)))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("accepted-hex64-label-after-81-bytes", t, "accepted_risk")
            .text(format!("{h}{}secret", " ".repeat(81)))
            .secret(h),
    );
    // pencere İÇİNDE kalması gerekenler (PASS beklenir)
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r2-hex64-label-same-line-100-bytes", t, "r2_hex")
            .text(format!("api secret{}{h}", " ".repeat(90)))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r2-hex64-label-prev-line-lf", t, "r2_hex")
            .text(format!("private\n{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r2-hex64-turkish-sifre-label", t, "r2_hex")
            .text(format!("şifre: {h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, true);
    v.push(
        Vector::new("r2-hex64-label-homoglyph", t, "r2_hex")
            .text(format!("{}: {h}", homoglyph("secret")))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r2-hex64-label-zwsp-split", t, "r2_hex")
            .text(format!("sec\u{200B}ret: {h}"))
            .secret(h),
    );
    let h = hex_str(r, 40, false);
    v.push(
        Vector::new("r2-hex40-0x-labeled", t, "r2_hex")
            .text(format!("token 0x{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r2-hex64-mixed-with-label-in-json", t, "r2_hex")
            .text(format!("{{\"pk\":\"{h}\"}}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r2-hex64-label-word-embedded", t, "r2_hex")
            .text(format!("monkey wrench secrets: {h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    let (a, b) = h.split_at(32);
    v.push(
        Vector::new("r2-hex64-split-lines-no-label", t, "r2_hex")
            .text(format!("{a}\n{b}"))
            .secret(h.clone())
            .secret(a)
            .secret(b),
    );

    // ---- diceware: 3 harfli sözcük / soneksiz / farklı biçimler
    for (id, text, tok, accepted) in [
        (
            "r2-word-diceware-3letter-words-suffix",
            "phrase red_fox_cat_dog_v2",
            "red_fox_cat_dog_v2",
            false,
        ),
        (
            "r2-word-diceware-3-words-suffix",
            "phrase correct_horse_battery_v2",
            "correct_horse_battery_v2",
            false,
        ),
        (
            "r2-word-diceware-space-separated",
            "phrase correct horse battery staple 2024",
            "correct horse battery staple",
            false,
        ),
        (
            "r2-word-diceware-camelcase",
            "phrase CorrectHorseBatteryStaple2024",
            "CorrectHorseBatteryStaple2024",
            false,
        ),
        (
            "r2-word-diceware-mixed-separators",
            "phrase correct_horse-battery_staple_v2",
            "correct_horse-battery_staple_v2",
            false,
        ),
        (
            "r2-word-diceware-digit-in-middle",
            "phrase correct_horse_9_battery_staple",
            "correct_horse_9_battery_staple",
            false,
        ),
        (
            "r2-word-diceware-5-words-no-suffix",
            "phrase correct_horse_battery_staple_lamp",
            "correct_horse_battery_staple_lamp",
            true,
        ),
        (
            "r2-word-diceware-4-words-no-suffix",
            "phrase correct_horse_battery_staple",
            "correct_horse_battery_staple",
            true,
        ),
        (
            "r2-word-diceware-uppercase-suffix",
            "phrase Winter_Garden_Purple_Lamp_V2",
            "Winter_Garden_Purple_Lamp_V2",
            false,
        ),
        (
            "r2-word-diceware-long-suffix",
            "phrase winter-garden-purple-lamp-20241119",
            "winter-garden-purple-lamp-20241119",
            false,
        ),
    ] {
        let id = if accepted {
            id.replacen("r2-", "accepted-", 1)
        } else {
            id.to_string()
        };
        v.push(
            Vector::new(&id, t, if accepted { "accepted_risk" } else { "r2_word" })
                .text(text)
                .secret(tok),
        );
    }
    v
}

/// r2 turunda guard'ın kabul ettiği yanlış pozitifler (bilgi) ve korunması gerekenler.
fn fp_probes2() -> Vec<Vector> {
    let t = Tier::FpProbe;
    let c = |id: &str, text: &str, keep: &str| Vector::new(id, t, "fp_probe").text(text).keep(keep);
    vec![
        c(
            "fp2-filename-4-words-suffix",
            "Annual_Budget_Review_Draft_v12.xlsx",
            "Annual_Budget_Review_Draft_v12",
        ),
        c(
            "fp2-filename-4-words-suffix-b",
            "Quarterly_Sales_Report_Final_v3.docx",
            "Quarterly_Sales_Report_Final_v3",
        ),
        c(
            "fp2-slug-4-words-digit",
            "see how-to-fix-the-broken-build-2024 for details",
            "how-to-fix-the-broken-build-2024",
        ),
        c(
            "fp2-git-hash-after-key-line",
            "rotated api key in this commit\n9fceb02d0ae598e95dc970b74767f19372d61af8",
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
        ),
        c(
            "fp2-git-hash-near-token-word",
            "token refresh fix 9fceb02d0ae598e95dc970b74767f19372d61af8",
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
        ),
        c(
            "fp2-git-hash-after-monkey",
            "monkeypatch applied in 9fceb02d0ae598e95dc970b74767f19372d61af8",
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
        ),
        c(
            "fp2-type-then-comment-version",
            "password: String, // uses TLS1.2/1.3",
            "uses TLS1.2/1.3",
        ),
        c(
            "fp2-rust-hex-literal",
            "const MUL: u64 = 0xBF58_476D_1CE4_E5B9;",
            "0xBF58_476D_1CE4_E5B9",
        ),
        c(
            "fp2-mac-address",
            "eth0 mac 00:1A:2B:3C:4D:5E:6F:70",
            "mac 00:1A:2B",
        ),
        c(
            "fp2-ssh-fingerprint",
            "SHA256 fingerprint AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            "fingerprint",
        ),
        c(
            "fp2-key-then-following-word",
            "api_key=0123456789abcdef0123456789abcdef\nfollowing steps",
            "following steps",
        ),
        c(
            "fp2-comment-with-version-after-type",
            "pub token: Token, // rev 2024.11",
            "rev 2024.11",
        ),
        c(
            "fp2-struct-token-option-type",
            "struct Cfg { password: String, token: Option<String>, key: [u8; 32] }",
            "token: Option<String>",
        ),
        c(
            "fp2-empty-string-new-literal",
            "let password: String = String::new(); // empty",
            "String::new()",
        ),
        c(
            "fp2-base64-data-uri-png-real",
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
            "data:image/png",
        ),
    ]
}

/// Korunması ZORUNLU yeni kontroller (guard'ın "korunan" dediği biçimler).
fn controls3() -> Vec<Vector> {
    let t = Tier::Control;
    let c =
        |id: &str, text: &str, keep: &str| Vector::new(id, t, "control_fp").text(text).keep(keep);
    vec![
        c(
            "ctl3-filename-3-words",
            "Quarterly_Report_Final_v3.docx and Annual-Budget-Review_v12.xlsx",
            "Annual-Budget-Review_v12",
        ),
        c(
            "ctl3-slug-short-words",
            "see how-to-fix-the-error-in-rust-2024 for the guide",
            "how-to-fix-the-error-in-rust-2024",
        ),
        c(
            "ctl3-phrase-no-suffix-3-words",
            "Meeting about correct_horse_battery planning",
            "Meeting about",
        ),
        c(
            "ctl3-type-annotations-plain",
            "fn login(password: &str, user: &User) -> Result<Session, AuthError>",
            "user: &User",
        ),
        c(
            "ctl3-none-literal",
            "password: Option<String> = None",
            "= None",
        ),
        c(
            "ctl3-hashed-comment",
            "pub password: String, // hashed with argon2id",
            "hashed with argon2id",
        ),
        c(
            "ctl3-hex-literal-const",
            "const SEED: u64 = 0x9E37_79B9_7F4A_7C15;",
            "const SEED",
        ),
        c(
            "ctl3-git-log-oneline",
            "9fceb02 Fix build\n3f2a9c1 Merge branch main\na1b2c3d4 Update deps",
            "Merge branch main",
        ),
        c(
            "ctl3-underscore-snake-5-words",
            "let max_connection_pool_size_per_host_v2 = 4;",
            "= 4;",
        ),
        c(
            "ctl3-title-case-sentence",
            "Annual Budget Review Draft Final Version",
            "Annual Budget Review",
        ),
    ]
}

// ------------------------------------------------- r1: guard istisnalarına karşı bypass sondaları

/// Rastgele küçük/büyük hex dizgisi.
fn hex_str(r: &mut Rng, n: usize, upper: bool) -> String {
    let s = r.string(b"0123456789abcdef", n);
    if upper { s.to_uppercase() } else { s }
}

/// Guard istisnalarını (40/64 hex, tip anotasyonu, Word_Word_v3, data URI, kuyruk anahtar sözcükleri)
/// hedefleyen bypass denemeleri. `r1-*`: kabul edilmemiş yüzey; `accepted-*`: kabul edilmiş risk.
fn r1_probes(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Stretch;
    let filler = "lorem ipsum dolor sit amet ".repeat(4); // > 64 bayt

    // ---- 40/64 hex istisnası
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-label-far", t, "r1_hex")
            .text(format!("master key {filler}{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-label-prev-line", t, "r1_hex")
            .text(format!("SECRET KEY\n{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-label-after", t, "r1_hex")
            .text(format!("{h} (this is the secret)"))
            .secret(h),
    );
    let h = hex_str(r, 64, true);
    let colon: String = h
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    v.push(
        Vector::new("r1-hex64-colon-pairs-private", t, "r1_hex")
            .text(format!("private key {colon}"))
            .secret(h)
            .secret(colon),
    );
    let h = hex_str(r, 64, false);
    let (a, b) = h.split_at(32);
    v.push(
        Vector::new("r1-hex64-split-halves-secret-label", t, "r1_hex")
            .text(format!("secret: {a} {b}"))
            .secret(h.clone())
            .secret(a)
            .secret(b),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-turkish-label", t, "r1_hex")
            .text(format!("gizli anahtar: {h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-json-short-key-name", t, "r1_hex")
            .text(format!("{{\"k\":\"{h}\"}}"))
            .secret(h),
    );
    let h = hex_str(r, 40, false);
    v.push(
        Vector::new("r1-hex40-legacy-github-label-far", t, "r1_hex")
            .text(format!("github token {filler}{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-0x-labeled-private-key", t, "r1_hex")
            .text(format!("eth private key: 0x{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, true);
    v.push(
        Vector::new("r1-hex64-upper-labeled-secret-eq", t, "r1_hex")
            .text(format!("SeCrEt={h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-labeled-json-apikey", t, "r1_hex")
            .text(format!("{{\"apiKey\":\"{h}\"}}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-label-on-previous-line-crlf", t, "r1_hex")
            .text(format!("private\r\n{h}"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("r1-hex64-label-exactly-65-bytes-before", t, "r1_hex")
            .text(format!("token{}{h}", " ".repeat(65)))
            .secret(h),
    );

    // ---- tip anotasyonu istisnası taklitleri (değer gerçek sır, tip gibi görünüyor)
    for (id, text, pw) in [
        (
            "r1-type-ref-lookalike",
            "password: &Hunter2xSynth9",
            "Hunter2xSynth9",
        ),
        (
            "r1-type-option-lookalike",
            "password: Option<Hunter2xSynth9>",
            "Hunter2xSynth9",
        ),
        (
            "r1-type-vec-lookalike",
            "password: Vec<Gizli7788Synth>",
            "Gizli7788Synth",
        ),
        (
            "r1-type-mut-lookalike",
            "pwd: &mut Syn7h3ticQ9x",
            "Syn7h3ticQ9x",
        ),
        (
            "r1-type-lifetime-lookalike",
            "password: &'a Hunter2xSynth9",
            "Hunter2xSynth9",
        ),
        (
            "r1-type-box-lookalike",
            "password: Box<Hunter2x-Synth9!>",
            "Hunter2x-Synth9!",
        ),
        (
            "r1-type-zeroizing-lookalike",
            "password: Zeroizing<Zk4nW8Synth77>",
            "Zk4nW8Synth77",
        ),
        (
            "r1-type-array-lookalike",
            "password: [Secret1Synth!; 3]",
            "Secret1Synth!",
        ),
        (
            "r1-type-then-real-assignment",
            "let password: &str = \"Hunter2x-Synth9\";",
            "Hunter2x-Synth9",
        ),
        (
            "r1-type-string-assignment",
            "password: String = \"Zk4$nW8-Synth\"",
            "Zk4$nW8-Synth",
        ),
        (
            "r1-type-string-from",
            "password: String::from(\"Hunter2x-Synth9\")",
            "Hunter2x-Synth9",
        ),
        (
            "r1-type-bare-str-then-value",
            "password: str Hunter2x-Synth9",
            "Hunter2x-Synth9",
        ),
        (
            "r1-type-pub-struct-field-default",
            "pub password: String, // default Hunter2x-Synth9",
            "Hunter2x-Synth9",
        ),
    ] {
        v.push(Vector::new(id, t, "r1_type").text(text).secret(pw));
    }

    // ---- Word_Word_v3 istisnası (sözcük benzeri parçalardan oluşan gerçek token/parola)
    for (id, text, tok) in [
        (
            "r1-word-diceware-underscore-unlabeled",
            "my phrase is correct_horse_battery_staple_v2 ok",
            "correct_horse_battery_staple_v2",
        ),
        (
            "r1-word-titlecase-unlabeled",
            "Winter_Garden_Purple_Lamp_2024",
            "Winter_Garden_Purple_Lamp_2024",
        ),
        (
            "r1-word-hyphen-invite-code",
            "invite code silent-river-golden-moon-7",
            "silent-river-golden-moon-7",
        ),
        (
            "r1-word-recovery-phrase-line",
            "recovery: tiger-lemon-cobalt-ember-v8",
            "tiger-lemon-cobalt-ember-v8",
        ),
        (
            "r1-word-labeled-token",
            "token=Alpha_Bravo_Charlie_v3",
            "Alpha_Bravo_Charlie_v3",
        ),
        (
            "r1-word-bearer",
            "Authorization: Bearer Alpha_Bravo_Charlie_v3",
            "Alpha_Bravo_Charlie_v3",
        ),
        (
            "r1-word-labeled-password",
            "password=correct_horse_battery_staple_v2",
            "correct_horse_battery_staple_v2",
        ),
    ] {
        v.push(Vector::new(id, t, "r1_word").text(text).secret(tok));
    }

    // ---- data URI: mime yalanı ve çözme-engelleme denemeleri
    let k = stripe_live(r);
    let b = base64_std(k.as_bytes());
    v.push(
        Vector::new("r1-datauri-text-plain-secret", t, "r1_datauri")
            .text(format!("data:text/plain;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(k.as_bytes());
    v.push(
        Vector::new("r1-datauri-png-mime-lie-text", t, "r1_datauri")
            .text(format!("data:image/png;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(base64_std(k.as_bytes()).as_bytes());
    v.push(
        Vector::new("r1-datauri-png-lie-double-base64", t, "r1_datauri")
            .text(format!("data:image/png;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let pw = "Hunter2x-Synth9";
    let b = base64_std(format!("password={pw}").as_bytes());
    v.push(
        Vector::new("r1-datauri-octet-stream-lie-password", t, "r1_datauri")
            .text(format!("data:application/octet-stream;base64,{b}"))
            .secret(pw)
            .secret(b),
    );
    let k = stripe_live(r);
    let mut raw = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
    raw.extend_from_slice(format!("\n{k}\n").as_bytes());
    let b = base64_std(&raw);
    v.push(
        Vector::new("r1-datauri-png-header-plus-text", t, "r1_datauri")
            .text(format!("data:image/png;base64,{b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(format!("note {k} end").as_bytes());
    let wrapped: String = b
        .as_bytes()
        .chunks(20)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n");
    v.push(
        Vector::new("r1-datauri-png-lie-mime-wrapped-lines", t, "r1_datauri")
            .text(format!("data:image/png;base64,{wrapped}"))
            .secret(k)
            .secret(b)
            .secret(wrapped.replace("\r\n", ""))
            .secret(wrapped.clone()),
    );
    let env = format!("DB_PASSWORD=Zx9!qL2#vB7mRT\nGH={}", ghp(r));
    let b = base64_std(env.as_bytes());
    v.push(
        Vector::new("r1-datauri-png-lie-env-dump", t, "r1_datauri")
            .text(format!("data:image/png;base64,{b}"))
            .secret("Zx9!qL2#vB7mRT")
            .secret(b),
    );
    let k = ghp(r);
    let enc = url_encode(&k);
    v.push(
        Vector::new("r1-datauri-plain-urlencoded-payload", t, "r1_datauri")
            .text(format!("data:text/plain,{enc}"))
            .secret(k)
            .secret(enc),
    );

    // ---- bölünmüş kuyruk: korunan kod anahtar sözcükleriyle kaçırma
    for (id, tail) in [
        ("r1-tail-keyword-prefix-export", "export9Zq4Lm"),
        ("r1-tail-keyword-prefix-return", "returnA1b2C3"),
        ("r1-tail-keyword-prefix-const", "constQ7xZ2p"),
        ("r1-tail-keyword-prefix-select-upper", "SELECTx9y8z7"),
        ("r1-tail-keyword-exact-return", "return"),
        ("r1-tail-keyword-exact-import", "import"),
        ("r1-tail-keyword-exact-export", "export"),
        ("r1-tail-keyword-exact-function", "function"),
    ] {
        let head = r.string(ALNUM, 24);
        v.push(
            Vector::new(id, t, "r1_tail")
                .text(format!("sk_live_{head}\n{tail}"))
                .secret(format!("sk_live_{head}{tail}"))
                .secret(tail)
                .secret(head),
        );
    }
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r1-tail-blank-line-between", t, "r1_tail")
            .text(format!("sk_live_{head}\n\nqwertzuiop"))
            .secret(format!("sk_live_{head}qwertzuiop"))
            .secret("qwertzuiop")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r1-tail-crlf", t, "r1_tail")
            .text(format!("sk_live_{head}\r\nqwertzuiop"))
            .secret("qwertzuiop")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r1-tail-two-lines", t, "r1_tail")
            .text(format!("sk_live_{head}\nqwertz\nuiopas"))
            .secret("qwertzuiopas")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("r1-tail-comment-prefixed", t, "r1_tail")
            .text(format!("sk_live_{head}\n// qwertzuiop"))
            .secret("qwertzuiop")
            .secret(head),
    );
    let head = r.string(ALNUM, 20);
    v.push(
        Vector::new("r1-tail-5-chars-only", t, "r1_tail")
            .text(format!("ghp_{head}\nQ7xZ2"))
            .secret(format!("ghp_{head}Q7xZ2"))
            .secret(head),
    );

    // ---- KABUL EDİLEN RİSK (guard bilinçli bıraktı; ayrı raporlanır)
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("accepted-hex64-unlabeled", t, "accepted_risk")
            .text(format!("value {h} end"))
            .secret(h),
    );
    let h = hex_str(r, 64, false);
    v.push(
        Vector::new("accepted-hex64-0x-unlabeled", t, "accepted_risk")
            .text(format!("0x{h}"))
            .secret(h),
    );
    let h = hex_str(r, 40, false);
    v.push(
        Vector::new("accepted-hex40-unlabeled", t, "accepted_risk")
            .text(format!("ref {h}"))
            .secret(h),
    );
    v.push(
        Vector::new("accepted-password-string-type-name", t, "accepted_risk")
            .text("password: String")
            .secret("String"),
    );
    v
}

// ------------------------------------------------- Ek kaçırma varyantları

/// Durdurma listesi, iki seviye çözme, base64, kuyruk ve ayraç kurallarını zorlayan kaçırma
/// varyantları. Yalnızca rapor (`Tier::Stretch`).
fn stretch2(r: &mut Rng) -> Vec<Vector> {
    let mut v = Vec::new();
    let t = Tier::Stretch;
    let em = "ayse.yilmaz@example.test";

    // -- durdurma listesi kaçırma: sır, listedeki sözcükle BAŞLIYOR veya listedeki sözcüğü içeriyor
    for (id, text, pw) in [
        (
            "stretch2-stoplist-required-prefix",
            "password is required-Synth9x",
            "required-Synth9x",
        ),
        (
            "stretch2-stoplist-incorrect-prefix",
            "your password is incorrect-Hunter9!",
            "incorrect-Hunter9!",
        ),
        (
            "stretch2-stoplist-quoted-phrase",
            "password is \"required horse battery staple\"",
            "required horse battery staple",
        ),
        (
            "stretch2-password-is-next-line",
            "the password is\nHunter2x-Synth9",
            "Hunter2x-Synth9",
        ),
        (
            "stretch2-parola-ise",
            "parola ise Gizli-Synth-7788",
            "Gizli-Synth-7788",
        ),
        (
            "stretch2-pwd-was",
            "my old pwd was Q7v!mZ3-Synth",
            "Q7v!mZ3-Synth",
        ),
        (
            "stretch2-password-is-colon",
            "password is: Zk4$nW8-Synth",
            "Zk4$nW8-Synth",
        ),
    ] {
        v.push(Vector::new(id, t, "stoplist").text(text).secret(pw));
    }

    // -- 3 seviye kodlama (guard en çok 2 seviye çözer)
    let k = stripe_live(r);
    let l1 = url_encode_all(&k);
    let l2 = l1.replace('%', "%25");
    let l3 = l2.replace('%', "%25");
    v.push(
        Vector::new("stretch2-url-3-levels-stripe", t, "multi_encoding")
            .text(format!("q={l3}"))
            .secret(k)
            .secret(l3),
    );
    let e1 = url_encode(em);
    let e2 = e1.replace('%', "%25");
    let e3 = e2.replace('%', "%25");
    v.push(
        Vector::new("stretch2-url-3-levels-email", t, "multi_encoding")
            .text(format!("invite?email={e3}"))
            .secret(em)
            .secret(e3),
    );
    v.push(
        Vector::new("stretch2-url-2-levels-email", t, "multi_encoding")
            .text(format!("invite?email={e2}"))
            .secret(em)
            .secret(e2),
    );
    // kaçış katmanı + base64 katmanı karışımı
    let k = ghp(r);
    let inner = url_encode_all(&k);
    let b = base64_std(inner.as_bytes());
    v.push(
        Vector::new("stretch2-base64-of-url-encoded-token", t, "multi_encoding")
            .text(format!("blob={b}"))
            .secret(k)
            .secret(b),
    );
    let k = stripe_live(r);
    let b = base64_std(format!("sk%5Flive%5F{}", &k[8..]).as_bytes());
    v.push(
        Vector::new(
            "stretch2-base64-of-partially-url-encoded",
            t,
            "multi_encoding",
        )
        .text(format!("x-data: {b}"))
        .secret(k)
        .secret(b),
    );

    // -- base64 içinde base64
    let k = stripe_live(r);
    let b2 = base64_std(base64_std(k.as_bytes()).as_bytes());
    v.push(
        Vector::new("stretch2-base64-in-base64-stripe", t, "multi_encoding")
            .text(format!("blob {b2}"))
            .secret(k)
            .secret(b2),
    );
    let b2 = base64_std(base64_std(format!("contact {em} now").as_bytes()).as_bytes());
    v.push(
        Vector::new("stretch2-base64-in-base64-email", t, "multi_encoding")
            .text(format!("blob {b2}"))
            .secret(em)
            .secret(b2),
    );
    let b1 = base64_std(b"my password is Hunter2x-Synth9 ok");
    v.push(
        Vector::new("stretch2-base64-of-password-sentence", t, "multi_encoding")
            .text(format!("note: {b1}"))
            .secret("Hunter2x-Synth9")
            .secret(b1),
    );
    let k = openai(r);
    let b = base64_url(k.as_bytes());
    v.push(
        Vector::new("stretch2-base64url-openai", t, "multi_encoding")
            .text(format!("t={b}"))
            .secret(k)
            .secret(b),
    );

    // -- bölünmüş kuyruk uzunlukları (guard kuralı: tam anahtardan sonra satırın TAMAMI >= 8 alfanümerik)
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("stretch2-split-tail-7-after-complete-key", t, "split_tail")
            .text(format!("sk_live_{head}\nqwertzu"))
            .secret(format!("sk_live_{head}qwertzu"))
            .secret("qwertzu")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new(
            "stretch2-split-tail-8-mixed-after-complete-key",
            t,
            "split_tail",
        )
        .text(format!("sk_live_{head}\nqwE9rtZu"))
        .secret(format!("sk_live_{head}qwE9rtZu"))
        .secret("qwE9rtZu")
        .secret(head),
    );
    let head = r.string(ALNUM, 20);
    v.push(
        Vector::new("stretch2-split-tail-7-incomplete-key", t, "split_tail")
            .text(format!("ghp_{head}\nabcdefg"))
            .secret(format!("ghp_{head}abcdefg"))
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("stretch2-split-tail-with-indent", t, "split_tail")
            .text(format!("sk_live_{head}\n    qwertzuiopas"))
            .secret(format!("sk_live_{head}qwertzuiopas"))
            .secret("qwertzuiopas")
            .secret(head),
    );
    let head = r.string(ALNUM, 24);
    v.push(
        Vector::new("stretch2-split-tail-trailing-text", t, "split_tail")
            .text(format!("sk_live_{head}\nqwertzuiopas and more"))
            .secret(format!("sk_live_{head}qwertzuiopas"))
            .secret("qwertzuiopas")
            .secret(head),
    );

    // -- ayraç kümesi dışı biçimler
    let c = card(r, "4", 16);
    let dot = group(&c, &[4, 4, 4, 4], ".");
    v.push(
        Vector::new("stretch2-card-dot-separated", t, "separators")
            .text(format!("pan {dot}"))
            .secret(c)
            .secret(dot),
    );
    let c = card(r, "5", 16);
    let us = group(&c, &[4, 4, 4, 4], "_");
    v.push(
        Vector::new("stretch2-card-underscore-separated", t, "separators")
            .text(format!("pan {us}"))
            .secret(c)
            .secret(us),
    );
    let c = card(r, "4", 16);
    let mixed = format!("{}-{}\n{}+{}", &c[0..4], &c[4..8], &c[8..12], &c[12..16]);
    v.push(
        Vector::new("stretch2-card-mixed-dash-newline-plus", t, "separators")
            .text(format!("pan {mixed}"))
            .secret(c)
            .secret(mixed),
    );
    let tc = tc_kimlik(r);
    let dot = format!("{}.{}.{}.{}", &tc[0..3], &tc[3..6], &tc[6..9], &tc[9..11]);
    v.push(
        Vector::new("stretch2-tc-dot-separated", t, "separators")
            .text(format!("TC {dot}"))
            .secret(tc)
            .secret(dot),
    );

    // -- \xNN / varlık / Unicode bileşimleri
    let xe: String = em.bytes().map(|b| format!("\\x{b:02x}")).collect();
    v.push(
        Vector::new("stretch2-xhex-email", t, "multi_encoding")
            .text(format!("m = \"{xe}\""))
            .secret(em)
            .secret(xe),
    );
    let ent = em.replace('@', "&commat;").replace('.', "&period;");
    v.push(
        Vector::new("stretch2-named-entities-email", t, "multi_encoding")
            .text(format!("mail {ent}"))
            .secret(em)
            .secret(ent),
    );
    let k = ghp(r);
    let zw = interleave(&k, '\u{200B}', 3);
    let pct = url_encode(&zw);
    v.push(
        Vector::new("stretch2-zwsp-then-url-encoded-token", t, "multi_encoding")
            .text(format!("t={pct}"))
            .secret(k)
            .secret(pct),
    );
    v
}

/// Tüm vektörler (deterministik).
pub fn all_vectors() -> Vec<Vector> {
    let mut r = Rng::new(0x5EC0_FFEE_2026_1118);
    let mut v = core(&mut r);
    v.extend(evasion(&mut r));
    v.extend(blacklist(&mut r));
    v.extend(controls());
    // Stretch en sonda üretilir: mevcut vektörlerin rastgele değerleri değişmesin.
    v.extend(stretch(&mut r));
    // Ek varyantlar da aynı gerekçeyle en sonda.
    v.extend(controls_extra());
    v.extend(fp_probes());
    v.extend(stretch2(&mut r));
    v.extend(r1_probes(&mut r));
    v.extend(r2_probes(&mut r));
    v.extend(fp_probes2());
    v.extend(controls3());
    v.extend(r3_probes(&mut r));
    v.extend(fp_probes3());
    v.extend(controls4());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn at_least_50_attack_vectors() {
        let all = all_vectors();
        let attacks = all
            .iter()
            .filter(|v| !matches!(v.tier, Tier::Control | Tier::FpProbe))
            .count();
        assert!(attacks >= 50, "yalnizca {attacks} saldiri vektoru var");
    }

    #[test]
    fn ids_are_unique() {
        let all = all_vectors();
        let set: HashSet<_> = all.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn every_attack_has_needles() {
        for v in all_vectors() {
            if !matches!(v.tier, Tier::Control | Tier::FpProbe) {
                assert!(!v.needles.is_empty(), "{} igne icermiyor", v.id);
                assert!(v.needles.iter().any(|n| n.chars().count() >= 6), "{}", v.id);
            }
        }
    }

    #[test]
    fn needles_actually_present_in_input() {
        // Vektör hatalı kurulmuşsa (iğne girdide yoksa) sızma testi anlamsız olur.
        for v in all_vectors() {
            if matches!(v.tier, Tier::Control | Tier::FpProbe) || v.payload == PayloadKind::Frame {
                continue;
            }
            let hay = format!("{}\n{}\n{}", v.process_name, v.window_title, v.text);
            assert!(
                v.needles.iter().any(|n| hay.contains(n.as_str())),
                "{}: iğne girdide yok",
                v.id
            );
        }
    }
}
