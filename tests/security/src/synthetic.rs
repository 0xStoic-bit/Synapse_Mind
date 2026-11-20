//! Atıf koşulları için SENTETİK besleme seti (Gate 1 üreteçleri; deterministik). `#[path]` ile eklenir.

#[allow(dead_code)] // `raw` yalnizca bazi ikililerde okunur
pub struct Synthetic {
    pub title: String,
    pub body: String,
    pub clips: Vec<String>,
    /// (kimlik, değer): bellekte ARANACAK ham sırlar.
    pub raw: Vec<(String, String)>,
}

pub fn synthetic_set() -> Synthetic {
    use s_redteam::synth::*;
    let mut rng = Rng::new(0x6A7E_2026_1119_0001);
    let stripe = format!("sk_live_{}", rng.string(ALNUM, 24));
    let aws_id = format!("AKIA{}", rng.string(UPPER_DIGIT, 16));
    let aws_secret = rng.string(B64_STD, 40);
    let ghp = format!("ghp_{}", rng.string(ALNUM, 36));
    let openai = format!("sk-proj-{}", rng.string(B64_URL, 48));
    let card_no = card(&mut rng, "4", 16);
    let card_sp = group(&card_no, &[4, 4, 4, 4], " ");
    let tc = tc_kimlik(&mut rng);
    let pw_a = "Hunter2x-Synth9-Gate2";
    let pw_b = "Zk4$nW8-Synth-Gate2";
    // Orta/son 12 karakter aramasının "example.test" gibi yaygın dizgilere çakışmaması için benzersiz.
    let email = format!(
        "g2.{}@zz-{}.invalid",
        rng.string(b"0123456789abcdef", 8),
        rng.string(b"0123456789abcdef", 8)
    );
    let pem_rows: Vec<String> = (0..4).map(|_| rng.string(B64_STD, 64)).collect();
    let jwt = format!(
        "{}.{}.{}",
        base64_url(br#"{"alg":"HS256","typ":"JWT"}"#),
        base64_url(br#"{"sub":"gate2-synthetic","role":"tester"}"#),
        rng.string(B64_URL, 43)
    );
    let title = format!("{stripe} - Gate2 Synthetic");
    let body = format!(
        "aws_access_key_id = {aws_id}\r\naws_secret_access_key = {aws_secret}\r\nAuthorization: Bearer {jwt}\r\ncard {card_sp}\r\npassword={pw_a}\r\nmail {email}\r\n-----BEGIN RSA PRIVATE KEY-----\r\n{}\r\n-----END RSA PRIVATE KEY-----\r\n",
        pem_rows.join("\r\n")
    );
    let clips = vec![
        format!("export GH_TOKEN={ghp} # contact {email}"),
        format!("kart {card_no} TC {tc} sifre: {pw_b}"),
        format!("OPENAI_API_KEY={openai}"),
    ];
    let mut raw: Vec<(String, String)> = vec![
        ("stripe".into(), stripe),
        ("aws_id".into(), aws_id),
        ("aws_secret".into(), aws_secret),
        ("ghp".into(), ghp),
        ("openai".into(), openai),
        ("card".into(), card_no),
        ("card_spaced".into(), card_sp),
        ("tc".into(), tc),
        ("password_a".into(), pw_a.into()),
        ("password_b".into(), pw_b.into()),
        ("email".into(), email),
        ("jwt".into(), jwt),
    ];
    for (i, r) in pem_rows.iter().enumerate() {
        raw.push((format!("pem_row{i}"), r.clone()));
    }
    Synthetic {
        title,
        body,
        clips,
        raw,
    }
}
