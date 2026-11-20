//! SQLCipher 4 anahtar türetimi (yalnızca denetim): ham anahtarla açılan bir veritabanında HMAC anahtarı
//! `PBKDF2-HMAC-SHA512(key, salt ^ 0x3a, iter = 2, dkLen = 32)` ile türetilir (salt = DB dosyasının ilk
//! 16 baytı). Türetilen anahtar bellekte kalıyor mu diye aranır; türetimin doğruluğu 1. sayfanın HMAC'i ile
//! doğrulanır (`verify_page1`), böylece "yanlış anahtarı aradık" riski kalmaz.

use sha2::{Digest, Sha512};

const BLOCK: usize = 128;

pub fn hmac_sha512(key: &[u8], data: &[&[u8]]) -> [u8; 64] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    for d in data {
        inner.update(d);
    }
    let ih = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA512, tek blok (dkLen <= 64).
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(out.len() <= 64 && iterations >= 1);
    let mut u = hmac_sha512(password, &[salt, &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..iterations {
        u = hmac_sha512(password, &[&u]);
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    out.copy_from_slice(&t[..out.len()]);
}

/// SQLCipher 4 (raw key) HMAC anahtarı: PBKDF2(key, salt ^ 0x3a, 2, 32).
pub fn derive_hmac_key(key: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    let mut mac_salt = [0u8; 16];
    for i in 0..16 {
        mac_salt[i] = salt[i] ^ 0x3a;
    }
    let mut out = [0u8; 32];
    pbkdf2_hmac_sha512(key, &mac_salt, 2, &mut out);
    out
}

/// Birinci sayfanın HMAC'ini doğrular (sayfa boyu 4096, reserve 80 = IV 16 + HMAC 64). HMAC, sayfanın
/// `[16, sayfa_boyu - reserve + 16)` aralığı ve little-endian sayfa numarası (1) üzerinden hesaplanır.
pub fn verify_page1(db: &[u8], hmac_key: &[u8; 32]) -> bool {
    const PAGE: usize = 4096;
    const RESERVE: usize = 80;
    if db.len() < PAGE {
        return false;
    }
    let page = &db[..PAGE];
    let covered = &page[16..PAGE - RESERVE + 16];
    let want = &page[PAGE - 64..];
    hmac_sha512(hmac_key, &[covered, &1u32.to_le_bytes()]).as_slice() == want
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn pbkdf2_hmac_sha512_known_vectors() {
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(b"password", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        );
        pbkdf2_hmac_sha512(b"password", b"salt", 2, &mut out);
        assert_eq!(
            hex(&out),
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
        );
    }

    #[test]
    fn hmac_sha512_rfc4231_case1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha512(&key, &[b"Hi There"])),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }
}
