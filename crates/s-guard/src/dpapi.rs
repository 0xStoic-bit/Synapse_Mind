//! Veritabanı anahtarı: OS CSPRNG ile 256-bit üretim ve Windows DPAPI ile kullanıcıya bağlı
//! sarma. Dosya I/O yoktur; hata mesajları anahtar ya da blob içermez. DPAPI tamponları
//! `LocalFree` öncesinde sıfırlanır.
//!
//! Anahtar değerle taşınmamalıdır (bayat yığın kopyaları). Tercih sırası: [`DbKey`] >
//! `*_into(&mut [u8; 32])` > kullanımdan kaldırılan `generate_db_key` / `unprotect_key`.

use std::fmt;
use zeroize::Zeroizing;

/// Anahtar koruma hataları (içerik taşımaz).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// DPAPI çağrısı başarısız (HRESULT).
    Dpapi(i32),
    /// Blob boş, bozuk veya beklenen anahtar uzunluğunda değil.
    InvalidBlob,
    /// Bu platformda DPAPI yok.
    UnsupportedPlatform,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::Dpapi(code) => write!(f, "DPAPI call failed (HRESULT {code:#010x})"),
            GuardError::InvalidBlob => f.write_str("invalid or corrupted key blob"),
            GuardError::UnsupportedPlatform => {
                f.write_str("DPAPI is not available on this platform")
            }
        }
    }
}

impl std::error::Error for GuardError {}

pub type Result<T> = std::result::Result<T, GuardError>;

/// İşletim sistemi CSPRNG'sinden 256-bit veritabanı anahtarı üretir ve DEĞERLE döndürür.
///
/// OS rastgelelik kaynağı yoksa güvenli bir yedek bulunmadığından panik eder
/// (zayıf anahtarla devam etmek yerine). Panik mesajı içerik taşımaz.
#[deprecated(
    note = "değerle dönüş çağrı çerçevelerinde bayat yığın kopyası bırakabilir; `DbKey::generate` veya `generate_db_key_into` kullanın"
)]
pub fn generate_db_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    generate_db_key_into(&mut key);
    key
}

/// OS CSPRNG'sinden 256-bit anahtarı doğrudan `out` tamponuna yazar (değerle dönüş yok).
/// OS rastgelelik kaynağı yoksa içerik taşımayan mesajla panik eder.
pub fn generate_db_key_into(out: &mut [u8; 32]) {
    getrandom::fill(&mut out[..]).expect("OS CSPRNG unavailable");
}

/// Anahtarı DPAPI ile (geçerli Windows kullanıcısına bağlı) sarar.
/// Çıktı diske yazılabilir; anahtarın kendisi değildir.
pub fn protect_key(key: &[u8; 32]) -> Result<Vec<u8>> {
    imp::protect(key)
}

/// `protect_key` ile sarılmış blob'dan anahtarı geri alır ve DEĞERLE döndürür. Bozuk/
/// kurcalanmış blob, başka kullanıcıya ait blob veya yanlış uzunluk `Err` döndürür.
#[deprecated(
    note = "değerle dönüş çağrı çerçevelerinde bayat yığın kopyası bırakabilir; `DbKey::load` veya `unprotect_key_into` kullanın"
)]
pub fn unprotect_key(blob: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    imp::unprotect_into(blob, &mut key)?;
    Ok(key)
}

/// `unprotect_key` ile aynı; anahtarı DPAPI çıktı tamponundan doğrudan `out`'a kopyalar
/// ve DPAPI tamponunu sıfırlayıp serbest bırakır (değerle dönüş yok). Hata durumunda
/// `out` değiştirilmez.
pub fn unprotect_key_into(blob: &[u8], out: &mut [u8; 32]) -> Result<()> {
    imp::unprotect_into(blob, out)
}

/// Heap'te tek kez ayrılan, adresi sabit 256-bit anahtar. İçerik kutu ayrıldıktan sonra
/// yerinde yazılır, taşınırken yalnızca işaretçi kopyalanır, Drop'ta sıfırlanır.
/// Bilinçli olarak `Clone`/`Copy`/`Debug` yok; baytlara [`DbKey::expose`] ile ödünç erişilir.
pub struct DbKey(Box<Zeroizing<[u8; 32]>>);

impl DbKey {
    /// Sıfır dolu kutuyu ayırır (anahtar baytı içermez; sonra yerinde doldurulur).
    fn zeroed() -> Self {
        DbKey(Box::new(Zeroizing::new([0u8; 32])))
    }

    /// OS CSPRNG'sinden yeni anahtar üretir (bkz. [`generate_db_key_into`]).
    pub fn generate() -> Self {
        let mut key = Self::zeroed();
        generate_db_key_into(&mut key.0);
        key
    }

    /// `protect_key` ile sarılmış blob'dan anahtarı yükler (bkz. [`unprotect_key_into`]).
    /// Hata durumunda hiçbir anahtar baytı kalmaz.
    pub fn load(blob: &[u8]) -> Result<Self> {
        let mut key = Self::zeroed();
        unprotect_key_into(blob, &mut key.0)?;
        Ok(key)
    }

    /// Anahtar baytlarına ödünç erişim.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Anahtarı DPAPI ile sarar (bkz. [`protect_key`]).
    pub fn protect(&self) -> Result<Vec<u8>> {
        protect_key(self.expose())
    }
}

#[cfg(windows)]
mod imp {
    use super::{GuardError, Result};
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;
    use zeroize::Zeroize;

    /// Uygulamaya özgü ek entropi: blob başka bir bağlamda çözülemez.
    const ENTROPY: &[u8] = b"s-recall/db-key/v1";

    fn in_blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).map_err(|_| GuardError::InvalidBlob)?,
            // DPAPI girdiyi yalnızca okur; `*mut` zorunluluğu API imzasından gelir.
            pbData: data.as_ptr().cast_mut(),
        })
    }

    fn dpapi_err(e: &windows::core::Error) -> GuardError {
        GuardError::Dpapi(e.code().0)
    }

    /// DPAPI'nin `LocalAlloc` ile ayırdığı çıktı tamponu: drop'ta sıfırlanır ve serbest bırakılır.
    struct OutBlob(CRYPT_INTEGER_BLOB);

    impl OutBlob {
        fn new() -> Self {
            OutBlob(CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            })
        }

        fn as_slice(&self) -> &[u8] {
            if self.0.pbData.is_null() {
                return &[];
            }
            // SAFETY: DPAPI başarıyla döndüğünde `pbData`, `cbData` bayt uzunluğunda geçerli
            // ve tek sahibi bu yapı olan bir tampona işaret eder; `self` ödünç alındığı
            // sürece serbest bırakılmaz.
            unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }
        }
    }

    impl Drop for OutBlob {
        fn drop(&mut self) {
            if self.0.pbData.is_null() {
                return;
            }
            // SAFETY: `pbData`, DPAPI'nin ayırdığı `cbData` baytlık tampondur ve burada
            // tek sahibiyiz; önce sıfırlanır, sonra tam bir kez `LocalFree` ile serbest
            // bırakılır (drop ikinci kez çalışmaz, işaretçi sonrasında kullanılmaz).
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                let _ = LocalFree(Some(HLOCAL(self.0.pbData.cast())));
            }
            self.0.pbData = std::ptr::null_mut();
            self.0.cbData = 0;
        }
    }

    pub(super) fn protect(key: &[u8; 32]) -> Result<Vec<u8>> {
        let input = in_blob(key)?;
        let entropy = in_blob(ENTROPY)?;
        let mut out = OutBlob::new();
        // SAFETY: `input` ve `entropy` çağrı süresince yaşayan geçerli baytlara işaret eder
        // ve yalnızca okunur; `out.0` yazılabilir geçerli bir CRYPT_INTEGER_BLOB'dur.
        // Açıklama dizgesi null, ayrılmış/prompt işaretçileri None, UI yasaktır.
        let res = unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        };
        res.map_err(|e| dpapi_err(&e))?;
        let blob = out.as_slice();
        if blob.is_empty() {
            return Err(GuardError::InvalidBlob);
        }
        Ok(blob.to_vec())
    }

    pub(super) fn unprotect_into(blob: &[u8], out_key: &mut [u8; 32]) -> Result<()> {
        if blob.is_empty() {
            return Err(GuardError::InvalidBlob);
        }
        let input = in_blob(blob)?;
        let entropy = in_blob(ENTROPY)?;
        let mut out = OutBlob::new();
        // SAFETY: `input` ve `entropy` çağrı süresince yaşayan geçerli baytlara işaret eder
        // ve yalnızca okunur; `out.0` yazılabilir geçerli bir CRYPT_INTEGER_BLOB'dur.
        // Açıklama çıktısı istenmez (None), prompt yok, UI yasaktır.
        let res = unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        };
        res.map_err(|e| dpapi_err(&e))?;
        let plain = out.as_slice();
        if plain.len() != 32 {
            return Err(GuardError::InvalidBlob);
        }
        // Doğrudan çağıranın tamponuna: ara `[u8; 32]` değeri oluşmaz. `out` (DPAPI
        // tamponu) drop'ta sıfırlanıp `LocalFree` edilir.
        out_key.copy_from_slice(plain);
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{GuardError, Result};

    pub(super) fn protect(_key: &[u8; 32]) -> Result<Vec<u8>> {
        Err(GuardError::UnsupportedPlatform)
    }

    pub(super) fn unprotect_into(_blob: &[u8], _out: &mut [u8; 32]) -> Result<()> {
        Err(GuardError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        generate_db_key_into(&mut k);
        k
    }

    #[test]
    fn generated_keys_are_distinct_and_nonzero() {
        let (a, b) = (new_key(), new_key());
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        let (x, y) = (DbKey::generate(), DbKey::generate());
        assert_ne!(x.expose(), y.expose());
        assert_ne!(x.expose(), &[0u8; 32]);
    }

    #[cfg(windows)]
    #[test]
    fn round_trip() {
        let key = new_key();
        let blob = protect_key(&key).expect("protect");
        assert!(blob.len() > 32);
        // Blob düz anahtarı içermez.
        assert!(!blob.windows(32).any(|w| w == &key[..]));
        let mut back = [0u8; 32];
        unprotect_key_into(&blob, &mut back).expect("unprotect");
        assert_eq!(back, key);
    }

    #[cfg(windows)]
    #[test]
    fn dbkey_round_trip_and_stable_address() {
        let key = DbKey::generate();
        let blob = key.protect().expect("protect");
        let loaded = DbKey::load(&blob).expect("load");
        assert_eq!(loaded.expose(), key.expose());
        // Taşıma yalnızca işaretçiyi kopyalar: bayt adresi değişmez.
        let before = loaded.expose().as_ptr();
        let moved = Some(loaded);
        let after = moved.as_ref().map(|k| k.expose().as_ptr());
        assert_eq!(Some(before), after);
    }

    #[cfg(windows)]
    #[test]
    #[allow(deprecated)]
    fn deprecated_value_api_still_round_trips() {
        let key = generate_db_key();
        let blob = protect_key(&key).expect("protect");
        let back = unprotect_key(&blob).expect("unprotect");
        assert_eq!(*back, *key);
    }

    #[cfg(windows)]
    #[test]
    fn protect_is_salted() {
        let key = new_key();
        let a = protect_key(&key).expect("a");
        let b = protect_key(&key).expect("b");
        assert_ne!(a, b);
        let (mut ka, mut kb) = ([0u8; 32], [0u8; 32]);
        unprotect_key_into(&a, &mut ka).expect("a");
        unprotect_key_into(&b, &mut kb).expect("b");
        assert_eq!(ka, kb);
    }

    #[cfg(windows)]
    #[test]
    fn corrupted_blob_is_rejected_and_out_untouched() {
        let key = new_key();
        let blob = protect_key(&key).expect("protect");
        // Şifreli gövde ve MAC bölgesinden tek bit çevir: reddedilmeli, `out` değişmemeli.
        for idx in [blob.len() * 3 / 4, blob.len() / 2, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[idx] ^= 0x01;
            let mut out = [0u8; 32];
            assert!(unprotect_key_into(&bad, &mut out).is_err(), "idx {idx}");
            assert_eq!(out, [0u8; 32], "idx {idx}: out must stay untouched");
            assert!(DbKey::load(&bad).is_err(), "idx {idx}");
        }
        // Başlık bölgesindeki değişiklik kabul edilse bile asla YANLIŞ anahtar döndürmez.
        for idx in 0..blob.len().min(64) {
            let mut bad = blob.clone();
            bad[idx] ^= 0x01;
            let mut out = [0u8; 32];
            if unprotect_key_into(&bad, &mut out).is_ok() {
                assert_eq!(out, key, "idx {idx} returned a different key");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn truncated_empty_and_garbage_blobs_are_rejected() {
        let key = new_key();
        let blob = protect_key(&key).expect("protect");
        let mut out = [0u8; 32];
        assert!(unprotect_key_into(&blob[..blob.len() - 8], &mut out).is_err());
        assert_eq!(
            unprotect_key_into(&[], &mut out).unwrap_err(),
            GuardError::InvalidBlob
        );
        assert!(unprotect_key_into(&[0u8; 64], &mut out).is_err());
        assert!(unprotect_key_into(b"not a dpapi blob at all", &mut out).is_err());
        assert_eq!(out, [0u8; 32]);
        assert!(DbKey::load(&[]).is_err());
    }

    #[test]
    fn errors_carry_no_secret_material() {
        let msg = GuardError::InvalidBlob.to_string();
        assert!(!msg.is_empty());
        let dbg = format!("{:?}", GuardError::Dpapi(-2146893813));
        assert!(dbg.starts_with("Dpapi"));
    }
}
