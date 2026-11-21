//! Yığın kalıntısı temizliği. Regex/SIMD/NFKC yolları ham metin parçalarını yığın
//! çerçevelerine dökebilir; bunlar `String` olmadığından `zeroize` edilemez. İşlem bittikten
//! sonra aynı yığın bölgesi büyük bir çerçeveyle ezilir.

use zeroize::Zeroize;

/// Ezilecek yığın boyutu (bayt). Tarama çağrı zincirinin derinliğini kaplayacak kadar büyük,
/// 1 MiB'lık ana iş parçacığı yığınına göre güvenli kadar küçük.
const WIPE_BYTES: usize = 192 * 1024;

/// Geçerli yığının altındaki `WIPE_BYTES` bölgesini sıfırlar. `#[inline(never)]` ve
/// `black_box` + volatile yazım, derleyicinin yazımları atmasını engeller.
#[inline(never)]
pub(crate) fn wipe_stack() {
    let mut buf = [0xA5u8; WIPE_BYTES];
    std::hint::black_box(&mut buf);
    buf.zeroize();
    std::hint::black_box(&buf);
}

#[cfg(test)]
mod tests {
    use super::wipe_stack;

    #[test]
    fn wipe_runs_and_returns() {
        wipe_stack();
    }
}
