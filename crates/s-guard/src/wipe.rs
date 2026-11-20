//! Yığın (stack) kalıntısı temizliği.
//!
//! Tarama çağrı zinciri (regex lazy-DFA/memchr/Aho-Corasick SIMD yolları, NFKC yineleyicileri,
//! derleyici geçicileri) ham metnin 16/32 baytlık parçalarını yığın çerçevelerine dökebilir
//! (özellikle `debug` derlemelerde vektör yazmaç dökümleri). Bu kalıntılar bir `String`
//! tamponu olmadığından `zeroize` ile silinemez; çağrı döndükten sonra aynı yığın bölgesi
//! büyük bir çerçeveyle ezilir. Yalnızca ham içerik işleyen iş parçacığında, işlem bittikten
//! SONRA çağrılır.

use zeroize::Zeroize;

/// Ezilecek yığın boyutu (bayt). Tarama çağrı zincirinin derinliğini kaplayacak kadar büyük,
/// 1 MiB'lık ana iş parçacığı yığınına göre güvenli kadar küçük.
const WIPE_BYTES: usize = 192 * 1024;

/// Geçerli yığının altındaki (`WIPE_BYTES`) bölgeyi sıfırlar.
///
/// `#[inline(never)]`: çerçeve çağıranın altında ayrı yer kaplar. Tampon önce sıfır olmayan
/// bir desenle doldurulup `black_box` ile gözlemlenir, sonra `zeroize` (volatile yazım) ile
/// silinir; derleyici yazımları atamaz.
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
