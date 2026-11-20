//! Gate 2 (RAM dump) altyapısı. Sahibi: redteam-auditor.
//!
//! * `spec`    : denetçi -> hedef paket tarifi (ikili); hedef sırları dosyadan okur, kendi üretmez.
//! * `scan`    : döküm dosyasında UTF-8 + UTF-16LE sır arama, döküm düzeni (yığın/yığın dışı) ayrıştırma.
//! * `dump`    : `MiniDumpWriteDump` (MiniDumpWithFullMemory) ile canlı çocuk süreç dökümü.
//! * `session` : hedefi başlat -> READY bekle -> döküm -> tara -> öldür -> döküm dosyasını sil.
//!
//! Hedef ikili (`gate2-target`) bu lib'in yalnızca `spec` modülünü kullanır ve `s-redteam`'e
//! bağlanmaz: hedefin imajında sentetik sır literali bulunmaz. TÜM VERİLER SENTETİKTİR.

pub mod scan;
pub mod spec;
pub mod sqlcipher;

#[cfg(windows)]
pub mod dump;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod winutil;
