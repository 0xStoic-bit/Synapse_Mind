//! Gate 2 (RAM dökümü) altyapısı.
//!
//! * `spec`: hedef paket tarifi · `scan`: UTF-8 + UTF-16LE sır arama · `dump`: `MiniDumpWriteDump`
//!   ile canlı döküm · `session`: başlat → döküm → tara → öldür → döküm dosyasını sil.
//!
//! Hedef ikili `s-redteam`'e bağlanmaz; imajında sentetik sır literali bulunmaz.

pub mod scan;
pub mod spec;
pub mod sqlcipher;

#[cfg(windows)]
pub mod dump;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod winutil;
