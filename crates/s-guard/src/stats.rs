//! Hafıza Paneli desteği: yalnızca SAYAÇ tutan istatistikler ve çalışma anında kullanıcı
//! kara listesi.
//!
//! `GuardStats` hiçbir içerik, süreç adı veya pencere başlığı tutmaz; yalnızca
//! `AtomicU64` sayaçlardır (süreç ömrü boyunca bellekte, diske yazılmaz). `UserBlocklist`
//! kullanıcının "bir uygulamayı hiç kaydetme" kararıyla eklediği süreç adlarını tutar
//! (kullanıcının kendi girdisi; paket içeriği değil).

use crate::scrub::Kind;
use crate::{DropReason, Verdict, blacklist};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

const DROP_REASONS: [DropReason; 4] = [
    DropReason::BlacklistedProcess,
    DropReason::PrivateWindow,
    DropReason::SensitiveFile,
    DropReason::IgnoredFormat,
];

fn drop_index(reason: DropReason) -> usize {
    match reason {
        DropReason::BlacklistedProcess => 0,
        DropReason::PrivateWindow => 1,
        DropReason::SensitiveFile => 2,
        DropReason::IgnoredFormat => 3,
    }
}

/// Bir paketin işlenmesinden çıkan, içerik taşımayan özet.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// Paket kullanıcı kara listesi yüzünden düştü mü?
    pub user_blocked: bool,
    /// Maskelenen her aralığın türü (başlık + süreç adı + metin).
    pub kinds: Vec<Kind>,
}

/// Süreç ömrü boyunca bellekte duran sayaçlar. İçerik yok.
#[derive(Debug, Default)]
pub struct GuardStats {
    processed: AtomicU64,
    dropped: [AtomicU64; 4],
    user_blocked: AtomicU64,
    redactions: [AtomicU64; 8],
}

/// [`GuardStats`]'ın anlık görüntüsü (yalnızca sayılar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardStatsSnapshot {
    /// Neden başına atılan paket sayısı (4 neden, sabit sırada).
    pub dropped: Vec<(DropReason, u64)>,
    /// Maske türü başına maskelenen aralık sayısı (8 tür, sabit sırada: `API_KEY`,
    /// `CREDIT_CARD`, `TC_KIMLIK`, `SSN`, `EMAIL`, `PRIVATE_KEY`, `JWT`, `PASSWORD`).
    pub redactions: Vec<(&'static str, u64)>,
    /// İşlenen toplam paket (atılanlar + maskelenenler).
    pub processed: u64,
}

impl GuardStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Anlık görüntü (sayaçlar `Relaxed` okunur; paneller için yeterli).
    pub fn snapshot(&self) -> GuardStatsSnapshot {
        GuardStatsSnapshot {
            dropped: DROP_REASONS
                .iter()
                .map(|&r| (r, self.dropped[drop_index(r)].load(Ordering::Relaxed)))
                .collect(),
            redactions: Kind::PANEL_ORDER
                .iter()
                .map(|k| {
                    (
                        k.name(),
                        self.redactions[k.panel_index()].load(Ordering::Relaxed),
                    )
                })
                .collect(),
            processed: self.processed.load(Ordering::Relaxed),
        }
    }

    /// `BlacklistedProcess` içinden kaç paketin KULLANICI kara listesi yüzünden atıldığı
    /// (`DropReason`'a yeni varyant eklenmedi; sözleşme/test uyumu için ayrı sayaç).
    pub fn user_blocked(&self) -> u64 {
        self.user_blocked.load(Ordering::Relaxed)
    }

    pub(crate) fn record(&self, verdict: &Verdict, outcome: &Outcome) {
        self.processed.fetch_add(1, Ordering::Relaxed);
        match verdict {
            Verdict::Dropped(reason) => {
                self.dropped[drop_index(*reason)].fetch_add(1, Ordering::Relaxed);
                if outcome.user_blocked {
                    self.user_blocked.fetch_add(1, Ordering::Relaxed);
                }
            }
            Verdict::Masked(_) => {
                for kind in &outcome.kinds {
                    self.redactions[kind.panel_index()].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Kullanıcının çalışma anında eklediği, hiç kaydedilmeyecek süreçler. Anahtarlar
/// büyük/küçük harf, görünmez karakter, homoglif ve `.exe` uzantısından bağımsız
/// (mevcut kara liste normalizasyonu) ve yoldan arındırılmış saklanır.
#[derive(Debug, Default)]
pub struct UserBlocklist {
    set: RwLock<HashSet<String>>,
}

/// Süreç adını anahtara çevirir: yol atılır, normalize edilir, `.exe` düşer.
fn key_of(process: &str) -> String {
    let name = process.rsplit(['\\', '/']).next().unwrap_or(process);
    let folded = blacklist::fold(name.trim());
    blacklist::process_stem(&folded).to_owned()
}

impl UserBlocklist {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Süreci kara listeye ekler (boş ad yok sayılır).
    pub fn add(&self, process: &str) {
        let key = key_of(process);
        if !key.is_empty() {
            self.set
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key);
        }
    }

    pub fn remove(&self, process: &str) {
        let key = key_of(process);
        self.set
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
    }

    /// Normalize edilmiş anahtarlar (alfabetik).
    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .set
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Süreç adı listede mi (aynı normalizasyonla)?
    pub fn is_blocked(&self, process: &str) -> bool {
        let key = key_of(process);
        !key.is_empty()
            && self
                .set
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_is_case_path_and_extension_insensitive() {
        let bl = UserBlocklist::new();
        bl.add("Spotify.EXE");
        bl.add("  C:\\Program Files\\Slack\\slack.exe ");
        bl.add("");
        assert_eq!(bl.list(), ["slack", "spotify"]);
        for p in ["spotify.exe", "SPOTIFY", "c:/x/Spotify.exe", "Slack.exe"] {
            assert!(bl.is_blocked(p), "{p}");
        }
        assert!(!bl.is_blocked("spotifyd.exe"));
        assert!(!bl.is_blocked(""));
        bl.remove("SLACK.EXE");
        assert_eq!(bl.list(), ["spotify"]);
        bl.remove("not-there");
        assert_eq!(bl.list(), ["spotify"]);
    }

    #[test]
    fn blocklist_normalizes_homoglyphs_and_invisibles() {
        let bl = UserBlocklist::new();
        bl.add("spotify.exe");
        assert!(bl.is_blocked("Sp\u{200B}otify.exe"));
        assert!(bl.is_blocked("s\u{0440}otify.exe")); // Kiril 'р'
        assert!(bl.is_blocked("\u{FF33}\u{FF50}otify"));
    }

    #[test]
    fn blocklist_is_shareable_across_threads() {
        let bl = UserBlocklist::new();
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let bl = Arc::clone(&bl);
                std::thread::spawn(move || bl.add(&format!("app{i}.exe")))
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(bl.list().len(), 4);
    }

    #[test]
    fn fresh_stats_are_zero_with_stable_shape() {
        let snap = GuardStats::new().snapshot();
        assert_eq!(snap.processed, 0);
        assert_eq!(snap.dropped.len(), 4);
        assert_eq!(snap.redactions.len(), 8);
        assert!(snap.dropped.iter().all(|&(_, n)| n == 0));
        let names: Vec<_> = snap.redactions.iter().map(|&(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "API_KEY",
                "CREDIT_CARD",
                "TC_KIMLIK",
                "SSN",
                "EMAIL",
                "PRIVATE_KEY",
                "JWT",
                "PASSWORD"
            ]
        );
    }
}
