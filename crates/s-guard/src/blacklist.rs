//! Kara liste: süreç adı, pencere başlığı ve dosya adı tabanlı anında DROP kararları.
//!
//! Karşılaştırmalar büyük/küçük harf duyarsızdır (Türkçe `İ` dahil). Buradaki
//! hiçbir fonksiyon girdiyi loglamaz; katlanmış (lowercase) kopyalar iş bitince
//! `zeroize` edilir.

use crate::normalize::{norm_char, push_grow};
use zeroize::Zeroize;

/// Parola yöneticisi süreç/başlık parçaları (substring eşleşmesi).
const PASSWORD_MANAGER_SUBSTRINGS: &[&str] = &[
    "1password",
    "bitwarden",
    "keepass", // keepassxc dahil
    "lastpass",
    "dashlane",
    "nordpass",
    "roboform",
    "enpass",
    "protonpass",
    "proton pass",
];

/// Kısa/belirsiz adlar: yalnızca süreç kökü (".exe" atılmış) tam eşleşirse.
const PASSWORD_MANAGER_EXACT_STEMS: &[&str] = &[
    "keeper",
    "authy",
    "pwsafe",
    "psono",
    "stickypassword",
    "zohovault",
];

/// Gizli/özel gezinti işaretleri (katlanmış başlıkta aranır).
const PRIVATE_WINDOW_MARKERS: &[&str] = &[
    "inprivate",
    "incognito",
    "private browsing",
    "private window",
    "(private)",
    "gizli sekme",
    "gizli pencere",
    "gizli mod",
    "özel gezinti",
    "ozel gezinti",
];

/// Hassas dosya uzantıları; ardından alfanümerik karakter GELMEMELİ.
const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".env", ".envrc", ".pem", ".key", ".pfx", ".p12", ".ppk", ".kdbx",
];

/// Hassas dosya adı parçaları (substring).
const SENSITIVE_NAME_SUBSTRINGS: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

/// Büyük/küçük harf ve Türkçe noktalı/noktasız i farkını gideren katlama.
/// Sonuç ham-türevidir: çağıran `zeroize` etmelidir.
pub(crate) fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    fold_into(&mut out, s);
    out
}

/// `fold`, ama doğrudan `out` tamponuna yazar (ara `String` oluşmaz); büyümede eski
/// tampon sıfırlanır.
pub(crate) fn fold_into(out: &mut String, s: &str) {
    for c in s.chars() {
        if c == 'ı' {
            push_grow(out, 'i');
            continue;
        }
        // Görünmez karakter atma, NFKC, homoglif/rakam katlaması, sonra küçük harf.
        // `İ`.to_lowercase() = 'i' + birleştirici nokta (U+0307); noktayı at.
        norm_char(c, |n| {
            for l in n.to_lowercase().filter(|&l| l != '\u{307}') {
                push_grow(out, l);
            }
        });
    }
}

/// ".exe" gibi uzantıyı atılmış, katlanmış süreç kökü.
pub(crate) fn process_stem(folded: &str) -> &str {
    folded.strip_suffix(".exe").unwrap_or(folded)
}

fn contains_password_manager(folded: &str) -> bool {
    PASSWORD_MANAGER_SUBSTRINGS
        .iter()
        .any(|needle| folded.contains(needle))
}

/// Süreç adı parola yöneticisine mi ait?
pub(crate) fn is_blacklisted_process(process_name: &str) -> bool {
    let mut folded = fold(process_name);
    let hit = contains_password_manager(&folded)
        || PASSWORD_MANAGER_EXACT_STEMS.contains(&process_stem(&folded));
    folded.zeroize();
    hit
}

/// Başlık bir parola yöneticisi arayüzünü (ör. tarayıcı eklentisi/web kasası) mı gösteriyor?
pub(crate) fn title_names_password_manager(title: &str) -> bool {
    let mut folded = fold(title);
    let hit = contains_password_manager(&folded);
    folded.zeroize();
    hit
}

/// Başlık gizli/özel gezinti penceresini mi işaret ediyor?
pub(crate) fn is_private_window(title: &str) -> bool {
    let mut folded = fold(title);
    let hit = PRIVATE_WINDOW_MARKERS.iter().any(|m| folded.contains(m));
    folded.zeroize();
    hit
}

/// Metin (başlık veya dosya yolu listesi) hassas bir dosya adı içeriyor mu?
pub(crate) fn mentions_sensitive_file(text: &str) -> bool {
    let mut folded = fold(text);
    let mut hit = SENSITIVE_NAME_SUBSTRINGS.iter().any(|n| folded.contains(n));
    if !hit {
        hit = SENSITIVE_EXTENSIONS.iter().any(|ext| {
            folded.match_indices(ext).any(|(idx, _)| {
                folded[idx + ext.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric())
            })
        });
    }
    folded.zeroize();
    hit
}

/// Süreç adı bilinen bir tarayıcı mı?
pub(crate) fn is_browser(process_name: &str) -> bool {
    const BROWSERS: &[&str] = &[
        "chrome",
        "msedge",
        "firefox",
        "brave",
        "opera",
        "opera_gx",
        "vivaldi",
        "iexplore",
        "chromium",
        "arc",
        "safari",
        "librewolf",
        "waterfox",
        "zen",
        "tor",
        "yandex",
        "browser",
        "duckduckgo",
        "thorium",
    ];
    let mut folded = fold(process_name);
    let hit = BROWSERS.contains(&process_stem(&folded));
    folded.zeroize();
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_manager_processes() {
        for n in [
            "1Password.exe",
            "BITWARDEN.EXE",
            "KeePass.exe",
            "KeePassXC.exe",
            "LastPass.exe",
            "Dashlane.exe",
            "Keeper.exe",
            "NordPass.exe",
        ] {
            assert!(is_blacklisted_process(n), "{n}");
        }
        for n in ["chrome.exe", "code.exe", "housekeeper.exe", "notepad.exe"] {
            assert!(!is_blacklisted_process(n), "{n}");
        }
    }

    #[test]
    fn private_windows() {
        for t in [
            "New tab - Google Chrome (Incognito)",
            "Microsoft Edge InPrivate",
            "Mozilla Firefox Private Browsing",
            "GİZLİ SEKME - Chrome",
            "Yeni Sekme - Gizli Pencere",
            "INCOGNITO",
            "Özel Gezinti - Firefox",
        ] {
            assert!(is_private_window(t), "{t}");
        }
        assert!(!is_private_window("Rust docs - Google Chrome"));
    }

    #[test]
    fn sensitive_files() {
        for t in [
            "C:\\app\\.env - Notepad",
            "config.ENV",
            ".env.local - VS Code",
            "server.pem",
            "tls.key - Notepad",
            "id_rsa",
            "C:\\Users\\x\\.ssh\\id_rsa.pub",
            "vault.kdbx",
            "cert.p12",
            "(.env)",
        ] {
            assert!(mentions_sensitive_file(t), "{t}");
        }
        for t in [
            "Environment Settings",
            "my.keyboard.txt",
            "dotenv docs",
            "monkey",
            "app.environment",
            "",
        ] {
            assert!(!mentions_sensitive_file(t), "{t}");
        }
    }

    #[test]
    fn browsers() {
        assert!(is_browser("chrome.exe"));
        assert!(is_browser("MsEdge.exe"));
        assert!(is_browser("firefox"));
        assert!(!is_browser("code.exe"));
        assert!(!is_browser("archive.exe"));
    }

    #[test]
    fn title_password_manager() {
        assert!(title_names_password_manager("Vault | Bitwarden - Chrome"));
        assert!(!title_names_password_manager("Rust book"));
    }
}
