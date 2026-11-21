//! DPAPI-protected database key (`key.bin`). Plaintext key bytes live only inside
//! `s_guard::DbKey`; never copied by value, logged or written unencrypted.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use s_guard::DbKey;

/// Subdirectory under `%LOCALAPPDATA%` storing Synapse Mind's encrypted state.
pub const APP_DATA_DIR_NAME: &str = "SynapseMind";
/// Filename of the DPAPI-wrapped 256-bit database key blob.
pub const KEY_FILE_NAME: &str = "key.bin";
/// Filename of the encrypted SQLite/SQLCipher store.
pub const DB_FILE_NAME: &str = "memory.db";

/// Resolves the per-user local data directory (`%LOCALAPPDATA%\SynapseMind` on Windows).
pub fn resolve_data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "LOCALAPPDATA environment variable is not set".to_owned())?;
        Ok(PathBuf::from(base).join(APP_DATA_DIR_NAME))
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(xdg).join("synapse-mind"));
        }
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "neither XDG_DATA_HOME nor HOME is set".to_owned())?;
        Ok(PathBuf::from(home).join(".local/share/synapse-mind"))
    }
}

/// Loads the DPAPI-wrapped key from `key_path`, or generates and persists a new one.
/// Corrupted or unreadable key files fail without overwriting the blob.
pub fn load_or_create_db_key(key_path: &Path) -> Result<DbKey, String> {
    match std::fs::read(key_path) {
        Ok(blob) => {
            DbKey::load(&blob).map_err(|e| format!("failed to unprotect database key: {e}"))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let key = DbKey::generate();
            let blob = key
                .protect()
                .map_err(|e| format!("failed to protect database key: {e}"))?;
            write_blob_atomically(key_path, &blob)?;
            Ok(key)
        }
        Err(err) => Err(format!("failed to read database key file: {err}")),
    }
}

fn write_blob_atomically(key_path: &Path, blob: &[u8]) -> Result<(), String> {
    let parent = key_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "key path has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create key directory: {e}"))?;

    let tmp_name = format!("{KEY_FILE_NAME}.tmp.{}", std::process::id());
    let tmp_path = parent.join(tmp_name);

    let write_res = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        file.write_all(blob)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("failed to write temporary key blob: {err}"));
    }

    if let Err(err) = std::fs::rename(&tmp_path, key_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("failed to commit key blob: {err}"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(label: &str) -> TempDirGuard {
        let dir = std::env::temp_dir().join(format!(
            "synapse-mind-keystore-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        TempDirGuard(dir)
    }

    #[cfg(windows)]
    #[test]
    fn creates_and_reloads_dpapi_key_without_plaintext_on_disk() {
        let dir = temp_dir("roundtrip");
        let key_path = dir.0.join(KEY_FILE_NAME);

        let first = load_or_create_db_key(&key_path).expect("creates new key");
        let on_disk = std::fs::read(&key_path).expect("blob exists on disk");
        assert!(on_disk.len() > 32);
        assert!(
            !on_disk.windows(32).any(|w| w == first.expose()),
            "key blob on disk must never contain raw 32-byte key"
        );

        let second = load_or_create_db_key(&key_path).expect("reloads existing key");
        assert_eq!(first.expose(), second.expose());
    }

    #[cfg(windows)]
    #[test]
    fn corrupted_key_blob_returns_error_without_overwriting() {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir.0).expect("create temp dir");
        let key_path = dir.0.join(KEY_FILE_NAME);
        let original = b"corrupted-not-dpapi";
        std::fs::write(&key_path, original).expect("seed corrupt blob");

        let err = match load_or_create_db_key(&key_path) {
            Ok(_) => panic!("must reject corrupt blob"),
            Err(e) => e,
        };
        assert!(err.contains("unprotect"), "unexpected error: {err}");
        assert_eq!(std::fs::read(&key_path).expect("read back"), original);
    }
}
