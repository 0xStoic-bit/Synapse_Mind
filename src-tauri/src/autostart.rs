//! Windows per-user startup preference (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
//!
//! Default is disabled (no registry entry is created on first launch). When enabled,
//! stores only the quoted executable path; never writes user content or secrets.

use std::path::Path;

/// Registry subkey under `HKEY_CURRENT_USER` for per-user Windows login startup.
pub const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
/// Registry value name for Synapse Mind under `RUN_SUBKEY`.
pub const VALUE_NAME: &str = "Synapse Mind";

/// Formats an executable path as a quoted Windows `Run` registry command line,
/// stripping any Windows `\\?\` verbatim path prefix.
pub fn format_run_command(exe_path: &Path) -> Result<String, String> {
    let raw = exe_path
        .to_str()
        .ok_or_else(|| "executable path contains non-UTF-8 characters".to_owned())?
        .trim();
    if raw.is_empty() {
        return Err("executable path is empty".to_owned());
    }
    let clean = if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        raw.to_owned()
    };
    if clean.contains('"') || clean.contains('\0') {
        return Err("executable path contains invalid characters".to_owned());
    }
    Ok(format!("\"{clean}\""))
}

/// Returns whether Synapse Mind is currently configured to launch at Windows sign-in.
pub fn is_enabled() -> bool {
    #[cfg(windows)]
    {
        is_enabled_in_subkey(RUN_SUBKEY, VALUE_NAME)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

/// Enables or disables per-user Windows sign-in startup in `HKCU\...\Run`.
pub fn set_enabled(enabled: bool) -> Result<bool, String> {
    #[cfg(windows)]
    {
        if enabled {
            let exe = std::env::current_exe()
                .map_err(|e| format!("failed to resolve current executable path: {e}"))?;
            let command = format_run_command(&exe)?;
            set_enabled_in_subkey(RUN_SUBKEY, VALUE_NAME, Some(&command))?;
            Ok(true)
        } else {
            set_enabled_in_subkey(RUN_SUBKEY, VALUE_NAME, None)?;
            Ok(false)
        }
    }

    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("autostart is only supported on Windows".to_owned())
    }
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn to_wide_le_bytes(s: &str) -> Vec<u8> {
    let wide = to_wide_null(s);
    let mut bytes = Vec::with_capacity(wide.len() * 2);
    for unit in wide {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

#[cfg(windows)]
struct RegKeyGuard(windows::Win32::System::Registry::HKEY);

#[cfg(windows)]
impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is an open `HKEY` handle owned exclusively by this guard.
            let _ = unsafe { windows::Win32::System::Registry::RegCloseKey(self.0) };
            self.0 = windows::Win32::System::Registry::HKEY::default();
        }
    }
}

#[cfg(windows)]
fn is_enabled_in_subkey(subkey: &str, value_name: &str) -> bool {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
        RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::core::PCWSTR;

    let subkey_w = to_wide_null(subkey);
    let value_w = to_wide_null(value_name);
    let mut raw_key = HKEY::default();

    // SAFETY: `subkey_w` is null-terminated UTF-16 alive across the call; `raw_key` receives
    // the opened key handle if `ERROR_SUCCESS` is returned.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &raw mut raw_key,
        )
    };
    if status != ERROR_SUCCESS {
        return false;
    }
    let key = RegKeyGuard(raw_key);

    let mut reg_type = REG_VALUE_TYPE::default();
    let mut cb_data: u32 = 0;
    // SAFETY: `key.0` is a valid open handle; `value_w` is null-terminated UTF-16; passing
    // `lpdata = None` queries only the type and byte length into `reg_type` and `cb_data`.
    let query_len_status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&raw mut reg_type),
            None,
            Some(&raw mut cb_data),
        )
    };
    if query_len_status != ERROR_SUCCESS || (reg_type != REG_SZ && reg_type != REG_EXPAND_SZ) {
        return false;
    }
    if cb_data <= 2 || cb_data > 65_536 {
        return false;
    }

    let mut buf = vec![0_u8; cb_data as usize];
    let mut read_len = cb_data;
    // SAFETY: `buf` has exact byte capacity `read_len` and stays pinned across the call.
    let read_status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(value_w.as_ptr()),
            None,
            Some(&raw mut reg_type),
            Some(buf.as_mut_ptr()),
            Some(&raw mut read_len),
        )
    };
    if read_status != ERROR_SUCCESS {
        return false;
    }

    let units: Vec<u16> = buf[..(read_len as usize).min(buf.len())]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|&u| u != 0)
        .collect();
    let text = String::from_utf16_lossy(&units);
    !text.trim().is_empty()
}

#[cfg(windows)]
fn set_enabled_in_subkey(
    subkey: &str,
    value_name: &str,
    command: Option<&str>,
) -> Result<(), String> {
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCreateKeyExW,
        RegDeleteValueW, RegOpenKeyExW, RegSetValueExW,
    };
    use windows::core::PCWSTR;

    let subkey_w = to_wide_null(subkey);
    let value_w = to_wide_null(value_name);

    match command {
        Some(cmd) => {
            let mut raw_key = HKEY::default();
            // SAFETY: `subkey_w` is null-terminated UTF-16; `raw_key` receives the opened/created
            // handle on `ERROR_SUCCESS`.
            let status = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey_w.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE,
                    None,
                    &raw mut raw_key,
                    None,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("failed to open startup registry key: {status:?}"));
            }
            let key = RegKeyGuard(raw_key);
            let data = to_wide_le_bytes(cmd);
            // SAFETY: `key.0` is an open handle with `KEY_SET_VALUE`; `value_w` is null-terminated
            // UTF-16; `data` is a valid null-terminated UTF-16LE byte slice for `REG_SZ`.
            let write_status = unsafe {
                RegSetValueExW(key.0, PCWSTR(value_w.as_ptr()), None, REG_SZ, Some(&data))
            };
            if write_status != ERROR_SUCCESS {
                return Err(format!(
                    "failed to write startup registry value: {write_status:?}"
                ));
            }
            Ok(())
        }
        None => {
            let mut raw_key = HKEY::default();
            // SAFETY: `subkey_w` is null-terminated UTF-16; `raw_key` receives the handle when present.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey_w.as_ptr()),
                    None,
                    KEY_SET_VALUE,
                    &raw mut raw_key,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(());
            }
            if status != ERROR_SUCCESS {
                return Err(format!("failed to open startup registry key: {status:?}"));
            }
            let key = RegKeyGuard(raw_key);
            // SAFETY: `key.0` is an open handle with `KEY_SET_VALUE`; `value_w` is null-terminated UTF-16.
            let del_status = unsafe { RegDeleteValueW(key.0, PCWSTR(value_w.as_ptr())) };
            if del_status == ERROR_SUCCESS || del_status == ERROR_FILE_NOT_FOUND {
                Ok(())
            } else {
                Err(format!(
                    "failed to remove startup registry value: {del_status:?}"
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_run_command_strips_verbatim_prefix_and_quotes() {
        let normal = Path::new(r"C:\Users\demo\AppData\Local\Synapse Mind\synapse-mind.exe");
        assert_eq!(
            format_run_command(normal).expect("format normal path"),
            r#""C:\Users\demo\AppData\Local\Synapse Mind\synapse-mind.exe""#
        );

        let verbatim = Path::new(r"\\?\C:\Program Files\Synapse Mind\synapse-mind.exe");
        assert_eq!(
            format_run_command(verbatim).expect("strip \\\\?\\ prefix"),
            r#""C:\Program Files\Synapse Mind\synapse-mind.exe""#
        );

        let unc = Path::new(r"\\?\UNC\server\share\synapse-mind.exe");
        assert_eq!(
            format_run_command(unc).expect("strip \\\\?\\UNC\\ prefix"),
            r#""\\server\share\synapse-mind.exe""#
        );

        assert!(format_run_command(Path::new("")).is_err());
        assert!(format_run_command(Path::new(r#"C:\bad"quote\app.exe"#)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn hkcu_roundtrip_on_isolated_test_subkey() {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteKeyW};
        use windows::core::PCWSTR;

        struct TestSubkeyGuard(String);
        impl Drop for TestSubkeyGuard {
            fn drop(&mut self) {
                let wide = to_wide_null(&self.0);
                // SAFETY: `wide` is null-terminated UTF-16 naming only the isolated unit-test subkey.
                let _ = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(wide.as_ptr())) };
            }
        }

        let subkey = format!(r"Software\SynapseMindTestAutostart-{}", std::process::id());
        let _cleanup = TestSubkeyGuard(subkey.clone());

        assert!(
            !is_enabled_in_subkey(&subkey, VALUE_NAME),
            "default startup state must be disabled when registry key is absent"
        );

        let cmd = r#""C:\Synthetic\Synapse Mind\synapse-mind.exe""#;
        set_enabled_in_subkey(&subkey, VALUE_NAME, Some(cmd)).expect("enable startup in test key");
        assert!(is_enabled_in_subkey(&subkey, VALUE_NAME));

        set_enabled_in_subkey(&subkey, VALUE_NAME, None).expect("disable startup in test key");
        assert!(!is_enabled_in_subkey(&subkey, VALUE_NAME));

        // Disabling again when already absent must remain idempotent.
        set_enabled_in_subkey(&subkey, VALUE_NAME, None).expect("idempotent disable");
        assert!(!is_enabled_in_subkey(&subkey, VALUE_NAME));
    }
}
