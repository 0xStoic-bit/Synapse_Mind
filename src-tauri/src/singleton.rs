//! Windows named-mutex singleton lock (ADR-001 Condition 1).
//!
//! Ensures only one Synapse Mind instance can open the store and assign monotonic
//! `event_id` values at a time.

/// Default Windows named mutex used by the production Synapse Mind process.
pub const SINGLETON_MUTEX_NAME: &str = "Local\\SynapseMind-Singleton";

/// Outcome of attempting to acquire the process singleton lock.
#[derive(Debug)]
pub enum AcquireOutcome {
    /// This process is the sole owner of the named mutex.
    Acquired(SingleInstanceGuard),
    /// Another instance already holds the named mutex; caller must exit before touching DB.
    AlreadyRunning,
}

/// RAII guard holding the OS named mutex handle for the lifetime of the process.
#[derive(Debug)]
pub struct SingleInstanceGuard {
    #[cfg(windows)]
    handle_raw: isize,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            if self.handle_raw != 0 {
                let handle = HANDLE(self.handle_raw as *mut core::ffi::c_void);
                // SAFETY: `handle_raw` is a valid non-null Win32 mutex handle created by
                // `CreateMutexW` and exclusively owned by this `SingleInstanceGuard`.
                let _ = unsafe { CloseHandle(handle) };
                self.handle_raw = 0;
            }
        }
    }
}

/// Attempts to acquire the global `Local\SynapseMind-Singleton` mutex.
pub fn acquire_default() -> Result<AcquireOutcome, String> {
    acquire_named(SINGLETON_MUTEX_NAME)
}

/// Attempts to acquire a named OS mutex without blocking.
pub fn acquire_named(name: &str) -> Result<AcquireOutcome, String> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
        use windows::Win32::System::Threading::CreateMutexW;
        use windows::core::PCWSTR;

        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: `wide` is a null-terminated UTF-16 string alive across the Win32 call.
        // `GetLastError` is read immediately after `CreateMutexW` before any other Win32 call.
        let (handle, last_err) = unsafe {
            let res = CreateMutexW(None, false, PCWSTR(wide.as_ptr()));
            let err = GetLastError();
            (res, err)
        };

        let handle = handle.map_err(|e| format!("CreateMutexW failed: {e}"))?;
        if last_err == ERROR_ALREADY_EXISTS {
            // SAFETY: `CreateMutexW` returned a valid duplicate handle to the existing mutex;
            // close it immediately before reporting `AlreadyRunning`.
            let _ = unsafe { CloseHandle(handle) };
            return Ok(AcquireOutcome::AlreadyRunning);
        }

        Ok(AcquireOutcome::Acquired(SingleInstanceGuard {
            handle_raw: handle.0 as isize,
        }))
    }

    #[cfg(not(windows))]
    {
        let _ = name;
        Ok(AcquireOutcome::Acquired(SingleInstanceGuard {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn named_mutex_allows_single_owner_and_releases_on_drop() {
        let pid = std::process::id();
        let name = format!("Local\\SynapseMind-Test-Singleton-{pid}-1");

        let first = match acquire_named(&name).expect("first acquire succeeds") {
            AcquireOutcome::Acquired(guard) => guard,
            AcquireOutcome::AlreadyRunning => panic!("unexpected existing mutex"),
        };

        match acquire_named(&name).expect("second acquire returns outcome") {
            AcquireOutcome::AlreadyRunning => {}
            AcquireOutcome::Acquired(_) => panic!("second instance must see AlreadyRunning"),
        }

        drop(first);

        match acquire_named(&name).expect("acquire after drop succeeds") {
            AcquireOutcome::Acquired(_guard) => {}
            AcquireOutcome::AlreadyRunning => panic!("mutex should be released after drop"),
        }
    }
}
