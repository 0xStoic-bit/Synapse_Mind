//! Gate 2 test-only hooks (`--features gate2-hooks`, OFF by default).
//!
//! Allows the `gate2-app` test harness to open the Memory Panel deterministically
//! via `--gate2-open-panel` without relying on fragile synthetic `Ctrl+M` keyboard
//! injection. Never compiled into release builds.

/// CLI flag checked in `gate2-hooks` builds to open the Memory Panel.
pub const CLI_OPEN_PANEL_FLAG: &str = "--gate2-open-panel";

/// Named Win32 auto-reset event used to trigger the Memory Panel on an already-running
/// `gate2-hooks` test instance.
pub const OPEN_PANEL_EVENT_NAME: &str = "Local\\SynapseMind-Gate2-OpenPanel";

/// CLI flag checked in `gate2-hooks` builds: pause capture right after the sensor
/// pipeline starts, so memory measurements are not driven by desktop activity.
pub const CLI_PAUSE_CAPTURE_FLAG: &str = "--gate2-pause-capture";

/// CLI prefix checked in `gate2-hooks` builds: override the embedder idle-unload
/// timeout (seconds), e.g. `--gate2-idle-unload-secs=60`.
pub const CLI_IDLE_UNLOAD_SECS_PREFIX: &str = "--gate2-idle-unload-secs=";

/// Capture pause applied by [`CLI_PAUSE_CAPTURE_FLAG`] (24 h, the UI's maximum).
pub const PAUSE_CAPTURE_DURATION: std::time::Duration = std::time::Duration::from_secs(86_400);

/// Returns `true` when `args` contains `--gate2-pause-capture`.
pub fn has_pause_capture_flag<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|arg| arg.as_ref() == CLI_PAUSE_CAPTURE_FLAG)
}

/// Parses `--gate2-idle-unload-secs=N` (N clamped to 5..=3600). Invalid values are ignored.
pub fn idle_unload_override<I, S>(args: I) -> Option<std::time::Duration>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().find_map(|arg| {
        arg.as_ref()
            .strip_prefix(CLI_IDLE_UNLOAD_SECS_PREFIX)
            .and_then(|v| v.parse::<u64>().ok())
            .map(|secs| std::time::Duration::from_secs(secs.clamp(5, 3600)))
    })
}

/// Returns `true` when `args` contains `--gate2-open-panel`.
pub fn has_open_panel_flag<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|arg| arg.as_ref() == CLI_OPEN_PANEL_FLAG)
}

/// If launched with `--gate2-open-panel` and a `gate2-hooks` instance is already
/// listening on [`OPEN_PANEL_EVENT_NAME`], signals it to open the Memory Panel and
/// returns `true` so this helper invocation exits before touching keystore/DB.
pub fn try_signal_existing_instance() -> bool {
    if !has_open_panel_flag(std::env::args()) {
        return false;
    }

    #[cfg(windows)]
    {
        signal_named_event(OPEN_PANEL_EVENT_NAME)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

/// Polls briefly for [`OPEN_PANEL_EVENT_NAME`] when `--gate2-open-panel` arrives while
/// the primary instance is still completing startup initialization.
pub fn wait_and_signal_existing_instance(timeout: std::time::Duration) -> bool {
    if !has_open_panel_flag(std::env::args()) {
        return false;
    }

    let deadline = std::time::Instant::now() + timeout;
    loop {
        if try_signal_existing_instance() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn signal_named_event(name: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{EVENT_MODIFY_STATE, OpenEventW, SetEvent};
    use windows::core::PCWSTR;

    let name_w = to_wide_null(name);
    // SAFETY: `name_w` is null-terminated UTF-16 alive across `OpenEventW`; if an existing
    // handle is returned, it is signaled once and closed immediately.
    let Ok(handle) = (unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(name_w.as_ptr())) })
    else {
        return false;
    };

    // SAFETY: `handle` was validly opened with `EVENT_MODIFY_STATE` above.
    let ok = unsafe { SetEvent(handle) }.is_ok();
    // SAFETY: `handle` is owned exclusively by this scope and closed once.
    let _ = unsafe { CloseHandle(handle) };
    ok
}

/// RAII guard owning the background listener thread and Win32 event handles for
/// [`OPEN_PANEL_EVENT_NAME`]. Signals shutdown and joins cleanly on drop.
pub struct Gate2HookGuard {
    #[cfg(windows)]
    shutdown_raw: isize,
    #[cfg(windows)]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Gate2HookGuard {
    /// Starts the `gate2-hooks` listener and, if `--gate2-open-panel` was passed
    /// to this process, schedules opening the Memory Panel once the event loop runs.
    pub fn install(app: &tauri::AppHandle) -> Self {
        if has_open_panel_flag(std::env::args()) {
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                if let Err(err) = crate::open_or_focus_panel_window(&handle) {
                    eprintln!("synapse-mind: gate2-hooks failed to open panel on startup: {err}");
                }
            });
        }

        #[cfg(windows)]
        {
            Self::spawn_windows_listener(app.clone(), OPEN_PANEL_EVENT_NAME)
        }

        #[cfg(not(windows))]
        {
            let _ = app;
            Self {}
        }
    }

    #[cfg(windows)]
    fn spawn_windows_listener(app: tauri::AppHandle, event_name: &str) -> Self {
        use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{CreateEventW, INFINITE, WaitForMultipleObjects};
        use windows::core::PCWSTR;

        let name_w = to_wide_null(event_name);
        // SAFETY: `name_w` is null-terminated UTF-16; `CreateEventW` creates an auto-reset
        // event owned by the listener thread below.
        let open_event = match unsafe { CreateEventW(None, false, false, PCWSTR(name_w.as_ptr())) }
        {
            Ok(h) => h,
            Err(err) => {
                eprintln!("synapse-mind: gate2-hooks failed to create open-panel event: {err}");
                return Self {
                    shutdown_raw: 0,
                    thread: None,
                };
            }
        };

        // SAFETY: `PCWSTR::null()` creates an unnamed manual-reset shutdown event.
        let shutdown_event = match unsafe { CreateEventW(None, true, false, PCWSTR::null()) } {
            Ok(h) => h,
            Err(err) => {
                // SAFETY: `open_event` was created above and must be closed on early failure.
                let _ = unsafe { CloseHandle(open_event) };
                eprintln!("synapse-mind: gate2-hooks failed to create shutdown event: {err}");
                return Self {
                    shutdown_raw: 0,
                    thread: None,
                };
            }
        };

        let open_raw = open_event.0 as isize;
        let shutdown_raw = shutdown_event.0 as isize;

        let thread = std::thread::Builder::new()
            .name("gate2-panel-hook".to_owned())
            .spawn(move || {
                let handles = [
                    HANDLE(shutdown_raw as *mut core::ffi::c_void),
                    HANDLE(open_raw as *mut core::ffi::c_void),
                ];
                loop {
                    // SAFETY: Both `HANDLE`s remain open until after this thread exits and is joined.
                    let waited = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
                    if waited == WAIT_OBJECT_0 {
                        break;
                    }
                    if waited.0 == WAIT_OBJECT_0.0 + 1 {
                        let app_clone = app.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(err) = crate::open_or_focus_panel_window(&app_clone) {
                                eprintln!(
                                    "synapse-mind: gate2-hooks failed to open panel on signal: {err}"
                                );
                            }
                        });
                    } else {
                        break;
                    }
                }
                // SAFETY: `open_raw` is closed once on listener exit before `Drop` finishes.
                let _ = unsafe { CloseHandle(HANDLE(open_raw as *mut core::ffi::c_void)) };
            })
            .ok();

        if thread.is_none() {
            // SAFETY: Thread failed to spawn; close both handles immediately.
            let _ = unsafe { CloseHandle(open_event) };
            let _ = unsafe { CloseHandle(shutdown_event) };
            return Self {
                shutdown_raw: 0,
                thread: None,
            };
        }

        Self {
            shutdown_raw,
            thread,
        }
    }
}

impl Drop for Gate2HookGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            use windows::Win32::System::Threading::SetEvent;

            if self.shutdown_raw != 0 {
                let shutdown = HANDLE(self.shutdown_raw as *mut core::ffi::c_void);
                // SAFETY: `shutdown_raw` is valid until closed below after joining the thread.
                let _ = unsafe { SetEvent(shutdown) };
                if let Some(handle) = self.thread.take() {
                    let _ = handle.join();
                }
                // SAFETY: Listener thread has exited; close the shutdown handle once.
                let _ = unsafe { CloseHandle(shutdown) };
                self.shutdown_raw = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gate2_open_panel_cli_flag() {
        assert!(!has_open_panel_flag(["synapse-mind.exe"]));
        assert!(!has_open_panel_flag([
            "synapse-mind.exe",
            "--s-sensor-uia-worker"
        ]));
        assert!(has_open_panel_flag([
            "synapse-mind.exe",
            "--gate2-open-panel"
        ]));
        assert!(has_open_panel_flag([
            "synapse-mind.exe",
            "--other",
            "--gate2-open-panel"
        ]));
    }

    #[test]
    fn parses_gate2_memory_measurement_flags() {
        use std::time::Duration;
        assert!(!has_pause_capture_flag(["synapse-mind.exe"]));
        assert!(has_pause_capture_flag([
            "synapse-mind.exe",
            "--gate2-pause-capture"
        ]));
        assert_eq!(idle_unload_override(["synapse-mind.exe"]), None);
        assert_eq!(
            idle_unload_override(["x", "--gate2-idle-unload-secs=60"]),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            idle_unload_override(["x", "--gate2-idle-unload-secs=1"]),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            idle_unload_override(["x", "--gate2-idle-unload-secs=abc"]),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    fn named_event_can_be_signaled_and_cleaned_up() {
        use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
        use windows::core::PCWSTR;

        let name = format!("Local\\SynapseMind-Gate2-Test-{}", std::process::id());
        assert!(!signal_named_event(&name), "absent event must return false");

        let name_w = to_wide_null(&name);
        // SAFETY: `name_w` is null-terminated UTF-16 for an isolated unit-test event handle.
        let evt = unsafe { CreateEventW(None, false, false, PCWSTR(name_w.as_ptr())) }
            .expect("create test event");
        assert!(signal_named_event(&name), "existing event must be signaled");
        // SAFETY: `evt` is valid; zero-timeout check verifies the event was set.
        let wait = unsafe { WaitForSingleObject(evt, 0) };
        assert_eq!(wait, WAIT_OBJECT_0);
        // SAFETY: `evt` is owned exclusively by this test and closed once.
        let _ = unsafe { CloseHandle(evt) };
    }
}
