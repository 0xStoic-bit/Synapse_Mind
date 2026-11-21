use std::sync::{Arc, Mutex};
use std::time::Duration;

use s_sensor::ControllerState;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};

use crate::{
    SharedPipeline, open_or_focus_panel_window, show_overlay_window, toggle_overlay_window,
};

pub const TRAY_ID: &str = "synapse-mind-tray";
const MENU_SEARCH_ID: &str = "tray_search";
const MENU_PANEL_ID: &str = "tray_panel";
const MENU_PAUSE_ID: &str = "tray_toggle_pause";
const MENU_AUTOSTART_ID: &str = "tray_autostart";
const MENU_QUIT_ID: &str = "tray_quit";
const TRAY_ICON_SIZE: u32 = 32;

/// Visual icon variant for the Synapse Mind system tray indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayVisualState {
    Active,
    Batching,
    PausedOrSuspended,
}

/// Maps the live sensor state and manual pause flag to a tray icon variant.
pub fn tray_visual_state(state: Option<ControllerState>, paused: bool) -> TrayVisualState {
    if paused {
        return TrayVisualState::PausedOrSuspended;
    }
    match state {
        Some(ControllerState::Active) => TrayVisualState::Active,
        Some(ControllerState::Batching) => TrayVisualState::Batching,
        Some(ControllerState::Suspended) | None => TrayVisualState::PausedOrSuspended,
    }
}

/// Formats the system tray tooltip strictly from non-sensitive sensor state metadata.
/// Window titles, app names, and search queries must never appear here.
pub fn format_tray_tooltip(
    state: Option<ControllerState>,
    paused: bool,
    pause_remaining: Option<Duration>,
) -> String {
    if paused {
        if let Some(remaining) = pause_remaining {
            let mins = remaining.as_secs().div_ceil(60).max(1);
            return format!("Synapse Mind: duraklatıldı ({mins} dk)");
        }
        return "Synapse Mind: duraklatıldı".to_owned();
    }

    match state {
        Some(ControllerState::Active) => "Synapse Mind: kaydediyor".to_owned(),
        Some(ControllerState::Suspended) => "Synapse Mind: askıda (oyun modu)".to_owned(),
        Some(ControllerState::Batching) => "Synapse Mind: biriktiriyor".to_owned(),
        None => "Synapse Mind: sensör kapalı".to_owned(),
    }
}

/// Returns the dynamic tray menu label for the capture pause/resume action.
pub fn tray_pause_menu_label(paused: bool) -> &'static str {
    if paused {
        "Devam et"
    } else {
        "1 saat duraklat"
    }
}

/// Renders a crisp 32x32 RGBA Synapse Mind tray icon for the given `TrayVisualState`.
pub fn render_tray_icon_rgba(variant: TrayVisualState) -> Vec<u8> {
    let (bg, fg): ([u8; 3], [u8; 3]) = match variant {
        TrayVisualState::Active => ([0, 95, 184], [255, 255, 255]),
        TrayVisualState::Batching => ([180, 83, 9], [255, 255, 255]),
        TrayVisualState::PausedOrSuspended => ([100, 116, 139], [226, 232, 240]),
    };

    let size = TRAY_ICON_SIZE as usize;
    let mut rgba = Vec::with_capacity(size * size * 4);

    for y in 0..size {
        for x in 0..size {
            let px = (x as f32) + 0.5;
            let py = (y as f32) + 0.5;
            let dx = (px - 16.0).abs() - 8.0;
            let dy = (py - 16.0).abs() - 8.0;
            let dist_rr = dx.max(0.0).hypot(dy.max(0.0)) + dx.max(dy).min(0.0) - 6.0;
            let bg_alpha = (0.5 - dist_rr).clamp(0.0, 1.0);
            if bg_alpha <= 0.0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            let r = (px - 16.0).hypot(py - 16.0);
            let ring_a = (1.1 - (r - 5.8).abs()).clamp(0.0, 1.0);
            let tick_v = (1.05 - (px - 16.0).abs()).clamp(0.0, 1.0)
                * (1.05
                    - 0.0_f32
                        .max(8.6 - (py - 16.0).abs())
                        .max((py - 16.0).abs() - 11.8))
                .clamp(0.0, 1.0);
            let tick_h = (1.05 - (py - 16.0).abs()).clamp(0.0, 1.0)
                * (1.05
                    - 0.0_f32
                        .max(8.6 - (px - 16.0).abs())
                        .max((px - 16.0).abs() - 11.8))
                .clamp(0.0, 1.0);

            let fg_a = ring_a.max(tick_v).max(tick_h);
            let r_ch = (f32::from(bg[0]) * (1.0 - fg_a) + f32::from(fg[0]) * fg_a).round() as u8;
            let g_ch = (f32::from(bg[1]) * (1.0 - fg_a) + f32::from(fg[1]) * fg_a).round() as u8;
            let b_ch = (f32::from(bg[2]) * (1.0 - fg_a) + f32::from(fg[2]) * fg_a).round() as u8;
            let a_ch = (bg_alpha * 255.0).round() as u8;
            rgba.extend_from_slice(&[r_ch, g_ch, b_ch, a_ch]);
        }
    }

    rgba
}

fn tray_image(variant: TrayVisualState) -> Image<'static> {
    Image::new_owned(
        render_tray_icon_rgba(variant),
        TRAY_ICON_SIZE,
        TRAY_ICON_SIZE,
    )
}

/// Synchronizes the live tray icon, tooltip, and pause/resume menu item text.
#[derive(Clone)]
pub struct TrayController {
    pipeline: SharedPipeline,
    pause_item: MenuItem<tauri::Wry>,
    autostart_item: CheckMenuItem<tauri::Wry>,
    last_visual: Arc<Mutex<Option<TrayVisualState>>>,
}

impl TrayController {
    pub fn sync_autostart(&self, enabled: bool) {
        let _ = self.autostart_item.set_checked(enabled);
    }

    pub fn sync(&self, app: &tauri::AppHandle) {
        let (state, paused, remaining) = snapshot_pipeline_state(&self.pipeline);
        let visual = tray_visual_state(state, paused);
        let tooltip = format_tray_tooltip(state, paused, remaining);

        let _ = self.pause_item.set_text(tray_pause_menu_label(paused));

        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            let _ = tray.set_tooltip(Some(tooltip));
            let should_update_icon = self
                .last_visual
                .lock()
                .map(|mut slot| {
                    if *slot != Some(visual) {
                        *slot = Some(visual);
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if should_update_icon {
                let _ = tray.set_icon(Some(tray_image(visual)));
            }
        }
    }
}

fn snapshot_pipeline_state(
    pipeline: &SharedPipeline,
) -> (Option<ControllerState>, bool, Option<Duration>) {
    let Ok(guard) = pipeline.lock() else {
        return (None, false, None);
    };
    match guard.as_ref() {
        Some(controller) => controller.raw_sensor_snapshot(),
        None => (None, false, None),
    }
}

fn subscribe_pipeline_state(
    pipeline: &SharedPipeline,
) -> Option<tokio::sync::watch::Receiver<ControllerState>> {
    let guard = pipeline.lock().ok()?;
    guard
        .as_ref()
        .and_then(|controller| controller.subscribe_sensor_state())
}

/// Initializes the Synapse Mind system tray icon, native context menu, and state watcher.
pub fn setup_tray(
    app: &tauri::AppHandle,
    pipeline: SharedPipeline,
) -> tauri::Result<TrayController> {
    let (initial_state, initial_paused, initial_remaining) = snapshot_pipeline_state(&pipeline);
    let initial_visual = tray_visual_state(initial_state, initial_paused);
    let initial_tooltip = format_tray_tooltip(initial_state, initial_paused, initial_remaining);

    let search_item =
        MenuItem::with_id(app, MENU_SEARCH_ID, "Ara (Alt+Space)", true, None::<&str>)?;
    let panel_item = MenuItem::with_id(app, MENU_PANEL_ID, "Hafıza Paneli", true, None::<&str>)?;
    let sep_top = PredefinedMenuItem::separator(app)?;
    let pause_item = MenuItem::with_id(
        app,
        MENU_PAUSE_ID,
        tray_pause_menu_label(initial_paused),
        true,
        None::<&str>,
    )?;
    let autostart_item = CheckMenuItem::with_id(
        app,
        MENU_AUTOSTART_ID,
        "Windows açılışında başlat",
        true,
        crate::autostart::is_enabled(),
        None::<&str>,
    )?;
    let sep_bottom = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(
        app,
        MENU_QUIT_ID,
        "Synapse Mind'dan çık",
        true,
        None::<&str>,
    )?;

    let menu = Menu::with_items(
        app,
        &[
            &search_item,
            &panel_item,
            &sep_top,
            &pause_item,
            &autostart_item,
            &sep_bottom,
            &quit_item,
        ],
    )?;

    let controller = TrayController {
        pipeline: Arc::clone(&pipeline),
        pause_item,
        autostart_item,
        last_visual: Arc::new(Mutex::new(Some(initial_visual))),
    };

    let menu_controller = controller.clone();
    let menu_pipeline = Arc::clone(&pipeline);

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tray_image(initial_visual))
        .tooltip(initial_tooltip)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_overlay_window(tray.app_handle());
            }
        })
        .on_menu_event(move |app, event| match event.id().as_ref() {
            MENU_SEARCH_ID => {
                show_overlay_window(app);
            }
            MENU_PANEL_ID => {
                if let Err(err) = open_or_focus_panel_window(app) {
                    eprintln!("synapse-mind: failed to open memory panel from tray: {err}");
                }
            }
            MENU_PAUSE_ID => {
                let (_, paused, _) = snapshot_pipeline_state(&menu_pipeline);
                if let Ok(guard) = menu_pipeline.lock()
                    && let Some(pipeline_ctrl) = guard.as_ref()
                {
                    if paused {
                        let _ = pipeline_ctrl.resume();
                    } else {
                        let _ = pipeline_ctrl.pause_for(Duration::from_secs(3600));
                    }
                }
                menu_controller.sync(app);
                if let Some(panel) = app.get_webview_window("panel") {
                    let _ = panel.emit("panel://refresh", ());
                }
            }
            MENU_AUTOSTART_ID => {
                let next = !crate::autostart::is_enabled();
                match crate::autostart::set_enabled(next) {
                    Ok(actual) => {
                        menu_controller.sync_autostart(actual);
                    }
                    Err(err) => {
                        eprintln!("synapse-mind: failed to toggle autostart from tray: {err}");
                        menu_controller.sync_autostart(crate::autostart::is_enabled());
                    }
                }
                if let Some(panel) = app.get_webview_window("panel") {
                    let _ = panel.emit("panel://refresh", ());
                }
            }
            MENU_QUIT_ID => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    let watch_rx = subscribe_pipeline_state(&pipeline);
    let watcher_app = app.clone();
    let watcher_ctrl = controller.clone();
    tauri::async_runtime::spawn(async move {
        let mut rx = watch_rx;
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            match rx.as_mut() {
                Some(receiver) => {
                    tokio::select! {
                        changed = receiver.changed() => {
                            if changed.is_err() {
                                rx = None;
                            }
                            watcher_ctrl.sync(&watcher_app);
                        }
                        _ = tick.tick() => {
                            watcher_ctrl.sync(&watcher_app);
                        }
                    }
                }
                None => {
                    tick.tick().await;
                    watcher_ctrl.sync(&watcher_app);
                }
            }
        }
    });

    Ok(controller)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_tooltip_maps_all_sensor_states_without_sensitive_fields() {
        assert_eq!(
            format_tray_tooltip(Some(ControllerState::Active), false, None),
            "Synapse Mind: kaydediyor"
        );
        assert_eq!(
            format_tray_tooltip(Some(ControllerState::Suspended), false, None),
            "Synapse Mind: askıda (oyun modu)"
        );
        assert_eq!(
            format_tray_tooltip(Some(ControllerState::Batching), false, None),
            "Synapse Mind: biriktiriyor"
        );
        assert_eq!(
            format_tray_tooltip(None, false, None),
            "Synapse Mind: sensör kapalı"
        );
        assert_eq!(
            format_tray_tooltip(
                Some(ControllerState::Suspended),
                true,
                Some(Duration::from_secs(3541))
            ),
            "Synapse Mind: duraklatıldı (60 dk)"
        );
        assert_eq!(
            format_tray_tooltip(
                Some(ControllerState::Active),
                true,
                Some(Duration::from_secs(12))
            ),
            "Synapse Mind: duraklatıldı (1 dk)"
        );
        assert_eq!(
            format_tray_tooltip(Some(ControllerState::Suspended), true, None),
            "Synapse Mind: duraklatıldı"
        );
    }

    #[test]
    fn tray_pause_menu_label_and_icon_variants_reflect_state() {
        assert_eq!(tray_pause_menu_label(false), "1 saat duraklat");
        assert_eq!(tray_pause_menu_label(true), "Devam et");

        assert_eq!(
            tray_visual_state(Some(ControllerState::Active), false),
            TrayVisualState::Active
        );
        assert_eq!(
            tray_visual_state(Some(ControllerState::Batching), false),
            TrayVisualState::Batching
        );
        assert_eq!(
            tray_visual_state(Some(ControllerState::Suspended), false),
            TrayVisualState::PausedOrSuspended
        );
        assert_eq!(
            tray_visual_state(Some(ControllerState::Active), true),
            TrayVisualState::PausedOrSuspended
        );

        let active_rgba = render_tray_icon_rgba(TrayVisualState::Active);
        let paused_rgba = render_tray_icon_rgba(TrayVisualState::PausedOrSuspended);
        let batch_rgba = render_tray_icon_rgba(TrayVisualState::Batching);
        assert_eq!(active_rgba.len(), 32 * 32 * 4);
        assert_eq!(paused_rgba.len(), 32 * 32 * 4);
        assert_eq!(batch_rgba.len(), 32 * 32 * 4);
        assert_ne!(active_rgba, paused_rgba);
        assert_ne!(active_rgba, batch_rgba);
    }
}
