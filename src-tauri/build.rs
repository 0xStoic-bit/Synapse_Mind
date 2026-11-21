fn main() {
    let attributes =
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "search",
            "hide_overlay",
            "is_demo_mode",
            "open_memory_panel",
            "open_overlay_with_query",
            "get_memory_panel_data",
            "pause_capture",
            "resume_capture",
            "add_blocked_app",
            "remove_blocked_app",
            "delete_recent_memory",
            "delete_all_memory",
            "set_autostart",
            "get_embedder_status",
            "retry_embedder_download",
        ]));
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
