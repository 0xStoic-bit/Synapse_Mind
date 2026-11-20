#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // UIA işçi alt komutu: sensör her UIA çıkarımını bu ikilinin tek atımlık kopyasında yapar
    // (Gate 2: UIAutomationCore iç yığın kalıntısı ana süreçte kalmaz). İşçi kipindeyse dönmez.
    s_sensor::run_uia_worker_if_requested();
    synapse_mind::run();
}
