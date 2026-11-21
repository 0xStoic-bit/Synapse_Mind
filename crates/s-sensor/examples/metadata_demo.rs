//! Yalnızca metadata basan sensör demosu: `cargo run -p s-sensor --example metadata_demo`.
//! Ham başlık, UIA metni ya da pano içeriği asla yazdırılmaz.

use std::time::Duration;

use s_sensor::{SensorConfig, extract_metadata, start_sensor_pipeline};

fn parse_duration_arg() -> Option<Duration> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--seconds"
            && let Some(val) = args.next()
            && let Ok(secs) = val.parse::<u64>()
        {
            return Some(Duration::from_secs(secs));
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    s_sensor::run_uia_worker_if_requested();
    let duration = parse_duration_arg();
    let (handle, mut rx) = start_sensor_pipeline(SensorConfig::default())?;
    let mut state_rx = handle.subscribe_state();
    let mut current_state = *state_rx.borrow_and_update();

    println!("s-sensor metadata demosu basladi (Ctrl+C ile cikis).");
    println!("Yalnizca metadata (event, pid, ts_ms, text_len) ve durum adlari basilir.");
    println!("durum: {current_state}");

    let deadline = duration.map(tokio::time::sleep);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            maybe_pkt = rx.recv() => {
                match maybe_pkt {
                    Some(packet) => {
                        let meta = extract_metadata(&packet);
                        // Ham paket kullanildigi an drop edilip zeroize edilir.
                        drop(packet);
                        println!("{meta}");
                    }
                    None => break,
                }
            }
            Ok(()) = state_rx.changed() => {
                let next_state = *state_rx.borrow_and_update();
                if next_state != current_state {
                    println!("durum: {current_state} -> {next_state}");
                    current_state = next_state;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Durdurma sinyali alindi.");
                break;
            }
            _ = async {
                if let Some(timer) = deadline.as_mut().as_pin_mut() {
                    timer.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                println!("Sure doldu, cikiliyor.");
                break;
            }
        }
    }

    handle.stop();
    Ok(())
}
