//! s-redteam: Gate 1 / Gate 2 sızma testleri. Sahibi: redteam-auditor.
//!
//! * `synth`   : sentetik veri üreteçleri (Luhn kart, TC kimlik, SSN, anahtarlar, kodlayıcılar)
//! * `vectors` : Gate 1 saldırı vektörleri (`all_vectors()`)
//! * `harness` : sızıntı dedektörü (`check_block`), guard API'sinden bağımsız
//!
//! Guard'a karşı koşan testler: `tests/gate1_pii.rs` (`s_guard::process` / `s_guard::run`).
//! TÜM VERİLER SENTETİKTİR; gerçek kimlik bilgisi yoktur.

pub mod harness;
pub mod synth;
pub mod vectors;
