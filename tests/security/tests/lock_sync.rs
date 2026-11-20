//! ADR-004: `tests/security/Cargo.lock` kök `Cargo.lock` ile senkron kalmalı. Kök kilitte olmayan
//! ya da farklı sürümde bir REGISTRY paketi bu workspace'e girerse (sürüm kayması) test başarısız olur.
//! Çözüm: kök `Cargo.lock`'u `tests/security/Cargo.lock` olarak kopyalayıp `cargo build` ile budayın.

use std::collections::BTreeSet;

/// (ad, sürüm) çiftleri; yalnızca `source = "registry+..."` (yol bağımlılıkları hariç).
fn registry_packages(lock: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(|v| v.trim().trim_matches('"').to_string())
        };
        if let (Some(n), Some(v), Some(src)) =
            (field("name = "), field("version = "), field("source = "))
            && src.starts_with("registry+")
        {
            out.insert((n, v));
        }
    }
    out
}

#[test]
fn security_lock_is_subset_of_root_lock() {
    let root =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
    let mine = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
    let (root, mine) = (registry_packages(&root), registry_packages(&mine));
    assert!(
        mine.len() > 20,
        "ayrıştırma başarısız: {} paket",
        mine.len()
    );
    let drift: Vec<_> = mine.difference(&root).collect();
    assert!(
        drift.is_empty(),
        "kok Cargo.lock ile surum kaymasi: {drift:?}"
    );
}
