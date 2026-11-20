#!/usr/bin/env bash
# ADR-004 kanıtı: `cargo tree -p s-guard` sürümleri kök ve tests/security workspace'inde AYNI olmalı.
# Not: bu workspace s-sensor/tokio özelliklerini de birleştirdiğinden ağaç, kökteki ağacın ÜST KÜMESİ olabilir
# (ör. tokio `signal` -> mio). Koşul: kökteki her (ad, sürüm) burada da bulunmalı; ayrıca ortak adların sürümü aynı.
set -euo pipefail
cd "$(dirname "$0")/../.."
a=$(mktemp); b=$(mktemp)
cargo tree -p s-guard --offline -e normal --prefix none | sed 's/ (\*)//; s/ (proc-macro)//; s/ (.*//' | sort -u >"$a"
(cd tests/security && cargo tree -p s-guard --offline -e normal --prefix none | sed 's/ (\*)//; s/ (proc-macro)//; s/ (.*//' | sort -u >"$b")
missing=$(comm -23 "$a" "$b" || true)
if [ -n "$missing" ]; then echo "FARKLI (kokte olup burada olmayan veya surumu farkli):"; echo "$missing"; exit 1; fi
extra=$(comm -13 "$a" "$b" || true)
echo "cargo tree -p s-guard: kok ($(wc -l <"$a") paket) tamamen icerilir; ek paketler (ozellik birlesimi): $(echo "$extra" | grep -c . || true)"
(cd tests/security && cargo test --test lock_sync)
