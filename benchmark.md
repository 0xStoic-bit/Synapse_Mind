# Benchmark Günlüğü

Sahibi: `benchmark-plotter`. Kural: yalnızca gerçek profilleme çıktısı (`.agents/rules/no_mock_data.md`, `.agents/rules/optimization_and_latency_tracking.md`).  
Not: `.gitignore` içinde `benchmarks/*` dışlandığından ham ölçüm dosyaları yerel `benchmarks/results/<tarih>/` altında tutulur; kalıcı özet kayıt bu dosyadır.

---

## v0.1.1 Ölçümleri (Uzun Sorgu Sınırı & Doğrulanmış Overlay 20 Arama) — 2026-11-21

### Ortam, Git Durumu ve Boşta Kanıtı
- **Tarih (UTC / Yerel):** `2026-11-21` (`11:51Z–11:55Z` / `14:51–14:55+03:00`)
- **Temel Git Commit / Çalışma Ağacı:** `0d4a86e` (dal: `v0.1.1`, `git status --short`: `41` girdi; `crates/s-core` sorgu uzunluk/token sınırı `v0.1.1 [DONE]`, `src-tauri/` + `ui/` NSIS/autostart/embedder-ui `v0.1.1 [DONE]` ve `benchmarks/` eklemeleri üzerinde commit/push olmadan ölçüldü)
- **Derleyici / Araç Zinciri:** `rustc 1.95.0 (59807616e 2026-04-14)`, `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- **Build Profili & Workspace Kilidi (ADR-004):** `benchmarks/Cargo.toml` (`--release`, `lto = "thin"`, `codegen-units = 1`); `benchmarks/Cargo.lock` kök `Cargo.lock` (`hf-hub = 0.5.0` dahil) ile güncellendi ve `Compare-Object` (`cargo tree` default: `0` fark; `--features fastembed`: yalnızca `fastembed v7.7.1 (*)` tekilleştirme satırı farkı, sürüm uyuşmazlığı yok)
- **Yayın İkilisi (Overlay Testi):** `src-tauri/target/release/synapse-mind.exe` (`45,317,120` B, `21.11.2026 13:51:50`, `cargo tauri build --features fastembed` ile üretilen ikili)
- **CPU / RAM / İşletim Sistemi:** `AMD Ryzen 7 8845HS w/ Radeon 780M Graphics` (`8` fiziksel çekirdek / `16` mantıksal işlemci, `3801 MHz`), `33,617,727,488` B RAM (`~31.31 GiB`), `Microsoft Windows 11 Home Single Language` (`10.0.26200`)
- **Embedding Önbelleği & Tohum:** `DualEmbedder` (FP32 `BGESmallENV15` + INT8 `BGESmallENV15Q`, `DEFAULT_QUERY_MAX_TOKENS=64`, `DEFAULT_MAX_VECTOR_QUERY_BYTES=200`, `DEFAULT_MAX_BM25_QUERY_BYTES=4096`, `DEFAULT_MAX_BM25_TERMS=32`) salt okunur yerel önbellekten (`%LOCALAPPDATA%\s-recall\fastembed_cache`) ağ erişimi olmadan yüklendi (`init_ms = 569.3 ms`). Sentetik tohum: `0x53524543414C4C32`.
- **Boşta Kanıtı (`benchmarks/results/2026-11-21/idle_checks.log`):**
  - `PRE_CORE_GUARD_SEARCH` (`11:51:05Z`): `active_build_or_app_procs=0`, `cpu_load_pct=1` → `POST_CORE_GUARD_SEARCH` (`11:51:32Z`): `active=0`, `cpu_load_pct=4`
  - `PRE_DUAL_EMBEDDER` (`11:52:19Z`): `active_build_or_app_procs=0`, `cpu_load_pct=0` → `POST_DUAL_EMBEDDER` (`11:54:23Z`): `active=0`, `cpu_load_pct=3`
  - `PRE_OVERLAY_MEMORY_V011` (`11:54:26Z`): `active_build_or_app_procs=0`, `cpu_load_pct=0` → `POST_OVERLAY_MEMORY_V011` (`11:55:02Z`): `active=0`, `cpu_load_pct=3`
- **Çalıştırılan Tek Satır Komutlar:**
  - `cargo run --manifest-path benchmarks/Cargo.toml --release --offline -- --out-dir benchmarks\results\2026-11-21`
  - `cargo run --manifest-path benchmarks/Cargo.toml --release --features fastembed --offline -- --only dual --out-dir benchmarks\results\2026-11-21`
  - `powershell -ExecutionPolicy Bypass -File benchmarks\measure_overlay_memory.ps1 -WaitSeconds 10 -SearchCount 20 -Tag release_v011 -OutDir benchmarks\results\2026-11-21`
- **Ham Çıktı Dosyaları:**
  - `benchmarks/results/2026-11-21/summary_core.json`, `summary_core.txt`, `raw_samples_core.csv`
  - `benchmarks/results/2026-11-21/summary_dual.json`, `summary_dual.txt`, `raw_samples_dual.csv`
  - `benchmarks/results/2026-11-21/overlay_memory_release_v011.json`, `overlay_memory_release_v011.txt`
  - `benchmarks/results/2026-11-21/idle_checks.log`

---

### 1. Tekil Sorgu Gömme FP32 — Uzunluk & Türkçe Eğrisi (`DualEmbedder::embed_one`, `DEFAULT_QUERY_MAX_TOKENS = 64`)

Hedef SLA (`AGENT_CONTRACTS.md`): **`p95 < 20.0 ms`**. (`dual_fp32_embed_one_4kb_guarded` çağrıda `s_core::truncate_query_prefix(q, DEFAULT_MAX_VECTOR_QUERY_BYTES)` [`200 B`] uygulayarak zamanlar; diğer satırlar doğrudan `embed_one(q)` ölçümüdür.)

| Senaryo | Ort. Girdi (B / char) | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) | SLA (`p95 < 20 ms`) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `dual_fp32_embed_one_query_64b` | 60 / 60 | 20 | 300 | 8.88 | 11.76 | 13.64 | 6.53 | 16.13 | 9.11 | **PASS** |
| `dual_fp32_embed_one_short_200b` | 195 / 195 | 20 | 300 | 17.02 | 19.15 | 19.88 | 14.47 | 22.23 | 17.11 | **PASS** |
| `dual_fp32_embed_one_4kb_guarded` | 4091 → 196 eff B | 20 | 300 | 17.29 | 19.39 | 20.14 | 14.51 | 23.35 | 17.40 | **PASS** (`-77.98%` vs v0.1.0 4KB) |
| `dual_fp32_embed_one_query_256b` | 252 / 252 | 20 | 300 | 19.16 | 21.23 | 21.67 | 15.98 | 23.05 | 19.18 | **FAIL** (`>= 20 ms`) |
| `dual_fp32_embed_one_tr_256b` | 250 / 217 (TR UTF-8) | 20 | 300 | 20.82 | 22.10 | 24.27 | 19.44 | 27.23 | 20.94 | **FAIL** (`>= 20 ms`) |
| `dual_fp32_embed_one_query_512b` | 507 / 507 | 20 | 300 | 20.83 | 22.15 | 24.58 | 19.42 | 25.89 | 20.93 | **FAIL** (`>= 20 ms`) |
| `dual_fp32_embed_one_medium_4kb` | 4091 / 4091 (64 tok tavanı) | 10 | 300 | 21.98 | 23.35 | 24.97 | 20.54 | 27.32 | 22.08 | **FAIL** (`>= 20 ms`) |

- **Gözlem:** `DEFAULT_QUERY_MAX_TOKENS=64` tek başına 4 KB girdinin `p95` gecikmesini `88.06 ms` → `23.35 ms` seviyesine düşürse de `20.0 ms` SLA'yı geçememektedir; `256 B` İngilizce (`21.23 ms`), `256 B` Türkçe (`22.10 ms`) ve `512 B` (`22.15 ms`) de `>= 20 ms` olduğu için `DEFAULT_MAX_VECTOR_QUERY_BYTES = 200` + `truncate_query_prefix` ön kesmesi (`19.39 ms` **PASS**) gerekliliği ampirik olarak doğrulandı.

---

### 2. Toplu İndeksleme INT8 & Uçtan Uca Hibrit Arama (`DualEmbedder`, 1000 Olay)

`dual_int8_embed_batch_*` içinde toplu indeksleme oturumu `512` token penceresinde tutulur. `dual_e2e_1k_*` ısınma turunda `hybrid_search_detailed` ile `semantic_used=true` ve `query_truncated` (`kısa=false`, `4kb=true`) doğrulandı (`open_encrypted`: geçici dizin, sentetik 256-bit anahtar, `open_ms=50.1`, `db_bytes=2,248,704`).

| Senaryo | Mod / Boyut | Ingest (ms) | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) | Hedef |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `dual_int8_embed_batch_16x200b` | `16 × ≈200 B` INT8 | – | 10 | 100 | 126.44 | 133.21 | 136.12 | 117.23 | 137.20 | 126.23 | – |
| `dual_int8_embed_batch_64x200b` | `64 × ≈200 B` INT8 | – | 5 | 50 | 565.80 | 584.50 | 615.80 | 528.22 | 615.80 | 564.49 | – |
| `dual_e2e_1k_in_memory` | `in_memory`, `avg=25 B` | 6373.7 | 15 | 100 | 12.31 | 14.74 | 14.98 | 10.63 | 15.75 | 12.50 | – |
| `dual_e2e_1k_in_memory_long_4kb` | `in_memory`, `avg=4091 B` | 6373.7 | 15 | 100 | 26.25 | 29.60 | 30.66 | 22.52 | 30.78 | 26.45 | **FAIL** (`p95 > 25 ms`) |
| `dual_e2e_1k_encrypted` | `open_encrypted`, `avg=25 B` | 6971.2 | 15 | 100 | 44.42 | 54.15 | 57.77 | 37.87 | 63.46 | 45.57 | – |
| `dual_e2e_1k_encrypted_long_4kb` | `open_encrypted`, `avg=4091 B` | 6971.2 | 15 | 100 | 89.20 | 95.55 | 100.68 | 83.49 | 105.44 | 89.98 | **FAIL** (`p95 > 45 ms`) |

---

### 3. `s_guard::process` & `s_core::MemoryStore::hybrid_search` (4 KB Uzun BM25 Dahil)

`hybrid_search` ölçümleri `DeterministicBenchEmbedder` (`baseline p50=0.60 µs, p95=0.70 µs, p99=0.70 µs`) ile yürütüldü; v0.1.1'de eklenen `hybrid_search_10k_bm25_long_4kb`, `10,000` olaylı BM25-only depoda `32` tekil terime bölünen ~4 KB (`avg_query_bytes=4092`) FTS5 OR sorgusunu ölçer.

| Senaryo | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) | Not / Hedef |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `s_guard_short_200b_no_pii` | 100 | 1000 | 65.90 | 75.20 | 122.70 | 61.60 | 345.70 | 68.29 | `avg=195 B, red=0.0` |
| `s_guard_short_200b_pii_heavy` | 100 | 1000 | 88.00 | 112.30 | 274.40 | 66.90 | 5068.60 | 97.95 | `avg=188 B, red=5.7` |
| `s_guard_typical_1kb_no_pii` | 100 | 1000 | 142.90 | 236.40 | 391.20 | 131.50 | 1565.10 | 158.06 | `avg=1019 B, red=0.0` |
| `s_guard_typical_1kb_pii_heavy` | 100 | 1000 | 310.60 | 537.70 | 662.50 | 222.70 | 762.20 | 346.52 | `avg=1010 B, red=30.9` |
| `s_guard_medium_4kb_no_pii` | 50 | 500 | 420.50 | 714.40 | 756.60 | 400.00 | 1077.60 | 466.77 | `avg=4091 B, red=0.0` |
| `s_guard_medium_4kb_pii_heavy` | 50 | 500 | 1089.30 | 1527.00 | 1753.80 | 968.20 | 3473.40 | 1162.22 | `avg=4082 B, red=125.3` |
| `s_guard_long_64kb_no_pii` | 20 | 200 | 6791.10 | 10356.60 | 12803.00 | 6139.90 | 13175.30 | 7429.02 | `avg=65532 B, red=0.0` |
| `s_guard_long_64kb_pii_heavy` | 20 | 200 | 40105.10 | 47085.00 | 58201.50 | 34886.30 | 94031.70 | 40976.79 | `avg=65522 B, red=2007.5` |
| `s_guard_dropped_blacklisted_200b` | 100 | 1000 | 43.50 | 69.10 | 78.20 | 30.80 | 159.50 | 46.54 | `DROP` |
| `synthetic_query_embedder_baseline` | 50 | 500 | 0.60 | 0.70 | 0.70 | 0.50 | 0.70 | 0.61 | `embed_one` tabanı |
| `hybrid_search_1k_bm25_only` | 30 | 300 | 1256.00 | 2015.90 | 2527.10 | 721.90 | 2755.70 | 1337.65 | `events=1000, ingest=76.2 ms` |
| `hybrid_search_1k_vector_hybrid` | 30 | 300 | 2287.20 | 2873.60 | 3245.60 | 1679.60 | 3331.50 | 2344.11 | `events=1000, ingest=113.6 ms` |
| `hybrid_search_10k_bm25_only` | 20 | 200 | 2566.40 | 3729.50 | 5478.30 | 1087.40 | 46206.80 | 2812.74 | `events=10000, avg_q=25 B` |
| `hybrid_search_10k_vector_hybrid` | 20 | 200 | 10372.30 | 12713.10 | 13600.30 | 8783.40 | 14629.90 | 10635.33 | `events=10000, avg_q=25 B` |
| `hybrid_search_10k_bm25_long_4kb` | 20 | 200 | **18008.30** (`18.01 ms`) | **24816.50** (`24.82 ms`) | **27728.00** (`27.73 ms`) | 15730.40 | 28061.10 | 18727.11 | **FAIL** (`p95 > 5 ms`, `avg_q=4092 B`) |

---

### 4. Release Overlay `'20 arama'` Doğrulaması & Bellek (`synapse-mind.exe` — `fastembed` Etkin)

- **İzolasyon & Gerçek Veri Koruma Kanıtı:**
  - `LOCALAPPDATA` ve `WEBVIEW2_USER_DATA_FOLDER` geçici `Temp\synapse-mind-bench-appdata-870c524d90d2493399ab9bc2081949c4` klasörüne yönlendirildi; `FASTEMBED_CACHE_DIR` salt okunur önbelleğe (`%LOCALAPPDATA%\s-recall\fastembed_cache`) bağlandı.
  - İzole veri üretimi: `isolated_db_present=True` (`SynapseMind\memory.db` `86,016` B), `isolated_key_present=True` (`SynapseMind\key.bin` `262` B).
  - Gerçek kullanıcı verisi (`%LOCALAPPDATA%\SynapseMind`): **`real_user_data_untouched=True`** (`key.bin` `262` B `2026-11-20T09:08:12Z`, `memory.db` `49,725,440` B `2026-11-20T20:48:38Z` koşu öncesi/sonrası değişmedi).
- **20 Arama Uygulamaya Ulaşma Kanıtı (`search_verify_passed=True`):**
  - Gönderim yolu: `search_method=post_message_render_hwnd`, `queries_dispatched=20/20`.
  - UIA arama kutusu doğrulaması (`#search-input` `ValuePattern == query`): **`queries_input_matched=20/20`**.
  - UIA durum metni doğrulaması (`#status-text` `"Hazır"` → `"0 sonuç"`, gözlem aralıkları `231.4–417.5 ms`): **`queries_verified_in_app=20/20`**.
  - Rust host CPU artışı (`after_10s` → `after_20_searches`): **`host_cpu_delta_search_ms = 812.50 ms`** (`953.12 ms → 1765.62 ms`; v0.1.0 Sprint 4b'de `0.00 ms` idi).
  - Hafıza Paneli (`panel_trigger=uia_button_invoke_render`, `panel_found=True`, `panel_visible=True`) içinde `SearchLatencyTracker` göstergesi (`#kpi-last-search`): **`panel_last_search_text = "0.4 ms"`** (`panel_last_search_confirmed=True`).
  - Tepsi ve Stderr: `tray_evidence_status=process_tray_window` (`top|cls=tray_icon_app|title=|vis=False`), `stderr`: `WDA_EXCLUDEFROMCAPTURE` + `Mica`.

| Süreç / Rol | Aşama | Adet | PID | Working Set (MB) | Private Memory (MB) | CPU (ms) | Hedef (`< 50 MB`) |
|---|---|---:|---:|---:|---:|---:|---|
| `synapse-mind.exe` (`rust_core_daemon`) | `10 sn` sonrası | 1 | `121428` | **273.63** | **241.83** | 953.12 | **FAIL** (`fastembed` FP32+INT8 yüklü) |
| `synapse-mind.exe` (`rust_core_daemon`) | `20` arama sonrası | 1 | `121428` | **275.58** | **242.13** | 1765.62 | **FAIL** (`fastembed` FP32+INT8 yüklü) |
| `synapse-mind.exe` (`rust_core_daemon`) | Hafıza Paneli açık | 1 | `121428` | **279.70** | **246.03** | 1828.12 | **FAIL** (`fastembed` FP32+INT8 yüklü) |
| `synapse-mind.exe` (`uia_worker`) | `10 sn` / `20` arama / Panel | 1 | `93428` | 18.25 / 18.25 / 18.20 | 3.32 / 3.32 / 3.22 | 15.62 | Hedef dışı |
| `msedgewebview2.exe` toplamı | `10 sn` / `20` arama / Panel | 6 / 6 / 7 | – | 386.96 / 413.11 / 596.74 | 185.78 / 199.86 / 337.05 | – | Hedef dışı |
| **Birleşik Süreç Ağacı (`Total`)** | `10 sn` / `20` arama / Panel | 8 / 8 / 9 | – | **678.85 / 706.94 / 894.64** | **430.93 / 445.32 / 586.31** | – | Bilgilendirme |

> **Bellek Farkı Notu:** v0.1.0 Sprint 4b ikilisi (`17.07 MiB`, `DevHashEmbedder`) ana süreçte `36.98–43.48 MB` WS ile `< 50 MB` hedefini **PASS** ediyordu; v0.1.1 yayın ikilisi (`45.3 MB`, `--features fastembed`) başlatma sırasında FP32 + INT8 `DualEmbedder` modellerini işlem içine yüklediği için Rust Core Daemon Working Set'i `273.63–279.70 MB` (`Private 241.83–246.03 MB`) seviyesine çıkmakta ve `< 50 MB` hedefini **FAIL** etmektedir.
>
> **Güncelleme (kullanıcı kararı, 21.11.2026; orkestratör ölçümü):** uygulama tek FP32 oturum + ORT CPU arenası kapalı + boşta model boşaltma + çalışma kümesi iadesi kullanır. Deterministik ölçüm: `fastembed,gate2-hooks` yayın derlemesi, izole LOCALAPPDATA, `--gate2-pause-capture --gate2-idle-unload-secs=60`, 15 sn aralıklı ana süreç örnekleri (tek koşu, p50/p95 değil):
>
> | Evre | Working Set (MB) | Private (MB) | Hedef |
> |---|---:|---:|---|
> | Model yüklenmeden önce (t+15–60 s) | 49,0–49,1 | 18,3–18,5 | |
> | Model yüklü (t+75–120 s) | 207,5 | 169,5–169,6 | ~200 MB altı: sınırda |
> | Boşaltma sonrası (t+135 s) | 68,7 | 31,6 | |
> | Çalışma kümesi iadesi sonrası (t+150–210 s) | 1,6–4,3 | 31,6 | boşta < 50 MB: **PASS** |
>
> Gerçek masaüstünde yapılan iki 11–13 dk'lık ölçüm geçersizdir: yakalanan pencere olayları boşta sayacını sıfırladı. Betik: `idle_unload_det.ps1` (`komutlar.txt`).

---

## Sprint 4b Yeniden Ölçüm (gömülü arayüz, v0.1.0) — 2026-11-20

### Ortam, Git Durumu ve Boşta Kanıtı
- **Tarih (UTC / Yerel):** `2026-11-20` (`05:28Z` / `08:28+03:00`)
- **Temel Git Commit:** `8965907` (`git status --short`: `25` değiştirilmiş `M`, `1` izlenmeyen `??` girdi)
- **İkili:** `src-tauri/target/release/synapse-mind.exe` (`17,697,280` B, `20.11.2026 08:27:22`; `default = ["custom-protocol"]`, `tray-icon` + `image-png`, `s-sensor` öz süreç dışlama, `open_encrypted` + DPAPI `key.bin` + `DevHashEmbedder` + `uia-worker`)
- **CPU / RAM / İşletim Sistemi:** `AMD Ryzen 7 8845HS w/ Radeon 780M Graphics` (8C/16T, `3801 MHz`), `33,617,727,488` B RAM (`~31.31 GiB`), `Microsoft Windows 11 Home Single Language` (`10.0.26200`)
- **Boşta Kanıtı (`benchmarks/results/2026-11-20/idle_checks.log`):**
  - `PRE_SPRINT4B_CLEAN` (`2026-11-20T05:28:11.1011635Z`): `active_build_or_app_procs=0 ()`, `cpu_load_pct=8`
  - `POST_SPRINT4B_CLEAN` (`2026-11-20T05:28:41.8061249Z`): `active_build_or_app_procs=0 ()`, `cpu_load_pct=1`
- **Çalıştırılan Tek Satır Komut:**
  `powershell -ExecutionPolicy Bypass -File benchmarks\measure_overlay_memory.ps1 -WaitSeconds 10 -SearchCount 20 -Tag release_sprint4b`
- **Ham Çıktı Dosyaları:**
  - `benchmarks/results/2026-11-20/overlay_memory_release_sprint4b.json`
  - `benchmarks/results/2026-11-20/overlay_memory_release_sprint4b.txt`
  - `benchmarks/results/2026-11-20/idle_checks.log`
- **İzolasyon & Doğrulama:** `LOCALAPPDATA` ve `WEBVIEW2_USER_DATA_FOLDER` geçici `Temp\synapse-mind-bench-appdata-008dad568f4f404598c68c8ca7de5323` klasörüne yönlendirildi; kullanıcının gerçek `%LOCALAPPDATA%\SynapseMind` klasörüne dokunulmadı (`key.bin` `262` B `19.11.2026 15:10:49`, `memory.db` `11,333,632` B `20.11.2026 08:24:19` koşu öncesi ve sonrası birebir aynı).
- **Aşama Tetikleme & Sistem Tepsisi Kanıtı:**
  - Overlay penceresi bulundu (`overlay_found=True`, başlangıç `visible_before=False`, `Alt+Space` sonrası `opened_via_alt_space=False`, etkinleştirme sonrası `visible_after=True`).
  - `20/20` arama `Chrome_RenderWidgetHostHWND` üzerinden gönderildi (`search_method=post_message_render_hwnd`, `queries_dispatched=20/20`).
  - Hafıza Paneli (`"Synapse Mind · Hafıza Paneli"`) UIA düğme tetiklemesiyle açıldı (`panel_trigger=uia_button_invoke_overlay`, `panel_found=True`, `panel_visible=True`).
  - **Tepsi simgesi kanıtı:** `Shell_NotifyIcon` doğrudan okunamadığından (`shell_tray_hits` boş) süreç pencereleri tarandı; ana süreç (`PID 118024`) altında `tray_icon_app` penceresi (`top|cls=tray_icon_app|title=|vis=False`, `tray_evidence_status=process_tray_window`) doğrulandı.

### 1. Rust Core Daemon (`synapse-mind.exe` Ana Süreç — Hedef `< 50 MB`)

| Aşama | PID | Working Set (MB) | Private Memory (MB) | CPU (ms) | Hedef (`< 50 MB`) |
|---|---:|---:|---:|---:|---|
| `10 sn` sonrası | `118024` | 36.98 | 13.49 | 562.50 | **PASS** (WS & Private) |
| `20` arama sonrası | `118024` | 37.26 | 13.66 | 562.50 | **PASS** (WS & Private) |
| Hafıza Paneli açık | `118024` | 43.48 | 18.68 | 703.12 | **PASS** (WS & Private) |

### 2. UIA İşçi Alt Süreci (`< 50 MB` Hedefi Dışı, Raporlanan)

| Süreç / Rol | Aşama | Adet | PID | Working Set (MB) | Private Memory (MB) |
|---|---|---:|---:|---:|---:|
| `synapse-mind.exe` (`uia_worker`) | `10 sn` sonrası | 1 | `109288` | 15.80 | 2.07 |
| `synapse-mind.exe` (`uia_worker`) | `20` arama sonrası | 1 | `109288` | 15.80 | 2.07 |
| `synapse-mind.exe` (`uia_worker`) | Hafıza Paneli açık | 1 | `109288` | 15.80 | 2.07 |

### 3. WebView2 Alt Süreçleri (`< 50 MB` Hedefi Dışı, Raporlanan)

| Süreç / Rol | Aşama | Adet | PID | Working Set (MB) | Private Memory (MB) |
|---|---|---:|---:|---:|---:|
| `msedgewebview2.exe` (`webview2_main`) | `10 sn` sonrası | 1 | `120436` | 132.49 | 38.41 |
| `msedgewebview2.exe` (`gpu-process`) | `10 sn` sonrası | 1 | `94328` | 118.62 | 103.69 |
| `msedgewebview2.exe` (`renderer`) | `10 sn` sonrası | 1 | `110220` | 56.00 | 21.95 |
| `msedgewebview2.exe` (`NetworkService`) | `10 sn` sonrası | 1 | `108364` | 38.13 | 11.61 |
| `msedgewebview2.exe` (`StorageService`) | `10 sn` sonrası | 1 | `50956` | 19.52 | 7.28 |
| `msedgewebview2.exe` (`crashpad-handler`) | `10 sn` sonrası | 1 | `117580` | 10.12 | 2.61 |
| **WebView2 Alt Toplamı (`10 sn`)** | `10 sn` sonrası | **6** | – | **374.88** | **185.55** |
| `msedgewebview2.exe` (`webview2_main`) | `20` arama sonrası | 1 | `120436` | 133.91 | 38.57 |
| `msedgewebview2.exe` (`gpu-process`) | `20` arama sonrası | 1 | `94328` | 121.48 | 103.70 |
| `msedgewebview2.exe` (`renderer`) | `20` arama sonrası | 1 | `110220` | 63.90 | 27.27 |
| `msedgewebview2.exe` (`NetworkService`) | `20` arama sonrası | 1 | `108364` | 38.14 | 11.61 |
| `msedgewebview2.exe` (`StorageService`) | `20` arama sonrası | 1 | `50956` | 19.52 | 7.28 |
| `msedgewebview2.exe` (`crashpad-handler`) | `20` arama sonrası | 1 | `117580` | 10.12 | 2.61 |
| **WebView2 Alt Toplamı (`20` arama)** | `20` arama sonrası | **6** | – | **387.09** | **191.04** |
| `msedgewebview2.exe` (`webview2_main`) | Hafıza Paneli açık | 1 | `120436` | 142.31 | 44.93 |
| `msedgewebview2.exe` (`gpu-process`) | Hafıza Paneli açık | 1 | `94328` | 256.95 | 243.28 |
| `msedgewebview2.exe` (`renderer` #1) | Hafıza Paneli açık | 1 | `110220` | 65.29 | 28.48 |
| `msedgewebview2.exe` (`renderer` #2) | Hafıza Paneli açık | 1 | `120180` | 70.21 | 32.84 |
| `msedgewebview2.exe` (`NetworkService`) | Hafıza Paneli açık | 1 | `108364` | 38.26 | 11.70 |
| `msedgewebview2.exe` (`StorageService`) | Hafıza Paneli açık | 1 | `50956` | 19.56 | 7.30 |
| `msedgewebview2.exe` (`crashpad-handler`) | Hafıza Paneli açık | 1 | `117580` | 10.12 | 2.61 |
| **WebView2 Alt Toplamı (Hafıza Paneli)** | Hafıza Paneli açık | **7** | – | **602.69** | **371.14** |

### Metodoloji ve Sınırlar (Sprint 4b)
- Flamegraph profillemesi yapılmadığından herhangi bir darboğaz veya optimizasyon yorumu eklenmemiştir (`.agents/rules/optimization_and_latency_tracking.md`).
- Tüm değerler gerçek komut çıktılarından alınmıştır (`.agents/rules/no_mock_data.md`).

---

## Sprint 4 Temiz Ölçüm (v0.1.0) — 2026-11-20

### Ortam, Git Durumu ve Boşta Kanıtı
- **Tarih (UTC / Yerel):** `2026-11-20` (`00:52Z–01:00Z` / `03:52–04:00+03:00`)
- **Temel Git Commit:** `ce30f4249eda2abb7875f639c5488670f9ad3aa5` (`ce30f42`)
- **`git status --short` Özeti:** `77` değiştirilmiş (`M`), `31` izlenmeyen (`??`) girdi (Gate 2 PASS sonrası temizlenmiş ağaç: `s-core::DualEmbedder`, `s-guard` her değerlendirmede 192 KiB `wipe_stack()`, `s-sensor` tek atımlık `uia_worker`, `src-tauri` UIA kancası + Hafıza Paneli, `tests/security` Gate 2 ikilileri, `benchmarks` Sprint 4 eklemeleri).
- **Derleyici / Araç Zinciri:** `rustc 1.95.0 (59807616e 2026-04-14)`, `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- **Build Profili:** `--release` (`lto = "thin"`, `codegen-units = 1`, kök `Cargo.toml` ile birebir)
- **Workspace Kilidi (ADR-004):** `Compare-Object (cargo tree -p s-guard -p s-core --offline) (cargo tree --manifest-path benchmarks/Cargo.toml -p s-guard -p s-core --offline)` → **0 fark**
- **CPU:** `AMD Ryzen 7 8845HS w/ Radeon 780M Graphics` (8 fiziksel çekirdek, 16 mantıksal işlemci, maks. saat `3801 MHz`)
- **RAM:** `33,617,727,488` bayt (`~31.31 GiB`)
- **GPU (sistem bilgisi):** `AMD Radeon 780M Graphics`, `NVIDIA GeForce RTX 4060 Laptop GPU` (embedding ölçümleri CPU üzerinde çalıştırıldı)
- **İşletim Sistemi:** `Microsoft Windows 11 Home Single Language` (`10.0.26200`)
- **Sentetik Veri Tohumu:** `0x53524543414C4C32` (`SplitMix64`, deterministik ve tekrarlanabilir)
- **Boşta Kanıtı (`benchmarks/results/2026-11-20/idle_checks.log`):** Her senaryo öncesi ve sonrasında `cargo, rustc, cl, link, perl, nmake, gate2-*, synapse-mind` süreçleri sorgulandı:
  - `PRE_CORE_GUARD_SEARCH` (`00:52:05Z`): `active_build_or_app_procs=0`, `cpu_load_pct=3` → `POST_CORE_GUARD_SEARCH` (`00:52:27Z`): `active=0`, `cpu_load_pct=0`
  - `PRE_DUAL_EMBEDDER` (`00:52:58Z`): `active_build_or_app_procs=0`, `cpu_load_pct=0` → `POST_DUAL_EMBEDDER` (`00:54:27Z`): `active=0`, `cpu_load_pct=0`
  - `PRE_GATE2_UIA_LATENCY` (`00:54:39Z`): `active_build_or_app_procs=0`, `cpu_load_pct=1` → `POST_GATE2_UIA_LATENCY` (`00:54:51Z`): `active=0`, `cpu_load_pct=1`
  - `PRE_OVERLAY_UIA_WORKER` (`00:54:52Z`): `active_build_or_app_procs=0`, `cpu_load_pct=2` → `POST_OVERLAY_UIA_WORKER` (`00:54:56Z`): `active=0`, `cpu_load_pct=0`
  - `PRE_OVERLAY_MEMORY_FINAL` (`00:59:48Z`): `active_build_or_app_procs=0`, `cpu_load_pct=1` → `POST_OVERLAY_MEMORY_FINAL` (`01:00:10Z`): `active=0`, `cpu_load_pct=3`

### Çalıştırılan Tek Satır Komutlar
- `s_guard::process` + `s_core::MemoryStore::hybrid_search` (`1k` & `10k`):
  `cargo run --manifest-path benchmarks/Cargo.toml --release --offline -- --out-dir benchmarks/results/2026-11-20`
- `DualEmbedder` (FP32 tekil ≥300 örnek, INT8 16×200 B / 64×200 B toplu, 1000 olay bellek içi & `open_encrypted` E2E):
  `cargo run --manifest-path benchmarks/Cargo.toml --release --features fastembed --offline -- --only dual --out-dir benchmarks/results/2026-11-20`
- UIA işçi gecikmesi (`tests/security` içinde):
  `cargo build --release --bins --features encrypted,uia-worker`
  `..\..\target\release\gate2-uia-latency --samples 60`
- Gerçek release `synapse-mind.exe` UIA işçi başlatma / el sıkışma (`--s-sensor-uia-worker`):
  `.\benchmarks\target\release\s-bench.exe --only uia-overlay --out-dir benchmarks/results/2026-11-20`
- İzole `LOCALAPPDATA` ile release overlay bellek ölçümü (`10 sn` ve `20` arama sonrası):
  `powershell -ExecutionPolicy Bypass -File benchmarks\measure_overlay_memory.ps1 -WaitSeconds 10 -SearchCount 20 -OutDir benchmarks\results\2026-11-20`

### Ham Çıktı Dosyaları (`benchmarks/results/2026-11-20/`)
- `benchmarks/results/2026-11-20/summary_core.json`, `summary_core.txt`, `raw_samples_core.csv`
- `benchmarks/results/2026-11-20/summary_dual.json`, `summary_dual.txt`, `raw_samples_dual.csv`
- `benchmarks/results/2026-11-20/gate2_uia_latency.txt`
- `benchmarks/results/2026-11-20/summary_uia-overlay.json`, `summary_uia-overlay.txt`, `raw_samples_uia-overlay.csv`
- `benchmarks/results/2026-11-20/overlay_memory_release_sprint4.json`, `overlay_memory_release_sprint4.txt`
- `benchmarks/results/2026-11-20/idle_checks.log`

---

### 1. Tekil Sorgu Gömme FP32 (`DualEmbedder::embed_one` — `BGESmallENV15`, Release ONNX CPU)

`DualEmbedder::try_new_default()` toplam başlatma süresi (`init_ms`): `555.3 ms` (FP32 + INT8 modelleri birlikte önbellekten yüklendi). SLA hedefi: `p95 < 20 ms`.

| Senaryo | Girdi | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) | SLA (`p95 < 20 ms`) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `dual_fp32_embed_one_short_200b` | 1 × ≈200 B | 20 | 300 | 16.25 | 18.06 | 19.26 | 14.50 | 21.04 | 16.35 | **PASS** |
| `dual_fp32_embed_one_medium_4kb` | 1 × ≈4 KB | 10 | 300 | 84.16 | 88.06 | 89.53 | 78.94 | 102.55 | 84.44 | **FAIL** |

---

### 2. Toplu İndeksleme INT8 (`DualEmbedder::embed_batch` — `BGESmallENV15Q`, Release ONNX CPU)

| Senaryo | Batch Boyutu | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `dual_int8_embed_batch_16x200b` | 16 × ≈200 B | 10 | 100 | 98.68 | 103.23 | 103.79 | 94.97 | 106.41 | 98.91 |
| `dual_int8_embed_batch_64x200b` | 64 × ≈200 B | 5 | 50 | 455.89 | 464.80 | 486.00 | 447.61 | 486.00 | 456.50 |

---

### 3. Uçtan Uca (`DualEmbedder`: 1000 Olay Ingest INT8 + FP32 Sorgu + `hybrid_search` `k = 10`)

`open_encrypted` senaryosu geçici dizinde (`std::env::temp_dir()`) deterministik sentetik 256-bit anahtarla çalıştırıldı (`open_ms = 33.5 ms`, `db_bytes = 2,248,704`).

| Senaryo | Depo Modu | Olay / Kenar | Ingest (ms) | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `dual_e2e_1k_in_memory` | `open_in_memory` | 1000 / 900 | 5584.2 | 15 | 100 | 12.82 | 13.98 | 16.58 | 12.01 | 16.91 | 12.94 |
| `dual_e2e_1k_encrypted` | `open_encrypted` | 1000 / 900 | 6084.0 | 15 | 100 | 34.99 | 39.94 | 41.14 | 30.41 | 41.45 | 35.18 |

---

### 4. `s_guard::process` (192 KiB Yığın Silme Dahil) & `hybrid_search` (`1k` / `10k`)

#### 4a. `s_guard::process` Gecikmesi (Sprint 4 — Gate 2 192 KiB `wipe_stack()` Sonrası)

| Senaryo | Ort. Girdi (B) | Ort. Maskeleme | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `s_guard_short_200b_no_pii` | 195 | 0.0 | 100 | 1000 | 67.70 | 131.60 | 189.00 | 61.90 | 516.20 | 81.54 |
| `s_guard_short_200b_pii_heavy` | 188 | 5.7 | 100 | 1000 | 90.00 | 171.20 | 235.80 | 66.90 | 913.40 | 103.05 |
| `s_guard_typical_1kb_no_pii` | 1019 | 0.0 | 100 | 1000 | 142.00 | 257.90 | 323.00 | 131.80 | 564.80 | 164.66 |
| `s_guard_typical_1kb_pii_heavy` | 1010 | 30.9 | 100 | 1000 | 306.00 | 534.60 | 693.90 | 221.40 | 1562.10 | 344.28 |
| `s_guard_medium_4kb_no_pii` | 4091 | 0.0 | 50 | 500 | 421.60 | 732.40 | 858.10 | 394.10 | 4865.70 | 482.69 |
| `s_guard_medium_4kb_pii_heavy` | 4082 | 125.3 | 50 | 500 | 1094.90 | 1712.60 | 2134.20 | 947.10 | 2579.10 | 1207.66 |
| `s_guard_long_64kb_no_pii` | 65532 | 0.0 | 20 | 200 | 6998.70 | 9930.40 | 11667.60 | 6231.70 | 13406.10 | 7391.26 |
| `s_guard_long_64kb_pii_heavy` | 65522 | 2007.5 | 20 | 200 | 29576.70 | 34502.20 | 38888.70 | 25433.20 | 43946.50 | 30099.41 |
| `s_guard_dropped_blacklisted_200b` | 195 | 0.0 (DROP) | 100 | 1000 | 31.10 | 51.00 | 84.40 | 30.80 | 141.20 | 34.69 |

#### 4b. `s_guard::process` Sprint 3 vs Sprint 4 Karşılaştırması (192 KiB Yığın Silme Maliyeti)

`s_guard::evaluate` her çağrıda (erken kara liste düşürmesi dahil) `wipe::wipe_stack()` (`192 KiB` yığın çerçevesini `0xA5` doldurup `zeroize` ile silme) yürütür. Tarama yapmayan kara liste erken dönüş yolu (`s_guard_dropped_blacklisted_200b`) `p50 = 31.10 µs`, `p95 = 51.00 µs` ölçülmüştür.

| Senaryo | Sprint 3 p50 (µs) | Sprint 4 p50 (µs) | Δ p50 (µs) | Sprint 3 p95 (µs) | Sprint 4 p95 (µs) | Δ p95 (µs) |
|---|---:|---:|---:|---:|---:|---:|
| `s_guard_short_200b_no_pii` | 29.60 | 67.70 | +38.10 | 48.30 | 131.60 | +83.30 |
| `s_guard_short_200b_pii_heavy` | 48.20 | 90.00 | +41.80 | 74.80 | 171.20 | +96.40 |
| `s_guard_medium_4kb_no_pii` | 298.00 | 421.60 | +123.60 | 392.20 | 732.40 | +340.20 |
| `s_guard_medium_4kb_pii_heavy` | 896.00 | 1094.90 | +198.90 | 1406.80 | 1712.60 | +305.80 |
| `s_guard_long_64kb_no_pii` | 5739.60 | 6998.70 | +1259.10 | 7883.30 | 9930.40 | +2047.10 |
| `s_guard_long_64kb_pii_heavy` | 26562.00 | 29576.70 | +3014.70 | 31039.40 | 34502.20 | +3462.80 |

#### 4c. `s_core::MemoryStore::hybrid_search` Gecikmesi (Release, In-Memory DB, `k = 10`, `DeterministicBenchEmbedder`)

| Senaryo | Olay | Vektör Satırı | Kenar | Ingest (ms) | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `synthetic_query_embedder_baseline` | – | – | – | – | 50 | 500 | 0.60 | 0.70 | 0.70 | 0.50 | 0.70 | 0.60 |
| `hybrid_search_1k_bm25_only` | 1000 | 0 | 900 | 57.0 | 30 | 300 | 871.60 | 1505.40 | 1964.80 | 677.80 | 2417.70 | 960.37 |
| `hybrid_search_1k_vector_hybrid` | 1000 | 1000 | 900 | 84.7 | 30 | 300 | 1636.40 | 2227.40 | 2945.30 | 1391.00 | 3958.70 | 1738.40 |
| `hybrid_search_10k_bm25_only` | 10000 | 0 | 9000 | 610.7 | 20 | 200 | 1755.80 | 2799.50 | 3411.90 | 980.70 | 3628.50 | 1830.48 |
| `hybrid_search_10k_vector_hybrid` | 10000 | 10000 | 9000 | 752.0 | 20 | 200 | 7995.70 | 9649.30 | 10772.40 | 6990.20 | 11277.40 | 8156.64 |

---

### 5. UIA İşçi Gecikmesi (`gate2-uia-latency` & Gerçek `synapse-mind.exe`)

- **`gate2-uia-latency --samples 60`** (hedef pencere `hwnd=0xa5099c`, ayrı süreç, `text_len=830`, `node_count=11`):
  - `InProcess (eski yol)` kurulum: `8.39 ms`
  - `Worker (tek atımlık süreç)` kurulum: `46.98 ms`
- **Gerçek `src-tauri/target/release/synapse-mind.exe --s-sensor-uia-worker`** (`3` ısınma, `60` örnek): doğrudan `--s-sensor-uia-worker` alt komutu ile süreç başlatma + COM/UIA kurulumu + `SRWR` el sıkışma ve `SRQ1(null_hwnd)` → `SRW1` tam yaşam döngüsü ölçüldü.

| Ölçüm / Yol | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| `gate2-uia-latency`: `InProcess (eski yol)` | 60 | 10.89 | 13.96 | 14.25 | 9.40 | 14.54 | 11.20 |
| `gate2-uia-latency`: `Worker (tek atımlık süreç)` | 60 | 77.28 | 97.94 | 100.42 | 68.00 | 118.07 | 79.51 |
| `gate2-uia-latency`: `Worker el sıkışma (null HWND)` | 60 | 47.89 | 67.70 | 72.20 | 42.24 | 154.21 | 51.95 |
| `synapse-mind.exe`: `overlay_uia_worker_spawn_srwr` (`spawn + COM/UIA + SRWR`) | 60 | 26.25 | 43.83 | 52.39 | 23.27 | 52.39 | 27.86 |
| `synapse-mind.exe`: `overlay_uia_worker_null_hwnd_e2e` (`spawn + SRWR + SRQ1(null) + SRW1 + exit`) | 60 | 31.22 | 48.75 | 56.59 | 27.47 | 56.59 | 32.80 |

---

### 6. Release Overlay Bellek Ölçümü (`synapse-mind.exe`, İzole `LOCALAPPDATA`)

`src-tauri/target/release/synapse-mind.exe` (`17,085,952` B; varsayılan derleme, `open_encrypted` + DPAPI `key.bin` + `DevHashEmbedder` + `uia-worker`) geçici bir `LOCALAPPDATA` (`Temp\synapse-mind-bench-appdata-*`) ve `WEBVIEW2_USER_DATA_FOLDER` ile başlatıldı; kullanıcının gerçek `%LOCALAPPDATA%\SynapseMind` klasörüne dokunulmadı (`key.bin` ve `memory.db` zaman damgaları değişmedi). `10 sn` bekleme sonrasında pencere etkinleştirilerek `Chrome_RenderWidgetHostHWND` üzerinden `20/20` arama sorgusu gönderildi (`queries_dispatched=20/20`).

#### 6a. Rust Core Daemon (`synapse-mind.exe` Ana Süreç — Hedef `< 50 MB`)

| Aşama | PID | Working Set (MB) | Private Memory (MB) | Hedef (`< 50 MB`) |
|---|---:|---:|---:|---|
| `10 sn` sonrası | `28732` | 36.06 | 13.31 | **PASS** (WS & Private) |
| `20` arama sonrası | `28732` | 36.10 | 13.31 | **PASS** (WS & Private) |

#### 6b. Alt Süreçler: UIA İşçi & WebView2 (`< 50 MB` Hedefi Dışı, Raporlanan)

> **GEÇERSİZ:** bu değerler gömülü arayüz yerine hata sayfasını yükleyen ikiliye aittir (`custom-protocol` kapalı); yeniden ölçüm: 'Sprint 4b Yeniden Ölçüm'. Rust Core Daemon (§6a) ve diğer bölümler (gömme, guard, arama, UIA işçi) arayüzden bağımsızdır, olduğu gibi kalır.

| Süreç / Rol | Aşama | Adet | PID | Working Set (MB) | Private Memory (MB) |
|---|---|---:|---:|---:|---:|
| `synapse-mind.exe` (`uia_worker`) | `10 sn` sonrası | 1 | `114144` | 15.75 | 2.06 |
| `synapse-mind.exe` (`uia_worker`) | `20` arama sonrası | 1 | `114144` | 15.75 | 2.06 |
| `msedgewebview2.exe` (`webview2_main`) | `10 sn` sonrası | 1 | `106044` | 130.58 | 38.79 |
| `msedgewebview2.exe` (`gpu-process`) | `10 sn` sonrası | 1 | `118676` | 97.25 | 93.94 |
| `msedgewebview2.exe` (`renderer`) | `10 sn` sonrası | 1 | `94404` | 57.07 | 24.81 |
| `msedgewebview2.exe` (`NetworkService`) | `10 sn` sonrası | 1 | `88500` | 38.45 | 11.74 |
| `msedgewebview2.exe` (`StorageService`) | `10 sn` sonrası | 1 | `118208` | 19.02 | 7.14 |
| `msedgewebview2.exe` (`crashpad-handler`) | `10 sn` sonrası | 1 | `110640` | 10.12 | 2.65 |
| **WebView2 Alt Toplamı (`10 sn`)** | `10 sn` sonrası | **6** | – | **352.49** | **179.07** |
| `msedgewebview2.exe` (`webview2_main`) | `20` arama sonrası | 1 | `106044` | 131.12 | 38.77 |
| `msedgewebview2.exe` (`gpu-process`) | `20` arama sonrası | 1 | `118676` | 97.24 | 86.91 |
| `msedgewebview2.exe` (`renderer`) | `20` arama sonrası | 1 | `94404` | 59.29 | 25.75 |
| `msedgewebview2.exe` (`NetworkService`) | `20` arama sonrası | 1 | `88500` | 38.48 | 11.73 |
| `msedgewebview2.exe` (`StorageService`) | `20` arama sonrası | 1 | `118208` | 19.02 | 7.14 |
| `msedgewebview2.exe` (`crashpad-handler`) | `20` arama sonrası | 1 | `110640` | 10.12 | 2.65 |
| **WebView2 Alt Toplamı (`20` arama)** | `20` arama sonrası | **6** | – | **355.27** | **172.96** |

### Metodoloji ve Sınırlar (Sprint 4)
- Bu koşuda flamegraph profillemesi yapılmadığından herhangi bir darboğaz iddiası veya `unsafe`/C optimizasyon önerisi eklenmemiştir (`.agents/rules/optimization_and_latency_tracking.md`).
- Tüm değerler gerçek komut çıktılarından alınmıştır (`.agents/rules/no_mock_data.md`).

---

## Sprint 3 İlk Resmi Release Ölçümleri — 2026-11-19

### Ortam ve Donanım Bilgisi
- **Tarih (UTC / Yerel):** `2026-11-19`
- **Temel Git Commit:** `ce30f42` (çalışma ağacında Sprint 3 uncommitted değişiklikleri mevcut: `s-guard` R1 güncellemeleri, `s-core` `bundled-sqlcipher-vendored-openssl`, `src-tauri` Faz 4 kablolaması + tek örnek kilidi + DPAPI anahtar akışı, `benchmarks` Sprint 3 eklemeleri)
- **Derleyici / Araç Zinciri:** `rustc 1.95.0 (59807616e 2026-04-14)`, `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- **Build Profili:** `--release` (`lto = "thin"`, `codegen-units = 1`, kök `Cargo.toml` ile birebir)
- **Workspace Kilidi (ADR-004):** `Compare-Object (cargo tree -p s-guard -p s-core --offline) (cargo tree --manifest-path benchmarks/Cargo.toml -p s-guard -p s-core --offline)` → **0 fark**
- **CPU:** `AMD Ryzen 7 8845HS w/ Radeon 780M Graphics` (8 fiziksel çekirdek, 16 mantıksal işlemci, maks. saat `3801 MHz`)
- **RAM:** `33,617,727,488` bayt (`~31.31 GiB`)
- **GPU (sistem bilgisi):** `AMD Radeon 780M Graphics`, `NVIDIA GeForce RTX 4060 Laptop GPU` (embedding ölçümleri CPU üzerinde çalıştırıldı)
- **İşletim Sistemi:** `Microsoft Windows 11 Home Single Language` (`10.0.26200`)
- **Sentetik Veri Tohumu:** `0x53524543414C4C32` (`SplitMix64`, deterministik ve tekrarlanabilir)

### Çalıştırılan Tek Satır Komutlar
- Çekirdek (`s_guard::process` + `s_core::MemoryStore::hybrid_search`):
  `cargo run --manifest-path benchmarks/Cargo.toml --release --offline`
- `fastembed` FP32 vs INT8 (`BGESmallENV15` vs `BGESmallENV15Q`, ONNX CPU):
  `cargo run --manifest-path benchmarks/Cargo.toml --release --features fastembed --offline -- --only fastembed`
- Release overlay bellek ölçümü (`synapse-mind.exe` + WebView2):
  `powershell -ExecutionPolicy Bypass -File benchmarks\measure_overlay_memory.ps1`

### Ham Çıktı Dosyaları (`benchmarks/results/2026-11-19/`)
- `benchmarks/results/2026-11-19/summary_core.json`, `summary_core.txt`, `raw_samples_core.csv`
- `benchmarks/results/2026-11-19/summary_fastembed.json`, `summary_fastembed.txt`, `raw_samples_fastembed.csv`
- `benchmarks/results/2026-11-19/overlay_memory_release.json`, `overlay_memory_release.txt`

---

### 1. `s_guard::process` Gecikmesi (Release, Sprint 3 R1 Sonrası)

| Senaryo | Ort. Girdi (B) | Ort. Maskeleme | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `s_guard_short_200b_no_pii` | 195 | 0.0 | 100 | 1000 | 29.60 | 48.30 | 54.60 | 25.20 | 74.50 | 31.71 |
| `s_guard_short_200b_pii_heavy` | 188 | 5.7 | 100 | 1000 | 48.20 | 74.80 | 100.50 | 31.60 | 177.30 | 50.47 |
| `s_guard_medium_4kb_no_pii` | 4091 | 0.0 | 50 | 500 | 298.00 | 392.20 | 489.00 | 275.80 | 613.30 | 310.80 |
| `s_guard_medium_4kb_pii_heavy` | 4081 | 125.3 | 50 | 500 | 896.00 | 1406.80 | 1720.80 | 773.90 | 2586.30 | 987.63 |
| `s_guard_long_64kb_no_pii` | 65531 | 0.0 | 20 | 200 | 5739.60 | 7883.30 | 9160.10 | 4752.00 | 9558.30 | 6048.16 |
| `s_guard_long_64kb_pii_heavy` | 65521 | 2010.4 | 20 | 200 | 26562.00 | 31039.40 | 32172.60 | 14551.00 | 47209.30 | 26128.14 |

---

### 2. `s_core::MemoryStore::hybrid_search` Gecikmesi (Release, SQLCipher Bağlı `s-core`, In-Memory DB, `k = 10`)

`DeterministicBenchEmbedder` (sentetik 384-d birim normlu projeksiyon) ile FTS5 + `sqlite-vec` (`vec0`) + nedensellik zinciri maliyeti izole edilmiştir.

| Senaryo | Olay | Vektör Satırı | Kenar | Ingest (ms) | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `synthetic_query_embedder_baseline` | – | – | – | – | 50 | 500 | 1.10 | 1.20 | 1.30 | 1.00 | 1.30 | 1.11 |
| `hybrid_search_1k_bm25_only` | 1000 | 0 | 900 | 182.5 | 30 | 300 | 1763.80 | 2621.20 | 2864.80 | 872.10 | 3216.90 | 1846.26 |
| `hybrid_search_1k_vector_hybrid` | 1000 | 1000 | 900 | 228.6 | 30 | 300 | 3648.40 | 4820.90 | 6186.10 | 2179.60 | 19013.70 | 3695.13 |
| `hybrid_search_10k_bm25_only` | 10000 | 0 | 9000 | 1622.7 | 20 | 200 | 3530.40 | 5577.90 | 6709.60 | 1696.60 | 6874.00 | 3723.85 |
| `hybrid_search_10k_vector_hybrid` | 10000 | 10000 | 9000 | 2308.4 | 20 | 200 | 13220.30 | 16793.00 | 18282.30 | 9942.50 | 24050.20 | 13499.08 |

---

### 3. `fastembed` Karşılaştırması (`BGESmallENV15` FP32 vs `BGESmallENV15Q` INT8, Release ONNX CPU)

- **Önbellekten Başlatma (`init_ms`):** `BGESmallENV15 (FP32)` = `426.4 ms` (`onnx/model.onnx`, `133,093,490` B); `BGESmallENV15Q (INT8)` = `266.6 ms` (`model_optimized.onnx`, `66,465,124` B).
- **Vektör Benzerliği (`100` kısa metin, FP32 vs INT8):** `cos_vs_fp32_mean = 0.999999`, `cos_vs_fp32_p50 = 0.999999`, `cos_vs_fp32_min = 0.999998`, `max_elem_diff = 0.000612`.
- **Uçtan Uca (`hybrid_search_1k_e2e_bgsmall_q`):** `1000` olay `BGESmallENV15Q` ile `19,385.8 ms` sürede indekslenmiş (`900` kenar), `k = 10` gerçek ONNX sorgu gömme + FTS5 + `vec0` + nedensellik araması ölçülmüştür.

| Senaryo | Model / Mod | Girdi / Batch | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `fastembed_fp32_embed_one_short_200b` | `BGESmallENV15` (FP32) | 1 × ≈200 B | 10 | 100 | 14.65 | 17.00 | 17.92 | 12.26 | 18.07 | 14.85 |
| `fastembed_q_embed_one_short_200b` | `BGESmallENV15Q` (INT8) | 1 × ≈200 B | 10 | 100 | 22.60 | 25.06 | 25.92 | 20.48 | 28.73 | 22.79 |
| `fastembed_fp32_embed_one_medium_4kb` | `BGESmallENV15` (FP32) | 1 × ≈4 KB | 5 | 50 | 104.21 | 127.47 | 141.28 | 98.59 | 141.28 | 108.13 |
| `fastembed_q_embed_one_medium_4kb` | `BGESmallENV15Q` (INT8) | 1 × ≈4 KB | 5 | 50 | 112.23 | 118.29 | 136.53 | 100.21 | 136.53 | 112.28 |
| `fastembed_fp32_embed_batch_16x200b` | `BGESmallENV15` (FP32) | 16 × ≈200 B (toplam) | 5 | 50 | 120.86 | 128.23 | 130.94 | 112.55 | 130.94 | 121.03 |
| `fastembed_q_embed_batch_16x200b` | `BGESmallENV15Q` (INT8) | 16 × ≈200 B (toplam) | 5 | 50 | 103.80 | 115.91 | 123.16 | 98.77 | 123.16 | 104.87 |
| `hybrid_search_1k_e2e_bgsmall_q` | `BGESmallENV15Q` (E2E `k=10`) | 1000 olay + sorgu | 10 | 50 | 19.03 | 21.92 | 22.74 | 16.50 | 22.74 | 19.13 |

- **SLA Durumu:** Tekil kısa metin gömmede `BGESmallENV15Q` (`p50 = 22.60 ms`, `p95 = 25.06 ms`) ve `BGESmallENV15` (`p50 = 14.65 ms`, `p95 = 17.00 ms`), `< 5 ms` veya `p95 < 8 ms` (~6 ms) hedefini karşılamamaktadır (ölçüm sırasında arka planda paralel `nmake`/`cl`/`cargo` süreçlerinin çalıştığı gözlenmiştir). `BGESmallENV15Q` `16 × 200 B` toplu gömmede (`p50 = 103.80 ms` vs `120.86 ms`) ve model açılışında (`266.6 ms` vs `426.4 ms`) FP32'den hızlıdır.

---

### 4. Release Overlay Bellek Ölçümü (`synapse-mind.exe` + WebView2)

`src-tauri/target/release/synapse-mind.exe` başlatıldıktan `5 s` sonra tüm `ParentProcessId` süreci ağacı ölçülmüştür (mevcut derleme `open_in_memory` + `DevHashEmbedder` kullanır; `open_encrypted` ve `fastembed` henüz release overlay ikilisine bağlı değildir).

| Süreç / Rol | Adet | PID | Working Set (MB) | Private Memory (MB) |
|---|---:|---:|---:|---:|
| `synapse-mind.exe` (`rust_host`) | 1 | `83048` | 35.02 | 13.16 |
| `msedgewebview2.exe` (WebView2 ana süreç) | 1 | `115332` | 134.66 | 35.98 |
| `msedgewebview2.exe` (`gpu-process`) | 1 | `107792` | 116.26 | 102.51 |
| `msedgewebview2.exe` (`renderer`) | 1 | `87008` | 56.98 | 24.77 |
| `msedgewebview2.exe` (`NetworkService`) | 1 | `50012` | 38.09 | 11.34 |
| `msedgewebview2.exe` (`StorageService`) | 1 | `113492` | 19.10 | 7.18 |
| `msedgewebview2.exe` (`crashpad-handler`) | 1 | `110068` | 10.11 | 2.63 |
| **Alt Süreç Toplamı (`msedgewebview2.exe`)** | **6** | – | **375.20** | **184.41** |
| **Genel Toplam (`rust_host` + WebView2)** | **7** | – | **410.22** | **197.57** |

- **Bellek Hedefi (`< 50 MB`):** Rust host sürecinin özel belleği (`13.16 MB`, Working Set `35.02 MB`) `50 MB` altındadır; ancak WebView2 alt süreçleri dahil edildiğinde toplam bellek (`410.22 MB` Working Set, `197.57 MB` Private) `< 50 MB` hedefinin üzerindedir.

### Metodoloji ve Sınırlar (Sprint 3)
- Flamegraph profillemesi yapılmadığından (`wpr.exe` yükseltilmemiş oturumda `0xc5585011` hatası vermiş, `VSDiagnostics.exe` durdurmada yanıt vermemiş ve `cargo-flamegraph`/`samply`/`cdb` kurulu değildir) herhangi bir darboğaz veya optimizasyon çıkarımı yapılmamıştır (`.agents/rules/optimization_and_latency_tracking.md`).

---

## Sprint 2 Ölçümleri — 2026-11-18

### Ortam ve Donanım Bilgisi
- **Tarih (UTC / Yerel):** `2026-11-18`
- **Git Commit:** `63be9f1`
- **Derleyici / Araç Zinciri:** `rustc 1.95.0 (59807616e 2026-04-14)`, `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- **Build Profili:** `--release` (`lto = "thin"`, `codegen-units = 1`, kök `Cargo.toml` ile birebir)
- **Workspace Kilidi (ADR-004):** `benchmarks/Cargo.lock`, kök `Cargo.lock` dosyasından tohumlandı; `cargo tree -p s-guard -p s-core` karşılaştırması kök ile **0 fark** verdi.
- **CPU:** `AMD Ryzen 7 8845HS w/ Radeon 780M Graphics` (8 fiziksel çekirdek, 16 mantıksal işlemci, maks. saat `3801 MHz`)
- **RAM:** `33,617,727,488` bayt (`~31.31 GiB`)
- **GPU (sistem bilgisi):** `AMD Radeon 780M Graphics`, `NVIDIA GeForce RTX 4060 Laptop GPU` (ölçümler CPU üzerinde çalıştırıldı)
- **İşletim Sistemi:** `Microsoft Windows 11 Home Single Language`
- **Sentetik Veri Tohumu:** `0x53524543414C4C32` (`SplitMix64`, deterministik ve tekrarlanabilir)

### Çalıştırılan Tek Satır Komutlar
- Çekirdek (`s_guard::process` + `s_core::MemoryStore::hybrid_search`):
  `cargo run --manifest-path benchmarks/Cargo.toml --release`
- `fastembed` (`BAAI/bge-small-en-v1.5`, ONNX CPU):
  `cargo run --manifest-path benchmarks/Cargo.toml --release --features fastembed -- --only fastembed`

### Ham Çıktı Dosyaları (`benchmarks/results/2026-11-18/`)
- `benchmarks/results/2026-11-18/summary_core.json`
- `benchmarks/results/2026-11-18/summary_core.txt`
- `benchmarks/results/2026-11-18/raw_samples_core.csv`
- `benchmarks/results/2026-11-18/summary_fastembed.json`
- `benchmarks/results/2026-11-18/summary_fastembed.txt`
- `benchmarks/results/2026-11-18/raw_samples_fastembed.csv`

---

### 1. `s_guard::process` Gecikmesi (Kısa / Orta / Uzun; PII'siz ve PII Yoğun)

Her örnek önceden üretilmiş `RawCapturePacket` ile beslenir; zamanlayıcı yalnızca `s_guard::process(packet, event_id)` çağrısını ölçer. Yüzdelikler en yakın sıra (`nearest-rank`) yöntemiyle hesaplanmıştır.

| Senaryo | Ort. Girdi (B) | Ort. Maskeleme | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `s_guard_short_200b_no_pii` | 195 | 0.0 | 100 | 1000 | 26.60 | 45.10 | 51.60 | 22.10 | 122.70 | 30.00 |
| `s_guard_short_200b_pii_heavy` | 188 | 5.7 | 100 | 1000 | 40.40 | 70.30 | 106.30 | 27.10 | 423.30 | 44.64 |
| `s_guard_medium_4kb_no_pii` | 4091 | 0.0 | 50 | 500 | 268.00 | 441.20 | 621.20 | 249.50 | 766.70 | 304.64 |
| `s_guard_medium_4kb_pii_heavy` | 4081 | 125.3 | 50 | 500 | 626.90 | 1027.50 | 1246.90 | 538.60 | 2318.10 | 706.33 |
| `s_guard_long_64kb_no_pii` | 65531 | 0.0 | 20 | 200 | 5215.20 | 6685.70 | 7589.80 | 4372.00 | 7826.50 | 5359.16 |
| `s_guard_long_64kb_pii_heavy` | 65521 | 2010.4 | 20 | 200 | 17841.20 | 22281.10 | 23496.70 | 9960.60 | 24715.50 | 16920.74 |

---

### 2. `s_core::MemoryStore::hybrid_search` Gecikmesi (1k & 10k In-Memory DB, `k = 10`)

SQLite FTS5 + `sqlite-vec` (`vec0`, 384 boyutlu kosinüs) + nedensellik zinciri maliyetini ONNX çıkarımından izole etmek için `DeterministicBenchEmbedder` (sentetik, 384-d birim normlu belirlenimci projeksiyon) kullanıldı; tek başına sorgu gömme maliyeti taban çizgisi olarak aşağıda ayrıca raporlanmıştır.
- **BM25-only:** Olaylar `has_embedding_payload = false` ile eklendi (`event_vectors` tablosunda `0` satır; `hybrid_search(q, 10)` FTS5 BM25 + boş `vec0` + nedensellik zinciri çalıştırır).
- **Vektörlü (Hybrid):** Olaylar `has_embedding_payload = true` ile eklendi (`event_vectors` tablosunda `1000` / `10000` vektör; `hybrid_search(q, 10)` FTS5 BM25 + `vec0` KNN + `vec_distance_cosine` tamamlama + nedensellik zinciri çalıştırır).

| Senaryo | Olay | Vektör Satırı | Kenar | Ingest (ms) | Isınma | Örnek | p50 (µs) | p95 (µs) | p99 (µs) | Min (µs) | Maks (µs) | Ort. (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `synthetic_query_embedder_baseline` | – | – | – | – | 50 | 500 | 1.10 | 1.20 | 1.20 | 1.00 | 1.60 | 1.10 |
| `hybrid_search_1k_bm25_only` | 1000 | 0 | 900 | 258.8 | 30 | 300 | 2185.30 | 3276.20 | 3969.20 | 903.50 | 4315.60 | 2216.87 |
| `hybrid_search_1k_vector_hybrid` | 1000 | 1000 | 900 | 401.6 | 30 | 300 | 4054.80 | 6115.10 | 7113.50 | 2718.50 | 8829.30 | 4200.87 |
| `hybrid_search_10k_bm25_only` | 10000 | 0 | 9000 | 2236.0 | 20 | 200 | 4025.40 | 5914.00 | 6723.20 | 1596.20 | 7103.60 | 3914.83 |
| `hybrid_search_10k_vector_hybrid` | 10000 | 10000 | 9000 | 3139.6 | 20 | 200 | 13513.60 | 17143.70 | 20064.20 | 9747.10 | 24856.80 | 13914.38 |

---

### 3. `fastembed` Gömme Süresi (`--features fastembed`, `BAAI/bge-small-en-v1.5`)

`s_core::FastEmbedder::try_new_default()` (ONNX Runtime CPU) ilk başlatma + model indirme/yükleme süresi: `65,724.6 ms` (`65.72 s`).

| Senaryo | Girdi / Batch | Isınma | Örnek | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Maks (ms) | Ort. (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `fastembed_embed_one_short_200b` | 1 × ≈200 B | 5 | 50 | 18.06 | 23.41 | 25.50 | 15.75 | 25.50 | 18.72 |
| `fastembed_embed_one_medium_4kb` | 1 × ≈4 KB | 3 | 30 | 105.64 | 117.99 | 122.01 | 98.75 | 122.01 | 106.56 |
| `fastembed_embed_batch_16x200b` | 16 × ≈200 B (toplam batch) | 3 | 30 | 135.89 | 152.19 | 170.32 | 127.73 | 170.32 | 138.81 |

### Metodoloji ve Sınırlar
- Bu koşuda flamegraph profillemesi yapılmadığından herhangi bir darboğaz iddiası veya optimizasyon çıkarımı yapılmamıştır (`.agents/rules/optimization_and_latency_tracking.md`).
- `hybrid_search` ölçümlerinde gerçek ONNX gömme süresi ayrıştırılmıştır; uçtan uca gerçek zamanlı sorgu gecikmesi için `fastembed_embed_one_short_200b` (`p50 = 18.06 ms`) + `hybrid_search` (`p50 = 13.51 ms` @ 10k vektörlü) birlikte değerlendirilmelidir.
