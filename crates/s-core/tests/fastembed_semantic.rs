#![cfg(feature = "fastembed")]

use std::path::Path;
use std::time::{Duration, Instant};

use s_core::{
    AppContext, DEFAULT_MAX_VECTOR_QUERY_BYTES, DualEmbedder, Embedder, EmbedderStatus,
    EventSource, FastEmbedBackend, FastEmbedConfig, FastEmbedMode, FastEmbedder,
    HybridSearchConfig, ManagedEmbedder, ManagedEmbedderConfig, MaskedMemoryBlock, MemoryStore,
    is_model_cached, truncate_query_prefix,
};

fn make_block(event_id: u64, timestamp_ms: u64, app: &str, text: &str) -> MaskedMemoryBlock {
    let mut text_hash = [0_u8; 32];
    for (idx, byte) in text.as_bytes().iter().enumerate() {
        text_hash[idx % 32] = text_hash[idx % 32].wrapping_add(*byte);
    }
    MaskedMemoryBlock {
        event_id,
        timestamp_ms,
        app_context: AppContext {
            process_name: app.to_owned(),
            sanitized_title: app.to_owned(),
            is_browser: false,
        },
        clean_text: text.to_owned(),
        text_hash,
        redactions_count: 0,
        has_embedding_payload: true,
        source: EventSource::Accessibility,
    }
}

#[test]
fn fastembed_semantic_search_ranks_related_concepts_without_lexical_overlap() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let cache_dir = FastEmbedder::default_cache_dir();
    assert!(
        cache_dir.is_absolute(),
        "default model cache dir must be absolute: {}",
        cache_dir.display()
    );
    assert!(
        !cache_dir.starts_with(repo_root),
        "default model cache dir `{}` must reside outside repository `{}`",
        cache_dir.display(),
        repo_root.display()
    );

    let embedder = FastEmbedder::try_new_default()
        .expect("FastEmbedder must download/load bge-small-en-v1.5 into external cache");
    assert!(
        !repo_root.join(".fastembed_cache").exists(),
        "no .fastembed_cache directory may be created in repo root"
    );
    assert!(
        !crate_dir.join(".fastembed_cache").exists(),
        "no .fastembed_cache directory may be created in crate dir"
    );

    let mut store = MemoryStore::open_in_memory(embedder).expect("open MemoryStore");
    assert_eq!(store.next_event_id().expect("empty next_event_id"), 0);

    let docs = [
        (
            "garage.exe",
            "The automobile mechanic replaced the flat tire and checked the brake pads.",
        ),
        (
            "excel.exe",
            "Quarterly revenue forecast and shareholder dividend statement for the fiscal year.",
        ),
        (
            "notes.exe",
            "Baking sourdough bread requires starter fermentation and steam inside the oven.",
        ),
        (
            "WindowsTerminal.exe",
            "PostgreSQL deadlock occurred during a concurrent database transaction update.",
        ),
    ];

    for (idx, (app, text)) in docs.iter().enumerate() {
        let event_id = store.next_event_id().expect("next_event_id");
        assert_eq!(event_id, u64::try_from(idx).unwrap());
        let ts = 1_000_000 + event_id * 1_000;
        store
            .ingest_block(&make_block(event_id, ts, app, text))
            .expect("ingest semantic block");
    }
    assert_eq!(store.next_event_id().expect("after 4 blocks"), 4);

    let vector_only = HybridSearchConfig {
        bm25_weight: 0.0,
        vector_weight: 1.0,
        recency_weight: 0.0,
        ..HybridSearchConfig::default()
    };

    // Zero shared lexical tokens between each query and its target document.
    let cases = [
        ("car repair service auto workshop", 0_u64),
        ("SQL table locking failure", 3_u64),
        ("financial earnings stock investors", 1_u64),
        ("yeast dough pastry recipe", 2_u64),
    ];

    for (query, expected_id) in cases {
        let vec_hits = store
            .hybrid_search_with_config(query, 4, &vector_only)
            .expect("vector-only search");
        assert_eq!(
            vec_hits.len(),
            4,
            "expected all 4 embedded events in vector hits for `{query}`"
        );
        assert_eq!(
            vec_hits[0].event_id, expected_id,
            "vector-only semantic search misranked `{query}`: got event_id={} (score={}), expected={expected_id}",
            vec_hits[0].event_id, vec_hits[0].score
        );
        assert!(
            vec_hits[0].score > vec_hits[1].score,
            "top hit score ({}) must strictly exceed runner-up ({}) for `{query}`",
            vec_hits[0].score,
            vec_hits[1].score
        );

        let hybrid_hits = store.hybrid_search(query, 4).expect("hybrid search");
        assert_eq!(
            hybrid_hits[0].event_id, expected_id,
            "default hybrid search misranked `{query}`: got event_id={}, expected={expected_id}",
            hybrid_hits[0].event_id
        );
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    let mut dot = 0.0_f64;
    let mut na = 0.0_f64;
    let mut nb = 0.0_f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xf = f64::from(x);
        let yf = f64::from(y);
        dot += xf * yf;
        na += xf * xf;
        nb += yf * yf;
    }
    dot / (na.sqrt() * nb.sqrt())
}

#[test]
fn dual_embedder_routes_queries_to_fp32_and_batches_to_int8() {
    let embedder = DualEmbedder::try_new_default()
        .expect("DualEmbedder must initialize both BGESmallENV15 (FP32) and BGESmallENV15Q (INT8)");
    assert_eq!(embedder.dimension(), 384);

    let sample = "PostgreSQL deadlock occurred during concurrent database updates.";
    let fp32_vec = embedder.embed_one(sample).expect("FP32 embed_one");
    let int8_vecs = embedder
        .embed_batch(&[sample, "Sourdough fermentation and oven steam."])
        .expect("INT8 embed_batch");
    assert_eq!(fp32_vec.len(), 384);
    assert_eq!(int8_vecs.len(), 2);

    let sim = cosine(&fp32_vec, &int8_vecs[0]);
    assert!(
        sim > 0.99,
        "FP32 and INT8 BGE-small models must remain aligned in 384-d space, got cos={sim:.6}"
    );

    let mut store = MemoryStore::open_in_memory(embedder).expect("open MemoryStore<DualEmbedder>");
    let docs = [
        make_block(
            0,
            1_000_000,
            "garage.exe",
            "The automobile mechanic replaced the flat tire and checked the brake pads.",
        ),
        make_block(
            1,
            1_001_000,
            "WindowsTerminal.exe",
            "PostgreSQL deadlock occurred during a concurrent database transaction update.",
        ),
    ];
    store.ingest_batch(&docs).expect("batch ingest via INT8");

    let vector_only = HybridSearchConfig {
        bm25_weight: 0.0,
        vector_weight: 1.0,
        recency_weight: 0.0,
        ..HybridSearchConfig::default()
    };
    let hits = store
        .hybrid_search_with_config("SQL table locking failure", 2, &vector_only)
        .expect("FP32 query against INT8-indexed vectors");
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].event_id, 1);
    assert!(hits[0].score > hits[1].score);
}

struct IsolatedCacheGuard(std::path::PathBuf);

impl Drop for IsolatedCacheGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

fn prepare_isolated_model_cache(label: &str) -> IsolatedCacheGuard {
    use std::path::PathBuf;

    let isolated = std::env::temp_dir().join(format!("s-core-v011-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&isolated);

    let default_cache = DualEmbedder::default_cache_dir();
    let legacy_cache = std::env::var_os("LOCALAPPDATA").map(|local| {
        PathBuf::from(local)
            .join("s-recall")
            .join("fastembed_cache")
    });

    if s_core::is_dual_model_cached(&default_cache).unwrap_or(false) {
        copy_dir_recursive(&default_cache, &isolated).expect("copy default cache");
    } else if let Some(ref legacy) = legacy_cache
        && s_core::is_dual_model_cached(legacy).unwrap_or(false)
    {
        copy_dir_recursive(legacy, &isolated).expect("copy legacy s-recall cache");
    } else {
        std::fs::create_dir_all(&isolated).expect("create empty isolated cache");
    }

    IsolatedCacheGuard(isolated)
}

#[test]
#[ignore = "measures real ONNX CPU p50/p95/p99 across max_length 64/80/96 using isolated copy of local cache"]
fn measure_query_max_length_latency_matrix() {
    use std::time::Instant;

    fn percentile(sorted_ns: &[u64], pct: f64) -> f64 {
        let n = sorted_ns.len();
        let rank = ((pct / 100.0) * (n as f64)).ceil() as usize;
        let idx = rank.saturating_sub(1).min(n - 1);
        (sorted_ns[idx] as f64) / 1_000_000.0
    }

    let isolated = prepare_isolated_model_cache("measure-cache");
    assert!(
        s_core::is_dual_model_cached(&isolated.0).unwrap_or(false),
        "expected cached DualEmbedder models inside {}",
        isolated.0.display()
    );

    let en_200b = "compiling crate s-core in release mode with thin lto enabled sqlite-vec registered cosine distance metric over 384 dimensions tokio mpsc channel capacity 128 verified without blocking runtime";
    let en_256b = "compiling crate s-core in release mode with thin lto enabled sqlite-vec registered cosine distance metric over 384 dimensions tokio mpsc channel capacity 128 verified without blocking runtime hybrid search weights bm25 0.45 vector 0.45 recency 0.10 active";
    let tr_200b = "güvenlik şifreleme doğrulama ölçümü Türkçe karakterli sorgu çalışması ağaç gölgesi ışığında örümcek ağı çözümleme şifre çözme bellek sızıntısı engelleme denetimi başarısız derleme hatası";
    let tr_256b = "güvenlik şifreleme doğrulama ölçümü Türkçe karakterli sorgu çalışması ağaç gölgesi ışığında örümcek ağı çözümleme şifre çözme bellek sızıntısı engelleme denetimi başarısız derleme hatası çekirdek modülü pencere başlığı odak değişimi pano kopyalama";
    let paste_4kb = format!(
        "PostgreSQL deadlock occurred during concurrent database transaction update {}",
        "unrelated stack frame trace symbol line number memory address module offset ".repeat(56)
    );
    assert!(paste_4kb.len() >= 4096);

    let (tr_140b_cut, _) = s_core::truncate_query_prefix(tr_256b, 140);
    let (tr_160b_cut, _) = s_core::truncate_query_prefix(tr_256b, 160);
    let (tr_180b_cut, _) = s_core::truncate_query_prefix(tr_256b, 180);
    let (tr_200b_cut, _) = s_core::truncate_query_prefix(tr_256b, 200);
    let (tr_240b_cut, _) = s_core::truncate_query_prefix(tr_256b, 240);
    let (paste_160b_cut, _) = s_core::truncate_query_prefix(&paste_4kb, 160);
    let (paste_180b_cut, _) = s_core::truncate_query_prefix(&paste_4kb, 180);
    let (paste_200b_cut, _) = s_core::truncate_query_prefix(&paste_4kb, 200);
    let (paste_240b_cut, _) = s_core::truncate_query_prefix(&paste_4kb, 240);

    for max_tokens in [64_usize, 80, 96] {
        let embedder =
            DualEmbedder::try_new_with_cache_and_query_max_tokens(&isolated.0, max_tokens)
                .expect("init DualEmbedder");

        let cases: &[(&str, &str)] = &[
            ("en_200b", en_200b),
            ("en_256b", en_256b),
            ("tr_200b", tr_200b),
            ("tr_cut_140b", tr_140b_cut),
            ("tr_cut_160b", tr_160b_cut),
            ("tr_cut_180b", tr_180b_cut),
            ("tr_cut_200b", tr_200b_cut),
            ("tr_cut_240b", tr_240b_cut),
            ("4kb_raw", &paste_4kb),
            ("4kb_cut_160b", paste_160b_cut),
            ("4kb_cut_180b", paste_180b_cut),
            ("4kb_cut_200b", paste_200b_cut),
            ("4kb_cut_240b", paste_240b_cut),
        ];

        for (label, text) in cases {
            for _ in 0..15 {
                let _ = embedder.embed_one(text).expect("warmup");
            }
            let mut samples = Vec::with_capacity(120);
            for _ in 0..120 {
                let t0 = Instant::now();
                let _ = embedder.embed_one(text).expect("sample");
                samples.push(t0.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            println!(
                "max_tokens={max_tokens} case={label} bytes={} p50={:.2}ms p95={:.2}ms p99={:.2}ms",
                text.len(),
                percentile(&samples, 50.0),
                percentile(&samples, 95.0),
                percentile(&samples, 99.0),
            );
        }
    }
}

#[test]
fn dual_embedder_long_4kb_query_truncation_and_512_token_batch_indexing() {
    let isolated = prepare_isolated_model_cache("dual-4kb-test");
    let embedder = DualEmbedder::try_new_with_cache(&isolated.0)
        .expect("DualEmbedder must initialize from isolated cache");
    let mut store = MemoryStore::open_in_memory(embedder).expect("open store");

    // Place distinguishing concept around token ~220 (> 64 query token limit, < 512 batch limit)
    // to verify batch indexing (`BGESmallENV15Q`) keeps the 512-token window intact.
    let padding = "generic system background window focus activity log entry ".repeat(22);
    let docs = [
        make_block(
            0,
            1_000_000,
            "garage.exe",
            "The automobile mechanic replaced the flat tire and checked the brake pads.",
        ),
        make_block(
            1,
            1_001_000,
            "WindowsTerminal.exe",
            &format!(
                "{padding} PostgreSQL deadlock occurred during a concurrent database transaction update."
            ),
        ),
        make_block(
            2,
            1_002_000,
            "notes.exe",
            "Baking sourdough bread requires starter fermentation and steam inside the oven.",
        ),
        make_block(
            3,
            1_003_000,
            "excel.exe",
            "Quarterly revenue forecast and shareholder dividend statement for the fiscal year.",
        ),
    ];
    store
        .ingest_batch(&docs)
        .expect("ingest batch at 512 tokens");

    let vector_only = HybridSearchConfig {
        bm25_weight: 0.0,
        vector_weight: 1.0,
        recency_weight: 0.0,
        ..HybridSearchConfig::default()
    };
    let tail_hits = store
        .hybrid_search_with_config("SQL table locking failure", 4, &vector_only)
        .expect("semantic query hits tail concept beyond token 64");
    assert_eq!(tail_hits[0].event_id, 1);

    // 4 KB pasted query with informative prefix + noisy tail: target event must stay in top 3
    // and `query_truncated` must be `true`.
    let query_4kb = format!(
        "SQL table locking failure database transaction deadlock {}",
        "unrelated browser toolbar navigation frame pointer stack symbol ".repeat(68)
    );
    assert!(query_4kb.len() > 4096);

    let outcome = store
        .hybrid_search_detailed(&query_4kb, 4, &HybridSearchConfig::default())
        .expect("4kb detailed search");
    assert!(outcome.query_truncated);
    assert!(outcome.semantic_used);
    assert!(
        outcome.hits.iter().take(3).any(|h| h.event_id == 1),
        "expected target event 1 in top 3 for 4 KB query, got {:?}",
        outcome.hits.iter().map(|h| h.event_id).collect::<Vec<_>>()
    );

    // Empty query returns empty without truncating or running semantic inference.
    let empty_outcome = store
        .hybrid_search_detailed("   \n\t ", 4, &HybridSearchConfig::default())
        .expect("empty detailed search");
    assert!(empty_outcome.hits.is_empty());
    assert!(!empty_outcome.query_truncated);
    assert!(!empty_outcome.semantic_used);

    // Turkish multi-byte character query executes cleanly through query truncation + DualEmbedder.
    let tr_query = "güvenlik şifreleme doğrulama çözümü örümcek ağacı ışık";
    let tr_outcome = store
        .hybrid_search_detailed(tr_query, 4, &HybridSearchConfig::default())
        .expect("Turkish detailed search");
    assert!(!tr_outcome.query_truncated);
    assert!(tr_outcome.semantic_used);
}

#[test]
fn managed_embedder_loads_from_cache_and_notifies_ready() {
    let isolated = prepare_isolated_model_cache("managed-ready-test");
    let managed = s_core::ManagedEmbedder::new();
    let mut rx = managed.subscribe();
    assert_eq!(managed.status(), s_core::EmbedderStatus::NotDownloaded);

    let mut store = MemoryStore::open_in_memory(managed.clone()).expect("open store");
    store
        .ingest_block(&make_block(
            0,
            1_000_000,
            "WindowsTerminal.exe",
            "PostgreSQL deadlock occurred during concurrent database transaction",
        ))
        .expect("ingest before Ready succeeds via BM25");

    let handle = managed
        .spawn_dual_with_cache(&isolated.0)
        .expect("spawn dual init");
    handle
        .join()
        .expect("join thread")
        .expect("DualEmbedder init succeeds");

    assert_eq!(managed.status(), s_core::EmbedderStatus::Ready);
    assert_eq!(
        rx.borrow_and_update().clone(),
        s_core::EmbedderStatus::Ready
    );
    assert_eq!(store.backfill_missing_embeddings(16).expect("backfill"), 1);

    let out = store
        .hybrid_search_detailed(
            "SQL table locking failure",
            4,
            &HybridSearchConfig::default(),
        )
        .expect("semantic search after Ready");
    assert!(out.semantic_used);
    assert_eq!(out.hits.len(), 1);
    assert_eq!(out.hits[0].event_id, 0);
}

fn assert_single_mode_semantic_consistency(mode: FastEmbedMode, label: &str) {
    let isolated = prepare_isolated_model_cache(label);
    assert!(
        is_model_cached(&isolated.0, mode).expect("check model cache"),
        "expected {mode:?} model cached inside {}",
        isolated.0.display()
    );

    let embedder = FastEmbedBackend::try_new(&FastEmbedConfig {
        mode,
        cache_dir: isolated.0.clone(),
        ..FastEmbedConfig::default()
    })
    .expect("Single FastEmbedBackend init");
    assert!(!embedder.is_dual());
    assert_eq!(embedder.dimension(), 384);

    let mut store = MemoryStore::open_in_memory(embedder).expect("open store");
    let padding = "generic system background window focus activity log entry ".repeat(22);
    let docs = [
        (
            "garage.exe",
            "The automobile mechanic replaced the flat tire and checked the brake pads.",
        ),
        (
            "excel.exe",
            "Quarterly revenue forecast and shareholder dividend statement for the fiscal year.",
        ),
        (
            "notes.exe",
            "Baking sourdough bread requires starter fermentation and steam inside the oven.",
        ),
        (
            "WindowsTerminal.exe",
            "PostgreSQL deadlock occurred during a concurrent database transaction update.",
        ),
        (
            "WindowsTerminal.exe",
            &format!(
                "{padding} PostgreSQL deadlock occurred during a concurrent database transaction update."
            ),
        ),
    ];

    let blocks: Vec<MaskedMemoryBlock> = docs
        .iter()
        .enumerate()
        .map(|(i, (app, text))| make_block(i as u64, 1_000_000 + (i as u64) * 1_000, app, text))
        .collect();
    store
        .ingest_batch(&blocks)
        .expect("batch ingest Single mode");

    let vector_only = HybridSearchConfig {
        bm25_weight: 0.0,
        vector_weight: 1.0,
        recency_weight: 0.0,
        ..HybridSearchConfig::default()
    };

    // 4 semantic zero-lexical-overlap queries (compare against doc 0..=3, ignoring padded doc 4).
    let cases = [
        ("car repair service auto workshop", 0_u64),
        ("financial earnings stock investors", 1_u64),
        ("yeast dough pastry recipe", 2_u64),
        ("SQL table locking failure", 3_u64),
    ];

    for (query, expected_id) in cases {
        let vec_hits = store
            .hybrid_search_with_config(query, 5, &vector_only)
            .expect("Single mode vector-only search");
        assert_eq!(vec_hits.len(), 5);
        if expected_id == 3 {
            assert!(
                vec_hits[0].event_id == 3 || vec_hits[0].event_id == 4,
                "expected PostgreSQL deadlock doc (3 or 4), got {}",
                vec_hits[0].event_id
            );
        } else {
            assert_eq!(
                vec_hits[0].event_id, expected_id,
                "{mode:?} vector misranked `{query}`: got {}, expected {}",
                vec_hits[0].event_id, expected_id
            );
        }

        let hybrid_hits = store.hybrid_search(query, 5).expect("Single mode hybrid");
        if expected_id == 3 {
            assert!(hybrid_hits[0].event_id == 3 || hybrid_hits[0].event_id == 4);
        } else {
            assert_eq!(hybrid_hits[0].event_id, expected_id);
        }
    }

    // 4 KB pasted query + Turkish query consistency check.
    let query_4kb = format!(
        "SQL table locking failure database transaction deadlock {}",
        "unrelated browser toolbar navigation frame pointer stack symbol ".repeat(68)
    );
    let out_4kb = store
        .hybrid_search_detailed(&query_4kb, 5, &HybridSearchConfig::default())
        .expect("Single mode 4kb detailed search");
    assert!(out_4kb.query_truncated);
    assert!(out_4kb.semantic_used);
    assert!(
        out_4kb
            .hits
            .iter()
            .take(3)
            .any(|h| h.event_id == 3 || h.event_id == 4)
    );

    let tr_out = store
        .hybrid_search_detailed(
            "güvenlik şifreleme doğrulama çözümü örümcek ağacı ışık",
            4,
            &HybridSearchConfig::default(),
        )
        .expect("Single mode Turkish search");
    assert!(!tr_out.query_truncated);
    assert!(tr_out.semantic_used);
}

#[test]
fn single_int8_semantic_search_passes_and_is_self_consistent() {
    assert_single_mode_semantic_consistency(FastEmbedMode::SingleInt8, "single-int8-test");
}

#[test]
fn single_fp32_semantic_search_passes_and_is_self_consistent() {
    assert_single_mode_semantic_consistency(FastEmbedMode::SingleFp32, "single-fp32-test");
}

#[test]
fn managed_embedder_single_int8_idle_unload_and_reload_preserves_semantic_search() {
    let isolated = prepare_isolated_model_cache("single-int8-idle");
    let managed = ManagedEmbedder::with_config(ManagedEmbedderConfig {
        idle_unload_timeout: Some(Duration::from_millis(80)),
    });
    assert_eq!(
        managed.config().idle_unload_timeout,
        Some(Duration::from_millis(80))
    );

    managed
        .init_fastembed(FastEmbedConfig {
            mode: FastEmbedMode::SingleInt8,
            cache_dir: isolated.0.clone(),
            ..FastEmbedConfig::default()
        })
        .expect("init SingleInt8 inside ManagedEmbedder");
    assert!(managed.is_loaded());
    assert!(managed.is_ready());
    assert_eq!(managed.status(), EmbedderStatus::Ready);

    let mut store = MemoryStore::open_in_memory(managed.clone()).expect("open store");
    let docs = [
        make_block(
            0,
            1_000_000,
            "garage.exe",
            "The automobile mechanic replaced the flat tire and checked the brake pads.",
        ),
        make_block(
            1,
            1_001_000,
            "WindowsTerminal.exe",
            "PostgreSQL deadlock occurred during a concurrent database transaction update.",
        ),
    ];
    store
        .ingest_batch(&docs)
        .expect("ingest before idle unload");

    // Wait for background idle reaper to drop the ONNX session.
    let deadline = Instant::now();
    while managed.is_loaded() && deadline.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !managed.is_loaded(),
        "ManagedEmbedder must unload SingleInt8 session after idle timeout"
    );
    assert!(managed.idle_unload_count() >= 1);
    assert_eq!(managed.status(), EmbedderStatus::Ready);
    assert!(managed.is_ready());

    // Semantic search transparently reloads the local SingleInt8 session and ranks accurately.
    let vector_only = HybridSearchConfig {
        bm25_weight: 0.0,
        vector_weight: 1.0,
        recency_weight: 0.0,
        ..HybridSearchConfig::default()
    };
    let out = store
        .hybrid_search_detailed("SQL table locking failure", 2, &vector_only)
        .expect("semantic search after idle unload triggers lazy reload");
    assert!(out.semantic_used);
    assert!(managed.is_loaded());
    assert!(managed.reload_count() >= 1);
    assert_eq!(out.hits[0].event_id, 1);
}

#[cfg(windows)]
fn current_process_memory_mb() -> (f64, f64) {
    let pid = std::process::id();
    let script = format!(
        "$p = Get-Process -Id {pid}; Write-Output \"$($p.WorkingSet64),$($p.PrivateMemorySize64)\""
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .expect("query Get-Process memory");
    assert!(out.status.success(), "Get-Process failed");
    let raw = String::from_utf8_lossy(&out.stdout);
    let mut parts = raw.trim().split(',');
    let ws_bytes: f64 = parts.next().expect("ws").parse().expect("ws parse");
    let priv_bytes: f64 = parts.next().expect("priv").parse().expect("priv parse");
    (ws_bytes / 1_048_576.0, priv_bytes / 1_048_576.0)
}

#[cfg(not(windows))]
fn current_process_memory_mb() -> (f64, f64) {
    (0.0, 0.0)
}

fn percentile_ms(sorted_ns: &[u64], pct: f64) -> f64 {
    let n = sorted_ns.len();
    let rank = ((pct / 100.0) * (n as f64)).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    (sorted_ns[idx] as f64) / 1_000_000.0
}

fn build_bench_texts(count: usize, target_bytes: usize) -> Vec<String> {
    const FRAGS: &[&str] = &[
        "compiling crate s-core in release mode with thin lto enabled",
        "sqlite-vec registered cosine distance metric over 384 dimensions",
        "tokio mpsc channel capacity 128 verified without blocking runtime",
        "window focus switched from terminal to documentation tab in browser",
        "fts5 unicode61 index updated cleanly after upsert transaction commit",
        "borrow checker verified lifetime bounds across zeroize wrapper struct",
        "causality graph linked recent compile diagnostic to browser query",
        "hybrid search weights bm25 0.45 vector 0.45 recency 0.10 active",
    ];
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut s = String::with_capacity(target_bytes + 64);
        let mut j = i;
        while s.len() < target_bytes {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(FRAGS[j % FRAGS.len()]);
            j = j.wrapping_mul(3).wrapping_add(1);
        }
        if s.len() > target_bytes {
            let (prefix, _) = truncate_query_prefix(&s, target_bytes);
            s = prefix.to_owned();
        }
        out.push(s);
    }
    out
}

fn measure_embedder_option_isolated(label: &str, mode: FastEmbedMode, test_idle_unload: bool) {
    let isolated = prepare_isolated_model_cache(label);
    let (ws_base, priv_base) = current_process_memory_mb();

    let managed = ManagedEmbedder::with_config(ManagedEmbedderConfig {
        idle_unload_timeout: if test_idle_unload {
            Some(Duration::from_secs(600))
        } else {
            None
        },
    });
    let t_init = Instant::now();
    managed
        .init_fastembed(FastEmbedConfig {
            mode,
            cache_dir: isolated.0.clone(),
            ..FastEmbedConfig::default()
        })
        .expect("init fastembed option");
    let init_ms = t_init.elapsed().as_secs_f64() * 1000.0;
    let (ws_loaded, priv_loaded) = current_process_memory_mb();

    // Ingest 1000 synthetic ~200B events via `ingest_batch` and measure memory afterwards.
    let texts_1k = build_bench_texts(1000, 200);
    let blocks_1k: Vec<MaskedMemoryBlock> = texts_1k
        .iter()
        .enumerate()
        .map(|(i, text)| {
            make_block(
                i as u64,
                1_700_000_000_000 + (i as u64) * 1000,
                "Code.exe",
                text,
            )
        })
        .collect();
    let mut store = MemoryStore::open_in_memory(managed.clone()).expect("open store");
    let t_ingest = Instant::now();
    store.ingest_batch(&blocks_1k).expect("ingest 1000 events");
    let ingest_ms = t_ingest.elapsed().as_secs_f64() * 1000.0;
    let (ws_after_1k, priv_after_1k) = current_process_memory_mb();

    // Measure embed_one p50/p95/p99 for 200B and 4kb_guarded (w=20, n=300).
    let texts_200b = build_bench_texts(320, 200);
    let texts_4kb = build_bench_texts(320, 4096);

    for t in &texts_200b[..20] {
        let _ = std::hint::black_box(managed.embed_one(t).expect("warmup 200b"));
    }
    let mut samples_200b = Vec::with_capacity(300);
    for t in &texts_200b[20..] {
        let t0 = Instant::now();
        let v = std::hint::black_box(managed.embed_one(std::hint::black_box(t)).expect("200b"));
        samples_200b.push(t0.elapsed().as_nanos() as u64);
        assert_eq!(v.len(), 384);
    }
    samples_200b.sort_unstable();

    for t in &texts_4kb[..20] {
        let (cut, _) = truncate_query_prefix(t, DEFAULT_MAX_VECTOR_QUERY_BYTES);
        let _ = std::hint::black_box(managed.embed_one(cut).expect("warmup 4kb"));
    }
    let mut samples_4kb = Vec::with_capacity(300);
    for t in &texts_4kb[20..] {
        let t0 = Instant::now();
        let (cut, _) = truncate_query_prefix(
            std::hint::black_box(t.as_str()),
            DEFAULT_MAX_VECTOR_QUERY_BYTES,
        );
        let v = std::hint::black_box(managed.embed_one(std::hint::black_box(cut)).expect("4kb"));
        samples_4kb.push(t0.elapsed().as_nanos() as u64);
        assert_eq!(v.len(), 384);
    }
    samples_4kb.sort_unstable();

    let (ws_after_bench, priv_after_bench) = current_process_memory_mb();
    println!(
        "OPTION={label} mode={mode:?} init_ms={init_ms:.1} ingest_1k_ms={ingest_ms:.1} \
         mem_base_ws_mb={ws_base:.2} mem_base_priv_mb={priv_base:.2} \
         mem_loaded_ws_mb={ws_loaded:.2} mem_loaded_priv_mb={priv_loaded:.2} \
         mem_1k_ws_mb={ws_after_1k:.2} mem_1k_priv_mb={priv_after_1k:.2} \
         mem_post_ws_mb={ws_after_bench:.2} mem_post_priv_mb={priv_after_bench:.2} \
         embed_200b_p50_ms={:.2} embed_200b_p95_ms={:.2} embed_200b_p99_ms={:.2} \
         embed_4kb_guarded_p50_ms={:.2} embed_4kb_guarded_p95_ms={:.2} embed_4kb_guarded_p99_ms={:.2}",
        percentile_ms(&samples_200b, 50.0),
        percentile_ms(&samples_200b, 95.0),
        percentile_ms(&samples_200b, 99.0),
        percentile_ms(&samples_4kb, 50.0),
        percentile_ms(&samples_4kb, 95.0),
        percentile_ms(&samples_4kb, 99.0),
    );

    if test_idle_unload {
        assert!(managed.unload());
        std::thread::sleep(Duration::from_millis(250));
        let (ws_unloaded, priv_unloaded) = current_process_memory_mb();

        let t_reload = Instant::now();
        let out = store
            .hybrid_search_detailed(
                "sqlite vec0 cosine distance",
                5,
                &HybridSearchConfig::default(),
            )
            .expect("reload search");
        let reload_search_ms = t_reload.elapsed().as_secs_f64() * 1000.0;
        assert!(out.semantic_used);
        assert_eq!(managed.reload_count(), 1);
        let (ws_reloaded, priv_reloaded) = current_process_memory_mb();

        println!(
            "IDLE_UNLOAD={label} mem_unloaded_ws_mb={ws_unloaded:.2} mem_unloaded_priv_mb={priv_unloaded:.2} \
             reload_first_search_ms={reload_search_ms:.2} \
             mem_reloaded_ws_mb={ws_reloaded:.2} mem_reloaded_priv_mb={priv_reloaded:.2}"
        );
    }
}

#[test]
#[ignore = "run in isolated process for memory and latency measurement"]
fn measure_option_dual_default() {
    measure_embedder_option_isolated("opt-dual", FastEmbedMode::DualFp32QueryInt8Batch, false);
}

#[test]
#[ignore = "run in isolated process for memory and latency measurement"]
fn measure_option_single_int8() {
    measure_embedder_option_isolated("opt-single-int8", FastEmbedMode::SingleInt8, false);
}

#[test]
#[ignore = "run in isolated process for memory and latency measurement"]
fn measure_option_single_fp32() {
    measure_embedder_option_isolated("opt-single-fp32", FastEmbedMode::SingleFp32, false);
}

#[test]
#[ignore = "run in isolated process for idle unload memory and reload measurement"]
fn measure_option_single_int8_idle_unload() {
    measure_embedder_option_isolated("opt-single-int8-idle", FastEmbedMode::SingleInt8, true);
}

#[test]
#[ignore = "run in isolated process for idle unload memory and reload measurement"]
fn measure_option_dual_idle_unload() {
    measure_embedder_option_isolated("opt-dual-idle", FastEmbedMode::DualFp32QueryInt8Batch, true);
}

fn measure_realistic_ingest_isolated(
    label: &str,
    mode: FastEmbedMode,
    session_config: Vec<(String, String)>,
    intra_threads: Option<usize>,
) {
    let isolated = prepare_isolated_model_cache(label);
    let (ws_base, priv_base) = current_process_memory_mb();

    let managed = ManagedEmbedder::new();
    let t_init = Instant::now();
    managed
        .init_fastembed(FastEmbedConfig {
            mode,
            cache_dir: isolated.0.clone(),
            intra_threads,
            session_config,
            ..FastEmbedConfig::default()
        })
        .expect("init");
    let init_ms = t_init.elapsed().as_secs_f64() * 1000.0;
    let (ws_loaded, priv_loaded) = current_process_memory_mb();

    // Realistic incremental ingest: 1000 events ingested in small chunks of 8 (like sensor batches).
    let texts_1k = build_bench_texts(1000, 200);
    let blocks_1k: Vec<MaskedMemoryBlock> = texts_1k
        .iter()
        .enumerate()
        .map(|(i, text)| {
            make_block(
                i as u64,
                1_700_000_000_000 + (i as u64) * 1000,
                "Code.exe",
                text,
            )
        })
        .collect();
    let mut store = MemoryStore::open_in_memory(managed.clone()).expect("open store");
    let t_ingest = Instant::now();
    for chunk in blocks_1k.chunks(8) {
        store.ingest_batch(chunk).expect("ingest chunk 8");
    }
    let ingest_ms = t_ingest.elapsed().as_secs_f64() * 1000.0;
    let (ws_after_1k, priv_after_1k) = current_process_memory_mb();

    // 200B & 4kb_guarded embed_one latency (w=20, n=300)
    let texts_200b = build_bench_texts(320, 200);
    let texts_4kb = build_bench_texts(320, 4096);
    for t in &texts_200b[..20] {
        let _ = std::hint::black_box(managed.embed_one(t).expect("warmup"));
    }
    let mut s_200 = Vec::with_capacity(300);
    for t in &texts_200b[20..] {
        let t0 = Instant::now();
        let _ = std::hint::black_box(managed.embed_one(std::hint::black_box(t)).expect("200b"));
        s_200.push(t0.elapsed().as_nanos() as u64);
    }
    s_200.sort_unstable();

    for t in &texts_4kb[..20] {
        let (cut, _) = truncate_query_prefix(t, DEFAULT_MAX_VECTOR_QUERY_BYTES);
        let _ = std::hint::black_box(managed.embed_one(cut).expect("warmup"));
    }
    let mut s_4kb = Vec::with_capacity(300);
    for t in &texts_4kb[20..] {
        let t0 = Instant::now();
        let (cut, _) = truncate_query_prefix(
            std::hint::black_box(t.as_str()),
            DEFAULT_MAX_VECTOR_QUERY_BYTES,
        );
        let _ = std::hint::black_box(managed.embed_one(std::hint::black_box(cut)).expect("4kb"));
        s_4kb.push(t0.elapsed().as_nanos() as u64);
    }
    s_4kb.sort_unstable();
    let (ws_post, priv_post) = current_process_memory_mb();

    println!(
        "REALISTIC={label} init_ms={init_ms:.1} ingest_1k_ms={ingest_ms:.1} \
         base=({ws_base:.2}/{priv_base:.2}) loaded=({ws_loaded:.2}/{priv_loaded:.2}) \
         after_1k=({ws_after_1k:.2}/{priv_after_1k:.2}) post=({ws_post:.2}/{priv_post:.2}) \
         200b=({:.2}/{:.2}/{:.2}) 4kb_guarded=({:.2}/{:.2}/{:.2})",
        percentile_ms(&s_200, 50.0),
        percentile_ms(&s_200, 95.0),
        percentile_ms(&s_200, 99.0),
        percentile_ms(&s_4kb, 50.0),
        percentile_ms(&s_4kb, 95.0),
        percentile_ms(&s_4kb, 99.0),
    );
}

#[test]
#[ignore = "realistic chunked ingest memory check: Dual arena=0"]
fn measure_realistic_dual_arena0() {
    measure_realistic_ingest_isolated(
        "real-dual-arena0",
        FastEmbedMode::DualFp32QueryInt8Batch,
        vec![("session.enable_cpu_mem_arena".into(), "0".into())],
        None,
    );
}

#[test]
#[ignore = "realistic chunked ingest memory check: SingleInt8 default"]
fn measure_realistic_single_int8_default() {
    measure_realistic_ingest_isolated("real-s-int8", FastEmbedMode::SingleInt8, Vec::new(), None);
}

#[test]
#[ignore = "realistic chunked ingest memory check: SingleInt8 arena=0"]
fn measure_realistic_single_int8_arena0() {
    measure_realistic_ingest_isolated(
        "real-s-int8-arena0",
        FastEmbedMode::SingleInt8,
        vec![("session.enable_cpu_mem_arena".into(), "0".into())],
        None,
    );
}

#[test]
#[ignore = "realistic chunked ingest memory check: Dual default ORT"]
fn measure_realistic_dual_default() {
    measure_realistic_ingest_isolated(
        "real-dual",
        FastEmbedMode::DualFp32QueryInt8Batch,
        Vec::new(),
        None,
    );
}

#[test]
#[ignore = "realistic chunked ingest memory check: SingleFp32 default ORT"]
fn measure_realistic_single_fp32_default() {
    measure_realistic_ingest_isolated("real-s-fp32", FastEmbedMode::SingleFp32, Vec::new(), None);
}

#[test]
#[ignore = "realistic chunked ingest memory check: SingleFp32 arena=0"]
fn measure_realistic_single_fp32_arena0() {
    measure_realistic_ingest_isolated(
        "real-s-fp32-arena0",
        FastEmbedMode::SingleFp32,
        vec![("session.enable_cpu_mem_arena".into(), "0".into())],
        None,
    );
}

#[test]
fn fastembed_model_ids_and_encrypted_migration_from_devhash_and_dual_to_single_fp32() {
    use std::sync::atomic::{AtomicU64, Ordering};

    struct DevHashTestEmbedder;
    impl Embedder for DevHashTestEmbedder {
        fn model_id(&self) -> &str {
            s_core::MODEL_ID_DEVHASH
        }

        fn embed_batch(&self, texts: &[&str]) -> s_core::Result<Vec<Vec<f32>>> {
            Ok(texts
                .iter()
                .map(|t| {
                    let mut vec = vec![0.0_f32; s_core::EMBEDDING_DIM];
                    let mut any = false;
                    for token in t
                        .to_ascii_lowercase()
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|s| !s.is_empty())
                    {
                        any = true;
                        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
                        for &b in token.as_bytes() {
                            hash ^= u64::from(b);
                            hash = hash.wrapping_mul(0x0100_0000_01b3);
                        }
                        let idx =
                            usize::try_from(hash % (s_core::EMBEDDING_DIM as u64)).unwrap_or(0);
                        vec[idx] += 1.0;
                    }
                    if !any {
                        vec[0] = 1.0;
                    }
                    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
                    if norm > 0.0 {
                        for x in &mut vec {
                            *x /= norm;
                        }
                    }
                    vec
                })
                .collect())
        }
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let isolated_cache = prepare_isolated_model_cache("model-id-migration");
    let db_dir =
        std::env::temp_dir().join(format!("s-core-fastembed-mig-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&db_dir);
    std::fs::create_dir_all(&db_dir).expect("create isolated temp db dir");
    let _db_guard = IsolatedCacheGuard(db_dir.clone());
    let db_path = db_dir.join("encrypted_migration.db");
    let key = [0xa7_u8; 32];

    assert_eq!(
        FastEmbedMode::DualFp32QueryInt8Batch.index_model_id(),
        s_core::MODEL_ID_BGE_SMALL_EN_V15_Q_INT8
    );
    assert_eq!(
        FastEmbedMode::SingleInt8.index_model_id(),
        s_core::MODEL_ID_BGE_SMALL_EN_V15_Q_INT8
    );
    assert_eq!(
        FastEmbedMode::SingleFp32.index_model_id(),
        s_core::MODEL_ID_BGE_SMALL_EN_V15_FP32
    );

    // 1. Seed isolated encrypted DB with v0.1.0-style DevHash vectors (and drop store_meta row).
    {
        let mut seed =
            MemoryStore::open_encrypted(&db_path, &key, DevHashTestEmbedder).expect("seed devhash");
        assert_eq!(
            seed.stored_embedding_model_id()
                .expect("devhash meta")
                .as_deref(),
            Some(s_core::MODEL_ID_DEVHASH)
        );
        let docs = [
            make_block(
                0,
                1_000_000,
                "garage.exe",
                "The automobile mechanic replaced the flat tire and checked the brake pads.",
            ),
            make_block(
                1,
                1_001_000,
                "WindowsTerminal.exe",
                "PostgreSQL deadlock occurred during a concurrent database transaction update.",
            ),
            make_block(
                2,
                1_002_000,
                "notes.exe",
                "Baking sourdough bread requires starter fermentation and steam inside the oven.",
            ),
            make_block(
                3,
                1_003_000,
                "excel.exe",
                "Quarterly revenue forecast and shareholder dividend statement for the fiscal year.",
            ),
        ];
        seed.ingest_batch(&docs).expect("ingest devhash docs");
        seed.connection()
            .execute(
                "DELETE FROM store_meta WHERE key = ?1",
                [s_core::EMBEDDING_MODEL_META_KEY],
            )
            .expect("simulate v0.1.0 missing store_meta");
    }

    let vector_only = HybridSearchConfig {
        bm25_weight: 0.0,
        vector_weight: 1.0,
        recency_weight: 0.0,
        ..HybridSearchConfig::default()
    };

    // 2. Open with lazy ManagedEmbedder -> SingleFp32 + arena=0:
    // before Ready, store_meta must stay None; after Ready, backfill clears DevHash and embeds FP32.
    {
        let managed = ManagedEmbedder::new();
        let mut store = MemoryStore::open_encrypted(&db_path, &key, managed.clone())
            .expect("open encrypted with unready ManagedEmbedder");
        assert_eq!(store.stored_embedding_model_id().expect("meta"), None);

        managed
            .init_fastembed(FastEmbedConfig {
                mode: FastEmbedMode::SingleFp32,
                cache_dir: isolated_cache.0.clone(),
                session_config: vec![("session.enable_cpu_mem_arena".into(), "0".into())],
                ..FastEmbedConfig::default()
            })
            .expect("init SingleFp32");
        assert_eq!(managed.model_id(), s_core::MODEL_ID_BGE_SMALL_EN_V15_FP32);

        assert_eq!(store.backfill_missing_embeddings(128).expect("backfill"), 4);
        assert_eq!(
            store
                .stored_embedding_model_id()
                .expect("fp32 meta")
                .as_deref(),
            Some(s_core::MODEL_ID_BGE_SMALL_EN_V15_FP32)
        );
        assert_eq!(
            store.pending_embedding_backfill_count().expect("pending"),
            0
        );

        let car_hits = store
            .hybrid_search_with_config("car repair service auto workshop", 4, &vector_only)
            .expect("FP32 semantic search car");
        assert_eq!(car_hits[0].event_id, 0);
        let sql_hits = store
            .hybrid_search_with_config("SQL table locking failure", 4, &vector_only)
            .expect("FP32 semantic search sql");
        assert_eq!(sql_hits[0].event_id, 1);
    }

    // 3. Reopen with same SingleFp32 -> nothing cleared or pending.
    {
        let single_fp32 = FastEmbedBackend::try_new(&FastEmbedConfig {
            mode: FastEmbedMode::SingleFp32,
            cache_dir: isolated_cache.0.clone(),
            session_config: vec![("session.enable_cpu_mem_arena".into(), "0".into())],
            ..FastEmbedConfig::default()
        })
        .expect("SingleFp32 backend");
        assert_eq!(
            single_fp32.model_id(),
            s_core::MODEL_ID_BGE_SMALL_EN_V15_FP32
        );
        let mut reopened = MemoryStore::open_encrypted(&db_path, &key, single_fp32)
            .expect("reopen same SingleFp32");
        assert!(!reopened.reconcile_embedding_model().expect("reconcile"));
        assert_eq!(
            reopened
                .pending_embedding_backfill_count()
                .expect("pending"),
            0
        );
        assert_eq!(reopened.backfill_missing_embeddings(128).expect("no-op"), 0);
    }

    // 4. Switch to DualFp32QueryInt8Batch (`bge-small-en-v1.5-q-int8`) -> clears & re-embeds.
    {
        let dual = FastEmbedBackend::try_new(&FastEmbedConfig {
            mode: FastEmbedMode::DualFp32QueryInt8Batch,
            cache_dir: isolated_cache.0.clone(),
            ..FastEmbedConfig::default()
        })
        .expect("Dual backend");
        assert_eq!(dual.model_id(), s_core::MODEL_ID_BGE_SMALL_EN_V15_Q_INT8);
        let mut store_dual =
            MemoryStore::open_encrypted(&db_path, &key, dual).expect("reopen as Dual");
        assert_eq!(
            store_dual
                .stored_embedding_model_id()
                .expect("dual meta")
                .as_deref(),
            Some(s_core::MODEL_ID_BGE_SMALL_EN_V15_Q_INT8)
        );
        assert_eq!(
            store_dual
                .pending_embedding_backfill_count()
                .expect("pending after switch"),
            4
        );
        assert_eq!(
            store_dual
                .backfill_missing_embeddings(128)
                .expect("backfill dual"),
            4
        );
        let sql_hits = store_dual
            .hybrid_search_with_config("SQL table locking failure", 4, &vector_only)
            .expect("Dual semantic search sql");
        assert_eq!(sql_hits[0].event_id, 1);
    }

    // 5. Switch back from Dual (`q-int8`) to SingleFp32 (`fp32`) -> clears & re-embeds back to FP32.
    {
        let single_fp32 = FastEmbedBackend::try_new(&FastEmbedConfig {
            mode: FastEmbedMode::SingleFp32,
            cache_dir: isolated_cache.0.clone(),
            session_config: vec![("session.enable_cpu_mem_arena".into(), "0".into())],
            ..FastEmbedConfig::default()
        })
        .expect("SingleFp32 backend");
        let mut store_fp32 =
            MemoryStore::open_encrypted(&db_path, &key, single_fp32).expect("reopen as SingleFp32");
        assert_eq!(
            store_fp32
                .pending_embedding_backfill_count()
                .expect("pending after Dual -> SingleFp32"),
            4
        );
        assert_eq!(
            store_fp32
                .backfill_missing_embeddings(128)
                .expect("backfill SingleFp32"),
            4
        );
        assert_eq!(
            store_fp32
                .stored_embedding_model_id()
                .expect("meta")
                .as_deref(),
            Some(s_core::MODEL_ID_BGE_SMALL_EN_V15_FP32)
        );
        let hits = store_fp32
            .hybrid_search_with_config("yeast dough pastry recipe", 4, &vector_only)
            .expect("SingleFp32 semantic search");
        assert_eq!(hits[0].event_id, 2);
    }

    let raw_bytes = std::fs::read(&db_path).expect("read encrypted db bytes");
    assert!(!raw_bytes.starts_with(b"SQLite format 3\0"));
    assert!(
        !raw_bytes
            .windows("PostgreSQL deadlock".len())
            .any(|w| w == b"PostgreSQL deadlock")
    );
}
