#![cfg(feature = "fastembed")]

use std::path::Path;

use s_core::{
    AppContext, DualEmbedder, Embedder, EventSource, FastEmbedder, HybridSearchConfig,
    MaskedMemoryBlock, MemoryStore,
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
