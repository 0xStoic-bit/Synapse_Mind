//! Rule-based causality linking between sequential `MaskedMemoryBlock` events.

use std::collections::{HashMap, HashSet, VecDeque};

use rusqlite::{Connection, Transaction, params};
use s_types::{AppContext, CausalityEdge, EventSource, MaskedMemoryBlock};

use crate::{CoreError, Result};

/// Configuration for rule-based causality edge generation and chain traversal.
#[derive(Debug, Clone)]
pub struct CausalityConfig {
    /// Maximum allowed gap (in seconds) between two linked sequential events.
    pub max_window_seconds: u32,
    /// Maximum BFS hop depth when reconstructing `causality_chain` for a search hit.
    pub max_chain_depth: usize,
    /// Maximum edges included in a single `CausalityQueryHit::causality_chain`.
    pub max_chain_edges: usize,
}

impl Default for CausalityConfig {
    fn default() -> Self {
        Self {
            max_window_seconds: 120,
            max_chain_depth: 5,
            max_chain_edges: 16,
        }
    }
}

/// Evaluates deterministic causality rules between `prev` and `curr` within `config.max_window_seconds`.
pub fn classify_transition(
    prev: &MaskedMemoryBlock,
    curr: &MaskedMemoryBlock,
    config: &CausalityConfig,
) -> Option<CausalityEdge> {
    if prev.event_id == curr.event_id || curr.timestamp_ms < prev.timestamp_ms {
        return None;
    }
    let delta_ms = curr.timestamp_ms - prev.timestamp_ms;
    let max_window_ms = u64::from(config.max_window_seconds).saturating_mul(1000);
    if delta_ms > max_window_ms {
        return None;
    }
    let time_delta_seconds = u32::try_from(delta_ms / 1000).unwrap_or(u32::MAX);

    let relationship = if looks_like_error(prev)
        && looks_like_search_target(&curr.app_context)
        && (!prev
            .app_context
            .process_name
            .eq_ignore_ascii_case(&curr.app_context.process_name)
            || !prev.app_context.is_browser)
    {
        "searched_after_error"
    } else if is_clipboard_transition(prev, curr) {
        "pasted_from_clipboard"
    } else if !prev
        .app_context
        .process_name
        .eq_ignore_ascii_case(&curr.app_context.process_name)
    {
        "switched_app_after"
    } else if prev.app_context.sanitized_title != curr.app_context.sanitized_title {
        "switched_window_after"
    } else {
        return None;
    };

    Some(CausalityEdge {
        source_event_id: prev.event_id,
        target_event_id: curr.event_id,
        relationship: relationship.to_owned(),
        time_delta_seconds,
    })
}

fn contains_any_ascii_ci(haystack: &str, needles: &[&str]) -> bool {
    let lower = haystack.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn looks_like_error(block: &MaskedMemoryBlock) -> bool {
    const ERROR_MARKERS: &[&str] = &[
        "error",
        "exit code",
        "panic",
        "exception",
        "traceback",
        "failed",
        "fatal",
        "cannot find",
        "not found",
        "unresolved",
        "errno",
    ];
    contains_any_ascii_ci(&block.clean_text, ERROR_MARKERS)
        || contains_any_ascii_ci(&block.app_context.sanitized_title, ERROR_MARKERS)
}

fn looks_like_search_target(ctx: &AppContext) -> bool {
    const SEARCH_MARKERS: &[&str] = &[
        "search",
        "google",
        "duckduckgo",
        "bing",
        "stackoverflow",
        "stack overflow",
        "github",
        "docs.rs",
        "crates.io",
    ];
    ctx.is_browser || contains_any_ascii_ci(&ctx.sanitized_title, SEARCH_MARKERS)
}

/// Definitive clipboard-to-target rule (ADR-003): only `EventSource::Clipboard`
/// establishes a clipboard origin, eliminating user-controllable title/process
/// heuristics (`is_clipboard_context`) and non-clipboard text-overlap false positives.
fn is_clipboard_transition(prev: &MaskedMemoryBlock, curr: &MaskedMemoryBlock) -> bool {
    prev.source == EventSource::Clipboard && curr.source != EventSource::Clipboard
}

/// Fetches recent precursor blocks within the causality window and persists inferred edges.
pub(crate) fn link_event_in_tx(
    tx: &Transaction<'_>,
    curr: &MaskedMemoryBlock,
    config: &CausalityConfig,
) -> Result<Vec<CausalityEdge>> {
    let curr_id_i64 = i64::try_from(curr.event_id)
        .map_err(|_| CoreError::IntegerOverflow("event_id exceeds i64::MAX"))?;
    let curr_ts_i64 = i64::try_from(curr.timestamp_ms)
        .map_err(|_| CoreError::IntegerOverflow("timestamp_ms exceeds i64::MAX"))?;
    let window_ms = u64::from(config.max_window_seconds).saturating_mul(1000);
    let min_ts_i64 = i64::try_from(curr.timestamp_ms.saturating_sub(window_ms))
        .map_err(|_| CoreError::IntegerOverflow("min timestamp_ms exceeds i64::MAX"))?;

    let recent = {
        let mut stmt = tx.prepare_cached(
            "SELECT event_id, timestamp_ms, process_name, sanitized_title, is_browser,
                    clean_text, text_hash, redactions_count, has_embedding_payload, source
             FROM events
             WHERE timestamp_ms <= ?1 AND timestamp_ms >= ?2 AND event_id != ?3
             ORDER BY timestamp_ms DESC, event_id DESC
             LIMIT 4",
        )?;
        let rows = stmt.query_map(params![curr_ts_i64, min_ts_i64, curr_id_i64], |row| {
            row_to_masked_block(row)
        })?;
        let mut collected = Vec::new();
        for row in rows {
            collected.push(row?);
        }
        collected
    };

    let Some(immediate_prev) = recent.first() else {
        return Ok(Vec::new());
    };

    let mut edges = Vec::new();
    if let Some(edge) = classify_transition(immediate_prev, curr, config) {
        edges.push(edge);
    }

    // If the immediate precursor had empty text (e.g. transient focus switch),
    // inspect the nearest earlier substantive block within the same window so
    // `error -> search` or `clipboard -> paste` links are not severed.
    if immediate_prev.clean_text.trim().is_empty()
        && let Some(substantive_prev) = recent
            .iter()
            .skip(1)
            .find(|b| !b.clean_text.trim().is_empty())
        && let Some(edge) = classify_transition(substantive_prev, curr, config)
        && matches!(
            edge.relationship.as_str(),
            "searched_after_error" | "pasted_from_clipboard"
        )
    {
        edges.push(edge);
    }

    let mut insert_stmt = tx.prepare_cached(
        "INSERT OR IGNORE INTO causality_edges
             (source_event_id, target_event_id, relationship, time_delta_seconds)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for edge in &edges {
        let src = i64::try_from(edge.source_event_id)
            .map_err(|_| CoreError::IntegerOverflow("source_event_id exceeds i64::MAX"))?;
        let dst = i64::try_from(edge.target_event_id)
            .map_err(|_| CoreError::IntegerOverflow("target_event_id exceeds i64::MAX"))?;
        insert_stmt.execute(params![
            src,
            dst,
            edge.relationship,
            i64::from(edge.time_delta_seconds)
        ])?;
    }

    Ok(edges)
}

/// Reconstructs the bounded bidirectional causality chain connected to `anchor_event_id`.
pub(crate) fn load_causality_chain(
    conn: &Connection,
    anchor_event_id: u64,
    max_depth: usize,
    max_edges: usize,
) -> Result<Vec<CausalityEdge>> {
    let mut chains = load_causality_chains_batch(conn, &[anchor_event_id], max_depth, max_edges)?;
    Ok(chains.pop().unwrap_or_default())
}

/// Reconstructs bounded bidirectional causality chains for all `anchors` in order,
/// batching frontier edge queries per BFS depth across all anchors to minimize SQLite round-trips.
pub(crate) fn load_causality_chains_batch(
    conn: &Connection,
    anchors: &[u64],
    max_depth: usize,
    max_edges: usize,
) -> Result<Vec<Vec<CausalityEdge>>> {
    const CHUNK_SIZE: usize = 256;

    if anchors.is_empty() || max_depth == 0 || max_edges == 0 {
        return Ok(vec![Vec::new(); anchors.len()]);
    }

    let mut fetched_nodes: HashSet<u64> = HashSet::new();
    let mut frontier: Vec<u64> = Vec::with_capacity(anchors.len());
    for &anchor in anchors {
        if fetched_nodes.insert(anchor) {
            frontier.push(anchor);
        }
    }

    let mut seen_global_edges: HashSet<(u64, u64, String)> = HashSet::new();
    let mut adj: HashMap<u64, Vec<CausalityEdge>> = HashMap::new();

    for _depth in 0..max_depth {
        if frontier.is_empty() {
            break;
        }
        let mut next_frontier = Vec::new();
        for chunk in frontier.chunks(CHUNK_SIZE) {
            let bucket_len = chunk.len().next_power_of_two().min(CHUNK_SIZE);
            let mut id_params: Vec<i64> = Vec::with_capacity(bucket_len);
            for &id in chunk {
                id_params.push(
                    i64::try_from(id)
                        .map_err(|_| CoreError::IntegerOverflow("node_id exceeds i64::MAX"))?,
                );
            }
            if let Some(&pad_id) = id_params.first() {
                id_params.resize(bucket_len, pad_id);
            }
            let placeholders = vec!["?"; id_params.len()].join(",");
            let sql = format!(
                "SELECT source_event_id, target_event_id, relationship, time_delta_seconds
                 FROM causality_edges
                 WHERE source_event_id IN ({placeholders})
                 UNION ALL
                 SELECT source_event_id, target_event_id, relationship, time_delta_seconds
                 FROM causality_edges
                 WHERE target_event_id IN ({placeholders})"
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(
                rusqlite::params_from_iter(id_params.iter().chain(id_params.iter())),
                |row| {
                    let src: i64 = row.get(0)?;
                    let dst: i64 = row.get(1)?;
                    let relationship: String = row.get(2)?;
                    let delta: i64 = row.get(3)?;
                    Ok((src, dst, relationship, delta))
                },
            )?;
            for row in rows {
                let (src_i64, dst_i64, relationship, delta_i64) = row?;
                let src = u64::try_from(src_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative source_event_id in DB"))?;
                let dst = u64::try_from(dst_i64)
                    .map_err(|_| CoreError::IntegerOverflow("negative target_event_id in DB"))?;
                let delta = u32::try_from(delta_i64).map_err(|_| {
                    CoreError::IntegerOverflow("time_delta_seconds out of u32 range")
                })?;

                if seen_global_edges.insert((src, dst, relationship.clone())) {
                    let edge = CausalityEdge {
                        source_event_id: src,
                        target_event_id: dst,
                        relationship,
                        time_delta_seconds: delta,
                    };
                    adj.entry(src).or_default().push(edge.clone());
                    if src != dst {
                        adj.entry(dst).or_default().push(edge);
                    }
                    if fetched_nodes.insert(src) {
                        next_frontier.push(src);
                    }
                    if fetched_nodes.insert(dst) {
                        next_frontier.push(dst);
                    }
                }
            }
        }
        frontier = next_frontier;
    }

    for edges in adj.values_mut() {
        edges.sort_by(|a, b| {
            a.source_event_id
                .cmp(&b.source_event_id)
                .then_with(|| a.target_event_id.cmp(&b.target_event_id))
                .then_with(|| a.relationship.cmp(&b.relationship))
        });
    }

    let mut results = Vec::with_capacity(anchors.len());
    for &anchor in anchors {
        let mut visited_nodes = HashSet::new();
        let mut seen_edges: HashSet<(u64, u64, String)> = HashSet::new();
        let mut chain = Vec::new();
        let mut queue = VecDeque::new();

        visited_nodes.insert(anchor);
        queue.push_back((anchor, 0_usize));

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= max_depth || chain.len() >= max_edges {
                continue;
            }
            if let Some(node_edges) = adj.get(&node_id) {
                for edge in node_edges {
                    if chain.len() >= max_edges {
                        break;
                    }
                    if seen_edges.insert((
                        edge.source_event_id,
                        edge.target_event_id,
                        edge.relationship.clone(),
                    )) {
                        chain.push(edge.clone());
                    }
                    let neighbor = if edge.source_event_id == node_id {
                        edge.target_event_id
                    } else {
                        edge.source_event_id
                    };
                    if visited_nodes.insert(neighbor) {
                        queue.push_back((neighbor, depth + 1));
                    }
                }
            }
        }

        chain.sort_by(|a, b| {
            a.source_event_id
                .cmp(&b.source_event_id)
                .then_with(|| a.target_event_id.cmp(&b.target_event_id))
                .then_with(|| a.relationship.cmp(&b.relationship))
        });
        results.push(chain);
    }

    Ok(results)
}

pub(crate) fn row_to_masked_block(row: &rusqlite::Row<'_>) -> rusqlite::Result<MaskedMemoryBlock> {
    let event_id_i64: i64 = row.get(0)?;
    let timestamp_ms_i64: i64 = row.get(1)?;
    let process_name: String = row.get(2)?;
    let sanitized_title: String = row.get(3)?;
    let is_browser_i64: i64 = row.get(4)?;
    let clean_text: String = row.get(5)?;
    let hash_vec: Vec<u8> = row.get(6)?;
    let redactions_i64: i64 = row.get(7)?;
    let has_embed_i64: i64 = row.get(8)?;
    let source_code: String = row.get(9)?;

    let text_hash: [u8; 32] = hash_vec.try_into().map_err(|v: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Blob,
            format!("expected 32-byte text_hash, got {}", v.len()).into(),
        )
    })?;

    let event_id = u64::try_from(event_id_i64).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
    })?;
    let timestamp_ms = u64::try_from(timestamp_ms_i64).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Integer, Box::new(err))
    })?;
    let source = EventSource::parse(&source_code).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            format!("unknown event source code {source_code:?}").into(),
        )
    })?;
    if redactions_i64 < 0 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Integer,
            "negative redactions_count in DB".into(),
        ));
    }

    Ok(MaskedMemoryBlock {
        event_id,
        timestamp_ms,
        app_context: AppContext {
            process_name,
            sanitized_title,
            is_browser: is_browser_i64 != 0,
        },
        clean_text,
        text_hash,
        redactions_count: u16::try_from(redactions_i64).unwrap_or(u16::MAX),
        has_embedding_payload: has_embed_i64 != 0,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(
        event_id: u64,
        timestamp_ms: u64,
        process_name: &str,
        sanitized_title: &str,
        is_browser: bool,
        clean_text: &str,
    ) -> MaskedMemoryBlock {
        let mut hash = [0_u8; 32];
        let bytes = clean_text.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            hash[i % 32] ^= *b;
        }
        MaskedMemoryBlock {
            event_id,
            timestamp_ms,
            app_context: AppContext {
                process_name: process_name.to_owned(),
                sanitized_title: sanitized_title.to_owned(),
                is_browser,
            },
            clean_text: clean_text.to_owned(),
            text_hash: hash,
            redactions_count: 0,
            has_embedding_payload: !clean_text.trim().is_empty(),
            source: EventSource::Accessibility,
        }
    }

    #[test]
    fn searched_after_error_within_window() {
        let cfg = CausalityConfig::default();
        let err = make_block(
            1,
            1_000_000,
            "WindowsTerminal.exe",
            "cargo build",
            false,
            "error: linking with link.exe failed (Exit Code 1)",
        );
        let search = make_block(
            2,
            1_015_000,
            "brave.exe",
            "pyo3 abi3 symbol not found - Search",
            true,
            "StackOverflow pyo3 abi3 linking fix",
        );
        let edge = classify_transition(&err, &search, &cfg).expect("edge expected");
        assert_eq!(edge.source_event_id, 1);
        assert_eq!(edge.target_event_id, 2);
        assert_eq!(edge.relationship, "searched_after_error");
        assert_eq!(edge.time_delta_seconds, 15);
    }

    #[test]
    fn clipboard_transition_requires_event_source_and_ignores_title_heuristic() {
        let cfg = CausalityConfig::default();

        // User-controlled title or process containing "clipboard" without `EventSource::Clipboard`
        // must NOT forge a `pasted_from_clipboard` edge.
        let fake_clip = make_block(
            10,
            2_000_000,
            "clipboard",
            "Clipboard API - MDN",
            false,
            "#[link(name = \"python3\")]",
        );
        let editor = make_block(
            11,
            2_010_000,
            "Code.exe",
            "build.rs - VS Code",
            false,
            "fn main() { println!(\"cargo:rustc-link-lib=python3\"); }",
        );
        let edge1 = classify_transition(&fake_clip, &editor, &cfg).expect("app switch expected");
        assert_eq!(edge1.relationship, "switched_app_after");

        // Shared >=16-char text or identical text_hash between non-Clipboard events is not a paste.
        let browser = make_block(
            20,
            3_000_000,
            "brave.exe",
            "StackOverflow",
            true,
            "println!(\"cargo:rustc-rerun-if-changed=build.rs\");",
        );
        let vscode = make_block(
            21,
            3_008_000,
            "Code.exe",
            "build.rs - VS Code",
            false,
            "fn main() {\n    println!(\"cargo:rustc-rerun-if-changed=build.rs\");\n}",
        );
        let edge2 = classify_transition(&browser, &vscode, &cfg).expect("app switch expected");
        assert_eq!(edge2.relationship, "switched_app_after");

        let mut identical_hash_target = browser.clone();
        identical_hash_target.event_id = 22;
        identical_hash_target.timestamp_ms = 3_009_000;
        identical_hash_target.app_context.process_name = "Code.exe".to_owned();
        let edge3 = classify_transition(&browser, &identical_hash_target, &cfg)
            .expect("app switch expected");
        assert_eq!(edge3.relationship, "switched_app_after");

        // Genuine `EventSource::Clipboard` still links even when target title mentions "Clipboard".
        let mut real_clip = fake_clip;
        real_clip.source = EventSource::Clipboard;
        let mut clipboard_titled_target = editor;
        clipboard_titled_target.app_context.sanitized_title = "Clipboard notes.md".to_owned();
        let edge4 = classify_transition(&real_clip, &clipboard_titled_target, &cfg)
            .expect("real clipboard edge");
        assert_eq!(edge4.relationship, "pasted_from_clipboard");
        assert_eq!(edge4.time_delta_seconds, 10);
    }

    #[test]
    fn pasted_from_clipboard_by_event_source_for_short_copy() {
        let cfg = CausalityConfig::default();
        // <16 karakter: içerik eşleşmesi yetmez; kesin sinyal `source == Clipboard`.
        let mut copy = make_block(30, 4_000_000, "brave.exe", "Docs", true, "cargo fmt");
        let paste = make_block(
            31,
            4_005_000,
            "WindowsTerminal.exe",
            "pwsh",
            false,
            "PS> cargo fmt",
        );
        assert!(
            classify_transition(&copy, &paste, &cfg)
                .is_none_or(|e| e.relationship != "pasted_from_clipboard")
        );

        copy.source = EventSource::Clipboard;
        let edge = classify_transition(&copy, &paste, &cfg).expect("source-based clipboard edge");
        assert_eq!(edge.relationship, "pasted_from_clipboard");
        assert_eq!(edge.time_delta_seconds, 5);

        // Ardışık iki kopyalama bir yapıştırma değildir.
        let mut second_copy = paste.clone();
        second_copy.source = EventSource::Clipboard;
        assert!(
            classify_transition(&copy, &second_copy, &cfg)
                .is_none_or(|e| e.relationship != "pasted_from_clipboard")
        );
    }

    #[test]
    fn switched_app_and_switched_window_and_outside_window() {
        let cfg = CausalityConfig::default();
        let a = make_block(1, 100_000, "Code.exe", "main.rs", false, "fn main() {}");
        let b = make_block(2, 130_000, "Slack.exe", "general", false, "shipped v0.1");
        let e1 = classify_transition(&a, &b, &cfg).expect("app switch");
        assert_eq!(e1.relationship, "switched_app_after");

        let b2 = make_block(3, 145_000, "Slack.exe", "engineering", false, "status ok");
        let e2 = classify_transition(&b, &b2, &cfg).expect("window switch");
        assert_eq!(e2.relationship, "switched_window_after");

        let same = make_block(
            4,
            150_000,
            "Slack.exe",
            "engineering",
            false,
            "status updated",
        );
        assert!(classify_transition(&b2, &same, &cfg).is_none());

        let exact_boundary = make_block(
            5,
            145_000 + 120_000,
            "Code.exe",
            "lib.rs",
            false,
            "boundary",
        );
        let e3 =
            classify_transition(&b2, &exact_boundary, &cfg).expect("exact 120s boundary included");
        assert_eq!(e3.time_delta_seconds, 120);

        let too_late = make_block(6, 145_000 + 120_001, "Code.exe", "lib.rs", false, "late");
        assert!(classify_transition(&b2, &too_late, &cfg).is_none());
    }

    #[test]
    fn row_to_masked_block_rejects_negative_event_id_and_timestamp() {
        let conn = Connection::open_in_memory().expect("open in memory");
        let hash = [0_u8; 32];

        let neg_id_err = conn
            .query_row(
                "SELECT -1, 1000, 'Code.exe', 'main.rs', 0, 'text', ?1, 0, 1, 'focus'",
                params![hash.as_slice()],
                row_to_masked_block,
            )
            .expect_err("negative event_id must fail conversion");
        assert!(matches!(
            neg_id_err,
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, _)
        ));

        let neg_ts_err = conn
            .query_row(
                "SELECT 1, -5, 'Code.exe', 'main.rs', 0, 'text', ?1, 0, 1, 'focus'",
                params![hash.as_slice()],
                row_to_masked_block,
            )
            .expect_err("negative timestamp_ms must fail conversion");
        assert!(matches!(
            neg_ts_err,
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Integer, _)
        ));
    }

    #[test]
    fn row_to_masked_block_round_trips_source_and_rejects_unknown_code() {
        let conn = Connection::open_in_memory().expect("open in memory");
        let hash = [0_u8; 32];
        for source in EventSource::ALL {
            let block = conn
                .query_row(
                    "SELECT 1, 1000, 'Code.exe', 'main.rs', 0, 'text', ?1, 0, 1, ?2",
                    params![hash.as_slice(), source.as_str()],
                    row_to_masked_block,
                )
                .expect("known source code");
            assert_eq!(block.source, source);
        }

        let err = conn
            .query_row(
                "SELECT 1, 1000, 'Code.exe', 'main.rs', 0, 'text', ?1, 0, 1, 'keyboard'",
                params![hash.as_slice()],
                row_to_masked_block,
            )
            .expect_err("unknown source code must fail conversion");
        assert!(matches!(
            err,
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, _)
        ));
    }
}
