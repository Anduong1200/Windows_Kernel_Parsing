//! FastDiff Native Core — High-performance algorithms for binary diffing.
//!
//! This crate provides PyO3 bindings for:
//! - SimHash (instruction-class locality-sensitive hashing)
//! - MinHash (Jaccard estimation over API-call sets)
//! - Winnowing (mnemonic k-gram fingerprinting)
//! - Two-stage matcher (filter → score pipeline)
//! - WL Hash (Weisfeiler-Leman neighborhood hashing)
//! - Legacy utilities (Jaccard, BFS, graph compare)

use pyo3::prelude::*;
use std::collections::{HashSet, HashMap, VecDeque};

// Algorithm modules
pub mod simhash;
pub mod minhash;
pub mod winnowing;
pub mod matcher;
pub mod wl_hash;

// =========================================================================
// PyO3 Wrappers — SimHash
// =========================================================================

/// Compute 64-bit SimHash from a list of mnemonic strings.
#[pyfunction]
fn py_compute_simhash(mnemonics: Vec<String>) -> u64 {
    simhash::compute_simhash_from_mnemonics(&mnemonics)
}

/// Compute Hamming distance between two SimHash values.
#[pyfunction]
fn py_simhash_distance(a: u64, b: u64) -> u32 {
    simhash::simhash_distance(a, b)
}

// =========================================================================
// PyO3 Wrappers — MinHash
// =========================================================================

/// Compute MinHash signature from a list of strings (e.g., API call names).
#[pyfunction]
#[pyo3(signature = (items, num_hashes=128))]
fn py_compute_minhash(items: Vec<String>, num_hashes: usize) -> Vec<u32> {
    minhash::compute_minhash(&items, num_hashes)
}

/// Estimate Jaccard similarity from two MinHash signatures.
#[pyfunction]
fn py_minhash_similarity(sig_a: Vec<u32>, sig_b: Vec<u32>) -> f64 {
    minhash::minhash_similarity(&sig_a, &sig_b)
}

// =========================================================================
// PyO3 Wrappers — Winnowing
// =========================================================================

/// Compute winnowing fingerprint from a mnemonic sequence.
#[pyfunction]
#[pyo3(signature = (mnemonics, k=5, w=4))]
fn py_compute_winnowing(mnemonics: Vec<String>, k: usize, w: usize) -> Vec<u64> {
    winnowing::compute_winnowing(&mnemonics, k, w)
}

/// Compute Jaccard similarity between two winnowing fingerprints.
#[pyfunction]
fn py_winnowing_similarity(fp_a: Vec<u64>, fp_b: Vec<u64>) -> f64 {
    winnowing::winnowing_similarity(&fp_a, &fp_b)
}

// =========================================================================
// PyO3 Wrappers — WL Hash
// =========================================================================

/// Compute WL neighborhood hash for a node.
#[pyfunction]
#[pyo3(signature = (node_label, neighbors_1hop, neighbors_2hop, rounds=2))]
fn py_compute_wl_hash(
    node_label: String,
    neighbors_1hop: Vec<String>,
    neighbors_2hop: Vec<String>,
    rounds: usize,
) -> u64 {
    wl_hash::compute_wl_hash(&node_label, &neighbors_1hop, &neighbors_2hop, rounds)
}

// =========================================================================
// PyO3 Wrappers — Batch Matcher
// =========================================================================

/// Batch compute sketches and match functions between two sets.
///
/// Arguments:
///   old_funcs: List of (ea, name, [mnemonics], [api_calls], size)
///   new_funcs: List of (ea, name, [mnemonics], [api_calls], size)
///   hamming_threshold: Max SimHash distance for candidate filter
///   top_k: Number of top matches per function
///
/// Returns: List of (old_ea, new_ea, score, hamming_dist)
#[pyfunction]
#[pyo3(signature = (old_funcs, new_funcs, hamming_threshold=10, top_k=20))]
fn py_batch_match(
    old_funcs: Vec<(u64, String, Vec<String>, Vec<String>, u32)>,
    new_funcs: Vec<(u64, String, Vec<String>, Vec<String>, u32)>,
    hamming_threshold: u32,
    top_k: usize,
) -> Vec<(u64, u64, f64, u32)> {
    // Build corpus (new) sketches
    let corpus: Vec<matcher::FunctionSketch> = new_funcs.iter().map(|(ea, name, mnems, apis, size)| {
        matcher::FunctionSketch {
            ea: *ea,
            name: name.clone(),
            simhash: simhash::compute_simhash_from_mnemonics(mnems),
            minhash: minhash::compute_minhash(apis, 128),
            winnowing: winnowing::compute_winnowing(mnems, 5, 4),
            size: *size,
        }
    }).collect();

    let config = matcher::MatchConfig {
        hamming_threshold,
        top_k,
        ..Default::default()
    };

    let mut results = Vec::new();

    for (ea, _name, mnems, apis, size) in &old_funcs {
        let query = matcher::FunctionSketch {
            ea: *ea,
            name: _name.clone(),
            simhash: simhash::compute_simhash_from_mnemonics(mnems),
            minhash: minhash::compute_minhash(apis, 128),
            winnowing: winnowing::compute_winnowing(mnems, 5, 4),
            size: *size,
        };

        let matches = matcher::match_function(&query, &corpus, &config);
        for m in matches {
            results.push((query.ea, m.corpus_ea, m.score, m.hamming_distance));
        }
    }

    results
}

// =========================================================================
// Legacy Functions (kept for backward compatibility)
// =========================================================================

/// Calculate Jaccard Similarity between two sets of strings.
#[pyfunction]
fn calculate_jaccard_similarity(set_a: Vec<String>, set_b: Vec<String>) -> f64 {
    let set_a: HashSet<_> = set_a.into_iter().collect();
    let set_b: HashSet<_> = set_b.into_iter().collect();
    let intersection_count = set_a.intersection(&set_b).count();
    let union_count = set_a.union(&set_b).count();
    if union_count == 0 { 0.0 } else { intersection_count as f64 / union_count as f64 }
}

/// A graph traversal to find connected nodes (BFS).
#[pyfunction]
fn bfs_traversal(
    start_node: String,
    adjacency_list: HashMap<String, Vec<String>>,
    max_depth: Option<usize>,
) -> Vec<String> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let max_depth = max_depth.unwrap_or(usize::MAX);

    visited.insert(start_node.clone());
    queue.push_back((start_node, 0));
    let mut result = Vec::new();

    while let Some((current_node, depth)) = queue.pop_front() {
        result.push(current_node.clone());
        if depth >= max_depth { continue; }
        if let Some(neighbors) = adjacency_list.get(&current_node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    visited.insert(neighbor.clone());
                    queue.push_back((neighbor.clone(), depth + 1));
                }
            }
        }
    }
    result
}

// =========================================================================
// Python Module Registration
// =========================================================================

#[pymodule]
fn logic_flow_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // SimHash
    m.add_function(wrap_pyfunction!(py_compute_simhash, m)?)?;
    m.add_function(wrap_pyfunction!(py_simhash_distance, m)?)?;

    // MinHash
    m.add_function(wrap_pyfunction!(py_compute_minhash, m)?)?;
    m.add_function(wrap_pyfunction!(py_minhash_similarity, m)?)?;

    // Winnowing
    m.add_function(wrap_pyfunction!(py_compute_winnowing, m)?)?;
    m.add_function(wrap_pyfunction!(py_winnowing_similarity, m)?)?;

    // WL Hash
    m.add_function(wrap_pyfunction!(py_compute_wl_hash, m)?)?;

    // Batch Matcher
    m.add_function(wrap_pyfunction!(py_batch_match, m)?)?;

    // Legacy
    m.add_function(wrap_pyfunction!(calculate_jaccard_similarity, m)?)?;
    m.add_function(wrap_pyfunction!(bfs_traversal, m)?)?;

    Ok(())
}
