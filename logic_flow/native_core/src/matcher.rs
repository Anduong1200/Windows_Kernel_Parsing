/// Two-stage function matcher — the core diffing pipeline.
///
/// Stage 1 (Filter): Use SimHash Hamming distance to narrow candidates.
/// Stage 2 (Score): Combine minhash + winnowing for refined similarity.
///
/// Designed for Rayon parallelism on corpus operations.

use crate::simhash;
use crate::minhash;
use crate::winnowing;

/// Pre-computed sketch for a single function.
#[derive(Clone, Debug)]
pub struct FunctionSketch {
    pub ea: u64,
    pub name: String,
    pub simhash: u64,
    pub minhash: Vec<u32>,
    pub winnowing: Vec<u64>,
    pub size: u32,
}

/// Configuration for the matching pipeline.
#[derive(Clone, Debug)]
pub struct MatchConfig {
    /// Maximum Hamming distance for Stage 1 filter (default: 10)
    pub hamming_threshold: u32,
    /// Number of top candidates to return (default: 20)
    pub top_k: usize,
    /// Weights for combining scores
    pub weight_minhash: f64,
    pub weight_winnowing: f64,
    pub weight_size: f64,
}

impl Default for MatchConfig {
    fn default() -> Self {
        MatchConfig {
            hamming_threshold: 10,
            top_k: 20,
            weight_minhash: 0.4,
            weight_winnowing: 0.4,
            weight_size: 0.2,
        }
    }
}

/// A single match result.
#[derive(Clone, Debug)]
pub struct MatchResult {
    pub corpus_index: usize,
    pub corpus_ea: u64,
    pub corpus_name: String,
    pub score: f64,
    pub hamming_distance: u32,
}

/// Stage 1: Filter candidates by SimHash Hamming distance.
///
/// Returns indices into `corpus` that have Hamming distance ≤ threshold.
pub fn filter_candidates(
    query: &FunctionSketch,
    corpus: &[FunctionSketch],
    hamming_threshold: u32,
) -> Vec<usize> {
    corpus.iter().enumerate()
        .filter(|(_, c)| simhash::simhash_distance(query.simhash, c.simhash) <= hamming_threshold)
        .map(|(i, _)| i)
        .collect()
}

/// Stage 2: Score filtered candidates using combined similarity.
///
/// Returns (index, score) pairs sorted by score descending, limited to top_k.
pub fn score_candidates(
    query: &FunctionSketch,
    corpus: &[FunctionSketch],
    candidate_indices: &[usize],
    config: &MatchConfig,
) -> Vec<(usize, f64)> {
    let mut scores: Vec<(usize, f64)> = candidate_indices.iter()
        .filter_map(|&idx| {
            if idx >= corpus.len() { return None; }
            let c = &corpus[idx];

            // MinHash similarity
            let sim_minhash = minhash::minhash_similarity(&query.minhash, &c.minhash);

            // Winnowing similarity
            let sim_winnowing = winnowing::winnowing_similarity(&query.winnowing, &c.winnowing);

            // Size similarity (1.0 if identical, decreases with difference)
            let size_sim = if query.size == 0 && c.size == 0 {
                1.0
            } else {
                let max_size = query.size.max(c.size) as f64;
                let min_size = query.size.min(c.size) as f64;
                if max_size > 0.0 { min_size / max_size } else { 1.0 }
            };

            let combined = config.weight_minhash * sim_minhash
                + config.weight_winnowing * sim_winnowing
                + config.weight_size * size_sim;

            Some((idx, combined))
        })
        .collect();

    // Sort by score descending
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Limit to top_k
    scores.truncate(config.top_k);
    scores
}

/// Full pipeline: filter → score → return top-K matches.
pub fn match_function(
    query: &FunctionSketch,
    corpus: &[FunctionSketch],
    config: &MatchConfig,
) -> Vec<MatchResult> {
    // Stage 1: Filter
    let candidates = filter_candidates(query, corpus, config.hamming_threshold);

    // Stage 2: Score
    let scored = score_candidates(query, corpus, &candidates, config);

    // Convert to MatchResult
    scored.iter().map(|&(idx, score)| {
        let c = &corpus[idx];
        MatchResult {
            corpus_index: idx,
            corpus_ea: c.ea,
            corpus_name: c.name.clone(),
            score,
            hamming_distance: simhash::simhash_distance(query.simhash, c.simhash),
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sketch(ea: u64, name: &str, classes: &[u8], apis: &[&str], mnems: &[&str], size: u32) -> FunctionSketch {
        let api_strs: Vec<String> = apis.iter().map(|s| s.to_string()).collect();
        let mnem_strs: Vec<String> = mnems.iter().map(|s| s.to_string()).collect();
        FunctionSketch {
            ea,
            name: name.to_string(),
            simhash: simhash::compute_simhash(classes),
            minhash: minhash::compute_minhash(&api_strs, 64),
            winnowing: winnowing::compute_winnowing(&mnem_strs, 3, 3),
            size,
        }
    }

    #[test]
    fn test_exact_match_scores_high() {
        let classes = vec![b'T', b'C', b'J', b'P', b'T', b'A', b'C', b'T'];
        let apis = vec!["IoCreateDevice", "RtlCopyMemory"];
        let mnems = vec!["mov", "call", "jmp", "cmp", "mov", "add", "call", "ret"];

        let query = make_sketch(0x1000, "func_a", &classes, &apis, &mnems, 200);
        let corpus = vec![
            make_sketch(0x2000, "func_b", &classes, &apis, &mnems, 200), // identical
        ];

        let config = MatchConfig::default();
        let results = match_function(&query, &corpus, &config);

        assert_eq!(results.len(), 1);
        assert!(results[0].score > 0.9, "Expected high score for identical sketch, got {}", results[0].score);
    }

    #[test]
    fn test_filter_excludes_distant() {
        let query = FunctionSketch {
            ea: 0x1000,
            name: "f".to_string(),
            simhash: 0x0000_0000_0000_0000,
            minhash: vec![0; 64],
            winnowing: vec![],
            size: 100,
        };
        let corpus = vec![
            FunctionSketch {
                ea: 0x2000,
                name: "g".to_string(),
                simhash: 0xFFFF_FFFF_FFFF_FFFF, // Max distance = 64
                minhash: vec![0; 64],
                winnowing: vec![],
                size: 100,
            },
        ];

        let candidates = filter_candidates(&query, &corpus, 10);
        assert!(candidates.is_empty(), "Should filter out distant hash");
    }

    #[test]
    fn test_top_k_limits_results() {
        let classes = vec![b'T', b'C', b'J', b'P'];
        let apis: Vec<&str> = vec![];
        let mnems = vec!["mov", "call", "jmp", "ret"];

        let query = make_sketch(0x1000, "query", &classes, &apis, &mnems, 100);

        // Create 50 similar corpus entries
        let corpus: Vec<FunctionSketch> = (0..50u64)
            .map(|i| make_sketch(0x2000 + i * 0x100, &format!("func_{}", i), &classes, &apis, &mnems, 100))
            .collect();

        let config = MatchConfig { top_k: 5, ..Default::default() };
        let results = match_function(&query, &corpus, &config);
        assert!(results.len() <= 5);
    }
}
