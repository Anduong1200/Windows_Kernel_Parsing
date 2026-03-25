/// Winnowing — Fingerprinting via k-gram hashing with window selection.
///
/// Generates a compact fingerprint for a mnemonic sequence by:
/// 1. Creating k-grams (k consecutive mnemonics)
/// 2. Hashing each k-gram
/// 3. Selecting the minimum hash in each sliding window of size w
/// 4. Deduplicating to produce the final fingerprint
///
/// Winnowing guarantees that any shared k-gram substring between two sequences
/// will produce at least one matching fingerprint element.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Default k-gram size.
pub const DEFAULT_K: usize = 5;
/// Default window size.
pub const DEFAULT_W: usize = 4;

/// Hash a k-gram (slice of strings joined).
#[inline]
fn hash_kgram(kgram: &[String]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for s in kgram {
        s.hash(&mut hasher);
        // Add separator to avoid collisions like ["ab","c"] vs ["a","bc"]
        0xFFu8.hash(&mut hasher);
    }
    hasher.finish()
}

/// Compute winnowing fingerprint from a mnemonic sequence.
///
/// Returns a sorted, deduplicated Vec<u64> of selected hash values.
pub fn compute_winnowing(mnemonics: &[String], k: usize, w: usize) -> Vec<u64> {
    let k = if k == 0 { DEFAULT_K } else { k };
    let w = if w == 0 { DEFAULT_W } else { w };

    if mnemonics.len() < k {
        // Not enough mnemonics for even one k-gram
        if mnemonics.is_empty() {
            return vec![];
        }
        // Hash the entire sequence as a single fingerprint
        return vec![hash_kgram(mnemonics)];
    }

    // Step 1: Generate k-gram hashes
    let num_kgrams = mnemonics.len() - k + 1;
    let kgram_hashes: Vec<u64> = (0..num_kgrams)
        .map(|i| hash_kgram(&mnemonics[i..i + k]))
        .collect();

    if kgram_hashes.len() < w {
        // Window larger than available hashes — just take the minimum
        if let Some(&min_h) = kgram_hashes.iter().min() {
            return vec![min_h];
        }
        return vec![];
    }

    // Step 2: Winnowing — select minimum hash in each window
    let mut selected: Vec<u64> = Vec::with_capacity(kgram_hashes.len());
    let mut prev_min_idx: Option<usize> = None;

    for window_start in 0..=(kgram_hashes.len() - w) {
        let window = &kgram_hashes[window_start..window_start + w];

        // Find rightmost minimum in window (rightmost to maximize freshness)
        let mut min_val = window[0];
        let mut min_idx = window_start;
        for (j, &h) in window.iter().enumerate() {
            if h <= min_val {
                min_val = h;
                min_idx = window_start + j;
            }
        }

        // Only add if this is a new selection
        if prev_min_idx != Some(min_idx) {
            selected.push(min_val);
            prev_min_idx = Some(min_idx);
        }
    }

    // Step 3: Sort and deduplicate
    selected.sort();
    selected.dedup();
    selected
}

/// Compute Jaccard similarity between two winnowing fingerprints.
///
/// Both fingerprints must be sorted (as produced by compute_winnowing).
pub fn winnowing_similarity(fp_a: &[u64], fp_b: &[u64]) -> f64 {
    if fp_a.is_empty() && fp_b.is_empty() {
        return 1.0;
    }
    if fp_a.is_empty() || fp_b.is_empty() {
        return 0.0;
    }

    // Merge-based intersection/union count (both sorted)
    let mut i = 0;
    let mut j = 0;
    let mut intersection = 0usize;
    let mut union = 0usize;

    while i < fp_a.len() && j < fp_b.len() {
        if fp_a[i] == fp_b[j] {
            intersection += 1;
            union += 1;
            i += 1;
            j += 1;
        } else if fp_a[i] < fp_b[j] {
            union += 1;
            i += 1;
        } else {
            union += 1;
            j += 1;
        }
    }
    union += (fp_a.len() - i) + (fp_b.len() - j);

    if union == 0 {
        return 1.0;
    }
    intersection as f64 / union as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_identical_sequences() {
        let seq = strs(&["mov", "push", "call", "ret", "mov", "push", "call", "ret"]);
        let fp1 = compute_winnowing(&seq, 3, 3);
        let fp2 = compute_winnowing(&seq, 3, 3);
        assert_eq!(winnowing_similarity(&fp1, &fp2), 1.0);
    }

    #[test]
    fn test_empty_sequence() {
        let fp = compute_winnowing(&[], 5, 4);
        assert!(fp.is_empty());
    }

    #[test]
    fn test_short_sequence() {
        let seq = strs(&["mov", "call"]);
        let fp = compute_winnowing(&seq, 5, 4);
        assert_eq!(fp.len(), 1); // Single hash for the whole thing
    }

    #[test]
    fn test_different_sequences_low_similarity() {
        let seq_a = strs(&["mov", "push", "call", "ret", "add", "sub", "jmp", "nop"]);
        let seq_b = strs(&["xor", "xor", "cmp", "jnz", "lea", "test", "jz", "ret"]);
        let fp_a = compute_winnowing(&seq_a, 3, 3);
        let fp_b = compute_winnowing(&seq_b, 3, 3);
        let sim = winnowing_similarity(&fp_a, &fp_b);
        assert!(sim < 0.5, "Expected low similarity, got {}", sim);
    }

    #[test]
    fn test_similar_sequences_moderate_similarity() {
        let seq_a = strs(&["mov", "push", "call", "ret", "mov", "add", "call", "ret"]);
        let mut seq_b = seq_a.clone();
        seq_b[5] = "sub".to_string(); // One change
        let fp_a = compute_winnowing(&seq_a, 3, 3);
        let fp_b = compute_winnowing(&seq_b, 3, 3);
        let sim = winnowing_similarity(&fp_a, &fp_b);
        assert!(sim > 0.3, "Expected moderate similarity, got {}", sim);
    }

    #[test]
    fn test_deterministic() {
        let seq = strs(&["mov", "push", "call", "ret", "jmp"]);
        let fp1 = compute_winnowing(&seq, DEFAULT_K, DEFAULT_W);
        let fp2 = compute_winnowing(&seq, DEFAULT_K, DEFAULT_W);
        assert_eq!(fp1, fp2);
    }
}
