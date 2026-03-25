/// MinHash — Jaccard similarity estimation via min-wise hashing.
///
/// For each function, compute k independent hash minimums over the set of
/// API calls (import names). The estimated Jaccard similarity is the fraction
/// of matching minimums.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Number of hash functions (higher = more accurate but more memory).
pub const DEFAULT_NUM_HASHES: usize = 128;

/// Compute a hash with a specific seed.
#[inline]
fn seeded_hash(value: &str, seed: u64) -> u32 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    value.hash(&mut hasher);
    hasher.finish() as u32
}

/// Compute MinHash signature for a set of strings (e.g., API call names).
///
/// Returns a Vec<u32> of length `num_hashes`, where each element is the
/// minimum hash value for that hash function across all items in the set.
pub fn compute_minhash(items: &[String], num_hashes: usize) -> Vec<u32> {
    let num_hashes = if num_hashes == 0 { DEFAULT_NUM_HASHES } else { num_hashes };
    let mut signature = vec![u32::MAX; num_hashes];

    if items.is_empty() {
        return signature;
    }

    for item in items {
        for (i, sig) in signature.iter_mut().enumerate() {
            let h = seeded_hash(item, i as u64);
            if h < *sig {
                *sig = h;
            }
        }
    }

    signature
}

/// Estimate Jaccard similarity from two MinHash signatures.
///
/// Returns a value in [0.0, 1.0]. Signatures must be the same length.
pub fn minhash_similarity(sig_a: &[u32], sig_b: &[u32]) -> f64 {
    if sig_a.len() != sig_b.len() || sig_a.is_empty() {
        return 0.0;
    }

    let matching = sig_a.iter().zip(sig_b.iter())
        .filter(|(&a, &b)| a == b)
        .count();

    matching as f64 / sig_a.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_sets_perfect_similarity() {
        let items: Vec<String> = vec!["IoCreateDevice", "RtlCopyMemory", "ExAllocatePool"]
            .into_iter().map(String::from).collect();
        let sig1 = compute_minhash(&items, DEFAULT_NUM_HASHES);
        let sig2 = compute_minhash(&items, DEFAULT_NUM_HASHES);
        assert_eq!(minhash_similarity(&sig1, &sig2), 1.0);
    }

    #[test]
    fn test_disjoint_sets_low_similarity() {
        let set_a: Vec<String> = vec!["IoCreateDevice", "RtlCopyMemory"]
            .into_iter().map(String::from).collect();
        let set_b: Vec<String> = vec!["ExAllocatePool", "MmMapIoSpace"]
            .into_iter().map(String::from).collect();

        let sig_a = compute_minhash(&set_a, DEFAULT_NUM_HASHES);
        let sig_b = compute_minhash(&set_b, DEFAULT_NUM_HASHES);
        let sim = minhash_similarity(&sig_a, &sig_b);
        // Disjoint sets should have low similarity (near 0, but not exact due to hash collisions)
        assert!(sim < 0.3, "Expected low similarity for disjoint sets, got {}", sim);
    }

    #[test]
    fn test_overlapping_sets() {
        let set_a: Vec<String> = vec!["IoCreateDevice", "RtlCopyMemory", "ExAllocatePool"]
            .into_iter().map(String::from).collect();
        let set_b: Vec<String> = vec!["IoCreateDevice", "RtlCopyMemory", "MmMapIoSpace"]
            .into_iter().map(String::from).collect();

        let sig_a = compute_minhash(&set_a, DEFAULT_NUM_HASHES);
        let sig_b = compute_minhash(&set_b, DEFAULT_NUM_HASHES);
        let sim = minhash_similarity(&sig_a, &sig_b);
        // Jaccard of {A,B,C} vs {A,B,D} = 2/4 = 0.5
        // MinHash should approximate this
        assert!(sim > 0.2 && sim < 0.8,
                "Expected ~0.5 for 2/4 overlap, got {}", sim);
    }

    #[test]
    fn test_empty_set() {
        let empty: Vec<String> = vec![];
        let sig = compute_minhash(&empty, DEFAULT_NUM_HASHES);
        assert_eq!(sig.len(), DEFAULT_NUM_HASHES);
        assert!(sig.iter().all(|&v| v == u32::MAX));
    }

    #[test]
    fn test_deterministic() {
        let items: Vec<String> = vec!["A", "B", "C"]
            .into_iter().map(String::from).collect();
        let s1 = compute_minhash(&items, 64);
        let s2 = compute_minhash(&items, 64);
        assert_eq!(s1, s2);
    }
}
