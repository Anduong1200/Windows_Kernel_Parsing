/// Weisfeiler-Leman (WL) neighborhood hashing for structural refinement.
///
/// For each function node, collects 1-hop and 2-hop callee/caller names,
/// then iteratively hashes the multiset of neighbor labels to produce
/// a structural context fingerprint.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Compute WL hash for a node given its label and neighbor labels.
///
/// Performs `rounds` iterations of WL relabeling:
/// - Round 0: hash(node_label)
/// - Round 1: hash(node_label, sorted(1-hop neighbors))
/// - Round 2: hash(node_label, sorted(1-hop neighbors), sorted(2-hop neighbors))
pub fn compute_wl_hash(
    node_label: &str,
    neighbors_1hop: &[String],
    neighbors_2hop: &[String],
    rounds: usize,
) -> u64 {
    let mut hasher = DefaultHasher::new();

    // Round 0: Just the node label
    node_label.hash(&mut hasher);

    if rounds >= 1 && !neighbors_1hop.is_empty() {
        // Round 1: Include sorted 1-hop neighbors
        let mut sorted_1hop: Vec<&str> = neighbors_1hop.iter().map(|s| s.as_str()).collect();
        sorted_1hop.sort();
        for n in &sorted_1hop {
            n.hash(&mut hasher);
        }
        // Also hash the count for disambiguation
        sorted_1hop.len().hash(&mut hasher);
    }

    if rounds >= 2 && !neighbors_2hop.is_empty() {
        // Round 2: Include sorted 2-hop neighbors
        let mut sorted_2hop: Vec<&str> = neighbors_2hop.iter().map(|s| s.as_str()).collect();
        sorted_2hop.sort();
        for n in &sorted_2hop {
            n.hash(&mut hasher);
        }
        sorted_2hop.len().hash(&mut hasher);
    }

    hasher.finish()
}

/// Distance between two WL hashes (0 = identical, 1 = different).
#[inline]
pub fn wl_hash_distance(a: u64, b: u64) -> u32 {
    if a == b { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_identical_neighborhoods() {
        let n1 = strs(&["IoCreateDevice", "RtlCopyMemory"]);
        let n2 = strs(&["ExAllocatePool"]);

        let h1 = compute_wl_hash("DriverEntry", &n1, &n2, 2);
        let h2 = compute_wl_hash("DriverEntry", &n1, &n2, 2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_neighbors_different_hash() {
        let n1a = strs(&["IoCreateDevice", "RtlCopyMemory"]);
        let n1b = strs(&["IoCreateDevice", "ExAllocatePool"]); // different

        let h1 = compute_wl_hash("func", &n1a, &[], 1);
        let h2 = compute_wl_hash("func", &n1b, &[], 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_order_invariant() {
        // WL hash sorts neighbors, so order shouldn't matter
        let n1 = strs(&["B", "A", "C"]);
        let n2 = strs(&["A", "B", "C"]);

        let h1 = compute_wl_hash("func", &n1, &[], 1);
        let h2 = compute_wl_hash("func", &n2, &[], 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_rounds_add_specificity() {
        let n1 = strs(&["A"]);
        let n2 = strs(&["B"]);

        // Round 0 (label only) should be same
        let h0a = compute_wl_hash("func", &n1, &n2, 0);
        let h0b = compute_wl_hash("func", &n1, &[], 0);
        assert_eq!(h0a, h0b);

        // Round 1 (with 1-hop) should still match since same 1-hop
        let h1a = compute_wl_hash("func", &n1, &n2, 1);
        let h1b = compute_wl_hash("func", &n1, &[], 1);
        assert_eq!(h1a, h1b); // Same 1-hop, 2-hop not used in round 1

        // Round 2 should differ
        let h2a = compute_wl_hash("func", &n1, &n2, 2);
        let h2b = compute_wl_hash("func", &n1, &[], 2);
        assert_ne!(h2a, h2b);
    }
}
