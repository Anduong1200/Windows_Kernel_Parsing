/// SimHash — 64-bit locality-sensitive hash over instruction-class sequences.
///
/// Each instruction is classified (Transfer/Arithmetic/Call/Jump/Logic/Compare/Other)
/// and hashed with position-dependent salting to produce a 64-bit fingerprint.
/// Similar instruction sequences produce hashes with low Hamming distance.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Instruction class codes (matches Python side)
const CLASS_TRANSFER: u8 = b'T';
const CLASS_ARITH: u8 = b'A';
const CLASS_CALL: u8 = b'C';
const CLASS_JUMP: u8 = b'J';
const CLASS_LOGIC: u8 = b'L';
const CLASS_COMPARE: u8 = b'P';
const CLASS_OTHER: u8 = b'X';

/// Map a mnemonic string to an instruction class byte.
pub fn classify_mnemonic(mnem: &str) -> u8 {
    let m = mnem.to_ascii_lowercase();
    let m = m.split_whitespace().next().unwrap_or("");
    match m {
        "mov" | "lea" | "push" | "pop" | "xchg" | "movzx" | "movsx" | "cmov"
        | "movsxd" | "movabs" | "movd" | "movq" => CLASS_TRANSFER,
        "add" | "sub" | "mul" | "div" | "inc" | "dec" | "imul" | "idiv" | "neg"
        | "adc" | "sbb" => CLASS_ARITH,
        "call" | "ret" | "retn" | "syscall" | "int" => CLASS_CALL,
        "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jge" | "jl" | "jle"
        | "ja" | "jae" | "jb" | "jbe" | "jc" | "jnc" | "jo" | "jno"
        | "js" | "jns" | "jp" | "jnp" | "jecxz" | "jrcxz" | "loop"
        | "loope" | "loopne" => CLASS_JUMP,
        "and" | "or" | "xor" | "not" | "shl" | "shr" | "sar" | "sal" | "rol"
        | "ror" | "rcl" | "rcr" | "bt" | "bts" | "btr" | "btc" | "bsf"
        | "bsr" | "bswap" | "andn" => CLASS_LOGIC,
        "cmp" | "test" => CLASS_COMPARE,
        _ => CLASS_OTHER,
    }
}

/// Compute a 64-bit SimHash from a sequence of instruction classes.
///
/// Algorithm:
/// 1. For each (position, class), compute hash_fn(class XOR position_salt)
/// 2. For each bit position 0..63, accumulate +1 if bit=1, -1 if bit=0
/// 3. Final hash: bit i = 1 if accumulator[i] > 0, else 0
pub fn compute_simhash(classes: &[u8]) -> u64 {
    if classes.is_empty() {
        return 0;
    }

    let mut v = [0i32; 64];

    for (pos, &class_byte) in classes.iter().enumerate() {
        // Position-dependent hash: combine class with position
        let mut hasher = DefaultHasher::new();
        let salted = (class_byte as u64) ^ (pos as u64).wrapping_mul(0x9E3779B97F4A7C15);
        salted.hash(&mut hasher);
        let h = hasher.finish();

        for bit in 0..64 {
            if (h >> bit) & 1 == 1 {
                v[bit] += 1;
            } else {
                v[bit] -= 1;
            }
        }
    }

    let mut result: u64 = 0;
    for bit in 0..64 {
        if v[bit] > 0 {
            result |= 1u64 << bit;
        }
    }
    result
}

/// Compute SimHash from a slice of mnemonic strings.
pub fn compute_simhash_from_mnemonics(mnemonics: &[String]) -> u64 {
    let classes: Vec<u8> = mnemonics.iter().map(|m| classify_mnemonic(m)).collect();
    compute_simhash(&classes)
}

/// Hamming distance between two SimHash values.
#[inline]
pub fn simhash_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_sequences_same_hash() {
        let classes = vec![CLASS_TRANSFER, CLASS_CALL, CLASS_JUMP, CLASS_COMPARE];
        let h1 = compute_simhash(&classes);
        let h2 = compute_simhash(&classes);
        assert_eq!(h1, h2);
        assert_eq!(simhash_distance(h1, h2), 0);
    }

    #[test]
    fn test_empty_sequence() {
        assert_eq!(compute_simhash(&[]), 0);
    }

    #[test]
    fn test_similar_sequences_low_distance() {
        let seq1 = vec![CLASS_TRANSFER, CLASS_CALL, CLASS_JUMP, CLASS_COMPARE,
                        CLASS_TRANSFER, CLASS_ARITH, CLASS_CALL, CLASS_TRANSFER];
        let mut seq2 = seq1.clone();
        seq2[3] = CLASS_LOGIC; // One change

        let h1 = compute_simhash(&seq1);
        let h2 = compute_simhash(&seq2);
        let dist = simhash_distance(h1, h2);
        // Should be small (< 20 bits for 1 change in 8 items)
        assert!(dist < 20, "Expected small distance, got {}", dist);
    }

    #[test]
    fn test_different_sequences_high_distance() {
        let seq1 = vec![CLASS_TRANSFER; 100];
        let seq2 = vec![CLASS_JUMP; 100];
        let h1 = compute_simhash(&seq1);
        let h2 = compute_simhash(&seq2);
        // Different classes should produce significantly different hashes
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_classify_mnemonic() {
        assert_eq!(classify_mnemonic("mov"), CLASS_TRANSFER);
        assert_eq!(classify_mnemonic("call"), CLASS_CALL);
        assert_eq!(classify_mnemonic("jmp"), CLASS_JUMP);
        assert_eq!(classify_mnemonic("add"), CLASS_ARITH);
        assert_eq!(classify_mnemonic("cmp"), CLASS_COMPARE);
        assert_eq!(classify_mnemonic("xor"), CLASS_LOGIC);
        assert_eq!(classify_mnemonic("nop"), CLASS_OTHER);
    }

    #[test]
    fn test_from_mnemonics() {
        let mnemonics: Vec<String> = vec!["mov", "call", "jmp", "ret"]
            .into_iter().map(String::from).collect();
        let h = compute_simhash_from_mnemonics(&mnemonics);
        assert_ne!(h, 0);
    }
}
