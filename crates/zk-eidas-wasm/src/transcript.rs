//! Fiat-Shamir transcript: SHA-256 hasher + AES-256-ECB counter-mode PRF.
//!
//! This is a faithful port of `vendor/longfellow-zk/lib/random/transcript.h`
//! and `vendor/longfellow-zk/lib/random/random.h`. Any byte-level divergence
//! from the C++ will cause proof verification to fail.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

use crate::field::Field;

// ---------------------------------------------------------------------------
// Constants (matching C++ util/crypto.h)
// ---------------------------------------------------------------------------

const PRF_KEY_SIZE: usize = 32;
const PRF_OUTPUT_SIZE: usize = 16;

// Tags for typed writes (matching C++ Transcript::TAG_*)
const TAG_BSTR: u8 = 0;
const TAG_FIELD_ELEM: u8 = 1;
const TAG_ARRAY: u8 = 2;

// ---------------------------------------------------------------------------
// FSPRF — AES-256-ECB counter-mode PRF
// ---------------------------------------------------------------------------

struct FsPrf {
    cipher: Aes256,
    counter: u64,
    saved: [u8; PRF_OUTPUT_SIZE],
    read_ptr: usize,
}

impl FsPrf {
    fn new(key: &[u8; PRF_KEY_SIZE]) -> Self {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        Self {
            cipher,
            counter: 0,
            saved: [0u8; PRF_OUTPUT_SIZE],
            read_ptr: PRF_OUTPUT_SIZE, // starts exhausted
        }
    }

    fn bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.read_ptr == PRF_OUTPUT_SIZE {
                self.refill();
            }
            *byte = self.saved[self.read_ptr];
            self.read_ptr += 1;
        }
    }

    fn refill(&mut self) {
        // Build 16-byte input: counter as u64 LE in first 8 bytes, rest zero.
        let mut input = GenericArray::default();
        input[..8].copy_from_slice(&self.counter.to_le_bytes());
        // bytes [8..16] are already zero from default()

        self.cipher.encrypt_block(&mut input);
        self.saved.copy_from_slice(&input);
        self.counter += 1;
        self.read_ptr = 0;
    }
}

// ---------------------------------------------------------------------------
// Transcript — SHA-256 Fiat-Shamir oracle
// ---------------------------------------------------------------------------

/// Fiat-Shamir transcript matching the C++ `Transcript` class exactly.
///
/// Usage pattern: writes absorb data into the SHA-256 state, and `bytes()`
/// snapshots the hash to derive a PRF key, then extracts pseudo-random bytes.
/// Any write after extraction invalidates the PRF (forces a fresh snapshot on
/// the next extraction).
pub struct Transcript {
    sha: Sha256,
    prf: Option<FsPrf>,
    #[allow(dead_code)]
    version: usize,
}

impl Transcript {
    /// Create a new transcript, initialized with `init_bytes`.
    /// Matches C++ `Transcript(init, init_len, version)`.
    pub fn new(init_bytes: &[u8], version: usize) -> Self {
        let mut t = Self {
            sha: Sha256::new(),
            prf: None,
            version,
        };
        t.write_bytes(init_bytes);
        t
    }

    /// Clone the transcript state (explicit, matching C++ `clone()`).
    pub fn fork(&self) -> Self {
        Self {
            sha: self.sha.clone(),
            prf: None, // PRF is never cloned
            version: self.version,
        }
    }

    // -----------------------------------------------------------------------
    // Typed write operations
    // -----------------------------------------------------------------------

    /// Write a byte string (TAG_BSTR + 8-byte LE length + payload).
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.tag(TAG_BSTR);
        self.length(data.len());
        self.write_untyped(data);
    }

    /// Write N zero bytes (TAG_BSTR + length + zeros).
    /// Matches C++ `write0(n)`.
    pub fn write_zeros(&mut self, n: usize) {
        self.tag(TAG_BSTR);
        self.length(n);

        let zeros = [0u8; 32];
        let mut remaining = n;
        while remaining > 32 {
            self.write_untyped(&zeros);
            remaining -= 32;
        }
        self.write_untyped(&zeros[..remaining]);
    }

    /// Write a single field element (TAG_FIELD_ELEM + serialized element).
    /// No length prefix for single elements.
    pub fn write_field_elt<F: Field>(&mut self, elt: &F::Elt, field: &F) {
        self.tag(TAG_FIELD_ELEM);
        let bytes = field.to_bytes(elt);
        self.write_untyped(&bytes);
    }

    /// Write an array of field elements (stride=1, count=elts.len()).
    /// Convenience wrapper around `write_field_array`.
    pub fn write_array<F: Field>(&mut self, elts: &[F::Elt], field: &F) {
        self.write_field_array::<F>(elts, 1, elts.len(), field);
    }

    /// Write an array of field elements (TAG_ARRAY + 8-byte LE count + elements).
    /// `stride` selects every stride-th element from `elts`.
    pub fn write_field_array<F: Field>(
        &mut self,
        elts: &[F::Elt],
        stride: usize,
        count: usize,
        field: &F,
    ) {
        self.tag(TAG_ARRAY);
        self.length(count);
        for i in 0..count {
            let bytes = field.to_bytes(&elts[i * stride]);
            self.write_untyped(&bytes);
        }
    }

    // -----------------------------------------------------------------------
    // Byte extraction (PRF)
    // -----------------------------------------------------------------------

    /// Extract `n` pseudo-random bytes from the transcript.
    ///
    /// On first call after any write, snapshots the SHA-256 state to derive
    /// an AES-256 key, then uses counter-mode AES-ECB as a PRF stream.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        if self.prf.is_none() {
            // Fork the SHA state (don't modify the original) and finalize.
            let key_hash = self.sha.clone().finalize();
            let mut key = [0u8; PRF_KEY_SIZE];
            key.copy_from_slice(&key_hash);
            self.prf = Some(FsPrf::new(&key));
        }
        let mut buf = vec![0u8; n];
        self.prf.as_mut().unwrap().bytes(&mut buf);
        buf
    }

    /// Fill a mutable slice with pseudo-random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        if self.prf.is_none() {
            let key_hash = self.sha.clone().finalize();
            let mut key = [0u8; PRF_KEY_SIZE];
            key.copy_from_slice(&key_hash);
            self.prf = Some(FsPrf::new(&key));
        }
        self.prf.as_mut().unwrap().bytes(buf);
    }

    // -----------------------------------------------------------------------
    // Random element / natural / choose (from C++ RandomEngine)
    // -----------------------------------------------------------------------

    /// Sample a random field element. Matches C++ `RandomEngine::elt(F)`.
    pub fn elt<F: Field>(&mut self, field: &F) -> F::Elt {
        field.sample(&mut |n| self.bytes(n))
    }

    /// Sample `count` random field elements into a Vec.
    pub fn elt_vec<F: Field>(&mut self, count: usize, field: &F) -> Vec<F::Elt> {
        (0..count).map(|_| self.elt(field)).collect()
    }

    /// Random natural number in `[0, n)`. Rejection sampling with minimal
    /// bitmask, matching C++ `RandomEngine::nat(n)`.
    pub fn nat(&mut self, n: usize) -> usize {
        assert!(n > 0, "nat(0)");

        // Compute minimum number of bytes needed.
        let mut l = 0usize;
        let mut nn = n;
        while nn != 0 {
            nn >>= 8;
            l += 1;
        }

        let msk = Self::mask(n);

        loop {
            let buf = self.bytes(l);
            // Little-endian read.
            let mut r: usize = 0;
            for i in (0..l).rev() {
                r = (r << 8) | (buf[i] as usize);
            }
            r &= msk;
            if r < n {
                return r;
            }
        }
    }

    /// Choose `k` distinct random naturals in `[0, n)`.
    /// Partial Fisher-Yates shuffle, matching C++ `RandomEngine::choose`.
    pub fn choose(&mut self, n: usize, k: usize) -> Vec<usize> {
        assert!(n >= k, "choose: n < k");
        let mut a: Vec<usize> = (0..n).collect();
        let mut result = Vec::with_capacity(k);
        for i in 0..k {
            let j = i + self.nat(n - i);
            a.swap(i, j);
            result.push(a[i]);
        }
        result
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Output a 1-byte tag, invalidating the PRF.
    fn tag(&mut self, t: u8) {
        self.write_untyped(&[t]);
    }

    /// Output an 8-byte little-endian length, invalidating the PRF.
    fn length(&mut self, x: usize) {
        self.write_untyped(&(x as u64).to_le_bytes());
    }

    /// Raw write into the SHA state, invalidating the PRF.
    fn write_untyped(&mut self, data: &[u8]) {
        self.prf = None; // invalidate PRF on any write
        self.sha.update(data);
    }

    /// Minimal bitmask where `(n & mask) == n`.
    /// Matches C++ `RandomEngine::mask(n)`.
    fn mask(n: usize) -> usize {
        let mut m: usize = 0;
        while (n & m) != n {
            m = (m << 1) | 1;
        }
        m
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::gf2_128::Gf2_128;

    #[test]
    fn transcript_write_and_extract() {
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        let out = t.bytes(16);
        assert_eq!(out.len(), 16);
        // Extracting again without writing gives the next PRF block (different).
        let out2 = t.bytes(16);
        assert_ne!(out, out2);
    }

    #[test]
    fn transcript_deterministic() {
        let mut t1 = Transcript::new(&[0x42], 7);
        let mut t2 = Transcript::new(&[0x42], 7);

        t1.write_bytes(&[1, 2, 3]);
        t2.write_bytes(&[1, 2, 3]);

        let out1 = t1.bytes(16);
        let out2 = t2.bytes(16);
        assert_eq!(out1, out2, "identical transcripts must produce identical output");
    }

    #[test]
    fn transcript_write_resets_prf() {
        let mut t1 = Transcript::new(&[0x42], 7);
        let mut t2 = Transcript::new(&[0x42], 7);

        // Both do the same writes.
        t1.write_bytes(&[1, 2, 3]);
        t2.write_bytes(&[1, 2, 3]);

        // t1 extracts, then writes, then extracts again.
        let _ = t1.bytes(16);
        t1.write_bytes(&[4, 5]);
        let after_reset = t1.bytes(16);

        // t2 does both writes then extracts.
        t2.write_bytes(&[4, 5]);
        let direct = t2.bytes(16);

        assert_eq!(
            after_reset, direct,
            "PRF must reset after write so both paths agree"
        );
    }

    #[test]
    fn transcript_different_init_different_output() {
        let mut t1 = Transcript::new(&[0x01], 7);
        let mut t2 = Transcript::new(&[0x02], 7);
        t1.write_bytes(&[1, 2, 3]);
        t2.write_bytes(&[1, 2, 3]);
        assert_ne!(t1.bytes(16), t2.bytes(16));
    }

    #[test]
    fn transcript_nat() {
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        for _ in 0..100 {
            let v = t.nat(50);
            assert!(v < 50, "nat(50) returned {v}");
        }
    }

    #[test]
    fn transcript_nat_1() {
        // nat(1) must always return 0.
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        for _ in 0..10 {
            assert_eq!(t.nat(1), 0);
        }
    }

    #[test]
    fn transcript_choose() {
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        let chosen = t.choose(100, 10);
        assert_eq!(chosen.len(), 10);
        // All distinct.
        let mut sorted = chosen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 10, "choose must return distinct values");
        // All in range.
        assert!(chosen.iter().all(|&x| x < 100));
    }

    #[test]
    fn transcript_choose_full() {
        // Choosing all elements should be a permutation.
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        let chosen = t.choose(5, 5);
        assert_eq!(chosen.len(), 5);
        let mut sorted = chosen.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn transcript_elt_gf2() {
        let f = Gf2_128;
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        let e1 = t.elt(&f);
        let e2 = t.elt(&f);
        // Two samples should (almost certainly) differ.
        assert_ne!(e1, e2);
    }

    #[test]
    fn transcript_field_elem_write() {
        let f = Gf2_128;
        let mut t1 = Transcript::new(&[0x42], 7);
        let mut t2 = Transcript::new(&[0x42], 7);
        let e = f.of_scalar(42);
        t1.write_field_elt::<Gf2_128>(&e, &f);
        t2.write_field_elt::<Gf2_128>(&e, &f);
        assert_eq!(t1.bytes(16), t2.bytes(16));
    }

    #[test]
    fn transcript_field_array_write() {
        let f = Gf2_128;
        let mut t1 = Transcript::new(&[0x42], 7);
        let mut t2 = Transcript::new(&[0x42], 7);
        let elts = vec![f.of_scalar(1), f.of_scalar(2), f.of_scalar(3)];
        t1.write_field_array::<Gf2_128>(&elts, 1, 3, &f);
        t2.write_field_array::<Gf2_128>(&elts, 1, 3, &f);
        assert_eq!(t1.bytes(32), t2.bytes(32));
    }

    #[test]
    fn mask_computation() {
        assert_eq!(Transcript::mask(0), 0);
        assert_eq!(Transcript::mask(1), 1);
        assert_eq!(Transcript::mask(2), 3);
        assert_eq!(Transcript::mask(3), 3);
        assert_eq!(Transcript::mask(4), 7);
        assert_eq!(Transcript::mask(7), 7);
        assert_eq!(Transcript::mask(8), 15);
        assert_eq!(Transcript::mask(100), 127);
        assert_eq!(Transcript::mask(255), 255);
        assert_eq!(Transcript::mask(256), 511);
    }

    #[test]
    fn prf_counter_mode() {
        // Extracting 32 bytes should span two AES blocks (16 each).
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);
        let full = t.bytes(32);

        // Reset and extract in two halves.
        let mut t2 = Transcript::new(&[0x42], 7);
        t2.write_bytes(&[1, 2, 3]);
        let first = t2.bytes(16);
        let second = t2.bytes(16);

        assert_eq!(&full[..16], &first[..]);
        assert_eq!(&full[16..], &second[..]);
    }

    #[test]
    fn write_zeros() {
        let mut t1 = Transcript::new(&[0x42], 7);
        let mut t2 = Transcript::new(&[0x42], 7);
        t1.write_zeros(50);
        t2.write_bytes(&[0u8; 50]);
        assert_eq!(t1.bytes(16), t2.bytes(16));
    }

    #[test]
    fn fork_preserves_state() {
        let mut t = Transcript::new(&[0x42], 7);
        t.write_bytes(&[1, 2, 3]);

        let mut forked = t.fork();

        // Both should produce the same output from the same SHA state.
        assert_eq!(t.bytes(16), forked.bytes(16));
    }
}
