//! Circuit data structures and deserialization from zstd-compressed binary format.
//!
//! The binary format matches the C++ `proto/circuit.h` serialization, with
//! 3-byte little-endian sizes, delta-encoded quad indices, and a trailing
//! 32-byte circuit ID.

use std::io::Read;

use crate::error::VerifyError;
use crate::field::Field;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const K_ID_SIZE: usize = 32;
const K_MAX_LAYERS: usize = 10000;

// ---------------------------------------------------------------------------
// ReadBuf — reusable cursor over a byte slice
// ---------------------------------------------------------------------------

/// A simple forward-only byte buffer reader.
pub struct ReadBuf<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ReadBuf<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn have(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], VerifyError> {
        if !self.have(n) {
            return Err(VerifyError::CircuitParse);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a 3-byte little-endian integer (kBytesPerSizeT = 3).
    pub fn read_u24_le(&mut self) -> Result<usize, VerifyError> {
        let bytes = self.read_bytes(3)?;
        Ok(bytes[0] as usize | (bytes[1] as usize) << 8 | (bytes[2] as usize) << 16)
    }

    pub fn position(&self) -> usize {
        self.pos
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Quadratic constraint term: coefficient * EQ(g|G) * EQ(h[0]|H0) * EQ(h[1]|H1)
#[derive(Clone, Debug)]
pub struct QuadTerm {
    pub g: usize,
    pub h: [usize; 2],
    pub v_idx: usize,
}

/// A single circuit layer.
#[derive(Clone, Debug)]
pub struct Layer {
    pub nw: usize,
    pub logw: usize,
    pub quads: Vec<QuadTerm>,
}

/// A parsed Longfellow circuit.
#[derive(Clone, Debug)]
pub struct Circuit<F: Field> {
    pub nv: usize,
    pub logv: usize,
    pub nc: usize,
    pub logc: usize,
    pub nl: usize,
    pub ninputs: usize,
    pub npub_in: usize,
    pub subfield_boundary: usize,
    pub layers: Vec<Layer>,
    pub constants: Vec<F::Elt>,
    pub id: [u8; K_ID_SIZE],
}

impl<F: Field> Circuit<F> {
    /// Total number of quad terms across all layers.
    ///
    /// Mirrors C++ `Circuit::nterms()`.
    pub fn nterms(&self) -> usize {
        self.layers.iter().map(|l| l.quads.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Delta decoding
// ---------------------------------------------------------------------------

/// Decode a signed delta stored in unsigned form with LSB as sign bit.
pub fn decode_delta(prev: usize, encoded: usize) -> usize {
    if encoded & 1 != 0 {
        prev.wrapping_sub(encoded >> 1) // negative delta
    } else {
        prev + (encoded >> 1) // positive delta
    }
}

// ---------------------------------------------------------------------------
// Deserialization
// ---------------------------------------------------------------------------

impl<F: Field> Circuit<F> {
    /// Parse a circuit from raw (decompressed) bytes.
    ///
    /// Returns the parsed circuit and the number of bytes consumed, so the
    /// caller can continue parsing a second circuit from the remaining data.
    pub fn from_bytes(data: &[u8], f: &F) -> Result<(Self, usize), VerifyError> {
        let mut buf = ReadBuf::new(data);

        // Version
        let version = buf.read_bytes(1)?[0];
        if version != 1 {
            return Err(VerifyError::CircuitParse);
        }

        // Field ID
        let field_id = buf.read_u24_le()?;
        if field_id != F::FIELD_ID as usize {
            return Err(VerifyError::UnsupportedField(field_id as u8));
        }

        // Header
        let nv = buf.read_u24_le()?;
        let nc = buf.read_u24_le()?;
        let npub_in = buf.read_u24_le()?;
        let subfield_boundary = buf.read_u24_le()?;
        let ninputs = buf.read_u24_le()?;
        let nl = buf.read_u24_le()?;
        let numconst = buf.read_u24_le()?;

        // Validation
        if npub_in > ninputs || subfield_boundary > ninputs || nl > K_MAX_LAYERS {
            return Err(VerifyError::CircuitParse);
        }

        // Constants
        let mut constants = Vec::with_capacity(numconst);
        for _ in 0..numconst {
            let bytes = buf.read_bytes(F::BYTES)?;
            let elt = f.of_bytes(bytes).ok_or(VerifyError::CircuitParse)?;
            constants.push(elt);
        }

        // Layers
        let mut layers = Vec::with_capacity(nl);
        for _ in 0..nl {
            let logw = buf.read_u24_le()?;
            let nw = buf.read_u24_le()?;
            let nq = buf.read_u24_le()?;

            let mut quads = Vec::with_capacity(nq);
            let mut prev_g: usize = 0;
            let mut prev_h0: usize = 0;
            let mut prev_h1: usize = 0;

            for _ in 0..nq {
                let delta_g = buf.read_u24_le()?;
                let delta_h0 = buf.read_u24_le()?;
                let delta_h1 = buf.read_u24_le()?;
                let vi = buf.read_u24_le()?;

                let g = decode_delta(prev_g, delta_g);
                let h0 = decode_delta(prev_h0, delta_h0);
                let h1 = decode_delta(prev_h1, delta_h1);

                if vi >= numconst {
                    return Err(VerifyError::CircuitParse);
                }

                quads.push(QuadTerm {
                    g,
                    h: [h0, h1],
                    v_idx: vi,
                });
                prev_g = g;
                prev_h0 = h0;
                prev_h1 = h1;
            }

            layers.push(Layer { nw, logw, quads });
        }

        // Circuit ID (32 bytes)
        let id_bytes = buf.read_bytes(K_ID_SIZE)?;
        let mut id = [0u8; K_ID_SIZE];
        id.copy_from_slice(id_bytes);

        let consumed = buf.position();

        Ok((
            Circuit {
                nv,
                logv: lg(nv),
                nc,
                logc: lg(nc),
                nl,
                ninputs,
                npub_in,
                subfield_boundary,
                layers,
                constants,
                id,
            },
            consumed,
        ))
    }
}

/// Ceiling log2: smallest k such that 2^k >= n.
fn lg(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

// ---------------------------------------------------------------------------
// Zstd decompression
// ---------------------------------------------------------------------------

/// Decompress a zstd-compressed circuit blob.
pub fn decompress_circuit(compressed: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let mut decoder = ruzstd::streaming_decoder::StreamingDecoder::new(compressed)
        .map_err(|_| VerifyError::Decompress)?;
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| VerifyError::Decompress)?;
    Ok(decompressed)
}
