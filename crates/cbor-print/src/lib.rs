//! Chunked QR transport protocol.
//!
//! Splits any binary blob into QR-code-sized chunks with an 8-byte header,
//! and reassembles them on the scanning side. Compression uses deflate-raw
//! (RFC 1951) for cross-platform compatibility with browser `CompressionStream`.
//!
//! # Holder binding & paper proofs
//!
//! This protocol transports cryptographic proofs — it does not bind them to a
//! presenter. A printed QR proof is a static artifact: anyone who possesses the
//! paper can present it. For real-world compliance (eIDAS LoA Substantial/High),
//! the verifier must establish holder identity through an external channel, e.g.:
//!
//! - **Document number disclosure** — include the credential's document number
//!   as a plaintext field alongside the QR codes. The verifier cross-references
//!   it against a physical ID presented in person. This is the recommended
//!   default for paper-based flows.
//! - **Biometric commitment** — the ZK proof attests a hash of the holder's
//!   biometrics; the verifier checks biometrics live.
//! - **Interactive holder binding** — challenge-response via a digital wallet
//!   (not applicable to paper, but available for online flows).
//!
//! Without at least one of these mechanisms, a paper proof only demonstrates
//! that *some* validly-issued credential satisfies the proven predicates.
//!
//! # Protocol header (8 bytes)
//!
//! ```text
//! [version:1][proof_id:2][seq:1][total:1][part_index:1][part_count:1][flags:1]
//! ```
//!
//! | Field       | Size    | Description |
//! |-------------|---------|-------------|
//! | version     | 1 byte  | Protocol version (currently 1) |
//! | proof_id    | 2 bytes | Links chunks belonging to the same document |
//! | seq         | 1 byte  | Chunk sequence number (0-indexed) |
//! | total       | 1 byte  | Total chunks for this document |
//! | part_index  | 1 byte  | This document's position in a multi-doc set (0-indexed) |
//! | part_count  | 1 byte  | Total documents in the set |
//! | flags       | 1 byte  | Bit 0: compressed. Bits 1-2: logical op (00=single, 01=and, 10=or) |

use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::collections::HashMap;
use std::io::Read;

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 8;
/// QR Version 40, Low ECC, binary mode.
pub const QR_MAX_BINARY: usize = 2953;
pub const MAX_PAYLOAD: usize = QR_MAX_BINARY - HEADER_SIZE;

/// Logical operation for multi-document sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogicalOp {
    Single = 0b00,
    And = 0b01,
    Or = 0b10,
}

impl LogicalOp {
    fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0b01 => Self::And,
            0b10 => Self::Or,
            _ => Self::Single,
        }
    }
}

/// Parsed 8-byte chunk header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    pub version: u8,
    pub doc_id: u16,
    pub seq: u8,
    pub total: u8,
    pub part_index: u8,
    pub part_count: u8,
    pub compressed: bool,
    pub logical_op: LogicalOp,
}

/// Encode a header into 8 bytes.
pub fn encode_header(h: &ChunkHeader) -> [u8; HEADER_SIZE] {
    let mut buf = [0u8; HEADER_SIZE];
    buf[0] = h.version;
    buf[1] = (h.doc_id >> 8) as u8;
    buf[2] = h.doc_id as u8;
    buf[3] = h.seq;
    buf[4] = h.total;
    buf[5] = h.part_index;
    buf[6] = h.part_count;
    buf[7] = if h.compressed { 1 } else { 0 } | ((h.logical_op as u8 & 0x03) << 1);
    buf
}

/// Parse an 8-byte header. Returns `None` if data is too short or version mismatches.
pub fn parse_header(data: &[u8]) -> Option<ChunkHeader> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    let version = data[0];
    if version != PROTOCOL_VERSION {
        return None;
    }
    Some(ChunkHeader {
        version,
        doc_id: ((data[1] as u16) << 8) | data[2] as u16,
        seq: data[3],
        total: data[4],
        part_index: data[5],
        part_count: data[6],
        compressed: (data[7] & 0x01) != 0,
        logical_op: LogicalOp::from_bits(data[7] >> 1),
    })
}

/// Compress bytes using deflate-raw (RFC 1951).
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = DeflateEncoder::new(data, Compression::default());
    let mut out = Vec::new();
    encoder
        .read_to_end(&mut out)
        .map_err(|e| format!("compress: {e}"))?;
    Ok(out)
}

/// Decompress deflate-raw bytes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("decompress: {e}"))?;
    Ok(out)
}

/// Split a binary blob into QR-ready chunks.
///
/// The blob is first compressed with deflate-raw, then split into chunks
/// of at most [`MAX_PAYLOAD`] bytes, each prefixed with an 8-byte header.
pub fn encode_chunks(
    data: &[u8],
    doc_id: u16,
    part_index: u8,
    part_count: u8,
    logical_op: LogicalOp,
) -> Result<Vec<Vec<u8>>, String> {
    let compressed = compress(data)?;
    encode_chunks_raw(&compressed, doc_id, part_index, part_count, logical_op, true)
}

/// Split already-compressed (or raw) bytes into QR-ready chunks.
pub fn encode_chunks_raw(
    payload: &[u8],
    doc_id: u16,
    part_index: u8,
    part_count: u8,
    logical_op: LogicalOp,
    compressed: bool,
) -> Result<Vec<Vec<u8>>, String> {
    let total_chunks = payload.len().div_ceil(MAX_PAYLOAD);
    if total_chunks > 255 {
        return Err(format!(
            "data too large: needs {total_chunks} chunks (max 255)"
        ));
    }

    let mut chunks = Vec::with_capacity(total_chunks);
    for i in 0..total_chunks {
        let start = i * MAX_PAYLOAD;
        let end = (start + MAX_PAYLOAD).min(payload.len());
        let header = encode_header(&ChunkHeader {
            version: PROTOCOL_VERSION,
            doc_id,
            seq: i as u8,
            total: total_chunks as u8,
            part_index,
            part_count,
            compressed,
            logical_op,
        });
        let mut chunk = Vec::with_capacity(HEADER_SIZE + (end - start));
        chunk.extend_from_slice(&header);
        chunk.extend_from_slice(&payload[start..end]);
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// Collector: accumulates scanned chunks and reassembles when complete.
#[derive(Debug, Default)]
pub struct ChunkCollector {
    chunks: HashMap<u16, HashMap<u8, Vec<u8>>>,
    totals: HashMap<u16, u8>,
    headers: HashMap<u16, ChunkHeader>,
}

impl ChunkCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a scanned chunk (raw QR data including header). Returns `true` if new.
    pub fn add(&mut self, data: &[u8]) -> bool {
        let header = match parse_header(data) {
            Some(h) => h,
            None => return false,
        };

        let doc_id = header.doc_id;
        let seq = header.seq;
        let total = header.total;

        let chunks = self.chunks.entry(doc_id).or_default();

        if !self.totals.contains_key(&doc_id) {
            self.totals.insert(doc_id, total);
            self.headers.insert(doc_id, header);
        }

        if self.totals.get(&doc_id) != Some(&total) {
            return false; // conflicting total
        }

        if chunks.contains_key(&seq) {
            return false; // duplicate
        }

        chunks.insert(seq, data[HEADER_SIZE..].to_vec());
        true
    }

    /// Check if all chunks for a document have been collected.
    pub fn is_doc_complete(&self, doc_id: u16) -> bool {
        let (Some(chunks), Some(&total)) = (self.chunks.get(&doc_id), self.totals.get(&doc_id))
        else {
            return false;
        };
        chunks.len() == total as usize
    }

    /// Reassemble a complete document's payload (compressed bytes).
    pub fn reassemble(&self, doc_id: u16) -> Option<Vec<u8>> {
        if !self.is_doc_complete(doc_id) {
            return None;
        }
        let chunks = self.chunks.get(&doc_id)?;
        let total = *self.totals.get(&doc_id)? as usize;
        let mut result = Vec::new();
        for i in 0..total {
            result.extend_from_slice(chunks.get(&(i as u8))?);
        }
        Some(result)
    }

    /// Reassemble and decompress a complete document.
    pub fn reassemble_and_decompress(&self, doc_id: u16) -> Result<Vec<u8>, String> {
        let compressed = self
            .reassemble(doc_id)
            .ok_or_else(|| "document incomplete".to_string())?;
        let header = self
            .headers
            .get(&doc_id)
            .ok_or_else(|| "no header".to_string())?;
        if header.compressed {
            decompress(&compressed)
        } else {
            Ok(compressed)
        }
    }

    /// Get header for a document.
    pub fn header(&self, doc_id: u16) -> Option<&ChunkHeader> {
        self.headers.get(&doc_id)
    }

    /// Get all known document IDs.
    pub fn doc_ids(&self) -> Vec<u16> {
        self.chunks.keys().copied().collect()
    }

    /// Get scan progress: (scanned, total).
    pub fn progress(&self, doc_id: u16) -> (usize, usize) {
        let chunks = self.chunks.get(&doc_id);
        let total = self.totals.get(&doc_id);
        match (chunks, total) {
            (Some(c), Some(&t)) => (c.len(), t as usize),
            _ => (0, 0),
        }
    }

    /// Check if all expected documents are complete.
    pub fn is_all_complete(&self) -> bool {
        if self.chunks.is_empty() {
            return false;
        }
        let Some(first) = self.headers.values().next() else {
            return false;
        };
        let expected = first.part_count as usize;
        if self.chunks.len() != expected {
            return false;
        }
        self.chunks.keys().all(|id| self.is_doc_complete(*id))
    }

    /// Reset the collector.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.totals.clear();
        self.headers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = ChunkHeader {
            version: PROTOCOL_VERSION,
            doc_id: 0x1234,
            seq: 2,
            total: 5,
            part_index: 0,
            part_count: 1,
            compressed: true,
            logical_op: LogicalOp::And,
        };
        let encoded = encode_header(&h);
        let parsed = parse_header(&encoded).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn rejects_short_header() {
        assert!(parse_header(&[1, 2, 3]).is_none());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut data = [0u8; 8];
        data[0] = 99;
        assert!(parse_header(&data).is_none());
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let original = b"hello world, this is a test of deflate-raw compression!";
        let compressed = compress(original).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
        assert!(compressed.len() < original.len());
    }

    #[test]
    fn single_chunk_small_data() {
        let data = vec![42u8; 100];
        let chunks = encode_chunks(&data, 1, 0, 1, LogicalOp::Single).unwrap();
        assert_eq!(chunks.len(), 1);

        let header = parse_header(&chunks[0]).unwrap();
        assert_eq!(header.doc_id, 1);
        assert_eq!(header.seq, 0);
        assert_eq!(header.total, 1);
        assert!(header.compressed);
    }

    #[test]
    fn multi_chunk_large_data() {
        // ~10KB compressed should need multiple chunks
        let data = vec![0u8; 50_000];
        let chunks = encode_chunks(&data, 7, 0, 1, LogicalOp::Single).unwrap();
        assert!(chunks.len() >= 1);

        for (i, chunk) in chunks.iter().enumerate() {
            let header = parse_header(chunk).unwrap();
            assert_eq!(header.doc_id, 7);
            assert_eq!(header.seq, i as u8);
            assert_eq!(header.total, chunks.len() as u8);
            assert!(chunk.len() <= QR_MAX_BINARY);
        }
    }

    #[test]
    fn collector_reassemble() {
        let data = b"reassembly test data that should survive chunking roundtrip";
        let chunks = encode_chunks(data, 1, 0, 1, LogicalOp::Single).unwrap();

        let mut collector = ChunkCollector::new();
        for chunk in &chunks {
            assert!(collector.add(chunk));
        }

        assert!(collector.is_doc_complete(1));
        let result = collector.reassemble_and_decompress(1).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn collector_dedup() {
        let data = b"dedup test";
        let chunks = encode_chunks(data, 1, 0, 1, LogicalOp::Single).unwrap();

        let mut collector = ChunkCollector::new();
        assert!(collector.add(&chunks[0]));
        assert!(!collector.add(&chunks[0])); // duplicate
    }

    #[test]
    fn collector_progress() {
        // Use raw (uncompressed) chunks to guarantee multiple chunks
        let data = vec![0u8; MAX_PAYLOAD + 100];
        let chunks =
            encode_chunks_raw(&data, 1, 0, 1, LogicalOp::Single, false).unwrap();
        assert_eq!(chunks.len(), 2);

        let mut collector = ChunkCollector::new();
        collector.add(&chunks[0]);
        assert_eq!(collector.progress(1), (1, 2));
        assert!(!collector.is_doc_complete(1));
    }

    #[test]
    fn collector_conflicting_total_rejected() {
        let mut collector = ChunkCollector::new();

        // chunk claiming total=3
        let h1 = encode_header(&ChunkHeader {
            version: PROTOCOL_VERSION,
            doc_id: 1,
            seq: 0,
            total: 3,
            part_index: 0,
            part_count: 1,
            compressed: true,
            logical_op: LogicalOp::Single,
        });
        let mut c1 = h1.to_vec();
        c1.extend_from_slice(b"payload");
        assert!(collector.add(&c1));

        // chunk with same doc_id but total=5
        let h2 = encode_header(&ChunkHeader {
            version: PROTOCOL_VERSION,
            doc_id: 1,
            seq: 1,
            total: 5,
            part_index: 0,
            part_count: 1,
            compressed: true,
            logical_op: LogicalOp::Single,
        });
        let mut c2 = h2.to_vec();
        c2.extend_from_slice(b"other");
        assert!(!collector.add(&c2));
    }

    #[test]
    fn multi_doc_compound() {
        let doc_a = b"document A content";
        let doc_b = b"document B content";

        let chunks_a = encode_chunks(doc_a, 1, 0, 2, LogicalOp::And).unwrap();
        let chunks_b = encode_chunks(doc_b, 2, 1, 2, LogicalOp::And).unwrap();

        let mut collector = ChunkCollector::new();
        for c in &chunks_a {
            collector.add(c);
        }
        assert!(!collector.is_all_complete()); // only 1 of 2 docs

        for c in &chunks_b {
            collector.add(c);
        }
        assert!(collector.is_all_complete());

        let result_a = collector.reassemble_and_decompress(1).unwrap();
        let result_b = collector.reassemble_and_decompress(2).unwrap();
        assert_eq!(result_a, doc_a);
        assert_eq!(result_b, doc_b);

        assert_eq!(collector.header(1).unwrap().logical_op, LogicalOp::And);
    }
}
