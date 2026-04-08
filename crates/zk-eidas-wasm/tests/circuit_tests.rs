use zk_eidas_wasm::circuit::*;
use zk_eidas_wasm::field::{fp256::Fp256, gf2_128::Gf2_128};

#[test]
fn parse_real_1attr_circuit() {
    let compressed = include_bytes!("../../../demo/web/circuit-cache/mdoc-1attr.bin");
    let decompressed = decompress_circuit(compressed).unwrap();

    let fp = Fp256;
    let gf = Gf2_128;

    let (sig_circuit, consumed) = Circuit::from_bytes(&decompressed, &fp).unwrap();
    assert!(sig_circuit.nl > 0, "sig circuit should have layers");
    assert!(sig_circuit.npub_in > 0, "sig circuit should have public inputs");
    assert!(sig_circuit.ninputs > sig_circuit.npub_in);

    let (hash_circuit, _) = Circuit::<Gf2_128>::from_bytes(&decompressed[consumed..], &gf).unwrap();
    assert!(hash_circuit.nl > 0, "hash circuit should have layers");
    assert!(hash_circuit.npub_in > 0, "hash circuit should have public inputs");
    assert!(hash_circuit.ninputs > hash_circuit.npub_in);

    println!(
        "sig: nl={}, ninputs={}, npub={}",
        sig_circuit.nl, sig_circuit.ninputs, sig_circuit.npub_in
    );
    println!(
        "hash: nl={}, ninputs={}, npub={}",
        hash_circuit.nl, hash_circuit.ninputs, hash_circuit.npub_in
    );
}

#[test]
fn parse_all_circuit_sizes() {
    let workspace_root = env!("CARGO_MANIFEST_DIR").replace("/crates/zk-eidas-wasm", "");

    for n in 1..=4 {
        let path = format!(
            "{}/demo/web/circuit-cache/mdoc-{}attr.bin",
            workspace_root, n
        );
        let compressed = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("failed to read {}: {}", path, e);
        });
        let decompressed = decompress_circuit(&compressed).unwrap();

        let fp = Fp256;
        let gf = Gf2_128;

        let (sig, consumed) = Circuit::from_bytes(&decompressed, &fp).unwrap();
        let (hash, _) = Circuit::<Gf2_128>::from_bytes(&decompressed[consumed..], &gf).unwrap();

        assert!(sig.nl > 0, "sig circuit {} should have layers", n);
        assert!(hash.nl > 0, "hash circuit {} should have layers", n);

        println!(
            "{}attr — sig: nl={} ninputs={} npub={} | hash: nl={} ninputs={} npub={}",
            n, sig.nl, sig.ninputs, sig.npub_in, hash.nl, hash.ninputs, hash.npub_in
        );
    }
}

#[test]
fn decode_delta_positive() {
    assert_eq!(decode_delta(10, 6), 13); // delta = +3, encoded = 6
}

#[test]
fn decode_delta_negative() {
    assert_eq!(decode_delta(10, 5), 8); // delta = -2, encoded = 5
}

#[test]
fn decode_delta_zero() {
    assert_eq!(decode_delta(10, 0), 10); // delta = 0, encoded = 0
}

#[test]
fn decompress_invalid_fails() {
    let bad_data = vec![0xFF, 0xFF, 0xFF];
    assert!(decompress_circuit(&bad_data).is_err());
}

#[test]
fn parse_wrong_field_fails() {
    let compressed = include_bytes!("../../../demo/web/circuit-cache/mdoc-1attr.bin");
    let decompressed = decompress_circuit(compressed).unwrap();
    // First circuit is Fp256 (field_id=1), trying to parse as GF2_128 (field_id=4) should fail
    let gf = Gf2_128;
    assert!(Circuit::from_bytes(&decompressed, &gf).is_err());
}
