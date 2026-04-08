//! Benchmarks for the WASM Longfellow verifier.
//!
//! Generates a proof once using the C++ prover, then benchmarks the
//! pure-Rust `mdoc_verify` path at 1, 2, and 4 attributes.
//!
//! Run with:
//!   cargo bench -p zk-eidas-wasm --bench verify

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use std::time::Duration;
use longfellow_sys::mdoc::{AttributeRequest, MdocCircuit};
use longfellow_sys::safe::VerifyType;
use zk_eidas_types::credential::ClaimValue;

/// Everything needed to call `mdoc_verify` without touching the C++ prover.
struct VerifyFixture {
    circuit_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    pkx_hex: String,
    pky_hex: String,
    attributes: Vec<zk_eidas_wasm::mdoc::AttributeRequest>,
    nullifier_hash: [u8; 32],
    binding_hash: [u8; 32],
    escrow_digest: [u8; 32],
    version: usize,
    block_enc_hash: usize,
    block_enc_sig: usize,
}

fn build_fixture(nattr: usize) -> VerifyFixture {
    let claims: Vec<(&str, ClaimValue)> = match nattr {
        1 => vec![("age_over_18", ClaimValue::Boolean(true))],
        2 => vec![
            ("age_over_18", ClaimValue::Boolean(true)),
            ("nationality", ClaimValue::String("UA".into())),
        ],
        4 => vec![
            ("age_over_18", ClaimValue::Boolean(true)),
            ("nationality", ClaimValue::String("UA".into())),
            ("given_name", ClaimValue::String("Oleksandr".into())),
            ("family_name", ClaimValue::String("Vovkotrub".into())),
        ],
        _ => panic!("unsupported nattr={nattr}"),
    };

    let (mdoc_bytes, pub_key_x, pub_key_y) =
        zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(claims, "https://bench.example.com");

    let circuit_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../demo/web/circuit-cache/mdoc-{nattr}attr.bin"));
    let circuit =
        MdocCircuit::load(&circuit_path, nattr).expect("failed to load circuit");

    let pkx_hex = format!("0x{}", hex::encode(pub_key_x));
    let pky_hex = format!("0x{}", hex::encode(pub_key_y));
    let transcript = b"zk-eidas-demo";
    let now = "2026-01-01T00:00:00Z";
    let contract_hash = [0u8; 8];
    let escrow_fields = [[0u8; 32]; 8];

    let cpp_attrs: Vec<AttributeRequest> = match nattr {
        1 => vec![AttributeRequest {
            namespace: "org.iso.18013.5.1".into(),
            identifier: "age_over_18".into(),
            cbor_value: vec![0xf5],
            verify_type: VerifyType::Eq,
        }],
        2 => vec![
            AttributeRequest {
                namespace: "org.iso.18013.5.1".into(),
                identifier: "age_over_18".into(),
                cbor_value: vec![0xf5],
                verify_type: VerifyType::Eq,
            },
            AttributeRequest {
                namespace: "org.iso.18013.5.1".into(),
                identifier: "nationality".into(),
                cbor_value: vec![0x62, 0x55, 0x41],
                verify_type: VerifyType::Eq,
            },
        ],
        4 => vec![
            AttributeRequest {
                namespace: "org.iso.18013.5.1".into(),
                identifier: "age_over_18".into(),
                cbor_value: vec![0xf5],
                verify_type: VerifyType::Eq,
            },
            AttributeRequest {
                namespace: "org.iso.18013.5.1".into(),
                identifier: "nationality".into(),
                cbor_value: vec![0x62, 0x55, 0x41],
                verify_type: VerifyType::Eq,
            },
            AttributeRequest {
                namespace: "org.iso.18013.5.1".into(),
                identifier: "given_name".into(),
                cbor_value: vec![0x69, 0x4f, 0x6c, 0x65, 0x6b, 0x73, 0x61, 0x6e, 0x64, 0x72],
                verify_type: VerifyType::Eq,
            },
            AttributeRequest {
                namespace: "org.iso.18013.5.1".into(),
                identifier: "family_name".into(),
                cbor_value: vec![0x69, 0x56, 0x6f, 0x76, 0x6b, 0x6f, 0x74, 0x72, 0x75, 0x62],
                verify_type: VerifyType::Eq,
            },
        ],
        _ => unreachable!(),
    };

    let proof = longfellow_sys::mdoc::prove(
        &circuit,
        &mdoc_bytes,
        &pkx_hex,
        &pky_hex,
        transcript,
        &cpp_attrs,
        now,
        &contract_hash,
        &escrow_fields,
    )
    .expect("C++ prover failed");

    let version = circuit.version();
    let (block_enc_hash, block_enc_sig) = circuit.block_enc();
    let circuit_bytes = std::fs::read(&circuit_path).unwrap();

    let wasm_attrs: Vec<zk_eidas_wasm::mdoc::AttributeRequest> = cpp_attrs
        .iter()
        .map(|a| zk_eidas_wasm::mdoc::AttributeRequest {
            id: a.identifier.clone(),
            cbor_value: a.cbor_value.clone(),
            verification_type: a.verify_type as u8,
        })
        .collect();

    VerifyFixture {
        circuit_bytes,
        proof_bytes: proof.proof_bytes,
        pkx_hex,
        pky_hex,
        attributes: wasm_attrs,
        nullifier_hash: proof.nullifier_hash,
        binding_hash: proof.binding_hash,
        escrow_digest: proof.escrow_digest,
        version,
        block_enc_hash,
        block_enc_sig,
    }
}

fn bench_verify(c: &mut Criterion) {
    let transcript = b"zk-eidas-demo";
    let now = "2026-01-01T00:00:00Z";
    let contract_hash = [0u8; 8];
    let doc_type = "org.iso.18013.5.1.mDL";

    let mut group = c.benchmark_group("mdoc_verify");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.sampling_mode(SamplingMode::Flat);

    for nattr in [1] {
        let f = build_fixture(nattr);

        group.bench_function(&format!("{nattr}attr"), |b| {
            b.iter(|| {
                let result = zk_eidas_wasm::mdoc::mdoc_verify(
                    &f.circuit_bytes,
                    &f.proof_bytes,
                    &f.pkx_hex,
                    &f.pky_hex,
                    transcript,
                    &f.attributes,
                    now,
                    &contract_hash,
                    &f.nullifier_hash,
                    &f.binding_hash,
                    &f.escrow_digest,
                    doc_type,
                    f.version,
                    f.block_enc_hash,
                    f.block_enc_sig,
                );
                assert!(result.unwrap());
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
