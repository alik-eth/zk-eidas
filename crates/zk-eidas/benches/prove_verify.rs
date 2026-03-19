use criterion::{criterion_group, criterion_main, Criterion};
use zk_eidas::{Predicate, ZkCredential, ZkVerifier};
use zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt;

const CIRCUITS: &str = "../../circuits/build";

fn bench_prove_gte_signed(c: &mut Criterion) {
    let (sdjwt, _key) = build_ecdsa_signed_sdjwt(serde_json::json!({"age": 25}), "bench-issuer");

    c.bench_function("prove_gte_signed", |b| {
        b.iter(|| {
            ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
                .unwrap()
                .predicate("age", Predicate::gte(18))
                .prove()
                .unwrap()
        })
    });
}

fn bench_verify_gte_signed(c: &mut Criterion) {
    let (sdjwt, _key) = build_ecdsa_signed_sdjwt(serde_json::json!({"age": 25}), "bench-issuer");
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("age", Predicate::gte(18))
        .prove()
        .unwrap();

    c.bench_function("verify_gte_signed", |b| {
        b.iter(|| ZkVerifier::new(CIRCUITS).verify(&proof).unwrap())
    });
}

criterion_group! {
    name = benches;
    // ZK proving takes 10-30s per iteration; small sample avoids multi-minute bench runs
    config = Criterion::default().sample_size(10);
    targets = bench_prove_gte_signed, bench_verify_gte_signed
}
criterion_main!(benches);
