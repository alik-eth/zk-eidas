use std::collections::BTreeMap;
use zk_eidas_prover::CircuitLoader;
use zk_eidas_types::predicate::PredicateOp;

const ALL_OPS: [PredicateOp; 9] = [
    PredicateOp::Ecdsa,
    PredicateOp::Gte,
    PredicateOp::Lte,
    PredicateOp::Eq,
    PredicateOp::Neq,
    PredicateOp::Range,
    PredicateOp::SetMember,
    PredicateOp::Nullifier,
    PredicateOp::HolderBinding,
];

fn main() {
    let circuits_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "circuits/build".to_string());
    let output_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "demo/web/public/trusted-vks.json".to_string());

    let loader = CircuitLoader::new(&circuits_path);
    let mut vks: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    for op in ALL_OPS {
        let label = format!("{:?}", op);
        eprint!("  {label}... ");

        let artifacts = match loader.load(op) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("SKIP ({e})");
                continue;
            }
        };

        // In Circom/Groth16, VKs are already exported as vk.json during circuit build.
        // Read the vk.json file directly.
        let vk_path = artifacts.zkey_path.parent().unwrap().join("vk.json");
        match std::fs::read_to_string(&vk_path) {
            Ok(vk_json) => {
                let vk: serde_json::Value = serde_json::from_str(&vk_json)
                    .expect("failed to parse vk.json");
                eprintln!("OK");
                vks.insert(label, vk);
            }
            Err(e) => {
                eprintln!("SKIP (VK: {e})");
            }
        }
    }

    let json = serde_json::to_string_pretty(&vks).expect("JSON serialization failed");

    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&output_path, &json).expect("failed to write output file");

    eprintln!("\nWrote {} VKs to {output_path}", vks.len());
}
