const path = require("path");
const { wasm } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");

const circuitsDir = path.join(__dirname, "..");
const includeDir = path.join(circuitsDir, "node_modules");

(async () => {
    console.log("=== Identity Escrow — Verbose Walkthrough ===\n");

    // --- Setup ---
    console.log("[setup] Building Poseidon hash...");
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    console.log("[setup] Compiling identity_escrow circuit...");
    const circuit = await wasm(
        path.join(circuitsDir, "identity_escrow", "identity_escrow.circom"),
        { include: [includeDir] }
    );
    console.log("[setup] Done.\n");

    // --- Credential data (what the party wants to encrypt) ---
    const credData = [
        100,    // [0] surname hash
        200,    // [1] given_name hash
        300,    // [2] address_line_1
        400,    // [3] address_line_2
        500,    // [4] city + postal
        600,    // [5] country + doc_type
        12345,  // [6] document_number  <-- this is the ECDSA-committed field
        800,    // [7] date_of_birth
    ];
    const claimValue = 12345;
    const claimIndex = 6;
    const sdh = 111;        // sd_array_hash (from Stage 1)
    const mh = 222;         // message_hash (from Stage 1)
    const K = 987654321;    // random symmetric key

    console.log("--- INPUTS ---");
    console.log("credential_data:", credData);
    console.log("claim_value:", claimValue, `(= credential_data[${claimIndex}])`);
    console.log("claim_index:", claimIndex);
    console.log("sd_array_hash:", sdh);
    console.log("message_hash:", mh);
    console.log("K (symmetric key):", K);
    console.log();

    // --- Step 1: Compute commitment (what Stage 1 ECDSA proof outputs) ---
    const commitment = F.toString(poseidon([claimValue, sdh, mh]));
    console.log("--- STEP 1: Commitment chain ---");
    console.log(`commitment = Poseidon(${claimValue}, ${sdh}, ${mh})`);
    console.log(`         = ${commitment}`);
    console.log("This value comes from Stage 1 (ECDSA verify). The escrow circuit checks it matches.\n");

    // --- Step 2: Run the circuit ---
    console.log("--- STEP 2: Running circuit ---");
    const w = await circuit.calculateWitness({
        claim_value: claimValue,
        sd_array_hash: sdh,
        message_hash: mh,
        credential_data: credData,
        claim_index: claimIndex,
        K: K,
        commitment: commitment,
    }, true);
    await circuit.checkConstraints(w);
    console.log("Circuit satisfied! All constraints passed.\n");

    // --- Extract outputs ---
    const credentialHash = w[1].toString();
    const ciphertext = [];
    for (let i = 0; i < 8; i++) {
        ciphertext.push(w[2 + i].toString());
    }
    const keyCommitment = w[10].toString();

    console.log("--- OUTPUTS ---");
    console.log("credential_hash:", credentialHash);
    console.log("key_commitment: ", keyCommitment);
    console.log("ciphertext[0..7]:");
    for (let i = 0; i < 8; i++) {
        console.log(`  [${i}] ${ciphertext[i]}`);
    }
    console.log();

    // --- Step 3: Verify credential_hash ---
    console.log("--- STEP 3: Verify credential_hash ---");
    const expectedCredHash = F.toString(poseidon(credData));
    console.log(`Poseidon(${credData.join(", ")})`);
    console.log(`= ${expectedCredHash}`);
    console.log(`credential_hash matches: ${credentialHash === expectedCredHash}`);
    console.log();

    // --- Step 4: Verify key_commitment ---
    console.log("--- STEP 4: Verify key_commitment ---");
    const expectedKeyComm = F.toString(poseidon([K]));
    console.log(`Poseidon(${K}) = ${expectedKeyComm}`);
    console.log(`key_commitment matches: ${keyCommitment === expectedKeyComm}`);
    console.log();

    // --- Step 5: Decrypt and verify ---
    console.log("--- STEP 5: Decrypt ciphertext ---");
    console.log("For each i: plaintext[i] = ciphertext[i] - Poseidon(K, i)  (mod p)\n");
    const decrypted = [];
    for (let i = 0; i < 8; i++) {
        const ks = F.toString(poseidon([K, i]));
        const ct = F.e(ciphertext[i]);
        const ksF = F.e(ks);
        const plain = F.toString(F.sub(ct, ksF));
        const ok = plain === credData[i].toString();
        console.log(`  [${i}] keystream = Poseidon(${K}, ${i}) = ${ks.slice(0, 20)}...`);
        console.log(`       ciphertext = ${ciphertext[i].slice(0, 20)}...`);
        console.log(`       plaintext  = ${plain}  (original: ${credData[i]})  ${ok ? "OK" : "MISMATCH!"}`);
        decrypted.push(plain);
    }
    console.log();

    // --- Step 6: Integrity check ---
    console.log("--- STEP 6: Post-decryption integrity check ---");
    const recomputedHash = F.toString(poseidon(decrypted.map(x => F.e(x))));
    console.log(`Poseidon(decrypted_data) = ${recomputedHash}`);
    console.log(`credential_hash (proof)  = ${credentialHash}`);
    console.log(`Integrity verified: ${recomputedHash === credentialHash}`);
    console.log();

    // --- Step 7: Show the attack scenarios ---
    console.log("--- STEP 7: Attack scenarios ---\n");

    console.log("[attack 1] Wrong commitment (forged Stage 1):");
    try {
        await circuit.calculateWitness({
            claim_value: claimValue, sd_array_hash: sdh, message_hash: mh,
            credential_data: credData, claim_index: claimIndex, K: K,
            commitment: "9999999",
        }, true);
        console.log("  UNEXPECTED: circuit accepted!");
    } catch (err) {
        console.log(`  REJECTED: ${err.message.includes("Assert Failed") ? "Assert Failed" : err.message}`);
    }
    console.log();

    console.log("[attack 2] Wrong claim_index (lying about which field is committed):");
    try {
        await circuit.calculateWitness({
            claim_value: claimValue, sd_array_hash: sdh, message_hash: mh,
            credential_data: credData, claim_index: 0, K: K,  // index 0 has value 100, not 12345
            commitment: commitment,
        }, true);
        console.log("  UNEXPECTED: circuit accepted!");
    } catch (err) {
        console.log(`  REJECTED: ${err.message.includes("Assert Failed") ? "Assert Failed" : err.message}`);
    }
    console.log();

    console.log("[attack 3] Encrypting garbage (different data, same claim_value):");
    try {
        const garbage = [100, 200, 300, 400, 500, 600, 12345, 999999];  // slot 7 is garbage
        await circuit.calculateWitness({
            claim_value: claimValue, sd_array_hash: sdh, message_hash: mh,
            credential_data: garbage, claim_index: claimIndex, K: K,
            commitment: commitment,
        }, true);
        // This WILL pass the circuit — the circuit doesn't know slot 7 should be 800.
        // BUT: credential_hash will differ, so post-decryption integrity check fails.
        const gw = await circuit.calculateWitness({
            claim_value: claimValue, sd_array_hash: sdh, message_hash: mh,
            credential_data: garbage, claim_index: claimIndex, K: K,
            commitment: commitment,
        }, true);
        const garbageCredHash = gw[1].toString();
        console.log(`  Circuit accepted (it can't know the "real" data for non-committed fields)`);
        console.log(`  BUT credential_hash = ${garbageCredHash.slice(0, 30)}...`);
        console.log(`  Original cred_hash  = ${credentialHash.slice(0, 30)}...`);
        console.log(`  Hashes differ: ${garbageCredHash !== credentialHash} — counterparty detects the forgery`);
    } catch (err) {
        console.log(`  REJECTED: ${err.message}`);
    }
    console.log();

    console.log("=== Done ===");
    process.exit(0);
})();
