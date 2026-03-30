const path = require("path");
const { wasm } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");
const { expect } = require("chai");

const circuitsDir = path.join(__dirname, "..");
const includeDir = path.join(circuitsDir, "node_modules");

let poseidon, F;

function computeCommitment(cv, sdh, mh) {
    return F.toString(poseidon([cv, sdh, mh]));
}

function computePoseidon(...inputs) {
    return F.toString(poseidon(inputs));
}

describe("Special Circuits", function () {
    this.timeout(120000);

    before(async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    describe("nullifier", () => {
        let circuit;
        before(async () => {
            circuit = await wasm(
                path.join(circuitsDir, "nullifier", "nullifier.circom"),
                { include: [includeDir] }
            );
        });

        it("should pass with valid commitment and produce correct nullifier", async () => {
            const credId = 12345, contractHash = 67890, salt = 42;
            const sdh = 111, mh = 222;
            // credential_id is wired to Commitment.claim_value
            const commitment = computeCommitment(credId, sdh, mh);
            const expectedNullifier = computePoseidon(credId, contractHash, salt);

            const w = await circuit.calculateWitness({
                credential_id: credId,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                contract_hash: contractHash,
                salt: salt
            }, true);
            await circuit.checkConstraints(w);

            // nullifier is output signal [0]
            const output = w[1]; // witness[1] is first output
            expect(output.toString()).to.equal(expectedNullifier);
        });

        it("should fail with wrong commitment", async () => {
            const credId = 12345, contractHash = 67890, salt = 42;
            const sdh = 111, mh = 222;

            try {
                await circuit.calculateWitness({
                    credential_id: credId,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: "9999999",
                    contract_hash: contractHash,
                    salt: salt
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should produce same nullifier for same id+contract+salt regardless of claim context", async () => {
            const credId = 12345, contractHash = 67890, salt = 42;

            const sdh1 = 111, mh1 = 222;
            const commitment1 = computeCommitment(credId, sdh1, mh1);

            const w1 = await circuit.calculateWitness({
                credential_id: credId,
                sd_array_hash: sdh1,
                message_hash: mh1,
                commitment: commitment1,
                contract_hash: contractHash,
                salt: salt
            }, true);
            await circuit.checkConstraints(w1);

            const sdh2 = 333, mh2 = 444;
            const commitment2 = computeCommitment(credId, sdh2, mh2);

            const w2 = await circuit.calculateWitness({
                credential_id: credId,
                sd_array_hash: sdh2,
                message_hash: mh2,
                commitment: commitment2,
                contract_hash: contractHash,
                salt: salt
            }, true);
            await circuit.checkConstraints(w2);

            // Same credential_id + contract_hash + salt → same nullifier
            expect(w1[1].toString()).to.equal(w2[1].toString());
        });
    });

    describe("holder_binding", () => {
        let circuit;
        before(async () => {
            circuit = await wasm(
                path.join(circuitsDir, "holder_binding", "holder_binding.circom"),
                { include: [includeDir] }
            );
        });

        it("should pass with valid commitment and produce correct binding_hash", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const expectedBindingHash = computePoseidon(cv);

            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment
            }, true);
            await circuit.checkConstraints(w);

            // binding_hash is output signal — witness[1] is first output
            expect(w[1].toString()).to.equal(expectedBindingHash);
        });

        it("should produce different binding_hash for different claim_value", async () => {
            const cv1 = 42, cv2 = 99, sdh = 111, mh = 222;
            const commitment1 = computeCommitment(cv1, sdh, mh);
            const commitment2 = computeCommitment(cv2, sdh, mh);

            const w1 = await circuit.calculateWitness({
                claim_value: cv1,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment1
            }, true);

            const w2 = await circuit.calculateWitness({
                claim_value: cv2,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment2
            }, true);

            // Different claim values → different binding hashes
            expect(w1[1].toString()).to.not.equal(w2[1].toString());
        });

        it("should fail with wrong commitment", async () => {
            const cv = 42, sdh = 111, mh = 222;

            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: "9999999"
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });

    describe("identity_escrow", () => {
        let circuit;
        before(async () => {
            circuit = await wasm(
                path.join(circuitsDir, "identity_escrow", "identity_escrow.circom"),
                { include: [includeDir] }
            );
        });

        function keystreamElement(K, index) {
            return F.toString(poseidon([K, index]));
        }

        function fieldSub(ciphertextStr, keystreamStr) {
            const ct = F.e(ciphertextStr);
            const ks = F.e(keystreamStr);
            return F.toString(F.sub(ct, ks));
        }

        it("happy path: encrypt and decrypt roundtrip with credential_hash integrity", async () => {
            const credData = [100, 200, 300, 400, 500, 600, 12345, 800];
            const claimValue = 12345, claimIndex = 6;
            const sdh = 111, mh = 222, K = 987654321;
            const commitment = computeCommitment(claimValue, sdh, mh);

            const w = await circuit.calculateWitness({
                claim_value: claimValue,
                sd_array_hash: sdh,
                message_hash: mh,
                credential_data: credData,
                claim_index: claimIndex,
                K: K,
                commitment: commitment
            }, true);
            await circuit.checkConstraints(w);

            // w[1] = credential_hash, w[2..9] = ciphertext[0..7], w[10] = key_commitment
            const credentialHash = w[1].toString();
            const keyCommitment = w[10].toString();

            // Verify credential_hash = Poseidon(credData)
            const expectedCredHash = computePoseidon(...credData);
            expect(credentialHash).to.equal(expectedCredHash);

            // Verify key_commitment = Poseidon(K)
            const expectedKeyCommitment = computePoseidon(K);
            expect(keyCommitment).to.equal(expectedKeyCommitment);

            // Decrypt each ciphertext[i] and verify it matches credData[i]
            const decrypted = [];
            for (let i = 0; i < 8; i++) {
                const ct = w[2 + i].toString();
                const ks = keystreamElement(K, i);
                const plain = fieldSub(ct, ks);
                expect(plain).to.equal(credData[i].toString(), `decrypt mismatch at index ${i}`);
                decrypted.push(plain);
            }

            // Recompute Poseidon of decrypted data and verify it matches credential_hash
            const recomputedHash = F.toString(poseidon(decrypted.map(x => F.e(x))));
            expect(recomputedHash).to.equal(credentialHash);
        });

        it("claim_index = 0 works", async () => {
            const credData = [42, 200, 300, 400, 500, 600, 700, 800];
            const claimValue = 42, claimIndex = 0;
            const sdh = 111, mh = 222, K = 987654321;
            const commitment = computeCommitment(claimValue, sdh, mh);

            const w = await circuit.calculateWitness({
                claim_value: claimValue,
                sd_array_hash: sdh,
                message_hash: mh,
                credential_data: credData,
                claim_index: claimIndex,
                K: K,
                commitment: commitment
            }, true);
            await circuit.checkConstraints(w);

            // Decrypt ciphertext[0] and verify it gives back 42
            const ct0 = w[2].toString();
            const ks0 = keystreamElement(K, 0);
            const plain0 = fieldSub(ct0, ks0);
            expect(plain0).to.equal("42");
        });

        it("wrong commitment fails", async () => {
            const credData = [100, 200, 300, 400, 500, 600, 12345, 800];
            const claimValue = 12345, claimIndex = 6;
            const sdh = 111, mh = 222, K = 987654321;

            try {
                await circuit.calculateWitness({
                    claim_value: claimValue,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    credential_data: credData,
                    claim_index: claimIndex,
                    K: K,
                    commitment: "9999999"
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("claim_index pointing to wrong value fails", async () => {
            // credData[0] = 100, credData[6] = 12345, but claimIndex = 0 → selected = 100 != 12345
            const credData = [100, 200, 300, 400, 500, 600, 12345, 800];
            const claimValue = 12345, claimIndex = 0;
            const sdh = 111, mh = 222, K = 987654321;
            const commitment = computeCommitment(claimValue, sdh, mh);

            try {
                await circuit.calculateWitness({
                    claim_value: claimValue,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    credential_data: credData,
                    claim_index: claimIndex,
                    K: K,
                    commitment: commitment
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("claim_index out of range fails", async () => {
            // claimIndex = 8 → no IsEqual matches → selected = 0 → 0 != 12345
            const credData = [100, 200, 300, 400, 500, 600, 12345, 800];
            const claimValue = 12345, claimIndex = 8;
            const sdh = 111, mh = 222, K = 987654321;
            const commitment = computeCommitment(claimValue, sdh, mh);

            try {
                await circuit.calculateWitness({
                    claim_value: claimValue,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    credential_data: credData,
                    claim_index: claimIndex,
                    K: K,
                    commitment: commitment
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });
});
