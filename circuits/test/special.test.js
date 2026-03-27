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
});
