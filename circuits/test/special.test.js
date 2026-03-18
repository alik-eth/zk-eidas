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

        it("should pass with valid commitment and nullifier", async () => {
            const cv = 25, sdh = 111, mh = 222;
            const credSecret = 12345, scope = 67890;
            const commitment = computeCommitment(cv, sdh, mh);
            const nullifier = computePoseidon(credSecret, scope);

            const w = await circuit.calculateWitness({
                credential_secret: credSecret,
                sd_array_hash: sdh,
                message_hash: mh,
                claim_value: cv,
                commitment: commitment,
                scope: scope,
                nullifier: nullifier
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail with wrong nullifier", async () => {
            const cv = 25, sdh = 111, mh = 222;
            const credSecret = 12345, scope = 67890;
            const commitment = computeCommitment(cv, sdh, mh);

            try {
                await circuit.calculateWitness({
                    credential_secret: credSecret,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    claim_value: cv,
                    commitment: commitment,
                    scope: scope,
                    nullifier: "9999999"
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            const cv = 25, sdh = 111, mh = 222;
            const credSecret = 12345, scope = 67890;
            const nullifier = computePoseidon(credSecret, scope);

            try {
                await circuit.calculateWitness({
                    credential_secret: credSecret,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    claim_value: cv,
                    commitment: "9999999",
                    scope: scope,
                    nullifier: nullifier
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should produce same nullifier for same secret+scope regardless of claim", async () => {
            const credSecret = 12345, scope = 67890;

            const cv1 = 25, sdh1 = 111, mh1 = 222;
            const commitment1 = computeCommitment(cv1, sdh1, mh1);
            const nullifier = computePoseidon(credSecret, scope);

            const w1 = await circuit.calculateWitness({
                credential_secret: credSecret,
                sd_array_hash: sdh1,
                message_hash: mh1,
                claim_value: cv1,
                commitment: commitment1,
                scope: scope,
                nullifier: nullifier
            }, true);
            await circuit.checkConstraints(w1);

            const cv2 = 99, sdh2 = 333, mh2 = 444;
            const commitment2 = computeCommitment(cv2, sdh2, mh2);

            const w2 = await circuit.calculateWitness({
                credential_secret: credSecret,
                sd_array_hash: sdh2,
                message_hash: mh2,
                claim_value: cv2,
                commitment: commitment2,
                scope: scope,
                nullifier: nullifier
            }, true);
            await circuit.checkConstraints(w2);
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

        it("should pass with valid commitment and binding_hash", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const bindingHash = computePoseidon(cv);

            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                binding_hash: bindingHash
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail with wrong binding_hash", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);

            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    binding_hash: "9999999"
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const bindingHash = computePoseidon(cv);

            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: "9999999",
                    binding_hash: bindingHash
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });
});
