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

async function loadCircuit(name) {
    return await wasm(
        path.join(circuitsDir, "predicates", name + ".circom"),
        { include: [includeDir] }
    );
}

describe("Predicate Circuits", function () {
    this.timeout(120000);

    before(async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    describe("gte", () => {
        let circuit;
        before(async () => { circuit = await loadCircuit("gte"); });

        it("should pass when claim_value >= threshold", async () => {
            const cv = 25, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                threshold: 18
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should pass when claim_value == threshold", async () => {
            const cv = 18, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                threshold: 18
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail when claim_value < threshold", async () => {
            const cv = 15, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    threshold: 18
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            try {
                await circuit.calculateWitness({
                    claim_value: 25,
                    sd_array_hash: 111,
                    message_hash: 222,
                    commitment: "9999999",
                    threshold: 18
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });

    describe("lte", () => {
        let circuit;
        before(async () => { circuit = await loadCircuit("lte"); });

        it("should pass when claim_value <= threshold", async () => {
            const cv = 15, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                threshold: 18
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail when claim_value > threshold", async () => {
            const cv = 25, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    threshold: 18
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            try {
                await circuit.calculateWitness({
                    claim_value: 15,
                    sd_array_hash: 111,
                    message_hash: 222,
                    commitment: "9999999",
                    threshold: 18
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });

    describe("eq", () => {
        let circuit;
        before(async () => { circuit = await loadCircuit("eq"); });

        it("should pass when claim_value == expected", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                expected: 42
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail when claim_value != expected", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    expected: 99
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            try {
                await circuit.calculateWitness({
                    claim_value: 42,
                    sd_array_hash: 111,
                    message_hash: 222,
                    commitment: "9999999",
                    expected: 42
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });

    describe("neq", () => {
        let circuit;
        before(async () => { circuit = await loadCircuit("neq"); });

        it("should pass when claim_value != expected", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                expected: 99
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail when claim_value == expected", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    expected: 42
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            try {
                await circuit.calculateWitness({
                    claim_value: 42,
                    sd_array_hash: 111,
                    message_hash: 222,
                    commitment: "9999999",
                    expected: 99
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });

    describe("range", () => {
        let circuit;
        before(async () => { circuit = await loadCircuit("range"); });

        it("should pass when low <= claim_value <= high", async () => {
            const cv = 25, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                low: 18,
                high: 65
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail when claim_value < low", async () => {
            const cv = 10, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    low: 18,
                    high: 65
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail when claim_value > high", async () => {
            const cv = 70, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    low: 18,
                    high: 65
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            try {
                await circuit.calculateWitness({
                    claim_value: 25,
                    sd_array_hash: 111,
                    message_hash: 222,
                    commitment: "9999999",
                    low: 18,
                    high: 65
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });

    describe("set_member", () => {
        let circuit;
        before(async () => { circuit = await loadCircuit("set_member"); });

        function padSet(values) {
            const padded = new Array(16).fill(0);
            for (let i = 0; i < values.length; i++) {
                padded[i] = values[i];
            }
            return padded;
        }

        it("should pass when claim_value is in the set", async () => {
            const cv = 42, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const setValues = [10, 20, 42, 50];
            const w = await circuit.calculateWitness({
                claim_value: cv,
                sd_array_hash: sdh,
                message_hash: mh,
                commitment: commitment,
                set: padSet(setValues),
                set_len: setValues.length
            }, true);
            await circuit.checkConstraints(w);
        });

        it("should fail when claim_value is not in the set", async () => {
            const cv = 99, sdh = 111, mh = 222;
            const commitment = computeCommitment(cv, sdh, mh);
            const setValues = [10, 20, 42, 50];
            try {
                await circuit.calculateWitness({
                    claim_value: cv,
                    sd_array_hash: sdh,
                    message_hash: mh,
                    commitment: commitment,
                    set: padSet(setValues),
                    set_len: setValues.length
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });

        it("should fail with wrong commitment", async () => {
            const setValues = [10, 20, 42, 50];
            try {
                await circuit.calculateWitness({
                    claim_value: 42,
                    sd_array_hash: 111,
                    message_hash: 222,
                    commitment: "9999999",
                    set: padSet(setValues),
                    set_len: setValues.length
                }, true);
                expect.fail("Should have thrown");
            } catch (err) {
                expect(err.message).to.include("Assert Failed");
            }
        });
    });
});
