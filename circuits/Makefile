CIRCOM ?= circom
SNARKJS ?= snarkjs
NODE ?= node
BUILD_DIR := build
PTAU := pot21.ptau
PTAU_URL := https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau
# ECDSA circuit exceeds 2^21 constraints, needs pot22
PTAU_ECDSA := pot22.ptau
PTAU_ECDSA_URL := https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau
# Node memory for ECDSA circuit setup (~2.2M constraints)
NODE_MEM := --max-old-space-size=16384

PREDICATE_CIRCUITS := gte lte eq neq range set_member
SPECIAL_CIRCUITS := nullifier holder_binding
ECDSA_CIRCUIT := ecdsa_verify

ALL_STAGE2 := $(PREDICATE_CIRCUITS) $(SPECIAL_CIRCUITS)

.PHONY: all clean predicates specials ecdsa split-ecdsa ptau ptau-ecdsa help

help:
	@echo "Usage:"
	@echo "  make all        - Build everything (download ptau + compile + setup all circuits)"
	@echo "  make predicates - Build 6 predicate circuits (fast, ~30s)"
	@echo "  make specials   - Build nullifier + holder_binding (fast)"
	@echo "  make ecdsa      - Build ECDSA circuit (slow, ~15min, needs 16GB RAM)"
	@echo "  make split-ecdsa - Split ECDSA zkey into chunks for browser proving"
	@echo "  make ptau       - Download Powers of Tau files"
	@echo "  make clean      - Remove all build artifacts"

all: predicates specials ecdsa

ptau: $(PTAU)

ptau-ecdsa: $(PTAU_ECDSA)

$(PTAU):
	@echo "==> Downloading Powers of Tau 2^21 (Hermez ceremony, ~2.4GB)..."
	curl -L -o $(PTAU) $(PTAU_URL)

$(PTAU_ECDSA):
	@echo "==> Downloading Powers of Tau 2^22 (Hermez ceremony, ~4.6GB)..."
	curl -L -o $(PTAU_ECDSA) $(PTAU_ECDSA_URL)

# Generic rule for Stage 2 circuits (predicates + specials)
define STAGE2_RULE
$(BUILD_DIR)/$(1)/$(1).zkey: $(if $(filter $(PREDICATE_CIRCUITS),$(1)),predicates/$(1).circom,$(1)/$(1).circom) $(PTAU)
	@echo "==> Building $(1)..."
	@mkdir -p $(BUILD_DIR)/$(1)
	$(CIRCOM) $$< --r1cs --wasm --c --output $(BUILD_DIR)/$(1)/ -l node_modules
	make -C $(BUILD_DIR)/$(1)/$(1)_cpp/
	$(SNARKJS) groth16 setup $(BUILD_DIR)/$(1)/$(1).r1cs $(PTAU) $(BUILD_DIR)/$(1)/$(1)_0.zkey
	$(SNARKJS) zkey contribute $(BUILD_DIR)/$(1)/$(1)_0.zkey $(BUILD_DIR)/$(1)/$(1).zkey --name="zk-eidas" -e="zk-eidas-dev-entropy"
	$(SNARKJS) zkey export verificationkey $(BUILD_DIR)/$(1)/$(1).zkey $(BUILD_DIR)/$(1)/vk.json
	@rm -f $(BUILD_DIR)/$(1)/$(1)_0.zkey
	@echo "==> $(1) done."
endef

$(foreach c,$(ALL_STAGE2),$(eval $(call STAGE2_RULE,$(c))))

predicates: $(foreach c,$(PREDICATE_CIRCUITS),$(BUILD_DIR)/$(c)/$(c).zkey)

specials: $(foreach c,$(SPECIAL_CIRCUITS),$(BUILD_DIR)/$(c)/$(c).zkey)

# ECDSA circuit (needs pot22 + extra memory for Node.js)
ecdsa: $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey

$(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey: $(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).circom $(PTAU_ECDSA)
	@echo "==> Building ECDSA circuit (this takes ~15 minutes and needs 16GB RAM)..."
	@mkdir -p $(BUILD_DIR)/$(ECDSA_CIRCUIT)
	$(CIRCOM) $< --r1cs --wasm --c --output $(BUILD_DIR)/$(ECDSA_CIRCUIT)/ -l node_modules
	make -C $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT)_cpp/
	$(NODE) $(NODE_MEM) $$(which $(SNARKJS)) groth16 setup $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).r1cs $(PTAU_ECDSA) $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT)_0.zkey
	$(NODE) $(NODE_MEM) $$(which $(SNARKJS)) zkey contribute $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT)_0.zkey $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey --name="zk-eidas" -e="zk-eidas-dev-entropy"
	$(SNARKJS) zkey export verificationkey $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey $(BUILD_DIR)/$(ECDSA_CIRCUIT)/vk.json
	@rm -f $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT)_0.zkey
	@echo "==> ECDSA circuit done."

# Split ECDSA zkey into per-section chunk files for browser proving
split-ecdsa: $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey
	@echo "==> Splitting ECDSA zkey into per-section chunks..."
	$(NODE) $(NODE_MEM) scripts/split-zkey.mjs $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey
	@echo "==> Compressing chunks with gzip..."
	@for f in $(BUILD_DIR)/$(ECDSA_CIRCUIT)/$(ECDSA_CIRCUIT).zkey[b-k]; do \
		gzip -kf "$$f"; \
		echo "  $$f.gz"; \
	done
	@echo "==> Done. Upload .gz files to UploadThing."

clean:
	rm -rf $(BUILD_DIR)
