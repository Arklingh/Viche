# =============================================================================
# Viche — top-level orchestration.
#
# `make help` lists every target. The four meaningful flows are:
#
#   make setup          one-time: install forge-std + JS deps, fetch ptau
#   make circuits       compile the Circom circuit -> Groth16Verifier.sol + zkey
#   make build-contracts forge build (requires the generated verifier to exist
#                       OR VotingManager to depend only on the IVerifier iface)
#   make proof-demo     generate a real Groth16 proof for the sample input
#
# Requires: forge, cast, anvil (Foundry), circom, snarkjs, node, cargo, make.
# =============================================================================
.DEFAULT_GOAL := help

CIRCUIT_NAME  ?= vote
CIRCUIT_DEPTH ?= 20

CONTRACTS_DIR := contracts
CIRCUITS_DIR  := circuits

.PHONY: help setup install-foundry install-circom install-snarkjs \
        circuits download-ptau verifier build-contracts test-contracts \
        proof-demo check-rs build-rs test-rs frontend clean clean-circuits

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\n"} \
	     /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# One-time bootstrap
# ---------------------------------------------------------------------------
setup: ## One-time: install forge-std, npm deps, download ptau
	@echo ">> Installing forge-std into $(CONTRACTS_DIR)/lib"
	cd $(CONTRACTS_DIR) && forge install foundry-rs/forge-std --no-commit
	@echo ">> Installing JS deps (circomlib, snarkjs, circomlibjs)"
	cd $(CIRCUITS_DIR) && npm ci
	@echo ">> Downloading Powers-of-Tau ceremony file (dev only)"
	$(MAKE) download-ptau
	@echo ">> Setup complete."

install-foundry: ## Install Foundry via foundryup (curl | sh)
	curl -L https://foundry.paradigm.xyz | bash

install-circom: ## Install the circom compiler
	curl -L https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 \
	    -o /usr/local/bin/circom && chmod +x /usr/local/bin/circom

install-snarkjs: ## Install snarkjs globally
	npm install -g snarkjs

# ---------------------------------------------------------------------------
# ZK circuit pipeline (Phase 1)
# ---------------------------------------------------------------------------
download-ptau: ## Fetch powersOfTau28_hez_final_<depth>.ptau (dev ceremony)
	@mkdir -p $(CIRCUITS_DIR)/ptau
	@if [ ! -f $(CIRCUITS_DIR)/ptau/powersOfTau28_hez_final_$(CIRCUIT_DEPTH).ptau ]; then \
	    echo ">> Downloading ptau (depth $(CIRCUIT_DEPTH)) — this is large, please wait"; \
	    curl -L https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_$(CIRCUIT_DEPTH).ptau \
	        -o $(CIRCUITS_DIR)/ptau/powersOfTau28_hez_final_$(CIRCUIT_DEPTH).ptau; \
	else echo ">> ptau already present, skipping"; fi

circuits: download-ptau ## Compile circuit -> r1cs/wasm/zkey + Groth16Verifier.sol
	cd $(CIRCUITS_DIR) && CIRCUIT=$(CIRCUIT_NAME) MERKLE_TREE_DEPTH=$(CIRCUIT_DEPTH) ./scripts/compile.sh

verifier: ## Re-export just the Solidity verifier from the final zkey
	cd $(CIRCUITS_DIR) && CIRCUIT=$(CIRCUIT_NAME) node scripts/export_verifier.js

proof-demo: ## Generate a real Groth16 proof for the sample circuit input
	cd $(CIRCUITS_DIR) && CIRCUIT=$(CIRCUIT_NAME) node scripts/gen_proof.js

# ---------------------------------------------------------------------------
# Smart contracts (Phase 1)
# ---------------------------------------------------------------------------
build-contracts: ## forge build
	forge build

test-contracts: ## forge test -vvv
	forge test -vvv

# ---------------------------------------------------------------------------
# Rust workspace (Phase 2/3 stubs today)
# ---------------------------------------------------------------------------
check-rs: ## cargo check --workspace
	cargo check --workspace --all-targets

build-rs: ## cargo build --workspace (release for the relayer binary)
	cargo build --workspace --release

test-rs: ## cargo test --workspace
	cargo test --workspace

# ---------------------------------------------------------------------------
# Frontend (Phase 3 — placeholder targets)
# ---------------------------------------------------------------------------
frontend: ## Build the Leptos WASM bundle with Trunk (Phase 3)
	@echo "Phase 3 target — wire up Trunk + Tailwind when the frontend crate is implemented."
	cd crates/viche-frontend && trunk build --release

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
clean-circuits: ## Remove circuit build artifacts (keeps ptau)
	rm -rf $(CIRCUITS_DIR)/build

clean: clean-circuits ## Remove all generated artifacts
	rm -rf $(CONTRACTS_DIR)/out $(CONTRACTS_DIR)/cache $(CONTRACTS_DIR)/broadcast
	cargo clean
