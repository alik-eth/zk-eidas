// Wrapper header for bindgen — avoids C++ includes from mdoc_zk.h
// by manually providing the needed type definitions.

#include <stdint.h>

// From mdoc_zk.h — verification types
enum VerificationType {
  VERIFY_EQ = 0,
  VERIFY_LEQ = 1,
  VERIFY_GEQ = 2,
  VERIFY_NEQ = 3,
};

typedef struct {
  uint8_t namespace_id[64];
  uint8_t id[32];
  uint8_t cbor_value[64];
  unsigned long namespace_len, id_len, cbor_value_len;
  uint8_t verification_type;
} RequestedAttribute;

typedef struct {
  const char* system;
  const char circuit_hash[65];
  unsigned long num_attributes;
  unsigned long version;
  unsigned long block_enc_hash, block_enc_sig;
} ZkSpecStruct;

// Error codes
typedef enum {
  MDOC_PROVER_SUCCESS = 0,
  MDOC_PROVER_NULL_INPUT,
  MDOC_PROVER_INVALID_INPUT,
  MDOC_PROVER_CIRCUIT_PARSING_FAILURE,
  MDOC_PROVER_HASH_PARSING_FAILURE,
  MDOC_PROVER_WITNESS_CREATION_FAILURE,
  MDOC_PROVER_GENERAL_FAILURE,
  MDOC_PROVER_MEMORY_ALLOCATION_FAILURE,
  MDOC_PROVER_INVALID_ZK_SPEC_VERSION,
  MDOC_PROVER_ATTRIBUTE_TOO_LONG,
} MdocProverErrorCode;

typedef enum {
  MDOC_VERIFIER_SUCCESS = 0,
  MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE,
  MDOC_VERIFIER_HASH_PARSING_FAILURE,
  MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE,
  MDOC_VERIFIER_INVALID_INPUT,
  MDOC_VERIFIER_INVALID_PROOF,
  MDOC_VERIFIER_NULL_INPUT,
  MDOC_VERIFIER_INVALID_ZK_SPEC_VERSION,
  MDOC_VERIFIER_INVALID_CBOR,
} MdocVerifierErrorCode;

typedef enum {
  CIRCUIT_GENERATION_SUCCESS = 0,
  CIRCUIT_GENERATION_NULL_INPUT,
  CIRCUIT_GENERATION_INVALID_ZK_SPEC_VERSION,
  CIRCUIT_GENERATION_FAILURE,
} CircuitGenerationErrorCode;

// Function declarations
extern MdocProverErrorCode run_mdoc_prover(
    const uint8_t* bcp, unsigned long bcsz,
    const uint8_t* mdoc, unsigned long mdoc_len,
    const char* pkx, const char* pky,
    const uint8_t* transcript, unsigned long tr_len,
    const RequestedAttribute* attrs, unsigned long attrs_len,
    const char* now,
    const uint8_t* contract_hash,  /* 8 bytes */
    const uint8_t* escrow_fields,  /* 8×32=256 bytes */
    uint8_t** prf, unsigned long* proof_len,
    uint8_t nullifier_hash_out[32],
    uint8_t binding_hash_out[32],
    uint8_t escrow_digest_out[32],
    const ZkSpecStruct* zk_spec_version
);

extern MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t* bcp, unsigned long bcsz,
    const char* pkx, const char* pky,
    const uint8_t* transcript, unsigned long tr_len,
    const RequestedAttribute* attrs, unsigned long attrs_len,
    const char* now,
    const uint8_t* contract_hash,  /* 8 bytes */
    const uint8_t nullifier_hash[32],
    const uint8_t binding_hash[32],
    const uint8_t escrow_digest[32],
    const uint8_t* zkproof, unsigned long proof_len,
    const char* docType,
    const ZkSpecStruct* zk_spec_version
);

extern CircuitGenerationErrorCode generate_circuit(
    const ZkSpecStruct* zk_spec_version,
    uint8_t** cb, unsigned long* clen
);

extern int circuit_id(
    uint8_t id[32],
    const uint8_t* bcp, unsigned long bcsz,
    const ZkSpecStruct* zk_spec
);

extern const ZkSpecStruct* find_zk_spec(
    const char* system_name,
    const char* circuit_hash
);

// These are defined in the C++ library
#define kNumZkSpecs 12
extern const ZkSpecStruct kZkSpecs[12];

// Smoke test: prove + verify age_over_18 on built-in test mdoc.
// Returns 0 on success, negative on failure.
extern int longfellow_smoke_test(void);

// Prove + verify with pre-generated circuit (avoids ~16s circuit regeneration).
// Returns 0 on success, -2 on prove failure, -3 on verify failure.
// If proof_out/proof_len_out are non-null, caller receives proof bytes (must free).
extern int longfellow_prove_verify_cached(
    const uint8_t* circuit, unsigned long circuit_len,
    uint8_t** proof_out, unsigned long* proof_len_out);

// --- p7s circuit (Phase 2a, blob protocol v4) ---
//
// Task 20 switched the ABI from typed C arguments to byte-blobs so
// additional witness fields can land without per-task churn. Task 21
// appended nonce fields (v3); Task 22 adds json_context_offset (v4).
// Both blobs start with a little-endian u32 schema version; the
// authoritative layout lives in lib/circuits/p7s/p7s_zk.cc's
// "schema history" comment.
//
// Witness blob v4:
//   u32 version = 4
//   u32 context_len ; u8 context[32]
//   u32 signed_content_len ; u8 signed_content[1024]
//   u32 json_pk_offset ; u8 pk_hex[130]
//   u32 json_nonce_offset ; u8 nonce_hex[64]
//   u32 json_context_offset
//
// Public blob v4 (unchanged from v3):
//   u32 version = 4
//   u8 context_hash[32]
//   u8 pk[65]
//   u8 nonce[32]

typedef enum {
  P7S_SUCCESS = 0,
  P7S_NULL_INPUT = 1,
  P7S_INVALID_INPUT = 2,
  P7S_PROVER_FAILURE = 3,
  P7S_VERIFIER_FAILURE = 4,
  P7S_MEMORY_FAILURE = 5,
} P7sErrorCode;

extern P7sErrorCode p7s_prove(
    const uint8_t* witness_blob, unsigned long witness_blob_len,
    const uint8_t* public_blob, unsigned long public_blob_len,
    uint8_t** proof_out, unsigned long* proof_len_out);

extern P7sErrorCode p7s_verify(
    const uint8_t* public_blob, unsigned long public_blob_len,
    const uint8_t* proof, unsigned long proof_len);

extern void p7s_free_proof(uint8_t* proof);
