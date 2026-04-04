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
    uint8_t** prf, unsigned long* proof_len,
    const ZkSpecStruct* zk_spec_version
);

extern MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t* bcp, unsigned long bcsz,
    const char* pkx, const char* pky,
    const uint8_t* transcript, unsigned long tr_len,
    const RequestedAttribute* attrs, unsigned long attrs_len,
    const char* now,
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
