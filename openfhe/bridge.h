#ifndef BRIDGE_H
#define BRIDGE_H

#include "binfhe_c.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- PKE Error Handling (NEW) ---
typedef enum {
  PKE_OK = 0,
  PKE_ERR = 1 // Indicates an error occurred, check PKE_LastError()
} PKE_Err;

// Get last error message (thread-local, no need to free)
const char *PKE_LastError();

// Opaque pointers
typedef void *CryptoContextPtr;
typedef void *KeyPairPtr;
typedef void *PlaintextPtr;
typedef void *CiphertextPtr;
typedef void *ParamsBFVPtr;
typedef void *ParamsCKKSPtr;
typedef void *ParamsBGVPtr;
typedef void *EvalKeyPtr;

// Enums
typedef enum {
  HEStd_uniform,
  HEStd_error,
  HEStd_ternary,
} DistributionType;

typedef enum {
  HEStd_128_classic,
  HEStd_192_classic,
  HEStd_256_classic,
  HEStd_128_quantum,
  HEStd_192_quantum,
  HEStd_256_quantum,
  HEStd_NotSet,
} OFHESecurityLevel;

typedef enum {
  GAUSSIAN = 0,
  UNIFORM_TERNARY =
      1, // Default value, all schemes support this key distribution
  SPARSE_TERNARY = 2,
  SPARSE_ENCAPSULATED = 3, // For more effient bootstrapping in SIMD schemes
} OFHESecretKeyDist;

// --- CCParams ---
PKE_Err NewParamsBFV(ParamsBFVPtr *out);
PKE_Err ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p, uint64_t mod);
PKE_Err ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth);
void DestroyParamsBFV(ParamsBFVPtr p);

PKE_Err NewParamsBGV(ParamsBGVPtr *out);
PKE_Err ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p, uint64_t mod);
PKE_Err ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth);
void DestroyParamsBGV(ParamsBGVPtr p);

PKE_Err NewParamsCKKS(ParamsCKKSPtr *out);
PKE_Err ParamsCKKS_SetScalingModSize(ParamsCKKSPtr p, int modSize);
PKE_Err ParamsCKKS_SetBatchSize(ParamsCKKSPtr p, int batchSize);
PKE_Err ParamsCKKS_SetMultiplicativeDepth(ParamsCKKSPtr p, int depth);
PKE_Err ParamsCKKS_SetSecurityLevel(ParamsCKKSPtr p, OFHESecurityLevel level);
PKE_Err ParamsCKKS_SetRingDim(ParamsCKKSPtr p, uint64_t ringDim);
PKE_Err ParamsCKKS_SetScalingTechnique(ParamsCKKSPtr p, int technique);
PKE_Err ParamsCKKS_SetFirstModSize(ParamsCKKSPtr p, int modSize);
PKE_Err ParamsCKKS_SetNumLargeDigits(ParamsCKKSPtr p, int numDigits);
PKE_Err ParamsCKKS_SetSecretKeyDist(ParamsCKKSPtr p, OFHESecretKeyDist dist);
void DestroyParamsCKKS(ParamsCKKSPtr p);

// --- CryptoContext ---
PKE_Err NewCryptoContextBFV(ParamsBFVPtr p, CryptoContextPtr *out);
PKE_Err NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out);
PKE_Err NewCryptoContextCKKS(ParamsCKKSPtr p, CryptoContextPtr *out);

PKE_Err CryptoContext_Enable(CryptoContextPtr cc, int feature);
PKE_Err CryptoContext_KeyGen(CryptoContextPtr cc, KeyPairPtr *out);
PKE_Err CryptoContext_EvalMultKeyGen(CryptoContextPtr cc, KeyPairPtr keys);
PKE_Err CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                       int32_t *indices, int len);
uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc);
void DestroyCryptoContext(CryptoContextPtr cc);

// BFV/BGV specific
PKE_Err CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                          int len, PlaintextPtr *out);

// CKKS specific
// PlaintextPtr CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
//                                                    double *values, int len,
//                                                    uint32_t depth,
//                                                    uint32_t level,
//                                                    double scale);
PKE_Err CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
                                              double *values, int len,
                                              PlaintextPtr *out);
PKE_Err CryptoContext_Rescale(CryptoContextPtr cc, CiphertextPtr ct,
                              CiphertextPtr *out);

// Bootstrapping (CKKS)

// void CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
//                                        uint32_t numSlots);
// CiphertextPtr CryptoContext_EvalBootstrap(CryptoContextPtr cc,
//                                           CiphertextPtr ct);
// // Bootstrapping (CKKS)
// void CryptoContext_EvalBootstrapSetup(
//     CryptoContextPtr cc,
//     uint32_t slots); // uses defaults {5,4},{0,0}
// void CryptoContext_EvalBootstrapPrecompute(CryptoContextPtr cc, uint32_t
// slots);

// New API: returns 1 on success, 0 on error; errOut (malloc'ed) holds
// message on error.
// int CryptoContext_EvalBootstrapSetup(CryptoContextPtr cc, uint32_t slots,
//                                      char **errOut);

PKE_Err CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc,
                                                const uint32_t *levelBudget,
                                                int len);

// int CryptoContext_EvalBootstrapPrecompute(CryptoContextPtr cc, uint32_t
// slots,
//                                           char **errOut);
PKE_Err CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                          uint32_t slots);
PKE_Err CryptoContext_EvalBootstrap(CryptoContextPtr cc, CiphertextPtr ct,
                                    CiphertextPtr *out);
uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist);

// Common Operations
PKE_Err CryptoContext_Encrypt(CryptoContextPtr cc, KeyPairPtr keys,
                              PlaintextPtr pt, CiphertextPtr *out);
PKE_Err CryptoContext_Decrypt(CryptoContextPtr cc, KeyPairPtr keys,
                              CiphertextPtr ct, PlaintextPtr *out);
PKE_Err CryptoContext_EvalAdd(CryptoContextPtr cc, CiphertextPtr ct1,
                              CiphertextPtr ct2, CiphertextPtr *out);
PKE_Err CryptoContext_EvalSub(CryptoContextPtr cc, CiphertextPtr ct1,
                              CiphertextPtr ct2, CiphertextPtr *out);
PKE_Err CryptoContext_EvalMult(CryptoContextPtr cc, CiphertextPtr ct1,
                               CiphertextPtr ct2, CiphertextPtr *out);
PKE_Err CryptoContext_EvalRotate(CryptoContextPtr cc, CiphertextPtr ct,
                                 int32_t index, CiphertextPtr *out);

void FreeString(char *s);

// CryptoContext Serialization
size_t SerializeCryptoContextToString(CryptoContextPtr cc, char **outString);
CryptoContextPtr DeserializeCryptoContextFromString(const char *inString);

// KeyPair Serialization (Serialize individual keys)
size_t SerializePublicKeyToString(KeyPairPtr kp, char **outString);
KeyPairPtr DeserializePublicKeyFromString(
    const char *inString); // Returns a KP with only PK set

size_t SerializePrivateKeyToString(KeyPairPtr kp, char **outString);
KeyPairPtr DeserializePrivateKeyFromString(
    const char *inString); // Returns a KP with only SK set

// EvalMultKey (Relinearization Key) Serialization - Requires CryptoContext
size_t SerializeEvalMultKeyToString(
    CryptoContextPtr cc, const char *keyId,
    char **outString); // Assuming EvalMultKeyGen was called
void DeserializeEvalMultKeyFromString(CryptoContextPtr cc,
                                      const char *inString); // Loads into CC

// Ciphertext Serialization
size_t SerializeCiphertextToString(CiphertextPtr ct, char **outString);
CiphertextPtr DeserializeCiphertextFromString(const char *inString);

// --- KeyPair ---
// Need functions to access individual keys for deserialization reconstruction
PKE_Err GetPublicKey(KeyPairPtr kp, void **out_pk_sptr_wrapper);
PKE_Err GetPrivateKey(KeyPairPtr kp, void **out_sk_sptr_wrapper);
PKE_Err NewKeyPair(KeyPairPtr *out);
PKE_Err SetPublicKey(KeyPairPtr kp, void *pk);
PKE_Err SetPrivateKey(KeyPairPtr kp, void *sk);
void DestroyKeyPair(KeyPairPtr kp);

// --- Plaintext ---
// BFV/BGV Packed Value Access
PKE_Err Plaintext_GetPackedValueLength(PlaintextPtr pt, int *out_len);
PKE_Err Plaintext_GetPackedValueAt(PlaintextPtr pt, int i, int64_t *out_val);

// BGV specific
PKE_Err Plaintext_SetLength(PlaintextPtr pt, int len);

// CKKS Packed Value Access
PKE_Err Plaintext_GetRealPackedValueLength(PlaintextPtr pt,
                                           int *out_len); // Get data
PKE_Err Plaintext_GetRealPackedValueAt(PlaintextPtr pt, int i, double *out_val);

void DestroyPlaintext(PlaintextPtr pt);

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct);

#ifdef __cplusplus
}
#endif

#endif // BRIDGE_H
