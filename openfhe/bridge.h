#ifndef BRIDGE_H
#define BRIDGE_H

#include "binfhe_c.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointers to hide C++ implementation details
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
ParamsBFVPtr NewParamsBFV();
void ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p, uint64_t mod);
void ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth);
void DestroyParamsBFV(ParamsBFVPtr p);

ParamsBGVPtr NewParamsBGV();
void ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p, uint64_t mod);
void ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth);
void DestroyParamsBGV(ParamsBGVPtr p);

ParamsCKKSPtr NewParamsCKKS();
void ParamsCKKS_SetScalingModSize(ParamsCKKSPtr p, int modSize);
void ParamsCKKS_SetBatchSize(ParamsCKKSPtr p, int batchSize);
void ParamsCKKS_SetMultiplicativeDepth(ParamsCKKSPtr p, int depth);
void ParamsCKKS_SetSecurityLevel(ParamsCKKSPtr p, OFHESecurityLevel level);
void ParamsCKKS_SetRingDim(ParamsCKKSPtr p, uint64_t ringDim);
void ParamsCKKS_SetScalingTechnique(ParamsCKKSPtr p, int technique);
void ParamsCKKS_SetFirstModSize(ParamsCKKSPtr p, int modSize);
void ParamsCKKS_SetNumLargeDigits(ParamsCKKSPtr p, int numDigits);
void ParamsCKKS_SetSecretKeyDist(ParamsCKKSPtr p, OFHESecretKeyDist dist);
void DestroyParamsCKKS(ParamsCKKSPtr p);

// --- CryptoContext ---
CryptoContextPtr NewCryptoContextBFV(ParamsBFVPtr p);
CryptoContextPtr NewCryptoContextBGV(ParamsBGVPtr p);
CryptoContextPtr NewCryptoContextCKKS(ParamsCKKSPtr p);

void CryptoContext_Enable(CryptoContextPtr cc, int feature);
KeyPairPtr CryptoContext_KeyGen(CryptoContextPtr cc);
void CryptoContext_EvalMultKeyGen(CryptoContextPtr cc, KeyPairPtr keys);
void CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                    int32_t *indices, int len);
uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc);

// BFV specific
PlaintextPtr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc,
                                               int64_t *values, int len);

// CKKS specific
// PlaintextPtr CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
//                                                    double *values, int len,
//                                                    uint32_t depth,
//                                                    uint32_t level,
//                                                    double scale);
PlaintextPtr CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
                                                   double *values, int len);
CiphertextPtr CryptoContext_Rescale(CryptoContextPtr cc, CiphertextPtr ct);

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
int CryptoContext_EvalBootstrapSetup(CryptoContextPtr cc, uint32_t slots,
                                     char **errOut);

int CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc,
                                            const uint32_t *levelBudget,
                                            int len, char **errOut);

int CryptoContext_EvalBootstrapPrecompute(CryptoContextPtr cc, uint32_t slots,
                                          char **errOut);
int CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                      uint32_t slots, char **errOut);
CiphertextPtr CryptoContext_EvalBootstrap(CryptoContextPtr cc, CiphertextPtr ct,
                                          char **errOut);
uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist);

// Common Operations
CiphertextPtr CryptoContext_Encrypt(CryptoContextPtr cc, KeyPairPtr keys,
                                    PlaintextPtr pt);
CiphertextPtr CryptoContext_EvalAdd(CryptoContextPtr cc, CiphertextPtr ct1,
                                    CiphertextPtr ct2);
CiphertextPtr CryptoContext_EvalSub(CryptoContextPtr cc, CiphertextPtr ct1,
                                    CiphertextPtr ct2);
CiphertextPtr CryptoContext_EvalMult(CryptoContextPtr cc, CiphertextPtr ct1,
                                     CiphertextPtr ct2);
CiphertextPtr CryptoContext_EvalRotate(CryptoContextPtr cc, CiphertextPtr ct,
                                       int32_t index);
PlaintextPtr CryptoContext_Decrypt(CryptoContextPtr cc, KeyPairPtr keys,
                                   CiphertextPtr ct);

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

void DestroyCryptoContext(CryptoContextPtr cc);

// --- KeyPair ---
// Need functions to access individual keys for deserialization reconstruction
void *GetPublicKey(KeyPairPtr kp);
void *GetPrivateKey(KeyPairPtr kp);
KeyPairPtr
NewKeyPair(); // Function to create an empty KeyPair for reconstruction
void SetPublicKey(KeyPairPtr kp, void *pk);
void SetPrivateKey(KeyPairPtr kp, void *sk);
void DestroyKeyPair(KeyPairPtr kp);

// --- Plaintext ---
// BFV/BGV Packed Value Access
int Plaintext_GetPackedValueLength(PlaintextPtr pt);
int64_t Plaintext_GetPackedValueAt(PlaintextPtr pt, int i);

// BGV specific
void Plaintext_SetLength(PlaintextPtr pt, int len);

// CKKS Packed Value Access
int Plaintext_GetRealPackedValueLength(PlaintextPtr pt);
double Plaintext_GetRealPackedValueAt(PlaintextPtr pt, int i);

void DestroyPlaintext(PlaintextPtr pt);

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct);

#ifdef __cplusplus
}
#endif

#endif // BRIDGE_H
