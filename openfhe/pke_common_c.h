#ifndef PKE_COMMON_C_H
#define PKE_COMMON_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- PKE Error Handling ---
typedef enum {
  PKE_OK_CODE = 0,
  PKE_ERR_CODE = 1 // Indicates an error occurred
} PKE_Err_Code;

typedef struct {
  PKE_Err_Code code; // 0 for OK, non-zero for error (e.g., 1)
  char *msg; // Allocated error string if code != 0, NULL otherwise. Go side
             // MUST call FreePKEErrMsg on this if not NULL.
} PKEErr;

void FreePKEErrMsg(char *msg);

// --- Opaque Pointers ---
typedef void *CryptoContextPtr;
typedef void *KeyPairPtr;
typedef void *PlaintextPtr;
typedef void *CiphertextPtr;
typedef void *PrivateKeyPtr;
typedef void *PublicKeyPtr;
typedef void *EvalKeyPtr;
typedef void *EvalKeyMapPtr;
// Note: Scheme-specific params (ParamsBFVPtr, etc.) are in their own headers.

// --- Enums ---
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
  UNIFORM_TERNARY = 1,
  SPARSE_TERNARY = 2,
  SPARSE_ENCAPSULATED = 3,
} OFHESecretKeyDist;

// --- Common CryptoContext Functions ---
PKEErr CryptoContext_Enable(CryptoContextPtr cc, int feature);
PKEErr CryptoContext_KeyGen(CryptoContextPtr cc, KeyPairPtr *out);
PKEErr CryptoContext_EvalMultKeyGen(CryptoContextPtr cc, KeyPairPtr keys);
PKEErr CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                      int32_t *indices, int len);
PKEErr CryptoContext_EvalAutomorphismKeyGen(CryptoContextPtr cc,
                                            KeyPairPtr keys, uint32_t *indices,
                                            int len);
EvalKeyMapPtr CryptoContext_GetEvalAutomorphismKeyMap(CryptoContextPtr cc,
                                                      const char *keyTag);
uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc);
uint64_t CryptoContext_GetCyclotomicOrder(CryptoContextPtr cc);
int Ciphertext_GetLevel(CiphertextPtr ct);
uint32_t Ciphertext_GetNoiseScaleDeg(CiphertextPtr ct);
PKEErr Ciphertext_GetKeyTag(CiphertextPtr ct, char **outString);
void DestroyCryptoContext(CryptoContextPtr cc);
int GetNativeInt();

// --- Common Operations ---
PKEErr CryptoContext_Encrypt(CryptoContextPtr cc, KeyPairPtr keys,
                             PlaintextPtr pt, CiphertextPtr *out);
PKEErr CryptoContext_Decrypt(CryptoContextPtr cc, KeyPairPtr keys,
                             CiphertextPtr ct, PlaintextPtr *out);
PKEErr CryptoContext_EvalAdd(CryptoContextPtr cc, CiphertextPtr ct1,
                             CiphertextPtr ct2, CiphertextPtr *out);
PKEErr CryptoContext_EvalSub(CryptoContextPtr cc, CiphertextPtr ct1,
                             CiphertextPtr ct2, CiphertextPtr *out);
PKEErr CryptoContext_EvalMult(CryptoContextPtr cc, CiphertextPtr ct1,
                              CiphertextPtr ct2, CiphertextPtr *out);
PKEErr CryptoContext_EvalRotate(CryptoContextPtr cc, CiphertextPtr ct,
                                int32_t index, CiphertextPtr *out);
PKEErr CryptoContext_EvalAutomorphism(CryptoContextPtr cc, CiphertextPtr ct,
                                      uint32_t index, EvalKeyMapPtr evalKeyMap,
                                      CiphertextPtr *out);
PKEErr CryptoContext_EvalMerge(CryptoContextPtr cc, CiphertextPtr *cts,
                               int ct_count, CiphertextPtr *out);
PKEErr CryptoContext_EvalFastRotationPrecompute(CryptoContextPtr cc,
                                                CiphertextPtr ct, void **out);
PKEErr CryptoContext_EvalFastRotation(CryptoContextPtr cc, CiphertextPtr ct,
                                      int32_t index, uint32_t m, void *precomp,
                                      CiphertextPtr *out);
void DestroyFastRotationPrecompute(void *precomp);
PKEErr CryptoContext_EvalAddPlain(CryptoContextPtr cc, CiphertextPtr ct,
                                  PlaintextPtr pt, CiphertextPtr *out);
PKEErr CryptoContext_EvalSubPlain(CryptoContextPtr cc, CiphertextPtr ct,
                                  PlaintextPtr pt, CiphertextPtr *out);
PKEErr CryptoContext_EvalMultPlain(CryptoContextPtr cc, CiphertextPtr ct,
                                   PlaintextPtr pt, CiphertextPtr *out);

// --- KeyPair ---
PKEErr GetPublicKey(KeyPairPtr kp, void **out_pk_sptr_wrapper);
PKEErr GetPrivateKey(KeyPairPtr kp, void **out_sk_sptr_wrapper);
PKEErr KeyPair_GetPublicKey(KeyPairPtr kp, PublicKeyPtr *out);
PKEErr KeyPair_GetSecretKey(KeyPairPtr kp, PrivateKeyPtr *out);
PKEErr NewKeyPair(KeyPairPtr *out);
PKEErr SetPublicKey(KeyPairPtr kp, void *pk);
PKEErr SetPrivateKey(KeyPairPtr kp, void *sk);
void DestroyKeyPair(KeyPairPtr kp);

// --- Plaintext ---
PKEErr Plaintext_GetPackedValueLength(PlaintextPtr pt, int *out_len);
PKEErr Plaintext_GetPackedValueAt(PlaintextPtr pt, int i, int64_t *out_val);
PKEErr Plaintext_GetRealPackedValueLength(PlaintextPtr pt, int *out_len);
PKEErr Plaintext_GetRealPackedValueAt(PlaintextPtr pt, int i, double *out_val);
void DestroyPlaintext(PlaintextPtr pt);

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct);

// --- Serialization ---
// This helper must be defined here as it's used by serial.go
void FreeString(char *s);

size_t SerializeCryptoContextToBytes(CryptoContextPtr cc, char **outBytes);
CryptoContextPtr DeserializeCryptoContextFromBytes(const char *inData,
                                                   int inLen);

size_t SerializePublicKeyToBytes(KeyPairPtr kp, char **outBytes);
KeyPairPtr DeserializePublicKeyFromBytes(const char *inData, int inLen);

size_t SerializePrivateKeyToBytes(KeyPairPtr kp, char **outBytes);
KeyPairPtr DeserializePrivateKeyFromBytes(const char *inData, int inLen);

size_t SerializeEvalMultKeyToBytes(CryptoContextPtr cc, const char *keyId,
                                   char **outBytes);
void DeserializeEvalMultKeyFromBytes(CryptoContextPtr cc, const char *inData,
                                     int inLen);

size_t SerializeCiphertextToBytes(CiphertextPtr ct, char **outBytes);
CiphertextPtr DeserializeCiphertextFromBytes(const char *inData, int inLen);

PKEErr CryptoContext_GetParameterElementString(CryptoContextPtr cc,
                                               char **outString);

// --- Multiparty / Threshold FHE ---
// Multiparty key generation
PKEErr
CryptoContext_MultipartyKeyGen_FromPrivateKeys(CryptoContextPtr cc,
                                               PrivateKeyPtr *privateKeys,
                                               size_t numKeys, KeyPairPtr *out);
PKEErr CryptoContext_MultipartyKeyGen_FromPublicKey(CryptoContextPtr cc,
                                                    PublicKeyPtr publicKey,
                                                    int makeSparse, int fresh,
                                                    KeyPairPtr *out);

// Multiparty decryption
PKEErr CryptoContext_MultipartyDecryptLead(CryptoContextPtr cc,
                                           CiphertextPtr *ciphertexts,
                                           size_t numCiphertexts,
                                           PrivateKeyPtr privateKey,
                                           CiphertextPtr *outPartials);
PKEErr CryptoContext_MultipartyDecryptMain(CryptoContextPtr cc,
                                           CiphertextPtr *ciphertexts,
                                           size_t numCiphertexts,
                                           PrivateKeyPtr privateKey,
                                           CiphertextPtr *outPartials);
PKEErr CryptoContext_MultipartyDecryptFusion(CryptoContextPtr cc,
                                             CiphertextPtr *partialCiphertexts,
                                             size_t numPartials,
                                             PlaintextPtr *out);

// Multiparty evaluation key generation
PKEErr CryptoContext_MultiKeySwitchGen(CryptoContextPtr cc,
                                       PrivateKeyPtr oldPrivateKey,
                                       PrivateKeyPtr newPrivateKey,
                                       EvalKeyPtr evalKey, EvalKeyPtr *out);
PKEErr CryptoContext_MultiEvalSumKeyGen(CryptoContextPtr cc,
                                        PrivateKeyPtr privateKey,
                                        EvalKeyMapPtr evalKeyMap,
                                        const char *keyTag, EvalKeyMapPtr *out);
PKEErr CryptoContext_MultiEvalAtIndexKeyGen(CryptoContextPtr cc,
                                            PrivateKeyPtr privateKey,
                                            EvalKeyMapPtr evalKeyMap,
                                            int32_t *indices, size_t numIndices,
                                            const char *keyTag,
                                            EvalKeyMapPtr *out);
PKEErr CryptoContext_MultiMultEvalKey(CryptoContextPtr cc,
                                      PrivateKeyPtr privateKey,
                                      EvalKeyPtr evalKey, const char *keyTag,
                                      EvalKeyPtr *out);

// Key aggregation
PKEErr CryptoContext_MultiAddPubKeys(CryptoContextPtr cc, PublicKeyPtr pk1,
                                     PublicKeyPtr pk2, const char *keyTag,
                                     PublicKeyPtr *out);
PKEErr CryptoContext_MultiAddEvalKeys(CryptoContextPtr cc, EvalKeyPtr ek1,
                                      EvalKeyPtr ek2, const char *keyTag,
                                      EvalKeyPtr *out);
PKEErr CryptoContext_MultiAddEvalMultKeys(CryptoContextPtr cc, EvalKeyPtr ek1,
                                          EvalKeyPtr ek2, const char *keyTag,
                                          EvalKeyPtr *out);
PKEErr CryptoContext_MultiAddEvalSumKeys(CryptoContextPtr cc,
                                         EvalKeyMapPtr ekm1, EvalKeyMapPtr ekm2,
                                         const char *keyTag,
                                         EvalKeyMapPtr *out);
PKEErr CryptoContext_MultiAddEvalAutomorphismKeys(CryptoContextPtr cc,
                                                  EvalKeyMapPtr ekm1,
                                                  EvalKeyMapPtr ekm2,
                                                  const char *keyTag,
                                                  EvalKeyMapPtr *out);

// Base evaluation key generation (required for multiparty eval key workflow)
PKEErr CryptoContext_KeySwitchGen(CryptoContextPtr cc,
                                  PrivateKeyPtr oldPrivateKey,
                                  PrivateKeyPtr newPrivateKey, EvalKeyPtr *out);
PKEErr CryptoContext_InsertEvalMultKey(CryptoContextPtr cc,
                                       EvalKeyPtr *evalKeys, size_t numKeys);
PKEErr CryptoContext_InsertEvalSumKey(CryptoContextPtr cc,
                                      EvalKeyMapPtr evalKeyMap);
PKEErr CryptoContext_EvalSumKeyGenPrivate(CryptoContextPtr cc,
                                          PrivateKeyPtr privateKey,
                                          PublicKeyPtr publicKey);
PKEErr CryptoContext_EvalAtIndexKeyGenPrivate(CryptoContextPtr cc,
                                              PrivateKeyPtr privateKey,
                                              const int32_t *indices,
                                              size_t numIndices,
                                              PublicKeyPtr publicKey);
PKEErr CryptoContext_GetEvalSumKeyMap(CryptoContextPtr cc, const char *keyTag,
                                      EvalKeyMapPtr *out);

// Key tag functions
PKEErr PrivateKey_GetKeyTag(PrivateKeyPtr sk, char **outKeyTag);
PKEErr PublicKey_GetKeyTag(PublicKeyPtr pk, char **outKeyTag);
PKEErr EvalKey_GetKeyTag(EvalKeyPtr ek, char **outKeyTag);

// Interactive Bootstrapping functions (2-party method)
PKEErr CryptoContext_IntBootAdjustScale(CryptoContextPtr cc,
                                        CiphertextPtr ciphertext,
                                        CiphertextPtr *out);
PKEErr CryptoContext_IntBootDecrypt(CryptoContextPtr cc,
                                    PrivateKeyPtr privateKey,
                                    CiphertextPtr ciphertext,
                                    CiphertextPtr *out);
PKEErr CryptoContext_IntBootEncrypt(CryptoContextPtr cc, PublicKeyPtr publicKey,
                                    CiphertextPtr ciphertext,
                                    CiphertextPtr *out);
PKEErr CryptoContext_IntBootAdd(CryptoContextPtr cc, CiphertextPtr ciphertext1,
                                CiphertextPtr ciphertext2, CiphertextPtr *out);

// Ciphertext manipulation functions (for interactive bootstrapping)
PKEErr Ciphertext_Clone(CiphertextPtr ct, CiphertextPtr *out);
size_t Ciphertext_GetNumElements(CiphertextPtr ct);
PKEErr Ciphertext_SetElementAtIndex(CiphertextPtr ct, size_t index);
PKEErr Ciphertext_EraseFirstElement(CiphertextPtr ct);

// Cleanup functions for multiparty types
void DestroyPrivateKey(PrivateKeyPtr sk);
void DestroyPublicKey(PublicKeyPtr pk);
void DestroyEvalKey(EvalKeyPtr ek);
void DestroyEvalKeyMap(EvalKeyMapPtr ekm);

#ifdef __cplusplus
}
#endif

#endif // PKE_COMMON_C_H
