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
             // MUST call FreePKE_ErrMsg on this if not NULL.
} PKE_Err;

void FreePKE_ErrMsg(char *msg);

// --- Opaque Pointers ---
typedef void *CryptoContextPtr;
typedef void *KeyPairPtr;
typedef void *PlaintextPtr;
typedef void *CiphertextPtr;
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
PKE_Err CryptoContext_Enable(CryptoContextPtr cc, int feature);
PKE_Err CryptoContext_KeyGen(CryptoContextPtr cc, KeyPairPtr *out);
PKE_Err CryptoContext_EvalMultKeyGen(CryptoContextPtr cc, KeyPairPtr keys);
PKE_Err CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                       int32_t *indices, int len);
uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc);
int Ciphertext_GetLevel(CiphertextPtr ct);
void DestroyCryptoContext(CryptoContextPtr cc);

// --- Common Operations ---
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

// --- KeyPair ---
PKE_Err GetPublicKey(KeyPairPtr kp, void **out_pk_sptr_wrapper);
PKE_Err GetPrivateKey(KeyPairPtr kp, void **out_sk_sptr_wrapper);
PKE_Err NewKeyPair(KeyPairPtr *out);
PKE_Err SetPublicKey(KeyPairPtr kp, void *pk);
PKE_Err SetPrivateKey(KeyPairPtr kp, void *sk);
void DestroyKeyPair(KeyPairPtr kp);

// --- Plaintext ---
PKE_Err Plaintext_GetPackedValueLength(PlaintextPtr pt, int *out_len);
PKE_Err Plaintext_GetPackedValueAt(PlaintextPtr pt, int i, int64_t *out_val);
PKE_Err Plaintext_GetRealPackedValueLength(PlaintextPtr pt, int *out_len);
PKE_Err Plaintext_GetRealPackedValueAt(PlaintextPtr pt, int i, double *out_val);
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

PKE_Err CryptoContext_GetParameterElementString(CryptoContextPtr cc,
                                                char **outString);
#ifdef __cplusplus
}
#endif

#endif // PKE_COMMON_C_H
