// bridge.h
#ifndef BRIDGE_H
#define BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointers to hide C++ implementation details
typedef void* ParamsPtr;
typedef void* CryptoContextPtr;
typedef void* KeyPairPtr;
typedef void* PlaintextPtr;
typedef void* CiphertextPtr;

// --- Enums ---
// We'll map the C++ enums to simple integers for the C API
#define PKE_FEATURE 1
#define KEYSWITCH_FEATURE 2
#define LEVELEDSHE_FEATURE 4

// --- CCParams ---
ParamsPtr NewParamsBFVrns();
void Params_SetPlaintextModulus(ParamsPtr p, uint64_t mod);
void Params_SetMultiplicativeDepth(ParamsPtr p, int depth);
void DestroyParams(ParamsPtr p);

// --- CryptoContext ---
CryptoContextPtr NewCryptoContext(ParamsPtr p);
void CryptoContext_Enable(CryptoContextPtr cc, int feature);
KeyPairPtr CryptoContext_KeyGen(CryptoContextPtr cc);
void CryptoContext_EvalMultKeyGen(CryptoContextPtr cc, KeyPairPtr keys);
void CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc, KeyPairPtr keys, int32_t* indices, int len);
PlaintextPtr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t* values, int len);
CiphertextPtr CryptoContext_Encrypt(CryptoContextPtr cc, KeyPairPtr keys, PlaintextPtr pt);
CiphertextPtr CryptoContext_EvalAdd(CryptoContextPtr cc, CiphertextPtr ct1, CiphertextPtr ct2);
CiphertextPtr CryptoContext_EvalMult(CryptoContextPtr cc, CiphertextPtr ct1, CiphertextPtr ct2);
CiphertextPtr CryptoContext_EvalRotate(CryptoContextPtr cc, CiphertextPtr ct, int32_t index);
PlaintextPtr CryptoContext_Decrypt(CryptoContextPtr cc, KeyPairPtr keys, CiphertextPtr ct);
void DestroyCryptoContext(CryptoContextPtr cc);

// --- KeyPair ---
void DestroyKeyPair(KeyPairPtr kp);

// --- Plaintext ---
int Plaintext_GetPackedValueLength(PlaintextPtr pt);
int64_t Plaintext_GetPackedValueAt(PlaintextPtr pt, int i);
void DestroyPlaintext(PlaintextPtr pt);

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct);

#ifdef __cplusplus
}
#endif

#endif // BRIDGE_H
