// bridge.h (UPDATED)
#ifndef BRIDGE_H
#define BRIDGE_H

#include <stdint.h>

// --- Move these definitions OUTSIDE extern "C" ---
// (This is not strictly necessary for C but good C++ practice)
// --- End of moved definitions ---

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

// --- Enums ---
#define PKE_FEATURE 1
#define KEYSWITCH_FEATURE 2
#define LEVELEDSHE_FEATURE 4

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
void DestroyCryptoContext(CryptoContextPtr cc);

// --- KeyPair ---
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
