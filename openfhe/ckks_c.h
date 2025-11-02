#ifndef CKKS_C_H
#define CKKS_C_H
#ifdef __cplusplus
#include <complex> // Include complex header for C++ part
#endif
#include "pke_common_c.h"
#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for CKKS parameters
typedef void *ParamsCKKSPtr;

typedef struct {
  double real;
  double imag;
} complex_double_t;

// --- CKKS Params Functions ---
PKEErr NewParamsCKKS(ParamsCKKSPtr *out);
PKEErr ParamsCKKS_SetScalingModSize(ParamsCKKSPtr p, int modSize);
PKEErr ParamsCKKS_SetBatchSize(ParamsCKKSPtr p, int batchSize);
PKEErr ParamsCKKS_SetMultiplicativeDepth(ParamsCKKSPtr p, int depth);
PKEErr ParamsCKKS_SetSecurityLevel(ParamsCKKSPtr p, OFHESecurityLevel level);
PKEErr ParamsCKKS_SetRingDim(ParamsCKKSPtr p, uint64_t ringDim);
PKEErr ParamsCKKS_SetScalingTechnique(ParamsCKKSPtr p, int technique);
PKEErr ParamsCKKS_SetFirstModSize(ParamsCKKSPtr p, int modSize);
PKEErr ParamsCKKS_SetNumLargeDigits(ParamsCKKSPtr p, int numDigits);
PKEErr ParamsCKKS_SetSecretKeyDist(ParamsCKKSPtr p, OFHESecretKeyDist dist);
void DestroyParamsCKKS(ParamsCKKSPtr p);

// --- CKKS CryptoContext ---
PKEErr NewCryptoContextCKKS(ParamsCKKSPtr p, CryptoContextPtr *out);

// --- CKKS Plaintext ---
PKEErr CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
                                              double *values, int len,
                                              PlaintextPtr *out);
PKEErr CryptoContext_MakeCKKSComplexPackedPlaintext(CryptoContextPtr cc,
                                                     complex_double_t *values,
                                                     int len,
                                                     PlaintextPtr *out);

// --- CKKS Operations ---
PKEErr CryptoContext_Rescale(CryptoContextPtr cc, CiphertextPtr ct,
                              CiphertextPtr *out);

PKEErr CryptoContext_ModReduce(CryptoContextPtr cc, CiphertextPtr ct,
                                CiphertextPtr *out);

// --- CKKS Bootstrapping ---
PKEErr CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc,
                                                const uint32_t *levelBudget,
                                                int len);
PKEErr CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                          uint32_t slots);
PKEErr CryptoContext_EvalBootstrap(CryptoContextPtr cc, CiphertextPtr ct,
                                    CiphertextPtr *out);
PKEErr CryptoContext_EvalPoly(CryptoContextPtr cc, CiphertextPtr ct,
                               const double *coefficients, size_t count,
                               CiphertextPtr *out);

uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist);

// -- CKKS Complex number support ---
PKEErr Plaintext_GetComplexPackedValueLength(PlaintextPtr pt, int *out_len);
PKEErr Plaintext_GetComplexPackedValueAt(PlaintextPtr pt, int i,
                                          complex_double_t *out_val);

#ifdef __cplusplus
}
#endif

#endif // CKKS_C_H
