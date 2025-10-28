#ifndef CKKS_C_H
#define CKKS_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for CKKS parameters
typedef void *ParamsCKKSPtr;

// --- CKKS Params Functions ---
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

// --- CKKS CryptoContext ---
PKE_Err NewCryptoContextCKKS(ParamsCKKSPtr p, CryptoContextPtr *out);

// --- CKKS Plaintext ---
PKE_Err CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
                                              double *values, int len,
                                              PlaintextPtr *out);

// --- CKKS Operations ---
PKE_Err CryptoContext_Rescale(CryptoContextPtr cc, CiphertextPtr ct,
                              CiphertextPtr *out);

// --- CKKS Bootstrapping ---
PKE_Err CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc,
                                                const uint32_t *levelBudget,
                                                int len);
PKE_Err CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                          uint32_t slots);
PKE_Err CryptoContext_EvalBootstrap(CryptoContextPtr cc, CiphertextPtr ct,
                                    CiphertextPtr *out);

uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist);

#ifdef __cplusplus
}
#endif

#endif // CKKS_C_H
