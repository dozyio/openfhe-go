#ifndef BGV_C_H
#define BGV_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for BGV parameters
typedef void *ParamsBGVPtr;

// --- BGV Params Functions ---
PKEErr NewParamsBGV(ParamsBGVPtr *out);
PKEErr ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p, uint64_t mod);
PKEErr ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth);
PKEErr ParamsBGV_SetScalingTechnique(ParamsBGVPtr p, int technique);
PKEErr ParamsBGV_SetMultipartyMode(ParamsBGVPtr p, int mode);
PKEErr ParamsBGV_SetPREMode(ParamsBGVPtr p, int mode);
PKEErr ParamsBGV_SetPRENumHops(ParamsBGVPtr p, uint32_t numHops);
PKEErr ParamsBGV_SetStatisticalSecurity(ParamsBGVPtr p, uint32_t statSec);
PKEErr ParamsBGV_SetNumAdversarialQueries(ParamsBGVPtr p, uint32_t numQueries);
PKEErr ParamsBGV_SetRingDim(ParamsBGVPtr p, uint32_t ringDim);
PKEErr ParamsBGV_SetKeySwitchTechnique(ParamsBGVPtr p, int technique);
void DestroyParamsBGV(ParamsBGVPtr p);

// --- BGV CryptoContext ---
PKEErr NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out);

// --- BGV Plaintext ---
// (Note: BGV also uses the Packed encoding)
PKEErr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                          int len, PlaintextPtr *out);
PKEErr CryptoContext_MakeCoefPackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                              int len, PlaintextPtr *out);

// BGV-specific Plaintext methods
PKEErr Plaintext_SetLength(PlaintextPtr pt, int len);
PKEErr Plaintext_GetCoefPackedValue(PlaintextPtr pt, int64_t **out_values, int *out_len);

#ifdef __cplusplus
}
#endif

#endif // BGV_C_H
