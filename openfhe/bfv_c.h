#ifndef BFV_C_H
#define BFV_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for BFV parameters
typedef void *ParamsBFVPtr;

// --- BFV Params Functions ---
PKEErr NewParamsBFV(ParamsBFVPtr *out);
PKEErr ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p, uint64_t mod);
PKEErr ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth);
PKEErr ParamsBFV_SetSecurityLevel(ParamsBFVPtr p, OFHESecurityLevel level);
PKEErr ParamsBFV_SetRingDim(ParamsBFVPtr p, uint64_t ringDim);
void DestroyParamsBFV(ParamsBFVPtr p);

// --- BFV CryptoContext ---
PKEErr NewCryptoContextBFV(ParamsBFVPtr p, CryptoContextPtr *out);

// --- BFV Plaintext ---
// (Note: BFV uses the Packed encoding)
PKEErr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                         int len, PlaintextPtr *out);

#ifdef __cplusplus
}
#endif

#endif // BFV_C_H
