#ifndef BFV_C_H
#define BFV_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for BFV parameters
typedef void *ParamsBFVPtr;

// --- BFV Params Functions ---
PKE_Err NewParamsBFV(ParamsBFVPtr *out);
PKE_Err ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p, uint64_t mod);
PKE_Err ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth);
void DestroyParamsBFV(ParamsBFVPtr p);

// --- BFV CryptoContext ---
PKE_Err NewCryptoContextBFV(ParamsBFVPtr p, CryptoContextPtr *out);

// --- BFV Plaintext ---
// (Note: BFV uses the Packed encoding)
PKE_Err CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                          int len, PlaintextPtr *out);

#ifdef __cplusplus
}
#endif

#endif // BFV_C_H
