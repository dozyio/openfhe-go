#ifndef BGV_C_H
#define BGV_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for BGV parameters
typedef void *ParamsBGVPtr;

// --- BGV Params Functions ---
PKE_Err NewParamsBGV(ParamsBGVPtr *out);
PKE_Err ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p, uint64_t mod);
PKE_Err ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth);
void DestroyParamsBGV(ParamsBGVPtr p);

// --- BGV CryptoContext ---
PKE_Err NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out);

// --- BGV Plaintext ---
// (Note: BGV also uses the Packed encoding)
PKE_Err CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                          int len, PlaintextPtr *out);

// BGV-specific Plaintext method
PKE_Err Plaintext_SetLength(PlaintextPtr pt, int len);

#ifdef __cplusplus
}
#endif

#endif // BGV_C_H
