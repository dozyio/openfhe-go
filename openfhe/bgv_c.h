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
void DestroyParamsBGV(ParamsBGVPtr p);

// --- BGV CryptoContext ---
PKEErr NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out);

// --- BGV Plaintext ---
// (Note: BGV also uses the Packed encoding)
PKEErr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t *values,
                                          int len, PlaintextPtr *out);

// BGV-specific Plaintext method
PKEErr Plaintext_SetLength(PlaintextPtr pt, int len);

#ifdef __cplusplus
}
#endif

#endif // BGV_C_H
