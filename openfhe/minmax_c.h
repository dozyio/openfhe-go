#ifndef MINMAX_C_H
#define MINMAX_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// --- Min/Max Comparison Operations via Scheme Switching ---

// EvalMinSchemeSwitching finds the minimum value and its index (argmin)
// Returns two ciphertexts: one for the minimum value, one for the index
PKEErr CryptoContext_EvalMinSchemeSwitching(CryptoContextPtr cc,
                                            CiphertextPtr ciphertext,
                                            void *publicKey,
                                            uint32_t numValues,
                                            uint32_t numSlots, uint32_t pLWE,
                                            double scaleSign,
                                            CiphertextPtr *outValue,
                                            CiphertextPtr *outIndex);

// EvalMinSchemeSwitchingAlt is an alternative with higher precision (more FHEW
// operations) Returns two ciphertexts: minimum value and argmin index
PKEErr CryptoContext_EvalMinSchemeSwitchingAlt(CryptoContextPtr cc,
                                               CiphertextPtr ciphertext,
                                               void *publicKey,
                                               uint32_t numValues,
                                               uint32_t numSlots,
                                               uint32_t pLWE, double scaleSign,
                                               CiphertextPtr *outValue,
                                               CiphertextPtr *outIndex);

// EvalMaxSchemeSwitching finds the maximum value and its index (argmax)
// Returns two ciphertexts: one for the maximum value, one for the index
PKEErr CryptoContext_EvalMaxSchemeSwitching(CryptoContextPtr cc,
                                            CiphertextPtr ciphertext,
                                            void *publicKey,
                                            uint32_t numValues,
                                            uint32_t numSlots, uint32_t pLWE,
                                            double scaleSign,
                                            CiphertextPtr *outValue,
                                            CiphertextPtr *outIndex);

// EvalMaxSchemeSwitchingAlt is an alternative with higher precision (more FHEW
// operations) Returns two ciphertexts: maximum value and argmax index
PKEErr CryptoContext_EvalMaxSchemeSwitchingAlt(CryptoContextPtr cc,
                                               CiphertextPtr ciphertext,
                                               void *publicKey,
                                               uint32_t numValues,
                                               uint32_t numSlots,
                                               uint32_t pLWE, double scaleSign,
                                               CiphertextPtr *outValue,
                                               CiphertextPtr *outIndex);

#ifdef __cplusplus
}
#endif

#endif // MINMAX_C_H
