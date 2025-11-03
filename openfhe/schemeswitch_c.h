#ifndef SCHEMESWITCH_C_H
#define SCHEMESWITCH_C_H

#include "binfhe_c.h"
#include "pke_common_c.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Opaque Pointers ---
typedef void *SchSwchParamsPtr;
typedef void *LWEPrivateKeyPtr;

// --- BinFHE Parameter Set (matching OpenFHE enum) ---
typedef enum {
  BINFHE_TOY = 0,
  BINFHE_MEDIUM = 1,
  BINFHE_STD128_AP = 2,
  BINFHE_STD128 = 3,
  BINFHE_STD128_3 = 4,
  BINFHE_STD128_4 = 5,
  BINFHE_STD128Q = 6,
  BINFHE_STD128Q_3 = 7,
  BINFHE_STD128Q_4 = 8,
  BINFHE_STD192 = 9,
  BINFHE_STD192_3 = 10,
  BINFHE_STD192_4 = 11,
  BINFHE_STD192Q = 12,
  BINFHE_STD192Q_3 = 13,
  BINFHE_STD192Q_4 = 14,
  BINFHE_STD256 = 15,
  BINFHE_STD256_3 = 16,
  BINFHE_STD256_4 = 17,
  BINFHE_STD256Q = 18,
  BINFHE_STD256Q_3 = 19,
  BINFHE_STD256Q_4 = 20
} BinFHEParamSet;

// --- SchSwchParams Functions ---
PKEErr NewSchSwchParams(SchSwchParamsPtr *out);
void DestroySchSwchParams(SchSwchParamsPtr params);

PKEErr SchSwchParams_SetSecurityLevelCKKS(SchSwchParamsPtr params,
                                          OFHESecurityLevel level);
PKEErr SchSwchParams_SetSecurityLevelFHEW(SchSwchParamsPtr params,
                                          BinFHEParamSet level);
PKEErr SchSwchParams_SetNumSlotsCKKS(SchSwchParamsPtr params,
                                     uint32_t numSlots);
PKEErr SchSwchParams_SetNumValues(SchSwchParamsPtr params, uint32_t numValues);
PKEErr SchSwchParams_SetCtxtModSizeFHEWLargePrec(SchSwchParamsPtr params,
                                                 uint32_t ctxtModSize);
PKEErr SchSwchParams_SetComputeArgmin(SchSwchParamsPtr params, int flag);
PKEErr SchSwchParams_SetUseAltArgmin(SchSwchParamsPtr params, int flag);
PKEErr SchSwchParams_SetArbitraryFunctionEvaluation(SchSwchParamsPtr params,
                                                    int flag);
PKEErr SchSwchParams_SetOneHotEncoding(SchSwchParamsPtr params, int flag);

PKEErr SchSwchParams_GetSecurityLevelCKKS(SchSwchParamsPtr params,
                                          OFHESecurityLevel *out);
PKEErr SchSwchParams_GetSecurityLevelFHEW(SchSwchParamsPtr params,
                                          BinFHEParamSet *out);
PKEErr SchSwchParams_GetNumSlotsCKKS(SchSwchParamsPtr params, uint32_t *out);
PKEErr SchSwchParams_GetNumValues(SchSwchParamsPtr params, uint32_t *out);

// --- LWE Private Key Functions ---
void DestroyLWEPrivateKey(LWEPrivateKeyPtr key);

// --- Scheme Switching Setup Functions ---
PKEErr CryptoContext_EvalCKKStoFHEWSetup(CryptoContextPtr cc,
                                         SchSwchParamsPtr params,
                                         LWEPrivateKeyPtr *out);
PKEErr CryptoContext_EvalCKKStoFHEWKeyGen(CryptoContextPtr cc,
                                          KeyPairPtr keyPair,
                                          LWEPrivateKeyPtr lwesk);
PKEErr CryptoContext_EvalCKKStoFHEWPrecompute(CryptoContextPtr cc,
                                              double scale);

// Returns array of LWE ciphertexts - caller must free the array but not
// individual elements
PKEErr CryptoContext_EvalCKKStoFHEW(CryptoContextPtr cc,
                                    CiphertextPtr ciphertext,
                                    uint32_t numValues,
                                    LWECiphertextH **outArray, int *outLen);

PKEErr CryptoContext_EvalFHEWtoCKKSSetup(CryptoContextPtr cc,
                                         BinFHEContextH ccLWE,
                                         uint32_t numSlots, uint32_t logQ);
PKEErr CryptoContext_EvalFHEWtoCKKSKeyGen(CryptoContextPtr cc,
                                          KeyPairPtr keyPair,
                                          LWEPrivateKeyPtr lwesk);

// Default version with automatic parameters
PKEErr CryptoContext_EvalFHEWtoCKKS(CryptoContextPtr cc,
                                    LWECiphertextH *lweCiphertexts,
                                    int numCtxts, uint32_t numSlots, uint32_t p,
                                    CiphertextPtr *out);

// Extended version with more control
PKEErr CryptoContext_EvalFHEWtoCKKSExt(CryptoContextPtr cc,
                                       LWECiphertextH *lweCiphertexts,
                                       int numCtxts, uint32_t numSlots,
                                       uint32_t p, double pmin, double pmax,
                                       CiphertextPtr *out);

// Combined setup for bidirectional switching
PKEErr CryptoContext_EvalSchemeSwitchingSetup(CryptoContextPtr cc,
                                              SchSwchParamsPtr params,
                                              LWEPrivateKeyPtr *out);
PKEErr CryptoContext_EvalSchemeSwitchingKeyGen(CryptoContextPtr cc,
                                               KeyPairPtr keyPair,
                                               LWEPrivateKeyPtr lwesk);

// Get the BinFHE context used for scheme switching
PKEErr CryptoContext_GetBinCCForSchemeSwitch(CryptoContextPtr cc,
                                             BinFHEContextH *out);

// --- Comparison and Argmin Functions ---
PKEErr CryptoContext_EvalCompareSwitchPrecompute(CryptoContextPtr cc,
                                                 uint32_t pLWE,
                                                 double scaleSign);

// Note: Comparison and Argmin functions will be added in a future phase
// as they require additional BinFHE operations to be implemented first

#ifdef __cplusplus
}
#endif

#endif // SCHEMESWITCH_C_H
