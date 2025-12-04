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
PKEErr ParamsCKKS_SetDigitSize(ParamsCKKSPtr p, int digitSize);
PKEErr ParamsCKKS_SetKeySwitchTechnique(ParamsCKKSPtr p, int technique);
PKEErr ParamsCKKS_SetMultipartyMode(ParamsCKKSPtr p, int mode);
PKEErr ParamsCKKS_SetCKKSDataType(ParamsCKKSPtr p, int dataType);
PKEErr ParamsCKKS_SetInteractiveBootCompressionLevel(ParamsCKKSPtr p,
                                                     int compressionLevel);
void DestroyParamsCKKS(ParamsCKKSPtr p);

// --- CKKS CryptoContext ---
PKEErr NewCryptoContextCKKS(ParamsCKKSPtr p, CryptoContextPtr *out);

// --- CKKS Plaintext ---
PKEErr CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc,
                                             double *values, int len,
                                             PlaintextPtr *out);
PKEErr CryptoContext_MakeCKKSPackedPlaintextWithParams(CryptoContextPtr cc,
                                                       double *values, int len,
                                                       double scaleDeg,
                                                       int level,
                                                       PlaintextPtr *out);
PKEErr CryptoContext_MakeCKKSComplexPackedPlaintext(CryptoContextPtr cc,
                                                    complex_double_t *values,
                                                    int len, PlaintextPtr *out);
PKEErr CryptoContext_MakeCKKSComplexPackedPlaintextWithParams(
    CryptoContextPtr cc, complex_double_t *values, int len, double scaleDeg,
    int level, PlaintextPtr *out);

// --- CKKS Operations ---
PKEErr CryptoContext_Rescale(CryptoContextPtr cc, CiphertextPtr ct,
                             CiphertextPtr *out);

PKEErr CryptoContext_ModReduce(CryptoContextPtr cc, CiphertextPtr ct,
                               CiphertextPtr *out);
PKEErr CryptoContext_ModReduceInPlace(CryptoContextPtr cc, CiphertextPtr ct);

// Scalar and complex constant operations
PKEErr CryptoContext_EvalMultDouble(CryptoContextPtr cc, CiphertextPtr ct,
                                    double constant, CiphertextPtr *out);
PKEErr CryptoContext_EvalMultComplex(CryptoContextPtr cc, CiphertextPtr ct,
                                     complex_double_t constant,
                                     CiphertextPtr *out);
PKEErr CryptoContext_EvalAddDouble(CryptoContextPtr cc, CiphertextPtr ct,
                                   double constant, CiphertextPtr *out);
PKEErr CryptoContext_EvalAddComplex(CryptoContextPtr cc, CiphertextPtr ct,
                                    complex_double_t constant,
                                    CiphertextPtr *out);
PKEErr CryptoContext_EvalSubDouble(CryptoContextPtr cc, CiphertextPtr ct,
                                   double constant, CiphertextPtr *out);
PKEErr CryptoContext_EvalSubComplex(CryptoContextPtr cc, CiphertextPtr ct,
                                    complex_double_t constant,
                                    CiphertextPtr *out);

// In-place operations
PKEErr CryptoContext_EvalAddInPlaceDouble(CryptoContextPtr cc, CiphertextPtr ct,
                                          double constant);
PKEErr CryptoContext_EvalAddInPlaceComplex(CryptoContextPtr cc,
                                           CiphertextPtr ct,
                                           complex_double_t constant);
PKEErr CryptoContext_EvalSubInPlaceDouble(CryptoContextPtr cc, CiphertextPtr ct,
                                          double constant);
PKEErr CryptoContext_EvalSubInPlaceComplex(CryptoContextPtr cc,
                                           CiphertextPtr ct,
                                           complex_double_t constant);

// --- CKKS Bootstrapping ---
PKEErr CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc,
                                               const uint32_t *levelBudget,
                                               int len);
PKEErr CryptoContext_EvalBootstrapSetup(CryptoContextPtr cc,
                                        const uint32_t *levelBudget, int lbLen,
                                        const uint32_t *bsgsDim, int bsgsLen,
                                        uint32_t numSlots);
PKEErr CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc, KeyPairPtr keys,
                                         uint32_t slots);
PKEErr CryptoContext_EvalBootstrap(CryptoContextPtr cc, CiphertextPtr ct,
                                   CiphertextPtr *out);
PKEErr CryptoContext_EvalBootstrapWithIterations(CryptoContextPtr cc,
                                                 CiphertextPtr ct,
                                                 uint32_t numIterations,
                                                 uint32_t precision,
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
PKEErr Plaintext_GetComplexPackedValueBulk(PlaintextPtr pt,
                                           complex_double_t **out_values,
                                           int *out_len);

// --- CKKS Advanced Operations ---
PKEErr CryptoContext_EvalSumKeyGen(CryptoContextPtr cc, KeyPairPtr keys);
PKEErr CryptoContext_EvalSum(CryptoContextPtr cc, CiphertextPtr ct,
                             uint32_t batchSize, CiphertextPtr *out);
PKEErr CryptoContext_EvalInnerProduct(CryptoContextPtr cc, CiphertextPtr ct1,
                                      CiphertextPtr ct2, uint32_t batchSize,
                                      CiphertextPtr *out);

// --- CKKS Linear Weighted Sum ---
PKEErr CryptoContext_EvalLinearWSum(CryptoContextPtr cc, CiphertextPtr *ctVec,
                                    int ctCount, const double *constants,
                                    int constCount, CiphertextPtr *out);

// --- CKKS Function Evaluation (Chebyshev Approximation) ---
PKEErr CryptoContext_EvalLogistic(CryptoContextPtr cc, CiphertextPtr ct,
                                  double lowerBound, double upperBound,
                                  uint32_t polyDegree, CiphertextPtr *out);
PKEErr CryptoContext_EvalDivide(CryptoContextPtr cc, CiphertextPtr ct,
                                double lowerBound, double upperBound,
                                uint32_t polyDegree, CiphertextPtr *out);
PKEErr CryptoContext_EvalSin(CryptoContextPtr cc, CiphertextPtr ct,
                             double lowerBound, double upperBound,
                             uint32_t polyDegree, CiphertextPtr *out);
PKEErr CryptoContext_EvalCos(CryptoContextPtr cc, CiphertextPtr ct,
                             double lowerBound, double upperBound,
                             uint32_t polyDegree, CiphertextPtr *out);

// Callback function type for custom Chebyshev functions
// This will be implemented in Go and called from C++
extern double goChebyshevCallback(int callbackID, double x);

// Evaluate a custom function using Chebyshev approximation
// The function is provided via a callback ID that maps to a Go function
PKEErr CryptoContext_EvalChebyshevFunction(CryptoContextPtr cc, int callbackID,
                                           CiphertextPtr ct, double lowerBound,
                                           double upperBound,
                                           uint32_t polyDegree,
                                           CiphertextPtr *out);

// --- Chebyshev Coefficient Computation (from core/math/chebyshev.h) ---

// Compute Chebyshev coefficients for approximating a function
// This is useful for advanced users who want to:
// 1. Inspect coefficients before encryption
// 2. Reuse coefficients across multiple ciphertexts (via EvalChebyshevSeries)
// 3. Implement custom evaluation logic
typedef struct {
  double *coeffs;
  size_t length;
} ChebyshevCoeffs;

PKEErr EvalChebyshevCoefficients(int callbackID, double lowerBound,
                                 double upperBound, uint32_t degree,
                                 ChebyshevCoeffs *out);

void FreeChebyshevCoeffs(ChebyshevCoeffs *coeffs);

// Evaluate a Chebyshev series on encrypted data using pre-computed coefficients
// This is more efficient than EvalChebyshevFunction when evaluating the same
// function on multiple ciphertexts, as coefficients can be reused.
PKEErr CryptoContext_EvalChebyshevSeries(CryptoContextPtr cc, CiphertextPtr ct,
                                         const double *coefficients,
                                         size_t numCoeffs, double lowerBound,
                                         double upperBound, CiphertextPtr *out);

// --- TCKKS Interactive Multi-Party Bootstrapping ---
PKEErr CryptoContext_IntMPBootAdjustScale(CryptoContextPtr cc, CiphertextPtr ct,
                                          CiphertextPtr *out);
PKEErr CryptoContext_IntMPBootRandomElementGen(CryptoContextPtr cc,
                                               PublicKeyPtr pk,
                                               CiphertextPtr *out);
PKEErr CryptoContext_IntMPBootDecrypt(CryptoContextPtr cc, PrivateKeyPtr sk,
                                      CiphertextPtr c1, CiphertextPtr a,
                                      CiphertextPtr *out0, CiphertextPtr *out1);
PKEErr CryptoContext_IntMPBootAdd(CryptoContextPtr cc,
                                  CiphertextPtr **sharesPairVec,
                                  size_t numParties, CiphertextPtr *out0,
                                  CiphertextPtr *out1);
PKEErr CryptoContext_IntMPBootEncrypt(CryptoContextPtr cc, PublicKeyPtr pk,
                                      CiphertextPtr aggregatedH0,
                                      CiphertextPtr aggregatedH1,
                                      CiphertextPtr a, CiphertextPtr inCtxt,
                                      CiphertextPtr *out);

#ifdef __cplusplus
}
#endif

#endif // CKKS_C_H
