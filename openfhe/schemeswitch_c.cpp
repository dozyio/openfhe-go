#include "schemeswitch_c.h"
#include "binfhecontext.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"
#include "scheme/scheme-swch-params.h"
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

using namespace lbcrypto;

// --- Helper macros for error handling ---
#define TRY_CATCH_BEGIN try {
#define TRY_CATCH_END_RETURN_PKERR                                             \
  }                                                                            \
  catch (const std::exception &e) {                                            \
    PKEErr err;                                                                \
    err.code = PKE_ERR_CODE;                                                   \
    err.msg = strdup(e.what());                                                \
    return err;                                                                \
  }                                                                            \
  catch (...) {                                                                \
    PKEErr err;                                                                \
    err.code = PKE_ERR_CODE;                                                   \
    err.msg = strdup("Unknown error");                                         \
    return err;                                                                \
  }                                                                            \
  PKEErr err;                                                                  \
  err.code = PKE_OK_CODE;                                                      \
  err.msg = nullptr;                                                           \
  return err;

// --- Type conversions ---
static CryptoContext<DCRTPoly> *unwrapCC(CryptoContextPtr cc) {
  return static_cast<CryptoContext<DCRTPoly> *>(cc);
}

static SchSwchParams *unwrapSchSwchParams(SchSwchParamsPtr params) {
  return static_cast<SchSwchParams *>(params);
}

static LWEPrivateKey *unwrapLWEPrivateKey(LWEPrivateKeyPtr key) {
  return static_cast<LWEPrivateKey *>(key);
}

static KeyPair<DCRTPoly> *unwrapKeyPair(KeyPairPtr kp) {
  return static_cast<KeyPair<DCRTPoly> *>(kp);
}

static Ciphertext<DCRTPoly> *unwrapCiphertext(CiphertextPtr ct) {
  return static_cast<Ciphertext<DCRTPoly> *>(ct);
}

static std::shared_ptr<BinFHEContext> *unwrapBinFHEContext(BinFHEContextH h) {
  return static_cast<std::shared_ptr<BinFHEContext> *>(h);
}

static std::shared_ptr<LWECiphertextImpl> *
unwrapLWECiphertext(LWECiphertextH h) {
  return static_cast<std::shared_ptr<LWECiphertextImpl> *>(h);
}

// Convert BinFHEParamSet enum to OpenFHE BINFHE_PARAMSET
static BINFHE_PARAMSET convertBinFHEParamSet(BinFHEParamSet level) {
  switch (level) {
  case BINFHE_TOY:
    return TOY;
  case BINFHE_MEDIUM:
    return MEDIUM;
  case BINFHE_STD128_AP:
    return STD128_AP;
  case BINFHE_STD128:
    return STD128;
  case BINFHE_STD128_3:
    return STD128_3;
  case BINFHE_STD128_4:
    return STD128_4;
  case BINFHE_STD128Q:
    return STD128Q;
  case BINFHE_STD128Q_3:
    return STD128Q_3;
  case BINFHE_STD128Q_4:
    return STD128Q_4;
  case BINFHE_STD192:
    return STD192;
  case BINFHE_STD192_3:
    return STD192_3;
  case BINFHE_STD192_4:
    return STD192_4;
  case BINFHE_STD192Q:
    return STD192Q;
  case BINFHE_STD192Q_3:
    return STD192Q_3;
  case BINFHE_STD192Q_4:
    return STD192Q_4;
  case BINFHE_STD256:
    return STD256;
  case BINFHE_STD256_3:
    return STD256_3;
  case BINFHE_STD256_4:
    return STD256_4;
  case BINFHE_STD256Q:
    return STD256Q;
  case BINFHE_STD256Q_3:
    return STD256Q_3;
  case BINFHE_STD256Q_4:
    return STD256Q_4;
  default:
    return TOY;
  }
}

static BinFHEParamSet convertFromBinFHEParamSet(BINFHE_PARAMSET level) {
  switch (level) {
  case TOY:
    return BINFHE_TOY;
  case MEDIUM:
    return BINFHE_MEDIUM;
  case STD128_AP:
    return BINFHE_STD128_AP;
  case STD128:
    return BINFHE_STD128;
  case STD128_3:
    return BINFHE_STD128_3;
  case STD128_4:
    return BINFHE_STD128_4;
  case STD128Q:
    return BINFHE_STD128Q;
  case STD128Q_3:
    return BINFHE_STD128Q_3;
  case STD128Q_4:
    return BINFHE_STD128Q_4;
  case STD192:
    return BINFHE_STD192;
  case STD192_3:
    return BINFHE_STD192_3;
  case STD192_4:
    return BINFHE_STD192_4;
  case STD192Q:
    return BINFHE_STD192Q;
  case STD192Q_3:
    return BINFHE_STD192Q_3;
  case STD192Q_4:
    return BINFHE_STD192Q_4;
  case STD256:
    return BINFHE_STD256;
  case STD256_3:
    return BINFHE_STD256_3;
  case STD256_4:
    return BINFHE_STD256_4;
  case STD256Q:
    return BINFHE_STD256Q;
  case STD256Q_3:
    return BINFHE_STD256Q_3;
  case STD256Q_4:
    return BINFHE_STD256Q_4;
  default:
    return BINFHE_TOY;
  }
}

static SecurityLevel convertSecurityLevel(OFHESecurityLevel level) {
  // Direct mapping since both use the same values
  return static_cast<SecurityLevel>(level);
}

static OFHESecurityLevel convertFromSecurityLevel(SecurityLevel level) {
  // Direct mapping since both use the same values
  return static_cast<OFHESecurityLevel>(level);
}

// --- SchSwchParams Functions ---

PKEErr NewSchSwchParams(SchSwchParamsPtr *out) {
  TRY_CATCH_BEGIN
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }
  auto *params = new SchSwchParams();
  *out = params;
  TRY_CATCH_END_RETURN_PKERR
}

void DestroySchSwchParams(SchSwchParamsPtr params) {
  if (params) {
    delete unwrapSchSwchParams(params);
  }
}

PKEErr SchSwchParams_SetSecurityLevelCKKS(SchSwchParamsPtr params,
                                          OFHESecurityLevel level) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetSecurityLevelCKKS(
      convertSecurityLevel(level));
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetSecurityLevelFHEW(SchSwchParamsPtr params,
                                          BinFHEParamSet level) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetSecurityLevelFHEW(
      convertBinFHEParamSet(level));
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetNumSlotsCKKS(SchSwchParamsPtr params,
                                     uint32_t numSlots) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetNumSlotsCKKS(numSlots);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetNumValues(SchSwchParamsPtr params, uint32_t numValues) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetNumValues(numValues);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetCtxtModSizeFHEWLargePrec(SchSwchParamsPtr params,
                                                 uint32_t ctxtModSize) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetCtxtModSizeFHEWLargePrec(ctxtModSize);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetComputeArgmin(SchSwchParamsPtr params, int flag) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetComputeArgmin(flag != 0);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetUseAltArgmin(SchSwchParamsPtr params, int flag) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetUseAltArgmin(flag != 0);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetArbitraryFunctionEvaluation(SchSwchParamsPtr params,
                                                    int flag) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetArbitraryFunctionEvaluation(flag != 0);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_SetOneHotEncoding(SchSwchParamsPtr params, int flag) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  unwrapSchSwchParams(params)->SetOneHotEncoding(flag != 0);
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_GetSecurityLevelCKKS(SchSwchParamsPtr params,
                                          OFHESecurityLevel *out) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }
  *out = convertFromSecurityLevel(
      unwrapSchSwchParams(params)->GetSecurityLevelCKKS());
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_GetSecurityLevelFHEW(SchSwchParamsPtr params,
                                          BinFHEParamSet *out) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }
  *out = convertFromBinFHEParamSet(
      unwrapSchSwchParams(params)->GetSecurityLevelFHEW());
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_GetNumSlotsCKKS(SchSwchParamsPtr params, uint32_t *out) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }
  *out = unwrapSchSwchParams(params)->GetNumSlotsCKKS();
  TRY_CATCH_END_RETURN_PKERR
}

PKEErr SchSwchParams_GetNumValues(SchSwchParamsPtr params, uint32_t *out) {
  TRY_CATCH_BEGIN
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }
  *out = unwrapSchSwchParams(params)->GetNumValues();
  TRY_CATCH_END_RETURN_PKERR
}

// --- LWE Private Key Functions ---

void DestroyLWEPrivateKey(LWEPrivateKeyPtr key) {
  if (key) {
    delete unwrapLWEPrivateKey(key);
  }
}

// --- Scheme Switching Setup Functions ---

PKEErr CryptoContext_EvalCKKStoFHEWSetup(CryptoContextPtr cc,
                                         SchSwchParamsPtr params,
                                         LWEPrivateKeyPtr *out) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }

  auto result =
      (*unwrapCC(cc))->EvalCKKStoFHEWSetup(*unwrapSchSwchParams(params));
  auto *key = new LWEPrivateKey(result);
  *out = key;

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalCKKStoFHEWKeyGen(CryptoContextPtr cc,
                                          KeyPairPtr keyPair,
                                          LWEPrivateKeyPtr lwesk) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!keyPair) {
    throw std::invalid_argument("KeyPair pointer is null");
  }
  if (!lwesk) {
    throw std::invalid_argument("LWEPrivateKey pointer is null");
  }

  (*unwrapCC(cc))
      ->EvalCKKStoFHEWKeyGen(*unwrapKeyPair(keyPair),
                             *unwrapLWEPrivateKey(lwesk));

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalCKKStoFHEWPrecompute(CryptoContextPtr cc,
                                              double scale) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }

  (*unwrapCC(cc))->EvalCKKStoFHEWPrecompute(scale);

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalCKKStoFHEW(CryptoContextPtr cc,
                                    CiphertextPtr ciphertext,
                                    uint32_t numValues,
                                    LWECiphertextH **outArray, int *outLen) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!ciphertext) {
    throw std::invalid_argument("Ciphertext pointer is null");
  }
  if (!outArray) {
    throw std::invalid_argument("Output array pointer is null");
  }
  if (!outLen) {
    throw std::invalid_argument("Output length pointer is null");
  }

  auto result =
      (*unwrapCC(cc))->EvalCKKStoFHEW(*unwrapCiphertext(ciphertext), numValues);

  // Allocate array for handles
  *outLen = result.size();
  *outArray = (LWECiphertextH *)malloc(sizeof(LWECiphertextH) * result.size());
  if (!*outArray) {
    throw std::runtime_error(
        "Failed to allocate memory for LWE ciphertext array");
  }

  // Wrap each LWE ciphertext in a shared_ptr wrapper
  for (size_t i = 0; i < result.size(); ++i) {
    auto *wrapped = new std::shared_ptr<LWECiphertextImpl>(result[i]);
    (*outArray)[i] = wrapped;
  }

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalFHEWtoCKKSSetup(CryptoContextPtr cc,
                                         BinFHEContextH ccLWE,
                                         uint32_t numSlots, uint32_t logQ) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!ccLWE) {
    throw std::invalid_argument("BinFHEContext pointer is null");
  }

  (*unwrapCC(cc))
      ->EvalFHEWtoCKKSSetup(*unwrapBinFHEContext(ccLWE), numSlots, logQ);

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalFHEWtoCKKSKeyGen(CryptoContextPtr cc,
                                          KeyPairPtr keyPair,
                                          LWEPrivateKeyPtr lwesk) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!keyPair) {
    throw std::invalid_argument("KeyPair pointer is null");
  }
  if (!lwesk) {
    throw std::invalid_argument("LWEPrivateKey pointer is null");
  }

  (*unwrapCC(cc))
      ->EvalFHEWtoCKKSKeyGen(*unwrapKeyPair(keyPair),
                             *unwrapLWEPrivateKey(lwesk));

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalFHEWtoCKKS(CryptoContextPtr cc,
                                    LWECiphertextH *lweCiphertexts,
                                    int numCtxts, uint32_t numSlots, uint32_t p,
                                    CiphertextPtr *out) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!lweCiphertexts) {
    throw std::invalid_argument("LWE ciphertexts array is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }

  // Convert array of handles to vector of shared_ptrs
  std::vector<std::shared_ptr<LWECiphertextImpl>> vec;
  vec.reserve(numCtxts);
  for (int i = 0; i < numCtxts; ++i) {
    vec.push_back(*unwrapLWECiphertext(lweCiphertexts[i]));
  }

  auto result = (*unwrapCC(cc))->EvalFHEWtoCKKS(vec, numSlots, p);
  auto *wrapped = new Ciphertext<DCRTPoly>(result);
  *out = wrapped;

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalFHEWtoCKKSExt(CryptoContextPtr cc,
                                       LWECiphertextH *lweCiphertexts,
                                       int numCtxts, uint32_t numSlots,
                                       uint32_t p, double pmin, double pmax,
                                       CiphertextPtr *out) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!lweCiphertexts) {
    throw std::invalid_argument("LWE ciphertexts array is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }

  // Convert array of handles to vector of shared_ptrs
  std::vector<std::shared_ptr<LWECiphertextImpl>> vec;
  vec.reserve(numCtxts);
  for (int i = 0; i < numCtxts; ++i) {
    vec.push_back(*unwrapLWECiphertext(lweCiphertexts[i]));
  }

  auto result = (*unwrapCC(cc))->EvalFHEWtoCKKS(vec, numSlots, p, pmin, pmax);
  auto *wrapped = new Ciphertext<DCRTPoly>(result);
  *out = wrapped;

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalSchemeSwitchingSetup(CryptoContextPtr cc,
                                              SchSwchParamsPtr params,
                                              LWEPrivateKeyPtr *out) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!params) {
    throw std::invalid_argument("SchSwchParams pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }

  auto result =
      (*unwrapCC(cc))->EvalSchemeSwitchingSetup(*unwrapSchSwchParams(params));
  auto *key = new LWEPrivateKey(result);
  *out = key;

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalSchemeSwitchingKeyGen(CryptoContextPtr cc,
                                               KeyPairPtr keyPair,
                                               LWEPrivateKeyPtr lwesk) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!keyPair) {
    throw std::invalid_argument("KeyPair pointer is null");
  }
  if (!lwesk) {
    throw std::invalid_argument("LWEPrivateKey pointer is null");
  }

  (*unwrapCC(cc))
      ->EvalSchemeSwitchingKeyGen(*unwrapKeyPair(keyPair),
                                  *unwrapLWEPrivateKey(lwesk));

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_GetBinCCForSchemeSwitch(CryptoContextPtr cc,
                                             BinFHEContextH *out) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }
  if (!out) {
    throw std::invalid_argument("Output pointer is null");
  }

  auto result = (*unwrapCC(cc))->GetBinCCForSchemeSwitch();
  // Return the raw pointer from the shared_ptr for consistency with
  // BinFHEContext_New The shared_ptr keeps the object alive in the CKKS context
  *out = result.get();

  TRY_CATCH_END_RETURN_PKERR
}

PKEErr CryptoContext_EvalCompareSwitchPrecompute(CryptoContextPtr cc,
                                                 uint32_t pLWE,
                                                 double scaleSign) {
  TRY_CATCH_BEGIN
  if (!cc) {
    throw std::invalid_argument("CryptoContext pointer is null");
  }

  (*unwrapCC(cc))->EvalCompareSwitchPrecompute(pLWE, scaleSign);

  TRY_CATCH_END_RETURN_PKERR
}
