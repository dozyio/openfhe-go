#include "ckks_c.h"
#include "pke_helpers_c.h"
#include <complex>

using namespace lbcrypto;

extern "C" {

// --- CKKS Params Functions ---
PKEErr NewParamsCKKS(ParamsCKKSPtr *out) {
  try {
    if (!out) {
      return MakePKEError("NewParamsCKKS: null output pointer");
    }
    *out = new CCParams<CryptoContextCKKSRNS>();
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetScalingModSize(ParamsCKKSPtr p, int modSize) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetScalingModSize: null params");
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetScalingModSize(
        modSize);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetBatchSize(ParamsCKKSPtr p, int batchSize) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetBatchSize: null params");
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetBatchSize(
        batchSize);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetMultiplicativeDepth(ParamsCKKSPtr p, int depth) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetMultiplicativeDepth: null params");
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)
        ->SetMultiplicativeDepth(depth);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetSecurityLevel(ParamsCKKSPtr p, OFHESecurityLevel level) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetSecurityLevel: null params");
    }
    auto params = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
    params->SetSecurityLevel(static_cast<lbcrypto::SecurityLevel>(level));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetRingDim(ParamsCKKSPtr p, uint64_t ringDim) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetRingDim: null params");
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetRingDim(ringDim);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetScalingTechnique(ParamsCKKSPtr p, int technique) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetScalingTechnique: null params");
    }
    ScalingTechnique st;
    switch (technique) {
    case 0:
      st = lbcrypto::FIXEDMANUAL;
      break;
    case 1:
      st = lbcrypto::FIXEDAUTO;
      break;
    case 2:
      st = lbcrypto::FLEXIBLEAUTO;
      break;
    case 3:
      st = lbcrypto::FLEXIBLEAUTOEXT;
      break;
    case 6:
      st = lbcrypto::NORESCALE;
      break;
    default:
      st = lbcrypto::INVALID_RS_TECHNIQUE;
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetScalingTechnique(
        st);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetSecretKeyDist(ParamsCKKSPtr p, OFHESecretKeyDist dist) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetSecretKeyDist: null params");
    }
    auto params = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
    params->SetSecretKeyDist(static_cast<lbcrypto::SecretKeyDist>(dist));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetFirstModSize(ParamsCKKSPtr p, int modSize) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetFirstModSize: null params");
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetFirstModSize(
        modSize);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetNumLargeDigits(ParamsCKKSPtr p, int numDigits) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetNumLargeDigits: null params");
    }

    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetNumLargeDigits(
        numDigits);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetDigitSize(ParamsCKKSPtr p, int digitSize) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetDigitSize: null params");
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetDigitSize(
        digitSize);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetKeySwitchTechnique(ParamsCKKSPtr p, int technique) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetKeySwitchTechnique: null params");
    }
    // Map int to KeySwitchTechnique enum
    // INVALID = 0, BV = 1, HYBRID = 2 (same as in OpenFHE)
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)
        ->SetKeySwitchTechnique(static_cast<KeySwitchTechnique>(technique));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void DestroyParamsCKKS(ParamsCKKSPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
}

// --- CKKS CryptoContext ---
PKEErr NewCryptoContextCKKS(ParamsCKKSPtr p, CryptoContextPtr *out) {
  try {
    if (!p) {
      return MakePKEError("NewCryptoContextCKKS: null params");
    }
    if (!out) {
      return MakePKEError("NewCryptoContextCKKS: null output pointer");
    }
    auto params_ptr = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
    CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
    *out =
        reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- CKKS Plaintext ---
PKEErr CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                             double *values, int len,
                                             PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MakeCKKSPackedPlaintext: null context");
    }

    if (len > 0 && !values) {
      return MakePKEError("CryptoContext_MakeCKKSPackedPlaintext: non-zero "
                          "length with null values");
    }

    if (!out) {
      return MakePKEError(
          "CryptoContext_MakeCKKSPackedPlaintext: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<double> vec(values, values + len);
    Plaintext pt_sptr = cc_sptr->MakeCKKSPackedPlaintext(vec);
    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr
CryptoContext_MakeCKKSComplexPackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                             complex_double_t *values, int len,
                                             PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MakeCKKSComplexPackedPlaintext: null context");
    }

    if (len > 0 && !values) {
      return MakePKEError("CryptoContext_MakeCKKSComplexPackedPlaintext: "
                          "non-zero length with null values");
    }

    if (!out) {
      return MakePKEError(
          "CryptoContext_MakeCKKSComplexPackedPlaintext: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);

    // Convert C struct array to std::vector<std::complex<double>>
    std::vector<std::complex<double>> vec(len);
    for (int i = 0; i < len; ++i) {
      vec[i] = std::complex<double>(values[i].real, values[i].imag);
    }

    Plaintext pt_sptr = cc_sptr->MakeCKKSPackedPlaintext(vec);
    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetComplexPackedValueLength(PlaintextPtr pt_ptr_to_sptr,
                                             int *out_len) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueLength: null plaintext");
    }

    if (!out_len) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueLength: null output pointer");
    }

    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);

    // Assuming GetCKKSPackedValue is the method for complex (check OpenFHE
    // source if needed)
    *out_len = pt_sptr->GetCKKSPackedValue().size();

    return MakePKEOk();
  }

  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetComplexPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                                         complex_double_t *out) {
  try {
    if (!!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetComplexPackedValueAt: null plaintext");
    }

    if (!out) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueAt: null output pointer");
    }

    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    const auto &complex_vec =
        pt_sptr->GetCKKSPackedValue(); // Assuming this is correct

    // bounds check
    if (i < 0 || (size_t)i >= complex_vec.size()) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueAt: index out of bounds");
    }

    out->real = complex_vec[i].real();
    out->imag = complex_vec[i].imag();

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- CKKS Operations ---
PKEErr CryptoContext_Rescale(CryptoContextPtr cc_ptr_to_sptr,
                             CiphertextPtr ct_ptr_to_sptr, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Rescale: null context");
    }

    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Rescale: null ciphertext");
    }

    if (!out) {
      return MakePKEError("CryptoContext_Rescale: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->Rescale(ct_sptr);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_ModReduce(CryptoContextPtr cc_ptr_to_sptr,
                               CiphertextPtr ct_ptr_to_sptr,
                               CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_ModReduce: null context");
    }

    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_ModReduce: null ciphertext");
    }

    if (!out) {
      return MakePKEError("CryptoContext_ModReduce: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->ModReduce(ct_sptr);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalPoly(CryptoContextPtr cc_ptr_to_sptr,
                              CiphertextPtr ct_ptr_to_sptr,
                              const double *coefficients, size_t count,
                              CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalPoly: null context");
    }

    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalPoly: null input ciphertext");
    }

    if (count > 0 && !coefficients) {
      return MakePKEError("CryptoContext_EvalPoly: non-zero coefficient count "
                          "with null pointer");
    }

    if (!out) {
      return MakePKEError("CryptoContext_EvalPoly: null output pointer");
    }

    *out = nullptr; // Initialize output

    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);

    std::vector<double> coeffs(coefficients, coefficients + count);

    Ciphertext<DCRTPoly> result_ct_sptr = cc->EvalPoly(ct, coeffs);

    // Create a new shared_ptr container on the heap for the result
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- CKKS Bootstrapping ---
PKEErr CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc_ptr_to_sptr,
                                               const uint32_t *lb, int len) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalBootstrapSetup_Simple: null context");
    }
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<uint32_t> levelBudget;
    if (lb && len > 0)
      levelBudget.assign(lb, lb + len);
    else
      levelBudget = {4, 4}; // Default

    cc->EvalBootstrapSetup(levelBudget);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                         KeyPairPtr keys_raw_ptr,
                                         uint32_t slots) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    if (!cc) {
      return MakePKEError("CryptoContext_EvalBootstrapKeyGen: null context");
    }
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw || !kp_raw->secretKey) {
      return MakePKEError(
          "CryptoContext_EvalBootstrapKeyGen: missing secret key");
    }

    auto N = cc->GetRingDimension();
    if (slots == 0 || slots > N / 2)
      slots = (uint32_t)(N / 2);

    cc->EvalBootstrapKeyGen(kp_raw->secretKey, slots);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalBootstrap(CryptoContextPtr cc_ptr_to_sptr,
                                   CiphertextPtr ct_ptr_to_sptr,
                                   CiphertextPtr *out) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);
    if (!cc) {
      return MakePKEError("CryptoContext_EvalBootstrap: null context");
    }
    if (!ct) {
      return MakePKEError("CryptoContext_EvalBootstrap: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalBootstrap: null output pointer");
    }

    auto out_ct = cc->EvalBootstrap(ct);
    *out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(out_ct));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist) {
  // This is a static helper, no error handling needed
  std::vector<uint32_t> lb;
  if (levelBudget && len > 0)
    lb.assign(levelBudget, levelBudget + len);
  else
    lb = {4, 4};
  auto skd = static_cast<lbcrypto::SecretKeyDist>(secretKeyDist);
  return FHECKKSRNS::GetBootstrapDepth(lb, skd);
}

// --- CKKS Advanced Operations ---
PKEErr CryptoContext_EvalSumKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                   KeyPairPtr keys_raw_ptr) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSumKeyGen: null context");
    }
    if (!keys_raw_ptr) {
      return MakePKEError("CryptoContext_EvalSumKeyGen: null keypair");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);

    if (!kp_raw->secretKey) {
      return MakePKEError(
          "CryptoContext_EvalSumKeyGen: keypair has no secret key");
    }

    cc_sptr->EvalSumKeyGen(kp_raw->secretKey);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSum(CryptoContextPtr cc_ptr_to_sptr,
                             CiphertextPtr ct_ptr_to_sptr, uint32_t batchSize,
                             CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSum: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSum: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalSum: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalSum(ct_sptr, batchSize);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalInnerProduct(CryptoContextPtr cc_ptr_to_sptr,
                                      CiphertextPtr ct1_ptr_to_sptr,
                                      CiphertextPtr ct2_ptr_to_sptr,
                                      uint32_t batchSize, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalInnerProduct: null context");
    }
    if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalInnerProduct: null input ciphertext");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_EvalInnerProduct: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
    auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalInnerProduct(ct1_sptr, ct2_sptr, batchSize);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

} // extern "C"
