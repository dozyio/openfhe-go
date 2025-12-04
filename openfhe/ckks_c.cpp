#include "ckks_c.h"
#include "math/chebyshev.h"
#include "pke_helpers_c.h"
#include <complex>
#include <functional>

using namespace lbcrypto;

// Forward declaration of Go callback function
extern "C" double goChebyshevCallback(int callbackID, double x);

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

PKEErr ParamsCKKS_SetCKKSDataType(ParamsCKKSPtr p, int dataType) {
  try {
    if (!p) {
      return MakePKEError("ParamsCKKS_SetCKKSDataType: null params");
    }
    // Map int to CKKSDataType enum
    // REAL = 0, COMPLEX = 1 (from OpenFHE)
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetCKKSDataType(
        static_cast<CKKSDataType>(dataType));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsCKKS_SetInteractiveBootCompressionLevel(ParamsCKKSPtr p,
                                                     int compressionLevel) {
  try {
    if (!p) {
      return MakePKEError(
          "ParamsCKKS_SetInteractiveBootCompressionLevel: null params");
    }
    // Map int to COMPRESSION_LEVEL enum
    // COMPACT = 2, SLACK = 3 (from OpenFHE constants-defs.h)
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)
        ->SetInteractiveBootCompressionLevel(
            static_cast<COMPRESSION_LEVEL>(compressionLevel));

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

PKEErr CryptoContext_MakeCKKSPackedPlaintextWithParams(
    CryptoContextPtr cc_ptr_to_sptr, double *values, int len, double scaleDeg,
    int level, PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MakeCKKSPackedPlaintextWithParams: null context");
    }

    if (len > 0 && !values) {
      return MakePKEError("CryptoContext_MakeCKKSPackedPlaintextWithParams: "
                          "non-zero length with null values");
    }

    if (!out) {
      return MakePKEError("CryptoContext_MakeCKKSPackedPlaintextWithParams: "
                          "null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<double> vec(values, values + len);
    Plaintext pt_sptr = cc_sptr->MakeCKKSPackedPlaintext(vec, scaleDeg, level);
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

PKEErr CryptoContext_MakeCKKSComplexPackedPlaintextWithParams(
    CryptoContextPtr cc_ptr_to_sptr, complex_double_t *values, int len,
    double scaleDeg, int level, PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MakeCKKSComplexPackedPlaintextWithParams: null "
          "context");
    }

    if (len > 0 && !values) {
      return MakePKEError(
          "CryptoContext_MakeCKKSComplexPackedPlaintextWithParams: "
          "non-zero length with null values");
    }

    if (!out) {
      return MakePKEError(
          "CryptoContext_MakeCKKSComplexPackedPlaintextWithParams: null output "
          "pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);

    // Convert C struct array to std::vector<std::complex<double>>
    std::vector<std::complex<double>> vec(len);
    for (int i = 0; i < len; ++i) {
      vec[i] = std::complex<double>(values[i].real, values[i].imag);
    }

    Plaintext pt_sptr = cc_sptr->MakeCKKSPackedPlaintext(vec, scaleDeg, level);
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
    *out_len = static_cast<int>(pt_sptr->GetLength());
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetComplexPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                                         complex_double_t *out_val) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetComplexPackedValueAt: null plaintext");
    }
    if (!out_val) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueAt: null output pointer");
    }

    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    const std::vector<std::complex<double>> &vec =
        pt_sptr->GetCKKSPackedValue();

    if (i < 0 || static_cast<size_t>(i) >= vec.size()) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueAt: index out of range");
    }

    out_val->real = vec[i].real();
    out_val->imag = vec[i].imag();
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetComplexPackedValueBulk(PlaintextPtr pt_ptr_to_sptr,
                                           complex_double_t **out_values,
                                           int *out_len) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetComplexPackedValueBulk: null plaintext");
    }
    if (!out_values) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueBulk: null output values pointer");
    }
    if (!out_len) {
      return MakePKEError(
          "Plaintext_GetComplexPackedValueBulk: null output length pointer");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    const std::vector<std::complex<double>> &vec =
        pt_sptr->GetCKKSPackedValue();
    *out_len = vec.size();
    if (*out_len == 0) {
      *out_values = nullptr;
      return MakePKEOk();
    }
    *out_values =
        (complex_double_t *)malloc(*out_len * sizeof(complex_double_t));
    if (!*out_values) {
      return MakePKEError("Plaintext_GetComplexPackedValueBulk: malloc failed");
    }
    for (int i = 0; i < *out_len; ++i) {
      (*out_values)[i].real = vec[i].real();
      (*out_values)[i].imag = vec[i].imag();
    }
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

PKEErr CryptoContext_ModReduceInPlace(CryptoContextPtr cc_ptr_to_sptr,
                                      CiphertextPtr ct_ptr_to_sptr) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_ModReduceInPlace: null context");
    }

    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_ModReduceInPlace: null ciphertext");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    cc_sptr->ModReduceInPlace(ct_sptr);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// Scalar and complex constant operations
PKEErr CryptoContext_EvalMultDouble(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct_ptr_to_sptr,
                                    double constant, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMultDouble: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMultDouble: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalMultDouble: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalMult(ct_sptr, constant);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalMultComplex(CryptoContextPtr cc_ptr_to_sptr,
                                     CiphertextPtr ct_ptr_to_sptr,
                                     complex_double_t constant,
                                     CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMultComplex: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMultComplex: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalMultComplex: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    std::complex<double> c(constant.real, constant.imag);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalMult(ct_sptr, c);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalAddDouble(CryptoContextPtr cc_ptr_to_sptr,
                                   CiphertextPtr ct_ptr_to_sptr,
                                   double constant, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAddDouble: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAddDouble: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalAddDouble: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalAdd(ct_sptr, constant);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalAddComplex(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct_ptr_to_sptr,
                                    complex_double_t constant,
                                    CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAddComplex: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAddComplex: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalAddComplex: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    std::complex<double> c(constant.real, constant.imag);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalAdd(ct_sptr, c);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSubDouble(CryptoContextPtr cc_ptr_to_sptr,
                                   CiphertextPtr ct_ptr_to_sptr,
                                   double constant, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSubDouble: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSubDouble: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalSubDouble: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalSub(ct_sptr, constant);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSubComplex(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct_ptr_to_sptr,
                                    complex_double_t constant,
                                    CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSubComplex: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSubComplex: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalSubComplex: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    std::complex<double> c(constant.real, constant.imag);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalSub(ct_sptr, c);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// In-place operations
PKEErr CryptoContext_EvalAddInPlaceDouble(CryptoContextPtr cc_ptr_to_sptr,
                                          CiphertextPtr ct_ptr_to_sptr,
                                          double constant) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAddInPlaceDouble: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalAddInPlaceDouble: null ciphertext");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    cc_sptr->EvalAddInPlace(ct_sptr, constant);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalAddInPlaceComplex(CryptoContextPtr cc_ptr_to_sptr,
                                           CiphertextPtr ct_ptr_to_sptr,
                                           complex_double_t constant) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAddInPlaceComplex: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalAddInPlaceComplex: null ciphertext");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    std::complex<double> c(constant.real, constant.imag);
    cc_sptr->EvalAddInPlace(ct_sptr, c);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSubInPlaceDouble(CryptoContextPtr cc_ptr_to_sptr,
                                          CiphertextPtr ct_ptr_to_sptr,
                                          double constant) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSubInPlaceDouble: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalSubInPlaceDouble: null ciphertext");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    cc_sptr->EvalSubInPlace(ct_sptr, constant);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSubInPlaceComplex(CryptoContextPtr cc_ptr_to_sptr,
                                           CiphertextPtr ct_ptr_to_sptr,
                                           complex_double_t constant) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSubInPlaceComplex: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalSubInPlaceComplex: null ciphertext");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    std::complex<double> c(constant.real, constant.imag);
    cc_sptr->EvalSubInPlace(ct_sptr, c);

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

PKEErr CryptoContext_EvalBootstrapSetup(CryptoContextPtr cc_ptr_to_sptr,
                                        const uint32_t *lb, int lbLen,
                                        const uint32_t *bsgs, int bsgsLen,
                                        uint32_t numSlots) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalBootstrapSetup: null context");
    }
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);

    std::vector<uint32_t> levelBudget;
    if (lb && lbLen > 0)
      levelBudget.assign(lb, lb + lbLen);
    else
      levelBudget = {4, 4}; // Default

    std::vector<uint32_t> bsgsDim;
    if (bsgs && bsgsLen > 0)
      bsgsDim.assign(bsgs, bsgs + bsgsLen);
    else
      bsgsDim = {0, 0}; // Default

    cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
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

PKEErr CryptoContext_EvalBootstrapWithIterations(
    CryptoContextPtr cc_ptr_to_sptr, CiphertextPtr ct_ptr_to_sptr,
    uint32_t numIterations, uint32_t precision, CiphertextPtr *out) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);
    if (!cc) {
      return MakePKEError(
          "CryptoContext_EvalBootstrapWithIterations: null context");
    }
    if (!ct) {
      return MakePKEError(
          "CryptoContext_EvalBootstrapWithIterations: null ciphertext");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_EvalBootstrapWithIterations: null output pointer");
    }

    auto out_ct = cc->EvalBootstrap(ct, numIterations, precision);
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

PKEErr ParamsCKKS_SetMultipartyMode(ParamsCKKSPtr p_ptr_to_sptr, int mode) {
  try {
    if (!p_ptr_to_sptr) {
      return MakePKEError("ParamsCKKS_SetMultipartyMode: null params");
    }
    auto &params =
        *reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p_ptr_to_sptr);
    params.SetMultipartyMode(static_cast<MultipartyMode>(mode));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalLinearWSum(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr *ctVec, int ctCount,
                                    const double *constants, int constCount,
                                    CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalLinearWSum: null context");
    }
    if (!ctVec || ctCount <= 0) {
      return MakePKEError(
          "CryptoContext_EvalLinearWSum: invalid ciphertext vector");
    }
    if (!constants || constCount <= 0) {
      return MakePKEError(
          "CryptoContext_EvalLinearWSum: invalid constants vector");
    }
    if (ctCount != constCount) {
      return MakePKEError("CryptoContext_EvalLinearWSum: ciphertext and "
                          "constant counts must match");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalLinearWSum: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);

    // Convert the array of ciphertext pointers to a vector of
    // ReadOnlyCiphertext
    std::vector<ReadOnlyCiphertext<DCRTPoly>> ct_vec;
    ct_vec.reserve(ctCount);
    for (int i = 0; i < ctCount; i++) {
      auto &ct_sptr = GetCTSharedPtr(ctVec[i]);
      ct_vec.push_back(ct_sptr);
    }

    // Convert the constants array to a vector
    std::vector<double> const_vec(constants, constants + constCount);

    // Call EvalLinearWSum
    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalLinearWSum(ct_vec, const_vec);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalLogistic(CryptoContextPtr cc_ptr_to_sptr,
                                  CiphertextPtr ct_ptr_to_sptr,
                                  double lowerBound, double upperBound,
                                  uint32_t polyDegree, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalLogistic: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalLogistic: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalLogistic: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalLogistic(ct_sptr, lowerBound, upperBound, polyDegree);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalDivide(CryptoContextPtr cc_ptr_to_sptr,
                                CiphertextPtr ct_ptr_to_sptr, double lowerBound,
                                double upperBound, uint32_t polyDegree,
                                CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalDivide: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalDivide: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalDivide: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalDivide(ct_sptr, lowerBound, upperBound, polyDegree);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSin(CryptoContextPtr cc_ptr_to_sptr,
                             CiphertextPtr ct_ptr_to_sptr, double lowerBound,
                             double upperBound, uint32_t polyDegree,
                             CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSin: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSin: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalSin: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalSin(ct_sptr, lowerBound, upperBound, polyDegree);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalCos(CryptoContextPtr cc_ptr_to_sptr,
                             CiphertextPtr ct_ptr_to_sptr, double lowerBound,
                             double upperBound, uint32_t polyDegree,
                             CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalCos: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalCos: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalCos: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalCos(ct_sptr, lowerBound, upperBound, polyDegree);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// EvalChebyshevFunction with callback support
PKEErr CryptoContext_EvalChebyshevFunction(CryptoContextPtr cc_ptr_to_sptr,
                                           int callbackID,
                                           CiphertextPtr ct_ptr_to_sptr,
                                           double lowerBound, double upperBound,
                                           uint32_t polyDegree,
                                           CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalChebyshevFunction: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalChebyshevFunction: null input ciphertext");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_EvalChebyshevFunction: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    // Create a lambda that calls back to Go through the extern function
    auto func = [callbackID](double x) -> double {
      return goChebyshevCallback(callbackID, x);
    };

    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalChebyshevFunction(
        func, ct_sptr, lowerBound, upperBound, polyDegree);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- Chebyshev Coefficient Computation ---

PKEErr EvalChebyshevCoefficients(int callbackID, double lowerBound,
                                 double upperBound, uint32_t degree,
                                 ChebyshevCoeffs *out) {
  try {
    if (!out) {
      return MakePKEError("EvalChebyshevCoefficients: null output pointer");
    }
    if (degree == 0) {
      return MakePKEError("EvalChebyshevCoefficients: degree cannot be zero");
    }

    // Create a lambda that calls back to Go
    auto func = [callbackID](double x) -> double {
      return goChebyshevCallback(callbackID, x);
    };

    // Call OpenFHE's EvalChebyshevCoefficients
    std::vector<double> coeffs_vec = lbcrypto::EvalChebyshevCoefficients(
        func, lowerBound, upperBound, degree);

    // Allocate memory for coefficients (caller must free with
    // FreeChebyshevCoeffs)
    size_t len = coeffs_vec.size();
    double *coeffs_array = new double[len];
    for (size_t i = 0; i < len; i++) {
      coeffs_array[i] = coeffs_vec[i];
    }

    out->coeffs = coeffs_array;
    out->length = len;

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void FreeChebyshevCoeffs(ChebyshevCoeffs *coeffs) {
  if (coeffs && coeffs->coeffs) {
    delete[] coeffs->coeffs;
    coeffs->coeffs = nullptr;
    coeffs->length = 0;
  }
}

PKEErr CryptoContext_EvalChebyshevSeries(CryptoContextPtr cc_ptr_to_sptr,
                                         CiphertextPtr ct_ptr_to_sptr,
                                         const double *coefficients,
                                         size_t numCoeffs, double lowerBound,
                                         double upperBound,
                                         CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalChebyshevSeries: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalChebyshevSeries: null input ciphertext");
    }
    if (!coefficients) {
      return MakePKEError(
          "CryptoContext_EvalChebyshevSeries: null coefficients");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_EvalChebyshevSeries: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    // Convert C array to std::vector
    std::vector<double> coeffs_vec(coefficients, coefficients + numCoeffs);

    // Call OpenFHE's EvalChebyshevSeries
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalChebyshevSeries(
        ct_sptr, coeffs_vec, lowerBound, upperBound);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- TCKKS Interactive Multi-Party Bootstrapping ---
PKEErr CryptoContext_IntMPBootAdjustScale(CryptoContextPtr cc, CiphertextPtr ct,
                                          CiphertextPtr *out) {
  try {
    if (!cc) {
      return MakePKEError("IntMPBootAdjustScale: null crypto context");
    }
    if (!ct) {
      return MakePKEError("IntMPBootAdjustScale: null ciphertext");
    }
    if (!out) {
      return MakePKEError("IntMPBootAdjustScale: null output pointer");
    }

    auto cc_sptr = *reinterpret_cast<CryptoContextSharedPtr *>(cc);
    auto ct_sptr = *reinterpret_cast<CiphertextSharedPtr *>(ct);

    Ciphertext<DCRTPoly> result_ct = cc_sptr->IntMPBootAdjustScale(ct_sptr);
    *out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntMPBootRandomElementGen(CryptoContextPtr cc,
                                               PublicKeyPtr pk,
                                               CiphertextPtr *out) {
  try {
    if (!cc) {
      return MakePKEError("IntMPBootRandomElementGen: null crypto context");
    }
    if (!pk) {
      return MakePKEError("IntMPBootRandomElementGen: null public key");
    }
    if (!out) {
      return MakePKEError("IntMPBootRandomElementGen: null output pointer");
    }

    auto cc_sptr = *reinterpret_cast<CryptoContextSharedPtr *>(cc);
    auto pk_sptr = *reinterpret_cast<PublicKeySharedPtr *>(pk);

    Ciphertext<DCRTPoly> result_ct =
        cc_sptr->IntMPBootRandomElementGen(pk_sptr);
    *out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntMPBootDecrypt(CryptoContextPtr cc, PrivateKeyPtr sk,
                                      CiphertextPtr c1, CiphertextPtr a,
                                      CiphertextPtr *out0,
                                      CiphertextPtr *out1) {
  try {
    if (!cc) {
      return MakePKEError("IntMPBootDecrypt: null crypto context");
    }
    if (!sk) {
      return MakePKEError("IntMPBootDecrypt: null private key");
    }
    if (!c1) {
      return MakePKEError("IntMPBootDecrypt: null c1 ciphertext");
    }
    if (!a) {
      return MakePKEError("IntMPBootDecrypt: null a ciphertext");
    }
    if (!out0 || !out1) {
      return MakePKEError("IntMPBootDecrypt: null output pointer");
    }

    auto cc_sptr = *reinterpret_cast<CryptoContextSharedPtr *>(cc);
    auto sk_sptr = *reinterpret_cast<PrivateKeySharedPtr *>(sk);
    auto c1_sptr = *reinterpret_cast<CiphertextSharedPtr *>(c1);
    auto a_sptr = *reinterpret_cast<CiphertextSharedPtr *>(a);

    // IntMPBootDecrypt returns a std::vector<Ciphertext<DCRTPoly>> with 2
    // elements
    std::vector<Ciphertext<DCRTPoly>> sharesPair =
        cc_sptr->IntMPBootDecrypt(sk_sptr, c1_sptr, a_sptr);

    if (sharesPair.size() != 2) {
      return MakePKEError("IntMPBootDecrypt: expected 2 shares, got " +
                          std::to_string(sharesPair.size()));
    }

    *out0 =
        reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(sharesPair[0]));
    *out1 =
        reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(sharesPair[1]));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntMPBootAdd(CryptoContextPtr cc,
                                  CiphertextPtr **sharesPairVec,
                                  size_t numParties, CiphertextPtr *out0,
                                  CiphertextPtr *out1) {
  try {
    if (!cc) {
      return MakePKEError("IntMPBootAdd: null crypto context");
    }
    if (!sharesPairVec) {
      return MakePKEError("IntMPBootAdd: null sharesPairVec");
    }
    if (!out0 || !out1) {
      return MakePKEError("IntMPBootAdd: null output pointer");
    }

    auto cc_sptr = *reinterpret_cast<CryptoContextSharedPtr *>(cc);

    // Convert C array of arrays to
    // std::vector<std::vector<Ciphertext<DCRTPoly>>>
    std::vector<std::vector<Ciphertext<DCRTPoly>>> sharesPairVecCpp;
    for (size_t i = 0; i < numParties; i++) {
      std::vector<Ciphertext<DCRTPoly>> partyShares;
      // Each party has 2 shares (h0, h1)
      for (size_t j = 0; j < 2; j++) {
        auto ct_sptr =
            *reinterpret_cast<CiphertextSharedPtr *>(sharesPairVec[i][j]);
        partyShares.push_back(ct_sptr);
      }
      sharesPairVecCpp.push_back(partyShares);
    }

    std::vector<Ciphertext<DCRTPoly>> aggregatedShares =
        cc_sptr->IntMPBootAdd(sharesPairVecCpp);

    if (aggregatedShares.size() != 2) {
      return MakePKEError("IntMPBootAdd: expected 2 aggregated shares, got " +
                          std::to_string(aggregatedShares.size()));
    }

    *out0 = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(aggregatedShares[0]));
    *out1 = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(aggregatedShares[1]));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntMPBootEncrypt(CryptoContextPtr cc, PublicKeyPtr pk,
                                      CiphertextPtr aggregatedH0,
                                      CiphertextPtr aggregatedH1,
                                      CiphertextPtr a, CiphertextPtr inCtxt,
                                      CiphertextPtr *out) {
  try {
    if (!cc) {
      return MakePKEError("IntMPBootEncrypt: null crypto context");
    }
    if (!pk) {
      return MakePKEError("IntMPBootEncrypt: null public key");
    }
    if (!aggregatedH0 || !aggregatedH1) {
      return MakePKEError("IntMPBootEncrypt: null aggregated shares");
    }
    if (!a) {
      return MakePKEError("IntMPBootEncrypt: null a ciphertext");
    }
    if (!inCtxt) {
      return MakePKEError("IntMPBootEncrypt: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("IntMPBootEncrypt: null output pointer");
    }

    auto cc_sptr = *reinterpret_cast<CryptoContextSharedPtr *>(cc);
    auto pk_sptr = *reinterpret_cast<PublicKeySharedPtr *>(pk);
    auto h0_sptr = *reinterpret_cast<CiphertextSharedPtr *>(aggregatedH0);
    auto h1_sptr = *reinterpret_cast<CiphertextSharedPtr *>(aggregatedH1);
    auto a_sptr = *reinterpret_cast<CiphertextSharedPtr *>(a);
    auto inCtxt_sptr = *reinterpret_cast<CiphertextSharedPtr *>(inCtxt);

    // Create aggregated shares pair vector
    std::vector<Ciphertext<DCRTPoly>> aggregatedSharesPair;
    aggregatedSharesPair.push_back(h0_sptr);
    aggregatedSharesPair.push_back(h1_sptr);

    Ciphertext<DCRTPoly> result_ct = cc_sptr->IntMPBootEncrypt(
        pk_sptr, aggregatedSharesPair, a_sptr, inCtxt_sptr);

    *out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

} // extern "C"
