#include "bgv_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- BGV Params Functions ---
PKEErr NewParamsBGV(ParamsBGVPtr *out) {
  try {
    if (!out) {
      return MakePKEError("NewParamsBGV: null output pointer");
    }
    *out = new CCParams<CryptoContextBGVRNS>();
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p, uint64_t mod) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetPlaintextModulus: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetPlaintextModulus(
        mod);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetMultiplicativeDepth: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)
        ->SetMultiplicativeDepth(depth);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetScalingTechnique(ParamsBGVPtr p, int technique) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetScalingTechnique: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetScalingTechnique(
        static_cast<ScalingTechnique>(technique));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void DestroyParamsBGV(ParamsBGVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
}

// --- BGV CryptoContext ---
PKEErr NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out) {
  try {
    if (!p) {
      return MakePKEError("NewCryptoContextBGV: null params");
    }
    if (!out) {
      return MakePKEError("NewCryptoContextBGV: null output pointer");
    }
    auto params_ptr = reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
    CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
    *out =
        reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- BGV Plaintext ---
// Note: The C-API defines MakePackedPlaintext in both bfv_c.h and bgv_c.h.
// The Go CGO linker will pick one (e.g., from bfv_c.cpp).
// This is fine as the implementation is identical.
// We only need to implement the BGV-specific SetLength here.

PKEErr CryptoContext_MakeCoefPackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                             int64_t *values, int len,
                                             PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MakeCoefPackedPlaintext: null context");
    }
    if (!values && len > 0) {
      return MakePKEError("CryptoContext_MakeCoefPackedPlaintext: null values");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MakeCoefPackedPlaintext: null output pointer");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<int64_t> vec(values, values + len);
    Plaintext pt_sptr = cc_sptr->MakeCoefPackedPlaintext(vec);
    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_SetLength(PlaintextPtr pt_ptr_to_sptr, int len) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_SetLength: null plaintext");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    pt_sptr->SetLength(len);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetCoefPackedValue(PlaintextPtr pt_ptr_to_sptr,
                                    int64_t **out_values, int *out_len) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetCoefPackedValue: null plaintext");
    }
    if (!out_values) {
      return MakePKEError(
          "Plaintext_GetCoefPackedValue: null output values pointer");
    }
    if (!out_len) {
      return MakePKEError(
          "Plaintext_GetCoefPackedValue: null output length pointer");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    const std::vector<int64_t> &vec = pt_sptr->GetCoefPackedValue();
    *out_len = vec.size();
    if (*out_len == 0) {
      *out_values = nullptr;
      return MakePKEOk();
    }
    *out_values = (int64_t *)malloc(*out_len * sizeof(int64_t));
    if (!*out_values) {
      return MakePKEError("Plaintext_GetCoefPackedValue: malloc failed");
    }
    std::copy(vec.begin(), vec.end(), *out_values);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetMultipartyMode(ParamsBGVPtr p_ptr_to_sptr, int mode) {
  try {
    if (!p_ptr_to_sptr) {
      return MakePKEError("ParamsBGV_SetMultipartyMode: null params");
    }
    auto &params =
        *reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p_ptr_to_sptr);
    params.SetMultipartyMode(static_cast<MultipartyMode>(mode));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetPREMode(ParamsBGVPtr p, int mode) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetPREMode: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetPREMode(
        static_cast<ProxyReEncryptionMode>(mode));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetPRENumHops(ParamsBGVPtr p, uint32_t numHops) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetPRENumHops: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetPRENumHops(
        numHops);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetStatisticalSecurity(ParamsBGVPtr p, uint32_t statSec) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetStatisticalSecurity: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)
        ->SetStatisticalSecurity(statSec);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetNumAdversarialQueries(ParamsBGVPtr p, uint32_t numQueries) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetNumAdversarialQueries: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)
        ->SetNumAdversarialQueries(numQueries);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetRingDim(ParamsBGVPtr p, uint32_t ringDim) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetRingDim: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetRingDim(ringDim);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBGV_SetKeySwitchTechnique(ParamsBGVPtr p, int technique) {
  try {
    if (!p) {
      return MakePKEError("ParamsBGV_SetKeySwitchTechnique: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetKeySwitchTechnique(
        static_cast<KeySwitchTechnique>(technique));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

} // extern "C"
