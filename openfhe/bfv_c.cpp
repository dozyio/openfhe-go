#include "bfv_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- BFV Params Functions ---
PKEErr NewParamsBFV(ParamsBFVPtr *out) {
  try {
    if (!out) {
      return MakePKEError("NewParamsBFV: null output pointer");
    }
    *out = new CCParams<CryptoContextBFVRNS>();

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p, uint64_t mod) {
  try {
    if (!p) {
      return MakePKEError("ParamsBFV_SetPlaintextModulus: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)->SetPlaintextModulus(
        mod);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth) {
  try {
    if (!p) {
      return MakePKEError("ParamsBFV_SetMultiplicativeDepth: null params");
    }
    reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)
        ->SetMultiplicativeDepth(depth);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void DestroyParamsBFV(ParamsBFVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
}

// --- BFV CryptoContext ---
PKEErr NewCryptoContextBFV(ParamsBFVPtr p, CryptoContextPtr *out) {
  try {
    if (!p) {
      return MakePKEError("NewCryptoContextBFV: null params");
    }
    if (!out) {
      return MakePKEError("NewCryptoContextBFV: null output pointer");
    }
    auto params_ptr = reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
    CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
    *out =
        reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- BFV Plaintext ---
PKEErr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                          int64_t *values, int len,
                                          PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MakePackedPlaintext: null context");
    }
    if (len > 0 && !values) {
      return MakePKEError("CryptoContext_MakePackedPlaintext: non-zero length "
                          "with null values");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MakePackedPlaintext: null output pointer");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<int64_t> vec(values, values + len);
    Plaintext pt_sptr = cc_sptr->MakePackedPlaintext(vec);
    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

} // extern "C"
