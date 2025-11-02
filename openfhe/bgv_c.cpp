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

} // extern "C"
