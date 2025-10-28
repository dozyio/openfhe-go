#include "bgv_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- BGV Params Functions ---
PKE_Err NewParamsBGV(ParamsBGVPtr *out){PKE_TRY{
    if (!out){set_last_error_pke_str("NewParamsBGV: null output pointer");
return PKE_ERR;
}
*out = new CCParams<CryptoContextBGVRNS>();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p,
                                      uint64_t mod){PKE_TRY{if (!p){
    set_last_error_pke_str("ParamsBGV_SetPlaintextModulus: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetPlaintextModulus(mod);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth) {
  PKE_TRY {
    if (!p) {
      set_last_error_pke_str("ParamsBGV_SetMultiplicativeDepth: null params");
      return PKE_ERR;
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)
        ->SetMultiplicativeDepth(depth);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}
void DestroyParamsBGV(ParamsBGVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
}

// --- BGV CryptoContext ---
PKE_Err NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out){
    PKE_TRY{if (!p){set_last_error_pke_str("NewCryptoContextBGV: null params");
return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("NewCryptoContextBGV: null output pointer");
  return PKE_ERR;
}
auto params_ptr = reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
*out = reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

// --- BGV Plaintext ---
// Note: The C-API defines MakePackedPlaintext in both bfv_c.h and bgv_c.h.
// The Go CGO linker will pick one (e.g., from bfv_c.cpp).
// This is fine as the implementation is identical.
// We only need to implement the BGV-specific SetLength here.

PKE_Err Plaintext_SetLength(PlaintextPtr pt_ptr_to_sptr, int len) {
  PKE_TRY {
    if (!pt_ptr_to_sptr) {
      set_last_error_pke_str("Plaintext_SetLength: null plaintext");
      return PKE_ERR;
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    pt_sptr->SetLength(len);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}

} // extern "C"
