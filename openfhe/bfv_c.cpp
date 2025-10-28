#include "bfv_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- BFV Params Functions ---
PKE_Err NewParamsBFV(ParamsBFVPtr *out){PKE_TRY{
    if (!out){set_last_error_pke_str("NewParamsBFV: null output pointer");
return PKE_ERR;
}
*out = new CCParams<CryptoContextBFVRNS>();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p,
                                      uint64_t mod){PKE_TRY{if (!p){
    set_last_error_pke_str("ParamsBFV_SetPlaintextModulus: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)->SetPlaintextModulus(mod);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth) {
  PKE_TRY {
    if (!p) {
      set_last_error_pke_str("ParamsBFV_SetMultiplicativeDepth: null params");
      return PKE_ERR;
    }
    reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)
        ->SetMultiplicativeDepth(depth);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}
void DestroyParamsBFV(ParamsBFVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
}

// --- BFV CryptoContext ---
PKE_Err NewCryptoContextBFV(ParamsBFVPtr p, CryptoContextPtr *out){
    PKE_TRY{if (!p){set_last_error_pke_str("NewCryptoContextBFV: null params");
return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("NewCryptoContextBFV: null output pointer");
  return PKE_ERR;
}
auto params_ptr = reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
*out = reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

// --- BFV Plaintext ---
PKE_Err CryptoContext_MakePackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                          int64_t *values, int len,
                                          PlaintextPtr *out) {
  PKE_TRY {
    if (!cc_ptr_to_sptr) {
      set_last_error_pke_str("CryptoContext_MakePackedPlaintext: null context");
      return PKE_ERR;
    }
    if (len > 0 && !values) {
      set_last_error_pke_str("CryptoContext_MakePackedPlaintext: non-zero "
                             "length with null values");
      return PKE_ERR;
    }
    if (!out) {
      set_last_error_pke_str(
          "CryptoContext_MakePackedPlaintext: null output pointer");
      return PKE_ERR;
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<int64_t> vec(values, values + len);
    Plaintext pt_sptr = cc_sptr->MakePackedPlaintext(vec);
    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}

} // extern "C"
