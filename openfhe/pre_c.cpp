#include "pre_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

// Helper type for EvalKey (wraps shared_ptr<EvalKeyImpl>)
using EvalKeySharedPtr = lbcrypto::EvalKey<lbcrypto::DCRTPoly>;

inline EvalKeySharedPtr &GetEKSharedPtr(EvalKeyPtr ek_ptr_to_sptr) {
  return *reinterpret_cast<EvalKeySharedPtr *>(ek_ptr_to_sptr);
}

extern "C" {

// --- PRE (Proxy Re-Encryption) Functions ---

PKEErr CryptoContext_ReKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                              void *oldPrivateKey, void *newPublicKey,
                              EvalKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_ReKeyGen: null context");
    }
    if (!oldPrivateKey) {
      return MakePKEError("CryptoContext_ReKeyGen: null old private key");
    }
    if (!newPublicKey) {
      return MakePKEError("CryptoContext_ReKeyGen: null new public key");
    }
    if (!out) {
      return MakePKEError("CryptoContext_ReKeyGen: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &oldSK_sptr = GetSKSharedPtr(oldPrivateKey);
    auto &newPK_sptr = GetPKSharedPtr(newPublicKey);

    // Generate re-encryption key
    EvalKey<DCRTPoly> reencryptionKey =
        cc_sptr->ReKeyGen(oldSK_sptr, newPK_sptr);

    if (!reencryptionKey) {
      return MakePKEError("CryptoContext_ReKeyGen: ReKeyGen returned null key");
    }

    *out = reinterpret_cast<EvalKeyPtr>(new EvalKeySharedPtr(reencryptionKey));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_ReEncrypt(CryptoContextPtr cc_ptr_to_sptr,
                               CiphertextPtr ciphertext, EvalKeyPtr evalKey,
                               CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_ReEncrypt: null context");
    }
    if (!ciphertext) {
      return MakePKEError("CryptoContext_ReEncrypt: null ciphertext");
    }
    if (!evalKey) {
      return MakePKEError("CryptoContext_ReEncrypt: null eval key");
    }
    if (!out) {
      return MakePKEError("CryptoContext_ReEncrypt: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ciphertext);
    auto &ek_sptr = GetEKSharedPtr(evalKey);

    // Re-encrypt the ciphertext
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->ReEncrypt(ct_sptr, ek_sptr);

    if (!result_ct_sptr) {
      return MakePKEError(
          "CryptoContext_ReEncrypt: ReEncrypt returned null ciphertext");
    }

    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- EvalKey Management ---
void DestroyEvalKey(EvalKeyPtr ek) {
  delete reinterpret_cast<EvalKeySharedPtr *>(ek);
}

} // extern "C"
