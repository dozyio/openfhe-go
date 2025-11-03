#include "binfhe_c.h"
#include "binfhecontext.h"
#include "helpers_c.h"
#include <exception>
#include <utility>

// Helper macros for try/catch blocks
#define BINFHE_CATCH_RETURN()                                                  \
  catch (const std::exception &e) {                                            \
    return MakeBinFHEError(e.what());                                          \
  }                                                                            \
  catch (...) {                                                                \
    return MakeBinFHEError("Unknown C++ exception caught in PKE.");            \
  }

void FreeBinFHE_ErrMsg(char *msg) {
  if (msg) {
    // Use free() because DupString uses malloc/strdup
    free(msg);
  }
}

// --- Error Handling ---
static inline BinFHEErr MakeBinFHEOk() {
  return (BinFHEErr){BINFHE_OK_CODE, NULL};
}

static inline BinFHEErr MakeBinFHEError(const std::string &msg) {
  return (BinFHEErr){BINFHE_ERR_CODE, DupString(msg)};
}

// Cast void* handles back to C++ pointers
inline lbcrypto::BinFHEContext *AsBinFHEContext(BinFHEContextH h) {
  return static_cast<lbcrypto::BinFHEContext *>(h);
}
inline lbcrypto::LWEPrivateKey *AsLWESecretKey(LWESecretKeyH h) {
  return static_cast<lbcrypto::LWEPrivateKey *>(h);
}
inline lbcrypto::LWECiphertext *AsLWECiphertext(LWECiphertextH h) {
  return static_cast<lbcrypto::LWECiphertext *>(h);
}

extern "C" {

// --- Context ---
BinFHEErr BinFHEContext_New(BinFHEContextH *out) {
  try {
    if (!out) {
      return MakeBinFHEError("Null output pointer for BinFHEContext_New");
    }
    *out = new lbcrypto::BinFHEContext();
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

void BinFHEContext_Delete(BinFHEContextH h) {
  // Deleting nullptr is safe
  delete AsBinFHEContext(h);
}

BinFHEErr BinFHEContext_Generate(BinFHEContextH h, BINFHE_PARAMSET_C p,
                                 BINFHE_METHOD_C m) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }

    AsBinFHEContext(h)->GenerateBinFHEContext(
        static_cast<lbcrypto::BINFHE_PARAMSET>(p),
        static_cast<lbcrypto::BINFHE_METHOD>(m));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

// --- Keys ---
BinFHEErr BinFHEContext_KeyGen(BinFHEContextH h, LWESecretKeyH *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer for KeyGen");
    }
    // KeyGen returns by value, allocate new and move into it
    auto sk_val = AsBinFHEContext(h)->KeyGen();
    *out = new lbcrypto::LWEPrivateKey(std::move(sk_val));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

void LWESecretKey_Delete(LWESecretKeyH h) { delete AsLWESecretKey(h); }

BinFHEErr BinFHEContext_BTKeyGen(BinFHEContextH h, LWESecretKeyH skh) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!skh) {
      return MakeBinFHEError("Null LWESecretKey handle");
    }
    AsBinFHEContext(h)->BTKeyGen(*AsLWESecretKey(skh));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

// --- Operations ---
BinFHEErr BinFHEContext_Encrypt(BinFHEContextH h, LWESecretKeyH skh, int bit,
                                LWECiphertextH *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!skh) {
      return MakeBinFHEError("Null LWESecretKey handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer for Encrypt");
    }
    // Encrypt returns by value
    auto ct_val = AsBinFHEContext(h)->Encrypt(*AsLWESecretKey(skh), bit);
    *out = new lbcrypto::LWECiphertext(std::move(ct_val));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

void LWECiphertext_Delete(LWECiphertextH h) { delete AsLWECiphertext(h); }

BinFHEErr BinFHEContext_EvalBinGate(BinFHEContextH h, BINFHE_GATE_C gate,
                                    LWECiphertextH ah, LWECiphertextH bh,
                                    LWECiphertextH *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!ah) {
      return MakeBinFHEError("Null first LWECiphertext handle");
    }
    if (!bh) {
      return MakeBinFHEError("Null second LWECiphertext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer for EvalBinGate");
    }
    // EvalBinGate returns by value
    auto ct_val = AsBinFHEContext(h)->EvalBinGate(
        static_cast<lbcrypto::BINGATE>(gate), *AsLWECiphertext(ah),
        *AsLWECiphertext(bh));
    *out = new lbcrypto::LWECiphertext(std::move(ct_val));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_Bootstrap(BinFHEContextH h, LWECiphertextH inh,
                                  LWECiphertextH *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!inh) {
      return MakeBinFHEError("Null input LWECiphertext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer for Bootstrap");
    }
    // Bootstrap returns by value
    auto ct_val = AsBinFHEContext(h)->Bootstrap(*AsLWECiphertext(inh));
    *out = new lbcrypto::LWECiphertext(std::move(ct_val));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_Decrypt(BinFHEContextH h, LWESecretKeyH skh,
                                LWECiphertextH cth, int *out_bit) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!skh) {
      return MakeBinFHEError("Null LWESecretKey handle");
    }
    if (!cth) {
      return MakeBinFHEError("Null LWECiphertext handle");
    }
    if (!out_bit) {
      return MakeBinFHEError("Null output pointer for Decrypt");
    }

    lbcrypto::LWEPlaintext pt_result = 0; // Initialize
    AsBinFHEContext(h)->Decrypt(*AsLWESecretKey(skh), *AsLWECiphertext(cth),
                                &pt_result);
    *out_bit =
        static_cast<int>(pt_result); // Convert result LWEPlaintext (usually
                                     // NativeInteger::SignedDigit) to int
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_DecryptModulus(BinFHEContextH h, LWESecretKeyH skh,
                                       LWECiphertextH cth, uint64_t p,
                                       uint64_t *out_val) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!skh) {
      return MakeBinFHEError("Null LWESecretKey handle");
    }
    if (!cth) {
      return MakeBinFHEError("Null LWECiphertext handle");
    }
    if (!out_val) {
      return MakeBinFHEError("Null output pointer for DecryptModulus");
    }

    lbcrypto::LWEPlaintext pt_result = 0;
    AsBinFHEContext(h)->Decrypt(*AsLWESecretKey(skh), *AsLWECiphertext(cth),
                                &pt_result, p);
    *out_val = static_cast<uint64_t>(pt_result);
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

// --- Parameter Getters ---
BinFHEErr BinFHEContext_GetMaxPlaintextSpace(BinFHEContextH h, uint32_t *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer");
    }
    *out = static_cast<uint32_t>(
        AsBinFHEContext(h)->GetMaxPlaintextSpace().ConvertToInt());
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_Getn(BinFHEContextH h, uint32_t *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer");
    }
    // Get n from LWE params
    auto params = AsBinFHEContext(h)->GetParams();
    if (!params) {
      return MakeBinFHEError("BinFHE params not initialized");
    }
    auto lweParams = params->GetLWEParams();
    if (!lweParams) {
      return MakeBinFHEError("LWE params not initialized");
    }
    *out = static_cast<uint32_t>(lweParams->Getn());
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_Getq(BinFHEContextH h, uint64_t *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer");
    }
    // Get q from LWE params
    auto params = AsBinFHEContext(h)->GetParams();
    if (!params) {
      return MakeBinFHEError("BinFHE params not initialized");
    }
    auto lweParams = params->GetLWEParams();
    if (!lweParams) {
      return MakeBinFHEError("LWE params not initialized");
    }
    *out = static_cast<uint64_t>(lweParams->Getq().ConvertToInt());
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_GetBeta(BinFHEContextH h, uint32_t *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer");
    }
    auto beta = AsBinFHEContext(h)->GetBeta();
    *out = static_cast<uint32_t>(beta.ConvertToInt());
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

// --- Advanced Operations ---
BinFHEErr BinFHEContext_EvalSign(BinFHEContextH h, LWECiphertextH cth,
                                 LWECiphertextH *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!cth) {
      return MakeBinFHEError("Null LWECiphertext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer for EvalSign");
    }
    auto ct_val = AsBinFHEContext(h)->EvalSign(*AsLWECiphertext(cth));
    *out = new lbcrypto::LWECiphertext(std::move(ct_val));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_EvalFloor(BinFHEContextH h, LWECiphertextH cth,
                                  uint32_t bits, LWECiphertextH *out) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!cth) {
      return MakeBinFHEError("Null LWECiphertext handle");
    }
    if (!out) {
      return MakeBinFHEError("Null output pointer for EvalFloor");
    }
    auto ct_val = AsBinFHEContext(h)->EvalFloor(*AsLWECiphertext(cth), bits);
    *out = new lbcrypto::LWECiphertext(std::move(ct_val));
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

BinFHEErr BinFHEContext_DecryptModulusLWEKey(BinFHEContextH h, void *skh,
                                             LWECiphertextH cth, uint64_t p,
                                             uint64_t *out_val) {
  try {
    if (!h) {
      return MakeBinFHEError("Null BinFHEContext handle");
    }
    if (!skh) {
      return MakeBinFHEError("Null LWEPrivateKey handle");
    }
    if (!cth) {
      return MakeBinFHEError("Null LWECiphertext handle");
    }
    if (!out_val) {
      return MakeBinFHEError("Null output pointer for DecryptModulusLWEKey");
    }

    // Cast to LWEPrivateKey (same as LWESecretKey in OpenFHE)
    auto *lwesk = static_cast<lbcrypto::LWEPrivateKey *>(skh);

    lbcrypto::LWEPlaintext pt_result = 0;
    AsBinFHEContext(h)->Decrypt(*lwesk, *AsLWECiphertext(cth), &pt_result, p);
    *out_val = static_cast<uint64_t>(pt_result);
    return MakeBinFHEOk();
  }
  BINFHE_CATCH_RETURN()
}

} // extern "C"
