#include "binfhe_c.h"
#include "binfhecontext.h"
#include <exception>
#include <string>
#include <utility>

// Thread-local storage for the last error message
static thread_local std::string g_last_error_message;

// Helper to set the last error message
static inline void set_last_error(const std::exception &e) {
  g_last_error_message = e.what();
}
static inline void set_last_error_str(const std::string &msg) {
  g_last_error_message = msg;
}
static inline void clear_last_error() { g_last_error_message.clear(); }

// Function to retrieve the last error message
extern "C" const char *BinFHE_LastError() {
  return g_last_error_message.c_str();
}

// Helper macros for try/catch blocks
#define BINFHE_TRY                                                             \
  clear_last_error();                                                          \
  try

#define BINFHE_CATCH_RETURN(retval_on_error)                                   \
  catch (const std::exception &e) {                                            \
    set_last_error(e);                                                         \
    return retval_on_error;                                                    \
  }                                                                            \
  catch (...) {                                                                \
    set_last_error_str("Unknown C++ exception caught.");                       \
    return retval_on_error;                                                    \
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
BinFHEContextH BinFHEContext_New() {
  BINFHE_TRY { return new lbcrypto::BinFHEContext(); }
  BINFHE_CATCH_RETURN(nullptr)
}

void BinFHEContext_Delete(BinFHEContextH h) {
  // Deleting nullptr is safe
  delete AsBinFHEContext(h);
}

BinErr BinFHEContext_Generate(BinFHEContextH h, BINFHE_PARAMSET_C p,
                              BINFHE_METHOD_C m){
    BINFHE_TRY{if (!h){set_last_error_str("Null BinFHEContext handle");
return BIN_ERR;
}
AsBinFHEContext(h)->GenerateBinFHEContext(
    static_cast<lbcrypto::BINFHE_PARAMSET>(p),
    static_cast<lbcrypto::BINFHE_METHOD>(m));
return BIN_OK;
}
BINFHE_CATCH_RETURN(BIN_ERR)
}

// --- Keys ---
BinErr BinFHEContext_KeyGen(BinFHEContextH h, LWESecretKeyH *out) {
  BINFHE_TRY {
    if (!h) {
      set_last_error_str("Null BinFHEContext handle");
      return BIN_ERR;
    }
    if (!out) {
      set_last_error_str("Null output pointer for KeyGen");
      return BIN_ERR;
    }
    // KeyGen returns by value, allocate new and move into it
    auto sk_val = AsBinFHEContext(h)->KeyGen();
    *out = new lbcrypto::LWEPrivateKey(std::move(sk_val));
    return BIN_OK;
  }
  BINFHE_CATCH_RETURN(BIN_ERR)
}

void LWESecretKey_Delete(LWESecretKeyH h) { delete AsLWESecretKey(h); }

BinErr BinFHEContext_BTKeyGen(BinFHEContextH h, LWESecretKeyH skh){
    BINFHE_TRY{if (!h){set_last_error_str("Null BinFHEContext handle");
return BIN_ERR;
}
if (!skh) {
  set_last_error_str("Null LWESecretKey handle");
  return BIN_ERR;
}
AsBinFHEContext(h)->BTKeyGen(*AsLWESecretKey(skh));
return BIN_OK;
}
BINFHE_CATCH_RETURN(BIN_ERR)
}

// --- Operations ---
BinErr BinFHEContext_Encrypt(BinFHEContextH h, LWESecretKeyH skh, int bit,
                             LWECiphertextH *out) {
  BINFHE_TRY {
    if (!h) {
      set_last_error_str("Null BinFHEContext handle");
      return BIN_ERR;
    }
    if (!skh) {
      set_last_error_str("Null LWESecretKey handle");
      return BIN_ERR;
    }
    if (!out) {
      set_last_error_str("Null output pointer for Encrypt");
      return BIN_ERR;
    }
    // Encrypt returns by value
    auto ct_val = AsBinFHEContext(h)->Encrypt(*AsLWESecretKey(skh), bit);
    *out = new lbcrypto::LWECiphertext(std::move(ct_val));
    return BIN_OK;
  }
  BINFHE_CATCH_RETURN(BIN_ERR)
}

void LWECiphertext_Delete(LWECiphertextH h) { delete AsLWECiphertext(h); }

BinErr BinFHEContext_EvalBinGate(BinFHEContextH h, BINFHE_GATE_C gate,
                                 LWECiphertextH ah, LWECiphertextH bh,
                                 LWECiphertextH *out){
    BINFHE_TRY{if (!h){set_last_error_str("Null BinFHEContext handle");
return BIN_ERR;
}
if (!ah) {
  set_last_error_str("Null first LWECiphertext handle");
  return BIN_ERR;
}
if (!bh) {
  set_last_error_str("Null second LWECiphertext handle");
  return BIN_ERR;
}
if (!out) {
  set_last_error_str("Null output pointer for EvalBinGate");
  return BIN_ERR;
}
// EvalBinGate returns by value
auto ct_val =
    AsBinFHEContext(h)->EvalBinGate(static_cast<lbcrypto::BINGATE>(gate),
                                    *AsLWECiphertext(ah), *AsLWECiphertext(bh));
*out = new lbcrypto::LWECiphertext(std::move(ct_val));
return BIN_OK;
}
BINFHE_CATCH_RETURN(BIN_ERR)
}

BinErr BinFHEContext_Bootstrap(BinFHEContextH h, LWECiphertextH inh,
                               LWECiphertextH *out){
    BINFHE_TRY{if (!h){set_last_error_str("Null BinFHEContext handle");
return BIN_ERR;
}
if (!inh) {
  set_last_error_str("Null input LWECiphertext handle");
  return BIN_ERR;
}
if (!out) {
  set_last_error_str("Null output pointer for Bootstrap");
  return BIN_ERR;
}
// Bootstrap returns by value
auto ct_val = AsBinFHEContext(h)->Bootstrap(*AsLWECiphertext(inh));
*out = new lbcrypto::LWECiphertext(std::move(ct_val));
return BIN_OK;
}
BINFHE_CATCH_RETURN(BIN_ERR)
}

BinErr BinFHEContext_Decrypt(BinFHEContextH h, LWESecretKeyH skh,
                             LWECiphertextH cth, int *out_bit) {
  BINFHE_TRY {
    if (!h) {
      set_last_error_str("Null BinFHEContext handle");
      return BIN_ERR;
    }
    if (!skh) {
      set_last_error_str("Null LWESecretKey handle");
      return BIN_ERR;
    }
    if (!cth) {
      set_last_error_str("Null LWECiphertext handle");
      return BIN_ERR;
    }
    if (!out_bit) {
      set_last_error_str("Null output pointer for Decrypt");
      return BIN_ERR;
    }

    lbcrypto::LWEPlaintext pt_result = 0; // Initialize
    AsBinFHEContext(h)->Decrypt(*AsLWESecretKey(skh), *AsLWECiphertext(cth),
                                &pt_result);
    *out_bit =
        static_cast<int>(pt_result); // Convert result LWEPlaintext (usually
                                     // NativeInteger::SignedDigit) to int
    return BIN_OK;
  }
  BINFHE_CATCH_RETURN(BIN_ERR)
}

} // extern "C"
