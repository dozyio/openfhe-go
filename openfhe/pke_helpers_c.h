#ifndef PKE_HELPERS_C_H
#define PKE_HELPERS_C_H

// This is an *internal* header file, not part of the public C-API.
// It is included by pke_common_c.cpp, bfv_c.cpp, bgv_c.cpp, and ckks_c.cpp
// to share C++ helper functions, using declarations, and error macros.

#include "pke_common_c.h" // For PKE_Err, PKE_OK, PKE_ERR, and C types
#include <cstring>
#include <memory>
#include <openfhe/core/lattice/hal/default/dcrtpoly.h>
#include <openfhe/core/utils/serial.h>
#include <openfhe/core/utils/sertype.h>
#include <openfhe/pke/ciphertext-ser.h>
#include <openfhe/pke/ciphertext.h>
#include <openfhe/pke/cryptocontext-ser.h>
#include <openfhe/pke/cryptocontext.h>
#include <openfhe/pke/encoding/plaintext.h>
#include <openfhe/pke/gen-cryptocontext.h>
#include <openfhe/pke/key/key-ser.h>
#include <openfhe/pke/key/keypair.h>
#include <openfhe/pke/key/privatekey.h>
#include <openfhe/pke/key/publickey.h>
#include <openfhe/pke/openfhe.h>
#include <sstream>
#include <string>
#include <vector>

// --- Helper types and functions ---
using CryptoContextSharedPtr = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
using PlaintextSharedPtr = lbcrypto::Plaintext;
using CiphertextSharedPtr = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using KeyPairRawPtr = lbcrypto::KeyPair<lbcrypto::DCRTPoly> *;
using PublicKeySharedPtr = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
using PrivateKeySharedPtr = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;

inline CryptoContextSharedPtr &GetCCSharedPtr(CryptoContextPtr cc_ptr_to_sptr) {
  return *reinterpret_cast<CryptoContextSharedPtr *>(cc_ptr_to_sptr);
}
inline PlaintextSharedPtr &GetPTSharedPtr(PlaintextPtr pt_ptr_to_sptr) {
  return *reinterpret_cast<PlaintextSharedPtr *>(pt_ptr_to_sptr);
}
inline CiphertextSharedPtr &GetCTSharedPtr(CiphertextPtr ct_ptr_to_sptr) {
  return *reinterpret_cast<CiphertextSharedPtr *>(ct_ptr_to_sptr);
}
inline PublicKeySharedPtr &GetPKSharedPtr(void *pk_ptr_to_sptr) {
  return *reinterpret_cast<PublicKeySharedPtr *>(pk_ptr_to_sptr);
}
inline PrivateKeySharedPtr &GetSKSharedPtr(void *sk_ptr_to_sptr) {
  return *reinterpret_cast<PrivateKeySharedPtr *>(sk_ptr_to_sptr);
}

// --- PKE Error Handling ---
static thread_local std::string g_pke_last_error_message;

static inline void set_last_error_pke(const std::exception &e) {
  g_pke_last_error_message = e.what();
}
static inline void set_last_error_pke_str(const std::string &msg) {
  g_pke_last_error_message = msg;
}
static inline void clear_last_error_pke() { g_pke_last_error_message.clear(); }

// Helper macros for try/catch blocks
#define PKE_TRY                                                                \
  clear_last_error_pke();                                                      \
  try

#define PKE_CATCH_RETURN(retval_on_error)                                      \
  catch (const std::exception &e) {                                            \
    set_last_error_pke(e);                                                     \
    return retval_on_error;                                                    \
  }                                                                            \
  catch (...) {                                                                \
    set_last_error_pke_str("Unknown C++ exception caught in PKE.");            \
    return retval_on_error;                                                    \
  }

// --- String Helper ---
// Helper to copy std::string to C string (caller must free using C.free or
// FreeString)
static inline char *CopyStringToC(const std::string &s) {
  char *cstr = (char *)malloc(s.length() + 1);
  if (!cstr)
    return nullptr; // Handle malloc failure
  std::strcpy(cstr, s.c_str());
  return cstr;
}

#endif // PKE_HELPERS_C_H
