#ifndef PKE_HELPERS_C_H
#define PKE_HELPERS_C_H

// This is an *internal* header file, not part of the public C-API.
// It is included by pke_common_c.cpp, bfv_c.cpp, bgv_c.cpp, and ckks_c.cpp
// to share C++ helper functions, using declarations, and error macros.

#include "helpers_c.h"
#include "pke_common_c.h"
#include <cstdlib>
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
// Helper macro for try/catch blocks
#define PKE_CATCH_RETURN()                                                     \
  catch (const std::exception &e) {                                            \
    return MakePKEError(e.what());                                             \
  }                                                                            \
  catch (...) {                                                                \
    return MakePKEError("Unknown C++ exception caught in PKE.");               \
  }

static inline PKEErr MakePKEOk() { return (PKEErr){PKE_OK_CODE, NULL}; }

static inline PKEErr MakePKEError(const std::string &msg) {
  return (PKEErr){PKE_ERR_CODE, DupString(msg)};
}

#endif // PKE_HELPERS_C_H
