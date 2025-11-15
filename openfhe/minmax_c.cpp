#include "minmax_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- Min/Max Comparison Operations via Scheme Switching ---

PKEErr CryptoContext_EvalMinSchemeSwitching(CryptoContextPtr cc_ptr_to_sptr,
                                            CiphertextPtr ct_ptr_to_sptr,
                                            void *publicKey, uint32_t numValues,
                                            uint32_t numSlots, uint32_t pLWE,
                                            double scaleSign,
                                            CiphertextPtr *outValue,
                                            CiphertextPtr *outIndex) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitching: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitching: null ciphertext");
    }
    if (!publicKey) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitching: null public key");
    }
    if (!outValue || !outIndex) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitching: null output pointers");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    auto &pk_sptr = GetPKSharedPtr(publicKey);

    // Call OpenFHE function - returns std::vector<Ciphertext> with 2 elements
    auto result = cc_sptr->EvalMinSchemeSwitching(ct_sptr, pk_sptr, numValues,
                                                  numSlots, pLWE, scaleSign);

    if (result.size() != 2) {
      return MakePKEError("EvalMinSchemeSwitching returned unexpected number "
                          "of results (expected 2)");
    }

    // Return both ciphertexts: result[0] = min value, result[1] = argmin index
    *outValue = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[0]));
    *outIndex = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[1]));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalMinSchemeSwitchingAlt(
    CryptoContextPtr cc_ptr_to_sptr, CiphertextPtr ct_ptr_to_sptr,
    void *publicKey, uint32_t numValues, uint32_t numSlots, uint32_t pLWE,
    double scaleSign, CiphertextPtr *outValue, CiphertextPtr *outIndex) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitchingAlt: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitchingAlt: null ciphertext");
    }
    if (!publicKey) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitchingAlt: null public key");
    }
    if (!outValue || !outIndex) {
      return MakePKEError(
          "CryptoContext_EvalMinSchemeSwitchingAlt: null output pointers");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    auto &pk_sptr = GetPKSharedPtr(publicKey);

    // Call OpenFHE Alt version - more FHEW operations, higher precision
    auto result = cc_sptr->EvalMinSchemeSwitchingAlt(
        ct_sptr, pk_sptr, numValues, numSlots, pLWE, scaleSign);

    if (result.size() != 2) {
      return MakePKEError("EvalMinSchemeSwitchingAlt returned unexpected "
                          "number of results (expected 2)");
    }

    *outValue = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[0]));
    *outIndex = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[1]));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalMaxSchemeSwitching(CryptoContextPtr cc_ptr_to_sptr,
                                            CiphertextPtr ct_ptr_to_sptr,
                                            void *publicKey, uint32_t numValues,
                                            uint32_t numSlots, uint32_t pLWE,
                                            double scaleSign,
                                            CiphertextPtr *outValue,
                                            CiphertextPtr *outIndex) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitching: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitching: null ciphertext");
    }
    if (!publicKey) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitching: null public key");
    }
    if (!outValue || !outIndex) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitching: null output pointers");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    auto &pk_sptr = GetPKSharedPtr(publicKey);

    // Call OpenFHE function - returns std::vector<Ciphertext> with 2 elements
    auto result = cc_sptr->EvalMaxSchemeSwitching(ct_sptr, pk_sptr, numValues,
                                                  numSlots, pLWE, scaleSign);

    if (result.size() != 2) {
      return MakePKEError("EvalMaxSchemeSwitching returned unexpected number "
                          "of results (expected 2)");
    }

    // Return both ciphertexts: result[0] = max value, result[1] = argmax index
    *outValue = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[0]));
    *outIndex = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[1]));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalMaxSchemeSwitchingAlt(
    CryptoContextPtr cc_ptr_to_sptr, CiphertextPtr ct_ptr_to_sptr,
    void *publicKey, uint32_t numValues, uint32_t numSlots, uint32_t pLWE,
    double scaleSign, CiphertextPtr *outValue, CiphertextPtr *outIndex) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitchingAlt: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitchingAlt: null ciphertext");
    }
    if (!publicKey) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitchingAlt: null public key");
    }
    if (!outValue || !outIndex) {
      return MakePKEError(
          "CryptoContext_EvalMaxSchemeSwitchingAlt: null output pointers");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    auto &pk_sptr = GetPKSharedPtr(publicKey);

    // Call OpenFHE Alt version - more FHEW operations, higher precision
    auto result = cc_sptr->EvalMaxSchemeSwitchingAlt(
        ct_sptr, pk_sptr, numValues, numSlots, pLWE, scaleSign);

    if (result.size() != 2) {
      return MakePKEError("EvalMaxSchemeSwitchingAlt returned unexpected "
                          "number of results (expected 2)");
    }

    *outValue = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[0]));
    *outIndex = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result[1]));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

} // extern "C"
