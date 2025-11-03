#include "pke_common_c.h"
#include "helpers_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- PKE Error Handling ---
void FreePKEErrMsg(char *msg) {
  if (msg) {
    // Use free() because DupString uses malloc/strdup
    free(msg);
  }
}

// --- Common CryptoContext Functions ---
PKEErr CryptoContext_Enable(CryptoContextPtr cc_ptr_to_sptr, int feature) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Enable: null context");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);

    if (feature & lbcrypto::PKE)
      cc_sptr->Enable(PKE);
    if (feature & lbcrypto::KEYSWITCH)
      cc_sptr->Enable(KEYSWITCH);
    if (feature & lbcrypto::PRE)
      cc_sptr->Enable(PRE);
    if (feature & lbcrypto::LEVELEDSHE)
      cc_sptr->Enable(LEVELEDSHE);
    if (feature & lbcrypto::ADVANCEDSHE)
      cc_sptr->Enable(ADVANCEDSHE);
    if (feature & lbcrypto::MULTIPARTY)
      cc_sptr->Enable(MULTIPARTY);
    if (feature & lbcrypto::FHE)
      cc_sptr->Enable(FHE);
    if (feature & lbcrypto::SCHEMESWITCH)
      cc_sptr->Enable(SCHEMESWITCH);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_KeyGen(CryptoContextPtr cc_ptr_to_sptr, KeyPairPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_KeyGen: null context");
    }

    if (!out) {
      return MakePKEError("CryptoContext_KeyGen: null output pointer");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    *out = new KeyPair<DCRTPoly>(cc_sptr->KeyGen());
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalMultKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                    KeyPairPtr keys_raw_ptr) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMultKeyGen: null context");
    }
    if (!keys_raw_ptr) {
      return MakePKEError("CryptoContext_EvalMultKeyGen: null key");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw->secretKey) {
      return MakePKEError(
          "CryptoContext_EvalMultKeyGen: keypair has no secret key");
    }
    cc_sptr->EvalMultKeyGen(kp_raw->secretKey);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                      KeyPairPtr keys_raw_ptr, int32_t *indices,
                                      int len) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalRotateKeyGen: null context");
    }
    if (!keys_raw_ptr) {
      return MakePKEError("CryptoContext_EvalRotateKeyGen: null keypair");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw->secretKey) {
      return MakePKEError(
          "CryptoContext_EvalRotateKeyGen: keypair has no secret key");
    }
    if (len > 0 && !indices) {
      return MakePKEError(
          "CryptoContext_EvalRotateKeyGen: non-zero length with null indices");
    }
    std::vector<int32_t> vec(indices, indices + len);
    cc_sptr->EvalRotateKeyGen(kp_raw->secretKey, vec);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc_ptr_to_sptr) {
  // This is a simple getter, no error handling needed
  if (!cc_ptr_to_sptr)
    return 0;

  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);

  return cc->GetRingDimension();
}

void DestroyCryptoContext(CryptoContextPtr cc_ptr_to_sptr) {
  delete reinterpret_cast<CryptoContextSharedPtr *>(cc_ptr_to_sptr);
}

// --- Common Operations ---
PKEErr CryptoContext_Encrypt(CryptoContextPtr cc_ptr_to_sptr,
                             KeyPairPtr keys_raw_ptr,
                             PlaintextPtr pt_ptr_to_sptr, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Encrypt: null context");
    }
    if (!keys_raw_ptr) {
      return MakePKEError("CryptoContext_Encrypt: null keypair");
    }
    if (!pt_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Encrypt: null plaintext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_Encrypt: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw->publicKey) {
      return MakePKEError("CryptoContext_Encrypt: keypair has no public key");
    }

    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    Ciphertext<DCRTPoly> ct_sptr = cc_sptr->Encrypt(kp_raw->publicKey, pt_sptr);
    *out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_Decrypt(CryptoContextPtr cc_ptr_to_sptr,
                             KeyPairPtr keys_raw_ptr,
                             CiphertextPtr ct_ptr_to_sptr, PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Decrypt: null context");
    }
    if (!keys_raw_ptr) {
      return MakePKEError("CryptoContext_Decrypt: null keypair");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_Decrypt: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_Decrypt: null output");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw->secretKey) {
      return MakePKEError("CryptoContext_Decrypt: keypair has no secret key");
    }
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Plaintext pt_res_sptr;
    DecryptResult result =
        cc_sptr->Decrypt(kp_raw->secretKey, ct_sptr, &pt_res_sptr);

    if (!result.isValid) {
      return MakePKEError(
          "CryptoContext_Decrypt: decryption failed (isValid=false)");
    }

    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_res_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalAdd(CryptoContextPtr cc_ptr_to_sptr,
                             CiphertextPtr ct1_ptr_to_sptr,
                             CiphertextPtr ct2_ptr_to_sptr,
                             CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAdd: null context");
    }
    if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalAdd: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalAdd: null output pointer");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
    auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalAdd(ct1_sptr, ct2_sptr);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalSub(CryptoContextPtr cc_ptr_to_sptr,
                             CiphertextPtr ct1_ptr_to_sptr,
                             CiphertextPtr ct2_ptr_to_sptr,
                             CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSub: null context");
    }
    if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSub: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalSub: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
    auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalSub(ct1_sptr, ct2_sptr);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalMult(CryptoContextPtr cc_ptr_to_sptr,
                              CiphertextPtr ct1_ptr_to_sptr,
                              CiphertextPtr ct2_ptr_to_sptr,
                              CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMult: null context");
    }
    if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalMult: null input ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalMult: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
    auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalMult(ct1_sptr, ct2_sptr);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalRotate(CryptoContextPtr cc_ptr_to_sptr,
                                CiphertextPtr ct_ptr_to_sptr, int32_t index,
                                CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalRotate: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalRotate: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_EvalRotate: null output pointer");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalRotate(ct_sptr, index);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalFastRotationPrecompute(CryptoContextPtr cc_ptr_to_sptr,
                                                CiphertextPtr ct_ptr_to_sptr,
                                                void **out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalFastRotationPrecompute: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalFastRotationPrecompute: null ciphertext");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_EvalFastRotationPrecompute: null output pointer");
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    // EvalFastRotationPrecompute returns a shared_ptr<std::vector<DCRTPoly>>
    auto precomp = cc_sptr->EvalFastRotationPrecompute(ct_sptr);

    // Store the shared_ptr on the heap and return as void*
    *out = new std::shared_ptr<std::vector<DCRTPoly>>(precomp);

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalFastRotation(CryptoContextPtr cc_ptr_to_sptr,
                                      CiphertextPtr ct_ptr_to_sptr,
                                      int32_t index, uint32_t m, void *precomp,
                                      CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalFastRotation: null context");
    }
    if (!ct_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalFastRotation: null ciphertext");
    }
    if (!precomp) {
      return MakePKEError(
          "CryptoContext_EvalFastRotation: null precomputation");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_EvalFastRotation: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    auto &precomp_sptr =
        *reinterpret_cast<std::shared_ptr<std::vector<DCRTPoly>> *>(precomp);

    Ciphertext<DCRTPoly> result_ct_sptr =
        cc_sptr->EvalFastRotation(ct_sptr, index, m, precomp_sptr);
    *out = reinterpret_cast<CiphertextPtr>(
        new CiphertextSharedPtr(result_ct_sptr));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void DestroyFastRotationPrecompute(void *precomp) {
  if (precomp) {
    delete reinterpret_cast<std::shared_ptr<std::vector<DCRTPoly>> *>(precomp);
  }
}

// --- KeyPair ---
PKEErr GetPublicKey(KeyPairPtr kp_raw_ptr, void **out_pk_sptr_wrapper) {
  try {
    if (!kp_raw_ptr) {
      return MakePKEError("GetPublicKey: null keypair");
    }
    if (!out_pk_sptr_wrapper) {
      return MakePKEError("GetPublicKey: null output pointer");
    }
    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    if (!kp || !kp->publicKey) {
      return MakePKEError("GetPublicKey: keypair has no public key");
    }

    // Return a pointer to a *copy* of the shared_ptr, managed on heap
    auto *heap_sptr_ptr = new PublicKeySharedPtr(kp->publicKey);
    *out_pk_sptr_wrapper = reinterpret_cast<void *>(heap_sptr_ptr);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr GetPrivateKey(KeyPairPtr kp_raw_ptr, void **out_sk_sptr_wrapper) {
  try {
    if (!kp_raw_ptr) {
      return MakePKEError("GetPrivateKey: null keypair");
    }
    if (!out_sk_sptr_wrapper) {
      return MakePKEError("GetPrivateKey: null output pointer");
    }

    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    if (!kp || !kp->secretKey) {
      return MakePKEError("GetPrivateKey: keypair has no secret key");
    }

    // Return a pointer to a *copy* of the shared_ptr, managed on heap
    auto *heap_sptr_ptr = new PrivateKeySharedPtr(kp->secretKey);
    *out_sk_sptr_wrapper = reinterpret_cast<void *>(heap_sptr_ptr);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr NewKeyPair(KeyPairPtr *out) {
  try {
    if (!out) {
      return MakePKEError("NewKeyPair: null output pointer");
    }
    *out = reinterpret_cast<KeyPairPtr>(new KeyPair<DCRTPoly>());
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr SetPublicKey(KeyPairPtr kp_raw_ptr, void *pk_ptr_to_sptr) {
  try {
    if (!kp_raw_ptr) {
      return MakePKEError("SetPublicKey: null keypair");
    }
    if (!pk_ptr_to_sptr) {
      return MakePKEError("SetPublicKey: null public key pointer");
    }
    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    auto &pk_sptr = GetPKSharedPtr(pk_ptr_to_sptr);
    kp->publicKey = pk_sptr;
    delete reinterpret_cast<PublicKeySharedPtr *>(
        pk_ptr_to_sptr); // Clean up the heap-allocated shared_ptr wrapper
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr SetPrivateKey(KeyPairPtr kp_raw_ptr, void *sk_ptr_to_sptr) {
  try {
    if (!kp_raw_ptr) {
      return MakePKEError("SetPrivateKey: null keypair");
    }
    if (!sk_ptr_to_sptr) {
      return MakePKEError("SetPrivateKey: null private key pointer");
    }

    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    auto &sk_sptr = GetSKSharedPtr(sk_ptr_to_sptr);
    kp->secretKey = sk_sptr;
    delete reinterpret_cast<PrivateKeySharedPtr *>(
        sk_ptr_to_sptr); // Clean up the heap-allocated shared_ptr wrapper
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void DestroyKeyPair(KeyPairPtr kp_raw_ptr) {
  delete reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
}

// --- Plaintext ---
PKEErr Plaintext_GetPackedValueLength(PlaintextPtr pt_ptr_to_sptr,
                                      int *out_len) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetPackedValueLength: null plaintext");
    }
    if (!out_len) {
      return MakePKEError(
          "Plaintext_GetPackedValueLength: null output pointer");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    *out_len = pt_sptr->GetPackedValue().size();
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                                  int64_t *out_val) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetPackedValueAt: null plaintext");
    }
    if (!out_val) {
      return MakePKEError("Plaintext_GetPackedValueAt: null output pointer");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    // Add bounds check
    if (i < 0 || (size_t)i >= pt_sptr->GetPackedValue().size()) {
      return MakePKEError("Plaintext_GetPackedValueAt: index out of bounds");
    }
    *out_val = pt_sptr->GetPackedValue()[i];
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetRealPackedValueLength(PlaintextPtr pt_ptr_to_sptr,
                                          int *out_len) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetRealPackedValueLength: null plaintext");
    }
    if (!out_len) {
      return MakePKEError(
          "Plaintext_GetRealPackedValueLength: null output pointer");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    *out_len = pt_sptr->GetRealPackedValue().size();
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr Plaintext_GetRealPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                                      double *out_val) {
  try {
    if (!pt_ptr_to_sptr) {
      return MakePKEError("Plaintext_GetRealPackedValueAt: null plaintext");
    }
    if (!out_val) {
      return MakePKEError(
          "Plaintext_GetRealPackedValueAt: null output pointer");
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    // Add bounds check
    if (i < 0 || (size_t)i >= pt_sptr->GetRealPackedValue().size()) {
      return MakePKEError(
          "Plaintext_GetRealPackedValueAt: index out of bounds");
    }
    *out_val = pt_sptr->GetRealPackedValue()[i];
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

void DestroyPlaintext(PlaintextPtr pt_ptr_to_sptr) {
  delete reinterpret_cast<PlaintextSharedPtr *>(pt_ptr_to_sptr);
}

// --- Ciphertext ---
int Ciphertext_GetLevel(CiphertextPtr ct_ptr_to_sptr) {
  if (!ct_ptr_to_sptr) {
    return -1;
  }

  auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
  if (!ct_sptr) {
    return -1;
  }

  return static_cast<int>(ct_sptr->GetLevel()); // Cast size_t to int
}

void DestroyCiphertext(CiphertextPtr ct_ptr_to_sptr) {
  delete reinterpret_cast<CiphertextSharedPtr *>(ct_ptr_to_sptr);
}

// --- Serialization ---
void FreeString(char *s) {
  if (s) {
    free(s);
  }
}

// CryptoContext Serialization
size_t SerializeCryptoContextToBytes(CryptoContextPtr cc_ptr_to_sptr,
                                     char **outBytes) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    std::stringstream ss;
    Serial::Serialize(cc, ss, SerType::BINARY);
    std::string s = ss.str();
    size_t len = s.length();
    *outBytes = CopyStringToC(s);
    if (!*outBytes)
      return 0; // Handle malloc failure
    return len;
  } catch (...) {
    *outBytes = nullptr;
    return 0;
  }
}

CryptoContextPtr DeserializeCryptoContextFromBytes(const char *inData,
                                                   int inLen) {
  try {
    CryptoContext<DCRTPoly> cc;
    std::string s(inData, inLen);
    std::stringstream ss(s);
    Serial::Deserialize(cc, ss, SerType::BINARY);
    if (!cc)
      return nullptr;
    auto *heap_sptr_ptr = new CryptoContextSharedPtr(cc);
    return reinterpret_cast<CryptoContextPtr>(heap_sptr_ptr);
  } catch (...) {
    return nullptr;
  }
}

// PublicKey Serialization
size_t SerializePublicKeyToBytes(KeyPairPtr kp_raw_ptr, char **outBytes) {
  try {
    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    if (!kp || !kp->publicKey)
      return 0;
    std::stringstream ss;
    Serial::Serialize(kp->publicKey, ss, SerType::BINARY);
    std::string s = ss.str();
    *outBytes = CopyStringToC(s);
    if (!*outBytes)
      return 0;
    return s.length();
  } catch (...) {
    *outBytes = nullptr;
    return 0;
  }
}

KeyPairPtr DeserializePublicKeyFromBytes(const char *inData, int inLen) {
  try {
    PublicKey<DCRTPoly> pk;
    std::string s(inData, inLen);
    std::stringstream ss(s);
    Serial::Deserialize(pk, ss, SerType::BINARY);
    if (!pk)
      return nullptr;
    KeyPairRawPtr kp = new KeyPair<DCRTPoly>();
    kp->publicKey = pk;
    return reinterpret_cast<KeyPairPtr>(kp);
  } catch (...) {
    return nullptr;
  }
}

// PrivateKey Serialization
size_t SerializePrivateKeyToBytes(KeyPairPtr kp_raw_ptr, char **outBytes) {
  try {
    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    if (!kp || !kp->secretKey)
      return 0;
    std::stringstream ss;
    Serial::Serialize(kp->secretKey, ss, SerType::BINARY);
    std::string s = ss.str();
    *outBytes = CopyStringToC(s);
    if (!*outBytes)
      return 0;
    return s.length();
  } catch (...) {
    *outBytes = nullptr;
    return 0;
  }
}

KeyPairPtr DeserializePrivateKeyFromBytes(const char *inData, int inLen) {
  try {
    PrivateKey<DCRTPoly> sk;
    std::string s(inData, inLen);
    std::stringstream ss(s);
    Serial::Deserialize(sk, ss, SerType::BINARY);
    if (!sk)
      return nullptr;
    KeyPairRawPtr kp = new KeyPair<DCRTPoly>();
    kp->secretKey = sk;
    return reinterpret_cast<KeyPairPtr>(kp);
  } catch (...) {
    return nullptr;
  }
}

// EvalMultKey (Relinearization Key) Serialization
size_t SerializeEvalMultKeyToBytes(CryptoContextPtr cc_ptr_to_sptr,
                                   const char *keyId, char **outBytes) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    std::stringstream ss;
    if (!cc->SerializeEvalMultKey(ss, SerType::BINARY, std::string(keyId)))
      return 0;
    std::string s = ss.str();
    *outBytes = CopyStringToC(s);
    if (!*outBytes)
      return 0;
    return s.length();
  } catch (...) {
    *outBytes = nullptr;
    return 0;
  }
}

void DeserializeEvalMultKeyFromBytes(CryptoContextPtr cc_ptr_to_sptr,
                                     const char *inData, int inLen) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    std::string s(inData, inLen);
    std::stringstream ss(s);
    cc->DeserializeEvalMultKey(ss, SerType::BINARY);
  } catch (...) {
    // C-API function is void, cannot report error
  }
}

// Ciphertext Serialization
size_t SerializeCiphertextToBytes(CiphertextPtr ct_ptr_to_sptr,
                                  char **outBytes) {
  try {
    auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);
    std::stringstream ss;
    Serial::Serialize(ct, ss, SerType::BINARY);
    std::string s = ss.str();
    *outBytes = CopyStringToC(s);
    if (!*outBytes)
      return 0;
    return s.length();
  } catch (...) {
    *outBytes = nullptr;
    return 0;
  }
}

CiphertextPtr DeserializeCiphertextFromBytes(const char *inData, int inLen) {
  try {
    Ciphertext<DCRTPoly> ct;
    std::string s(inData, inLen);
    std::stringstream ss(s);
    Serial::Deserialize(ct, ss, SerType::BINARY);
    if (!ct)
      return nullptr;
    auto *heap_sptr_ptr = new CiphertextSharedPtr(ct);
    return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
  } catch (...) {
    return nullptr;
  }
}

// --- Debugging Function ---
PKEErr CryptoContext_GetParameterElementString(CryptoContextPtr cc_ptr_to_sptr,
                                               char **outString) {
  try {
    if (!cc_ptr_to_sptr) {
      *outString = nullptr;
      return MakePKEError("Null context pointer");
    }
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    if (!cc) {
      *outString = nullptr;
      return MakePKEError("Dereferenced context is null");
    }
    auto params = cc->GetCryptoParameters();
    if (!params) {
      *outString = nullptr;
      return MakePKEError("Failed to get crypto parameters");
    }
    auto elementParams = params->GetElementParams();
    if (!elementParams) {
      *outString = nullptr;
      return MakePKEError("Failed to get element parameters");
    }
    std::stringstream ss;
    ss << *elementParams;
    std::string s = ss.str();
    *outString = CopyStringToC(s);
    if (!*outString) {
      return MakePKEError("Failed to copy param string");
    }
    return MakePKEOk();
  } catch (const std::exception &e) {
    *outString = nullptr;
    return MakePKEError(e.what());
  } catch (...) {
    *outString = nullptr;
    return MakePKEError("Unknown C++ exception");
  }
}

int GetNativeInt() {
// Return the native integer size in bits (64 or 128)
// This is determined at compile time by OpenFHE's NATIVE_SIZE macro
#if defined(NATIVE_SIZE) && NATIVE_SIZE == 128
  return 128;
#else
  return 64;
#endif
}

} // extern "C"
