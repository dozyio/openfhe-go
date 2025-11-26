#include "helpers_c.h"
#include "pke_common_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- Multiparty / Threshold FHE Implementations ---

PKEErr CryptoContext_MultipartyKeyGen_FromPrivateKeys(
    CryptoContextPtr cc_ptr_to_sptr, PrivateKeyPtr *privateKeys, size_t numKeys,
    KeyPairPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MultipartyKeyGen_FromPrivateKeys: null context");
    }
    if (!privateKeys || numKeys == 0) {
      return MakePKEError("CryptoContext_MultipartyKeyGen_FromPrivateKeys: "
                          "null or empty private key vector");
    }
    if (!out) {
      return MakePKEError("CryptoContext_MultipartyKeyGen_FromPrivateKeys: "
                          "null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<PrivateKeySharedPtr> keyVec;
    keyVec.reserve(numKeys);

    for (size_t i = 0; i < numKeys; i++) {
      if (!privateKeys[i]) {
        return MakePKEError("CryptoContext_MultipartyKeyGen_FromPrivateKeys: "
                            "null private key at index " +
                            std::to_string(i));
      }
      keyVec.push_back(GetSKSharedPtr(privateKeys[i]));
    }

    auto keypair = cc_sptr->MultipartyKeyGen(keyVec);
    *out = new KeyPair<DCRTPoly>(keypair);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultipartyKeyGen_FromPublicKey(
    CryptoContextPtr cc_ptr_to_sptr, PublicKeyPtr publicKey, int makeSparse,
    int fresh, KeyPairPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MultipartyKeyGen_FromPublicKey: null context");
    }
    if (!publicKey) {
      return MakePKEError(
          "CryptoContext_MultipartyKeyGen_FromPublicKey: null public key");
    }
    if (!out) {
      return MakePKEError("CryptoContext_MultipartyKeyGen_FromPublicKey: null "
                          "output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &pk_sptr = GetPKSharedPtr(publicKey);

    auto keypair =
        cc_sptr->MultipartyKeyGen(pk_sptr, makeSparse != 0, fresh != 0);
    *out = new KeyPair<DCRTPoly>(keypair);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultipartyDecryptLead(CryptoContextPtr cc_ptr_to_sptr,
                                           CiphertextPtr *ciphertexts,
                                           size_t numCiphertexts,
                                           PrivateKeyPtr privateKey,
                                           CiphertextPtr *outPartials) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultipartyDecryptLead: null context");
    }
    if (!ciphertexts || numCiphertexts == 0) {
      return MakePKEError("CryptoContext_MultipartyDecryptLead: null or empty "
                          "ciphertext vector");
    }
    if (!privateKey) {
      return MakePKEError(
          "CryptoContext_MultipartyDecryptLead: null private key");
    }
    if (!outPartials) {
      return MakePKEError(
          "CryptoContext_MultipartyDecryptLead: null output array");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk_sptr = GetSKSharedPtr(privateKey);

    std::vector<CiphertextSharedPtr> ctVec;
    ctVec.reserve(numCiphertexts);
    for (size_t i = 0; i < numCiphertexts; i++) {
      if (!ciphertexts[i]) {
        return MakePKEError("CryptoContext_MultipartyDecryptLead: null "
                            "ciphertext at index " +
                            std::to_string(i));
      }
      ctVec.push_back(GetCTSharedPtr(ciphertexts[i]));
    }

    auto partials = cc_sptr->MultipartyDecryptLead(ctVec, sk_sptr);

    for (size_t i = 0; i < partials.size(); i++) {
      outPartials[i] = new CiphertextSharedPtr(partials[i]);
    }

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultipartyDecryptMain(CryptoContextPtr cc_ptr_to_sptr,
                                           CiphertextPtr *ciphertexts,
                                           size_t numCiphertexts,
                                           PrivateKeyPtr privateKey,
                                           CiphertextPtr *outPartials) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultipartyDecryptMain: null context");
    }
    if (!ciphertexts || numCiphertexts == 0) {
      return MakePKEError("CryptoContext_MultipartyDecryptMain: null or empty "
                          "ciphertext vector");
    }
    if (!privateKey) {
      return MakePKEError(
          "CryptoContext_MultipartyDecryptMain: null private key");
    }
    if (!outPartials) {
      return MakePKEError(
          "CryptoContext_MultipartyDecryptMain: null output array");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk_sptr = GetSKSharedPtr(privateKey);

    std::vector<CiphertextSharedPtr> ctVec;
    ctVec.reserve(numCiphertexts);
    for (size_t i = 0; i < numCiphertexts; i++) {
      if (!ciphertexts[i]) {
        return MakePKEError("CryptoContext_MultipartyDecryptMain: null "
                            "ciphertext at index " +
                            std::to_string(i));
      }
      ctVec.push_back(GetCTSharedPtr(ciphertexts[i]));
    }

    auto partials = cc_sptr->MultipartyDecryptMain(ctVec, sk_sptr);

    for (size_t i = 0; i < partials.size(); i++) {
      outPartials[i] = new CiphertextSharedPtr(partials[i]);
    }

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultipartyDecryptFusion(CryptoContextPtr cc_ptr_to_sptr,
                                             CiphertextPtr *partialCiphertexts,
                                             size_t numPartials,
                                             PlaintextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MultipartyDecryptFusion: null context");
    }
    if (!partialCiphertexts || numPartials == 0) {
      return MakePKEError("CryptoContext_MultipartyDecryptFusion: null or "
                          "empty partial ciphertext vector");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultipartyDecryptFusion: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);

    std::vector<CiphertextSharedPtr> partialVec;
    partialVec.reserve(numPartials);
    for (size_t i = 0; i < numPartials; i++) {
      if (!partialCiphertexts[i]) {
        return MakePKEError("CryptoContext_MultipartyDecryptFusion: null "
                            "partial ciphertext at index " +
                            std::to_string(i));
      }
      partialVec.push_back(GetCTSharedPtr(partialCiphertexts[i]));
    }

    PlaintextSharedPtr result;
    cc_sptr->MultipartyDecryptFusion(partialVec, &result);

    *out = new PlaintextSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiKeySwitchGen(CryptoContextPtr cc_ptr_to_sptr,
                                       PrivateKeyPtr oldPrivateKey,
                                       PrivateKeyPtr newPrivateKey,
                                       EvalKeyPtr evalKey, EvalKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiKeySwitchGen: null context");
    }
    if (!oldPrivateKey) {
      return MakePKEError(
          "CryptoContext_MultiKeySwitchGen: null old private key");
    }
    if (!newPrivateKey) {
      return MakePKEError(
          "CryptoContext_MultiKeySwitchGen: null new private key");
    }
    if (!evalKey) {
      return MakePKEError("CryptoContext_MultiKeySwitchGen: null eval key");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiKeySwitchGen: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &old_sk = GetSKSharedPtr(oldPrivateKey);
    auto &new_sk = GetSKSharedPtr(newPrivateKey);
    auto &ek = GetEKSharedPtr(evalKey);

    auto result = cc_sptr->MultiKeySwitchGen(old_sk, new_sk, ek);
    *out = new EvalKeySharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiEvalSumKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                        PrivateKeyPtr privateKey,
                                        EvalKeyMapPtr evalKeyMap,
                                        const char *keyTag,
                                        EvalKeyMapPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiEvalSumKeyGen: null context");
    }
    if (!privateKey) {
      return MakePKEError("CryptoContext_MultiEvalSumKeyGen: null private key");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiEvalSumKeyGen: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk = GetSKSharedPtr(privateKey);
    std::string tag = keyTag ? std::string(keyTag) : "";

    EvalKeyMapSharedPtr result;
    if (evalKeyMap) {
      auto &ekm = GetEKMSharedPtr(evalKeyMap);
      result = cc_sptr->MultiEvalSumKeyGen(sk, ekm, tag);
    } else {
      result = cc_sptr->MultiEvalSumKeyGen(sk, nullptr, tag);
    }

    *out = new EvalKeyMapSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiEvalAtIndexKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                            PrivateKeyPtr privateKey,
                                            EvalKeyMapPtr evalKeyMap,
                                            int32_t *indices, size_t numIndices,
                                            const char *keyTag,
                                            EvalKeyMapPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiEvalAtIndexKeyGen: null context");
    }
    if (!privateKey) {
      return MakePKEError(
          "CryptoContext_MultiEvalAtIndexKeyGen: null private key");
    }
    if (!indices || numIndices == 0) {
      return MakePKEError(
          "CryptoContext_MultiEvalAtIndexKeyGen: null or empty indices");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiEvalAtIndexKeyGen: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk = GetSKSharedPtr(privateKey);
    std::vector<int32_t> indexVec(indices, indices + numIndices);
    std::string tag = keyTag ? std::string(keyTag) : "";

    EvalKeyMapSharedPtr result;
    if (evalKeyMap) {
      auto &ekm = GetEKMSharedPtr(evalKeyMap);
      result = cc_sptr->MultiEvalAtIndexKeyGen(sk, ekm, indexVec, tag);
    } else {
      result = cc_sptr->MultiEvalAtIndexKeyGen(sk, nullptr, indexVec, tag);
    }

    *out = new EvalKeyMapSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiMultEvalKey(CryptoContextPtr cc_ptr_to_sptr,
                                      PrivateKeyPtr privateKey,
                                      EvalKeyPtr evalKey, const char *keyTag,
                                      EvalKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiMultEvalKey: null context");
    }
    if (!privateKey) {
      return MakePKEError("CryptoContext_MultiMultEvalKey: null private key");
    }
    if (!evalKey) {
      return MakePKEError("CryptoContext_MultiMultEvalKey: null eval key");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiMultEvalKey: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk = GetSKSharedPtr(privateKey);
    auto &ek = GetEKSharedPtr(evalKey);
    std::string tag = keyTag ? std::string(keyTag) : "";

    auto result = cc_sptr->MultiMultEvalKey(sk, ek, tag);
    *out = new EvalKeySharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiAddPubKeys(CryptoContextPtr cc_ptr_to_sptr,
                                     PublicKeyPtr pk1, PublicKeyPtr pk2,
                                     const char *keyTag, PublicKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiAddPubKeys: null context");
    }
    if (!pk1) {
      return MakePKEError("CryptoContext_MultiAddPubKeys: null public key 1");
    }
    if (!pk2) {
      return MakePKEError("CryptoContext_MultiAddPubKeys: null public key 2");
    }
    if (!out) {
      return MakePKEError("CryptoContext_MultiAddPubKeys: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &pk1_sptr = GetPKSharedPtr(pk1);
    auto &pk2_sptr = GetPKSharedPtr(pk2);
    std::string tag = keyTag ? std::string(keyTag) : "";

    auto result = cc_sptr->MultiAddPubKeys(pk1_sptr, pk2_sptr, tag);
    *out = new PublicKeySharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiAddEvalKeys(CryptoContextPtr cc_ptr_to_sptr,
                                      EvalKeyPtr ek1, EvalKeyPtr ek2,
                                      const char *keyTag, EvalKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiAddEvalKeys: null context");
    }
    if (!ek1) {
      return MakePKEError("CryptoContext_MultiAddEvalKeys: null eval key 1");
    }
    if (!ek2) {
      return MakePKEError("CryptoContext_MultiAddEvalKeys: null eval key 2");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalKeys: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ek1_sptr = GetEKSharedPtr(ek1);
    auto &ek2_sptr = GetEKSharedPtr(ek2);
    std::string tag = keyTag ? std::string(keyTag) : "";

    auto result = cc_sptr->MultiAddEvalKeys(ek1_sptr, ek2_sptr, tag);
    *out = new EvalKeySharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiAddEvalMultKeys(CryptoContextPtr cc_ptr_to_sptr,
                                          EvalKeyPtr ek1, EvalKeyPtr ek2,
                                          const char *keyTag, EvalKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiAddEvalMultKeys: null context");
    }
    if (!ek1) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalMultKeys: null eval key 1");
    }
    if (!ek2) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalMultKeys: null eval key 2");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalMultKeys: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ek1_sptr = GetEKSharedPtr(ek1);
    auto &ek2_sptr = GetEKSharedPtr(ek2);
    std::string tag = keyTag ? std::string(keyTag) : "";

    auto result = cc_sptr->MultiAddEvalMultKeys(ek1_sptr, ek2_sptr, tag);
    *out = new EvalKeySharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiAddEvalSumKeys(CryptoContextPtr cc_ptr_to_sptr,
                                         EvalKeyMapPtr ekm1, EvalKeyMapPtr ekm2,
                                         const char *keyTag,
                                         EvalKeyMapPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_MultiAddEvalSumKeys: null context");
    }
    if (!ekm1) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalSumKeys: null eval key map 1");
    }
    if (!ekm2) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalSumKeys: null eval key map 2");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalSumKeys: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ekm1_sptr = GetEKMSharedPtr(ekm1);
    auto &ekm2_sptr = GetEKMSharedPtr(ekm2);
    std::string tag = keyTag ? std::string(keyTag) : "";

    auto result = cc_sptr->MultiAddEvalSumKeys(ekm1_sptr, ekm2_sptr, tag);
    *out = new EvalKeyMapSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_MultiAddEvalAutomorphismKeys(
    CryptoContextPtr cc_ptr_to_sptr, EvalKeyMapPtr ekm1, EvalKeyMapPtr ekm2,
    const char *keyTag, EvalKeyMapPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalAutomorphismKeys: null context");
    }
    if (!ekm1) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalAutomorphismKeys: null eval key map 1");
    }
    if (!ekm2) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalAutomorphismKeys: null eval key map 2");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_MultiAddEvalAutomorphismKeys: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ekm1_sptr = GetEKMSharedPtr(ekm1);
    auto &ekm2_sptr = GetEKMSharedPtr(ekm2);
    std::string tag = keyTag ? std::string(keyTag) : "";

    auto result =
        cc_sptr->MultiAddEvalAutomorphismKeys(ekm1_sptr, ekm2_sptr, tag);
    *out = new EvalKeyMapSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// Base evaluation key generation functions
PKEErr CryptoContext_EvalSumKeyGenPrivate(CryptoContextPtr cc_ptr_to_sptr,
                                          PrivateKeyPtr privateKey,
                                          PublicKeyPtr publicKey) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_EvalSumKeyGenPrivate: null context");
    }
    if (!privateKey) {
      return MakePKEError(
          "CryptoContext_EvalSumKeyGenPrivate: null private key");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk = GetSKSharedPtr(privateKey);

    if (publicKey) {
      auto &pk = GetPKSharedPtr(publicKey);
      cc_sptr->EvalSumKeyGen(sk, pk);
    } else {
      cc_sptr->EvalSumKeyGen(sk);
    }

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_EvalAtIndexKeyGenPrivate(CryptoContextPtr cc_ptr_to_sptr,
                                              PrivateKeyPtr privateKey,
                                              const int32_t *indices,
                                              size_t numIndices,
                                              PublicKeyPtr publicKey) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError(
          "CryptoContext_EvalAtIndexKeyGenPrivate: null context");
    }
    if (!privateKey) {
      return MakePKEError(
          "CryptoContext_EvalAtIndexKeyGenPrivate: null private key");
    }
    if (!indices) {
      return MakePKEError(
          "CryptoContext_EvalAtIndexKeyGenPrivate: null indices");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk = GetSKSharedPtr(privateKey);

    // Convert C array to C++ vector
    std::vector<int32_t> indexList(indices, indices + numIndices);

    if (publicKey) {
      auto &pk = GetPKSharedPtr(publicKey);
      cc_sptr->EvalAtIndexKeyGen(sk, indexList, pk);
    } else {
      cc_sptr->EvalAtIndexKeyGen(sk, indexList);
    }

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_GetEvalSumKeyMap(CryptoContextPtr cc_ptr_to_sptr,
                                      const char *keyTag, EvalKeyMapPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_GetEvalSumKeyMap: null context");
    }
    if (!keyTag) {
      return MakePKEError("CryptoContext_GetEvalSumKeyMap: null keyTag");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_GetEvalSumKeyMap: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::string tag(keyTag);

    // Get the eval sum key map from the context
    auto &keyMap = cc_sptr->GetEvalSumKeyMap(tag);

    // Create a new shared pointer to the key map
    *out = new EvalKeyMapSharedPtr(
        std::make_shared<
            std::map<uint32_t, lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>(keyMap));

    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- Base Key Generation Functions for Multiparty ---

PKEErr CryptoContext_KeySwitchGen(CryptoContextPtr cc_ptr_to_sptr,
                                  PrivateKeyPtr oldPrivateKey,
                                  PrivateKeyPtr newPrivateKey,
                                  EvalKeyPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_KeySwitchGen: null context");
    }
    if (!oldPrivateKey) {
      return MakePKEError("CryptoContext_KeySwitchGen: null old private key");
    }
    if (!newPrivateKey) {
      return MakePKEError("CryptoContext_KeySwitchGen: null new private key");
    }
    if (!out) {
      return MakePKEError("CryptoContext_KeySwitchGen: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &oldSK_sptr = GetSKSharedPtr(oldPrivateKey);
    auto &newSK_sptr = GetSKSharedPtr(newPrivateKey);

    auto evalKey = cc_sptr->KeySwitchGen(oldSK_sptr, newSK_sptr);
    *out = new EvalKeySharedPtr(evalKey);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_InsertEvalMultKey(CryptoContextPtr cc_ptr_to_sptr,
                                       EvalKeyPtr *evalKeys, size_t numKeys) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_InsertEvalMultKey: null context");
    }
    if (!evalKeys || numKeys == 0) {
      return MakePKEError(
          "CryptoContext_InsertEvalMultKey: null or empty eval key vector");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<EvalKeySharedPtr> evalKeyVec;
    evalKeyVec.reserve(numKeys);

    for (size_t i = 0; i < numKeys; i++) {
      if (!evalKeys[i]) {
        return MakePKEError(
            "CryptoContext_InsertEvalMultKey: null eval key at index " +
            std::to_string(i));
      }
      evalKeyVec.push_back(GetEKSharedPtr(evalKeys[i]));
    }

    cc_sptr->InsertEvalMultKey(evalKeyVec);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_InsertEvalSumKey(CryptoContextPtr cc_ptr_to_sptr,
                                      EvalKeyMapPtr evalKeyMap) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_InsertEvalSumKey: null context");
    }
    if (!evalKeyMap) {
      return MakePKEError("CryptoContext_InsertEvalSumKey: null eval key map");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ekm_sptr = GetEKMSharedPtr(evalKeyMap);

    cc_sptr->InsertEvalSumKey(ekm_sptr);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// --- Key Tag Functions ---

PKEErr PrivateKey_GetKeyTag(PrivateKeyPtr sk, char **outKeyTag) {
  try {
    if (!sk) {
      return MakePKEError("PrivateKey_GetKeyTag: null private key");
    }
    if (!outKeyTag) {
      return MakePKEError("PrivateKey_GetKeyTag: null output pointer");
    }

    auto &sk_sptr = GetSKSharedPtr(sk);
    const std::string &keyTag = sk_sptr->GetKeyTag();
    *outKeyTag = DupString(keyTag);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr PublicKey_GetKeyTag(PublicKeyPtr pk, char **outKeyTag) {
  try {
    if (!pk) {
      return MakePKEError("PublicKey_GetKeyTag: null public key");
    }
    if (!outKeyTag) {
      return MakePKEError("PublicKey_GetKeyTag: null output pointer");
    }

    auto &pk_sptr = GetPKSharedPtr(pk);
    const std::string &keyTag = pk_sptr->GetKeyTag();
    *outKeyTag = DupString(keyTag);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr EvalKey_GetKeyTag(EvalKeyPtr ek, char **outKeyTag) {
  try {
    if (!ek) {
      return MakePKEError("EvalKey_GetKeyTag: null eval key");
    }
    if (!outKeyTag) {
      return MakePKEError("EvalKey_GetKeyTag: null output pointer");
    }

    auto &ek_sptr = GetEKSharedPtr(ek);
    const std::string &keyTag = ek_sptr->GetKeyTag();
    *outKeyTag = DupString(keyTag);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

// Cleanup functions
void DestroyPrivateKey(PrivateKeyPtr sk) {
  delete reinterpret_cast<PrivateKeySharedPtr *>(sk);
}

void DestroyPublicKey(PublicKeyPtr pk) {
  delete reinterpret_cast<PublicKeySharedPtr *>(pk);
}

// Note: DestroyEvalKey is in pre_c.cpp

void DestroyEvalKeyMap(EvalKeyMapPtr ekm) {
  delete reinterpret_cast<EvalKeyMapSharedPtr *>(ekm);
}

// --- Interactive Bootstrapping Functions ---

PKEErr CryptoContext_IntBootAdjustScale(CryptoContextPtr cc_ptr_to_sptr,
                                        CiphertextPtr ciphertext,
                                        CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_IntBootAdjustScale: null context");
    }
    if (!ciphertext) {
      return MakePKEError("CryptoContext_IntBootAdjustScale: null ciphertext");
    }
    if (!out) {
      return MakePKEError(
          "CryptoContext_IntBootAdjustScale: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct_sptr = GetCTSharedPtr(ciphertext);

    auto result = cc_sptr->IntBootAdjustScale(ct_sptr);
    *out = new CiphertextSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntBootDecrypt(CryptoContextPtr cc_ptr_to_sptr,
                                    PrivateKeyPtr privateKey,
                                    CiphertextPtr ciphertext,
                                    CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_IntBootDecrypt: null context");
    }
    if (!privateKey) {
      return MakePKEError("CryptoContext_IntBootDecrypt: null private key");
    }
    if (!ciphertext) {
      return MakePKEError("CryptoContext_IntBootDecrypt: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_IntBootDecrypt: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &sk_sptr = GetSKSharedPtr(privateKey);
    auto &ct_sptr = GetCTSharedPtr(ciphertext);

    auto result = cc_sptr->IntBootDecrypt(sk_sptr, ct_sptr);
    *out = new CiphertextSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntBootEncrypt(CryptoContextPtr cc_ptr_to_sptr,
                                    PublicKeyPtr publicKey,
                                    CiphertextPtr ciphertext,
                                    CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_IntBootEncrypt: null context");
    }
    if (!publicKey) {
      return MakePKEError("CryptoContext_IntBootEncrypt: null public key");
    }
    if (!ciphertext) {
      return MakePKEError("CryptoContext_IntBootEncrypt: null ciphertext");
    }
    if (!out) {
      return MakePKEError("CryptoContext_IntBootEncrypt: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &pk_sptr = GetPKSharedPtr(publicKey);
    auto &ct_sptr = GetCTSharedPtr(ciphertext);

    auto result = cc_sptr->IntBootEncrypt(pk_sptr, ct_sptr);
    *out = new CiphertextSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

PKEErr CryptoContext_IntBootAdd(CryptoContextPtr cc_ptr_to_sptr,
                                CiphertextPtr ciphertext1,
                                CiphertextPtr ciphertext2, CiphertextPtr *out) {
  try {
    if (!cc_ptr_to_sptr) {
      return MakePKEError("CryptoContext_IntBootAdd: null context");
    }
    if (!ciphertext1) {
      return MakePKEError("CryptoContext_IntBootAdd: null ciphertext1");
    }
    if (!ciphertext2) {
      return MakePKEError("CryptoContext_IntBootAdd: null ciphertext2");
    }
    if (!out) {
      return MakePKEError("CryptoContext_IntBootAdd: null output pointer");
    }

    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct1_sptr = GetCTSharedPtr(ciphertext1);
    auto &ct2_sptr = GetCTSharedPtr(ciphertext2);

    auto result = cc_sptr->IntBootAdd(ct1_sptr, ct2_sptr);
    *out = new CiphertextSharedPtr(result);
    return MakePKEOk();
  }
  PKE_CATCH_RETURN()
}

} // extern "C"
