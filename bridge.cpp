// bridge.cpp (Revised - Fix int32_t bug and C-linkage warnings)
#include "bridge.h"
#include <memory> // Include for shared_ptr
#include "pke/openfhe.h"
#include "pke/gen-cryptocontext.h" 

using namespace lbcrypto;

// --- Move these definitions OUTSIDE extern "C" ---
using CryptoContextSharedPtr = std::shared_ptr<CryptoContextImpl<DCRTPoly>>;
using PlaintextSharedPtr     = std::shared_ptr<PlaintextImpl>;
using CiphertextSharedPtr    = std::shared_ptr<CiphertextImpl<DCRTPoly>>;
using KeyPairRawPtr          = KeyPair<DCRTPoly>*; 

// Helper function to get the shared_ptr object from the C pointer
inline CryptoContextSharedPtr& GetCCSharedPtr(CryptoContextPtr cc_ptr_to_sptr) {
    return *reinterpret_cast<CryptoContextSharedPtr*>(cc_ptr_to_sptr);
}
// Helper function to get the Plaintext shared_ptr object from the C pointer
inline PlaintextSharedPtr& GetPTSharedPtr(PlaintextPtr pt_ptr_to_sptr) {
    return *reinterpret_cast<PlaintextSharedPtr*>(pt_ptr_to_sptr);
}
// Helper function to get the Ciphertext shared_ptr object from the C pointer
inline CiphertextSharedPtr& GetCTSharedPtr(CiphertextPtr ct_ptr_to_sptr) {
    return *reinterpret_cast<CiphertextSharedPtr*>(ct_ptr_to_sptr);
}
// --- End of moved definitions ---


extern "C" {

// --- CCParams --- (Correct)
ParamsPtr NewParamsBFVrns() {
    return new CCParams<CryptoContextBFVRNS>();
}
void Params_SetPlaintextModulus(ParamsPtr p, uint64_t mod) {
    reinterpret_cast<CCParams<CryptoContextBFVRNS>*>(p)->SetPlaintextModulus(mod);
}
void Params_SetMultiplicativeDepth(ParamsPtr p, int depth) {
    reinterpret_cast<CCParams<CryptoContextBFVRNS>*>(p)->SetMultiplicativeDepth(depth);
}
void DestroyParams(ParamsPtr p) {
    delete reinterpret_cast<CCParams<CryptoContextBFVRNS>*>(p);
}

// --- CryptoContext ---
CryptoContextPtr NewCryptoContext(ParamsPtr p) {
    auto params_ptr = reinterpret_cast<CCParams<CryptoContextBFVRNS>*>(p);
    CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
    auto* heap_sptr_ptr = new CryptoContextSharedPtr(cc_sptr);
    return reinterpret_cast<CryptoContextPtr>(heap_sptr_ptr);
}

void CryptoContext_Enable(CryptoContextPtr cc_ptr_to_sptr, int feature) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr); 
    if (feature == PKE_FEATURE) cc_sptr->Enable(PKE);
    else if (feature == KEYSWITCH_FEATURE) cc_sptr->Enable(KEYSWITCH);
    else if (feature == LEVELEDSHE_FEATURE) cc_sptr->Enable(LEVELEDSHE);
}

KeyPairPtr CryptoContext_KeyGen(CryptoContextPtr cc_ptr_to_sptr) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    return new KeyPair<DCRTPoly>(cc_sptr->KeyGen());
}

void CryptoContext_EvalMultKeyGen(CryptoContextPtr cc_ptr_to_sptr, KeyPairPtr keys_raw_ptr) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    cc_sptr->EvalMultKeyGen(kp_raw->secretKey);
}

// ****** THIS IS THE FIX ******
void CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc_ptr_to_sptr, KeyPairPtr keys_raw_ptr, int* indices, int len) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    
    // Explicitly create a vector of int32_t by casting each element
    // from the C-style 'int' array.
    std::vector<int32_t> vec;
    vec.reserve(len);
    for (int i = 0; i < len; ++i) {
        vec.push_back(static_cast<int32_t>(indices[i]));
    }

    // Call OpenFHE with the correctly typed vector
    cc_sptr->EvalRotateKeyGen(kp_raw->secretKey, vec); 
}
// ****** END OF FIX ******

PlaintextPtr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc_ptr_to_sptr, int64_t* values, int len) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    std::vector<int64_t> vec(values, values + len);
    Plaintext pt_sptr = cc_sptr->MakePackedPlaintext(vec);
    auto* heap_sptr_ptr = new PlaintextSharedPtr(pt_sptr);
    return reinterpret_cast<PlaintextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_Encrypt(CryptoContextPtr cc_ptr_to_sptr, KeyPairPtr keys_raw_ptr, PlaintextPtr pt_ptr_to_sptr) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    auto& pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr); 
    Ciphertext<DCRTPoly> ct_sptr = cc_sptr->Encrypt(kp_raw->publicKey, pt_sptr); 
    auto* heap_sptr_ptr = new CiphertextSharedPtr(ct_sptr);
    return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalAdd(CryptoContextPtr cc_ptr_to_sptr, CiphertextPtr ct1_ptr_to_sptr, CiphertextPtr ct2_ptr_to_sptr) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto& ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
    auto& ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalAdd(ct1_sptr, ct2_sptr);
    auto* heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
    return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalMult(CryptoContextPtr cc_ptr_to_sptr, CiphertextPtr ct1_ptr_to_sptr, CiphertextPtr ct2_ptr_to_sptr) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto& ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
    auto& ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalMult(ct1_sptr, ct2_sptr);
    auto* heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
    return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalRotate(CryptoContextPtr cc_ptr_to_sptr, CiphertextPtr ct_ptr_to_sptr, int index) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto& ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
    // Pass the 32-bit integer index directly
    Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalRotate(ct_sptr, static_cast<int32_t>(index));
    auto* heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
    return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

PlaintextPtr CryptoContext_Decrypt(CryptoContextPtr cc_ptr_to_sptr, KeyPairPtr keys_raw_ptr, CiphertextPtr ct_ptr_to_sptr) {
    auto& cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    auto& ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Plaintext pt_res_sptr; 
    DecryptResult result = cc_sptr->Decrypt(kp_raw->secretKey, ct_sptr, &pt_res_sptr);

    if (!result.isValid) {
         return nullptr;
    }

    auto* heap_sptr_ptr = new PlaintextSharedPtr(pt_res_sptr);
    return reinterpret_cast<PlaintextPtr>(heap_sptr_ptr);
}


void DestroyCryptoContext(CryptoContextPtr cc_ptr_to_sptr) {
    delete reinterpret_cast<CryptoContextSharedPtr*>(cc_ptr_to_sptr);
}

// --- KeyPair ---
void DestroyKeyPair(KeyPairPtr kp_raw_ptr) {
    delete reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
}

// --- Plaintext ---
int Plaintext_GetPackedValueLength(PlaintextPtr pt_ptr_to_sptr) {
    auto& pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    return pt_sptr->GetPackedValue().size();
}

int64_t Plaintext_GetPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i) {
    auto& pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr); 
    return pt_sptr->GetPackedValue()[i];
}

void DestroyPlaintext(PlaintextPtr pt_ptr_to_sptr) {
    delete reinterpret_cast<PlaintextSharedPtr*>(pt_ptr_to_sptr);
}

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct_ptr_to_sptr) {
    delete reinterpret_cast<CiphertextSharedPtr*>(ct_ptr_to_sptr);
}

} // extern "C"
