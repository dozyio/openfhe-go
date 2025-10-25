// bridge.cpp
#include "bridge.h"
#include "pke/gen-cryptocontext.h"
#include "pke/openfhe.h"
#include <memory>

using namespace lbcrypto;

// --- Helper types and functions (OUTSIDE extern "C") ---
using CryptoContextSharedPtr = std::shared_ptr<CryptoContextImpl<DCRTPoly>>;
using PlaintextSharedPtr = std::shared_ptr<PlaintextImpl>;
using CiphertextSharedPtr = std::shared_ptr<CiphertextImpl<DCRTPoly>>;
using KeyPairRawPtr = KeyPair<DCRTPoly> *;

inline CryptoContextSharedPtr &GetCCSharedPtr(CryptoContextPtr cc_ptr_to_sptr) {
  return *reinterpret_cast<CryptoContextSharedPtr *>(cc_ptr_to_sptr);
}
inline PlaintextSharedPtr &GetPTSharedPtr(PlaintextPtr pt_ptr_to_sptr) {
  return *reinterpret_cast<PlaintextSharedPtr *>(pt_ptr_to_sptr);
}
inline CiphertextSharedPtr &GetCTSharedPtr(CiphertextPtr ct_ptr_to_sptr) {
  return *reinterpret_cast<CiphertextSharedPtr *>(ct_ptr_to_sptr);
}
// --- End of helpers ---

extern "C" {

// --- CCParams ---
ParamsBFVPtr NewParamsBFV() { return new CCParams<CryptoContextBFVRNS>(); }
void ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p, uint64_t mod) {
  reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)->SetPlaintextModulus(
      mod);
}
void ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth) {
  reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)->SetMultiplicativeDepth(
      depth);
}
void DestroyParamsBFV(ParamsBFVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
}

ParamsCKKSPtr NewParamsCKKS() { return new CCParams<CryptoContextCKKSRNS>(); }
void ParamsCKKS_SetScalingModSize(ParamsCKKSPtr p, int modSize) {
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetScalingModSize(
      modSize);
}
void ParamsCKKS_SetBatchSize(ParamsCKKSPtr p, int batchSize) {
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetBatchSize(
      batchSize);
}
void ParamsCKKS_SetMultiplicativeDepth(ParamsCKKSPtr p, int depth) {
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetMultiplicativeDepth(
      depth);
}
void DestroyParamsCKKS(ParamsCKKSPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
}

// --- CryptoContext ---
CryptoContextPtr NewCryptoContextBFV(ParamsBFVPtr p) {
  auto params_ptr = reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
  CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
  auto *heap_sptr_ptr = new CryptoContextSharedPtr(cc_sptr);
  return reinterpret_cast<CryptoContextPtr>(heap_sptr_ptr);
}

CryptoContextPtr NewCryptoContextCKKS(ParamsCKKSPtr p) {
  auto params_ptr = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
  CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
  auto *heap_sptr_ptr = new CryptoContextSharedPtr(cc_sptr);
  return reinterpret_cast<CryptoContextPtr>(heap_sptr_ptr);
}

void CryptoContext_Enable(CryptoContextPtr cc_ptr_to_sptr, int feature) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  if (feature == PKE_FEATURE)
    cc_sptr->Enable(PKE);
  else if (feature == KEYSWITCH_FEATURE)
    cc_sptr->Enable(KEYSWITCH);
  else if (feature == LEVELEDSHE_FEATURE)
    cc_sptr->Enable(LEVELEDSHE);
}

KeyPairPtr CryptoContext_KeyGen(CryptoContextPtr cc_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  return new KeyPair<DCRTPoly>(cc_sptr->KeyGen());
}

void CryptoContext_EvalMultKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                  KeyPairPtr keys_raw_ptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
  cc_sptr->EvalMultKeyGen(kp_raw->secretKey);
}

void CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                    KeyPairPtr keys_raw_ptr, int32_t *indices,
                                    int len) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
  std::vector<int32_t> vec(indices, indices + len);
  cc_sptr->EvalRotateKeyGen(kp_raw->secretKey, vec);
}

PlaintextPtr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                               int64_t *values, int len) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  std::vector<int64_t> vec(values, values + len);
  Plaintext pt_sptr = cc_sptr->MakePackedPlaintext(vec);
  auto *heap_sptr_ptr = new PlaintextSharedPtr(pt_sptr);
  return reinterpret_cast<PlaintextPtr>(heap_sptr_ptr);
}

// *** NEW CKKS FUNCTIONS ***
PlaintextPtr
CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                      double *values, int len, uint32_t depth,
                                      uint32_t level, double scale) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  std::vector<double> vec(values, values + len);

  // Note: The simple-real-numbers example doesn't specify depth, level, or
  // scale. The MakeCKKSPackedPlaintext has multiple overloads. Let's use the
  // one that matches the python example's simplicity. The python
  // `MakeCKKSPackedPlaintext(vector)` calls the C++:
  // `MakeCKKSPackedPlaintext(const std::vector<double>& value, ...)`
  // This C++ function has defaults for noiseScaleDeg, level, params, slots.
  // Let's try to match that.
  Plaintext pt_sptr = cc_sptr->MakeCKKSPackedPlaintext(vec);

  auto *heap_sptr_ptr = new PlaintextSharedPtr(pt_sptr);
  return reinterpret_cast<PlaintextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_Rescale(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
  Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->Rescale(ct_sptr);
  auto *heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}
// *** END NEW ***

CiphertextPtr CryptoContext_Encrypt(CryptoContextPtr cc_ptr_to_sptr,
                                    KeyPairPtr keys_raw_ptr,
                                    PlaintextPtr pt_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  Ciphertext<DCRTPoly> ct_sptr = cc_sptr->Encrypt(kp_raw->publicKey, pt_sptr);
  auto *heap_sptr_ptr = new CiphertextSharedPtr(ct_sptr);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalAdd(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct1_ptr_to_sptr,
                                    CiphertextPtr ct2_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
  auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
  Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalAdd(ct1_sptr, ct2_sptr);
  auto *heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalSub(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct1_ptr_to_sptr,
                                    CiphertextPtr ct2_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
  auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
  Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalSub(ct1_sptr, ct2_sptr);
  auto *heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalMult(CryptoContextPtr cc_ptr_to_sptr,
                                     CiphertextPtr ct1_ptr_to_sptr,
                                     CiphertextPtr ct2_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
  auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
  Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalMult(ct1_sptr, ct2_sptr);
  auto *heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

CiphertextPtr CryptoContext_EvalRotate(CryptoContextPtr cc_ptr_to_sptr,
                                       CiphertextPtr ct_ptr_to_sptr,
                                       int32_t index) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
  Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalRotate(ct_sptr, index);
  auto *heap_sptr_ptr = new CiphertextSharedPtr(result_ct_sptr);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

PlaintextPtr CryptoContext_Decrypt(CryptoContextPtr cc_ptr_to_sptr,
                                   KeyPairPtr keys_raw_ptr,
                                   CiphertextPtr ct_ptr_to_sptr) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
  auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

  Plaintext pt_res_sptr;
  DecryptResult result =
      cc_sptr->Decrypt(kp_raw->secretKey, ct_sptr, &pt_res_sptr);

  if (!result.isValid) {
    return nullptr;
  }

  auto *heap_sptr_ptr = new PlaintextSharedPtr(pt_res_sptr);
  return reinterpret_cast<PlaintextPtr>(heap_sptr_ptr);
}

void DestroyCryptoContext(CryptoContextPtr cc_ptr_to_sptr) {
  delete reinterpret_cast<CryptoContextSharedPtr *>(cc_ptr_to_sptr);
}

// --- KeyPair ---
void DestroyKeyPair(KeyPairPtr kp_raw_ptr) {
  delete reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
}

// --- Plaintext ---
int Plaintext_GetPackedValueLength(PlaintextPtr pt_ptr_to_sptr) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  return pt_sptr->GetPackedValue().size();
}
int64_t Plaintext_GetPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  return pt_sptr->GetPackedValue()[i];
}

// *** NEW CKKS FUNCTIONS ***
int Plaintext_GetRealPackedValueLength(PlaintextPtr pt_ptr_to_sptr) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  // Need to decode first before accessing
  // pt_sptr->Decode();
  return pt_sptr->GetRealPackedValue().size();
}

double Plaintext_GetRealPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  // GetRealPackedValue() returns a std::vector<double>
  return pt_sptr->GetRealPackedValue()[i];
}
// *** END NEW ***

void DestroyPlaintext(PlaintextPtr pt_ptr_to_sptr) {
  delete reinterpret_cast<PlaintextSharedPtr *>(pt_ptr_to_sptr);
}

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct_ptr_to_sptr) {
  delete reinterpret_cast<CiphertextSharedPtr *>(ct_ptr_to_sptr);
}

} // extern "C"
