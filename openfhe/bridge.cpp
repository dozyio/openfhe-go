#include "bridge.h"
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

using namespace lbcrypto;

// --- Helper types and functions (OUTSIDE extern "C") ---
using CryptoContextSharedPtr = CryptoContext<DCRTPoly>;
using PlaintextSharedPtr = Plaintext;
using CiphertextSharedPtr = Ciphertext<DCRTPoly>;
using KeyPairRawPtr = KeyPair<DCRTPoly> *;
using PublicKeySharedPtr = PublicKey<DCRTPoly>;
using PrivateKeySharedPtr = PrivateKey<DCRTPoly>;

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

static void set_err(char **out, const char *msg) {
  if (!out)
    return;
  size_t n = std::strlen(msg);
  char *p = (char *)std::malloc(n + 1);
  if (p) {
    std::memcpy(p, msg, n + 1);
    *out = p;
  }
}
// --- End of helpers ---

extern "C" {

// --- CCParams ---
// BVF
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

// BGV
ParamsBGVPtr NewParamsBGV() { return new CCParams<CryptoContextBGVRNS>(); }
void ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p, uint64_t mod) {
  reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetPlaintextModulus(
      mod);
}
void ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth) {
  reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetMultiplicativeDepth(
      depth);
}
void DestroyParamsBGV(ParamsBGVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
}

// CKKS
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
void ParamsCKKS_SetSecurityLevel(ParamsCKKSPtr p, OFHESecurityLevel level) {
  auto params = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
  params->SetSecurityLevel(static_cast<lbcrypto::SecurityLevel>(level));
}
void ParamsCKKS_SetRingDim(ParamsCKKSPtr p, uint64_t ringDim) {
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetRingDim(ringDim);
}
void ParamsCKKS_SetScalingTechnique(ParamsCKKSPtr p, int technique) {
  // Map integer constants back to C++ enum
  ScalingTechnique st;
  // Use C++ enum names directly
  switch (technique) {
  case 0:
    st = lbcrypto::FIXEDMANUAL;
    break; // Use lbcrypto::FIXEDMANUAL, check value 0
  case 1:
    st = lbcrypto::FIXEDAUTO;
    break; // Use lbcrypto::FIXEDAUTO, check value 1
  case 2:
    st = lbcrypto::FLEXIBLEAUTO;
    break; // Use lbcrypto::FLEXIBLEAUTO, check value 2
  case 3:
    st = lbcrypto::FLEXIBLEAUTOEXT;
    break; // Use lbcrypto::FLEXIBLEAUTOEXT, check value 3
  // Add cases for COMPOSITESCALING* if you expose them later
  case 6:
    st = lbcrypto::NORESCALE;
    break; // Use lbcrypto::NORESCALE, check value 6
  default:
    st = lbcrypto::INVALID_RS_TECHNIQUE; // Or throw error
  }
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetScalingTechnique(
      st);
}
void ParamsCKKS_SetSecretKeyDist(ParamsCKKSPtr p, OFHESecretKeyDist dist) {
  auto params = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
  params->SetSecretKeyDist(static_cast<lbcrypto::SecretKeyDist>(dist));
}

void ParamsCKKS_SetFirstModSize(ParamsCKKSPtr p, int modSize) {
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetFirstModSize(
      modSize);
}
void ParamsCKKS_SetNumLargeDigits(ParamsCKKSPtr p, int numDigits) {
  reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetNumLargeDigits(
      numDigits);
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

CryptoContextPtr NewCryptoContextBGV(ParamsBGVPtr p) {
  auto params_ptr = reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
  CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
  auto *heap_sptr_ptr = new CryptoContextSharedPtr(cc_sptr);
  return reinterpret_cast<CryptoContextPtr>(heap_sptr_ptr);
}

void CryptoContext_Enable(CryptoContextPtr cc_ptr_to_sptr, int feature) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  // Use C++ enum names directly for comparison
  if (feature & lbcrypto::PKE)
    cc_sptr->Enable(PKE);
  if (feature & lbcrypto::KEYSWITCH)
    cc_sptr->Enable(KEYSWITCH);
  // PRE feature might need lbcrypto::PRE
  if (feature & lbcrypto::LEVELEDSHE)
    cc_sptr->Enable(LEVELEDSHE);
  if (feature & lbcrypto::ADVANCEDSHE)
    cc_sptr->Enable(ADVANCEDSHE);
  // MULTIPARTY feature might need lbcrypto::MULTIPARTY
  if (feature & lbcrypto::FHE)
    cc_sptr->Enable(FHE);
}

int CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                      KeyPairPtr keys_raw_ptr, uint32_t slots,
                                      char **errOut) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    if (!cc) {
      set_err(errOut, "null CryptoContext");
      return 0;
    }
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw || !kp_raw->secretKey) {
      set_err(errOut, "missing secret key");
      return 0;
    }

    auto N = cc->GetRingDimension();
    if (slots == 0 || slots > N / 2)
      slots = (uint32_t)(N / 2);

    // std::fprintf(stderr, "[OpenFHE] KeyGen: slots=%u\n", (unsigned)slots);
    // std::fflush(stderr);
    cc->EvalBootstrapKeyGen(kp_raw->secretKey, slots);
    // std::fprintf(stderr, "[OpenFHE] KeyGen: ok\n");
    // std::fflush(stderr);
    return 1;
  } catch (const std::exception &e) {
    set_err(errOut, e.what());
    // std::fprintf(stderr, "[OpenFHE] KeyGen exception: %s\n", e.what());
    // std::fflush(stderr);
    return 0;
  } catch (...) {
    // set_err(errOut, "unknown exception in EvalBootstrapKeyGen");
    // std::fprintf(stderr, "[OpenFHE] KeyGen unknown exception\n");
    std::fflush(stderr);
    return 0;
  }
}

CiphertextPtr CryptoContext_EvalBootstrap(CryptoContextPtr cc_ptr_to_sptr,
                                          CiphertextPtr ct_ptr_to_sptr,
                                          char **errOut) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);
    if (!cc) {
      set_err(errOut, "null CryptoContext");
      return nullptr;
    }
    if (!ct) {
      set_err(errOut, "null ciphertext");
      return nullptr;
    }

    // std::fprintf(stderr, "[OpenFHE] Bootstrap: begin\n");
    // std::fflush(stderr);
    auto out = cc->EvalBootstrap(ct);
    // std::fprintf(stderr, "[OpenFHE] Bootstrap: ok\n");
    // std::fflush(stderr);

    return reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(out));
  } catch (const std::exception &e) {
    set_err(errOut, e.what());
    // std::fprintf(stderr, "[OpenFHE] Bootstrap exception: %s\n", e.what());
    // std::fflush(stderr);
    return nullptr;
  } catch (...) {
    set_err(errOut, "unknown exception in EvalBootstrap");
    // std::fprintf(stderr, "[OpenFHE] Bootstrap unknown exception\n");
    // std::fflush(stderr);
    return nullptr;
  }
}

// TODO: Add support for levelBudget, correctionFactor and precompute
int CryptoContext_EvalBootstrapSetup(CryptoContextPtr cc_ptr_to_sptr,
                                     uint32_t slots, char **errOut) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    if (!cc) {
      set_err(errOut, "null CryptoContext");
      return 0;
    }

    auto N = cc->GetRingDimension();
    if (slots == 0 || slots > N / 2)
      slots = (uint32_t)(N / 2);

    std::vector<uint32_t> levelBudget{5, 4};
    std::vector<uint32_t> dim1{0, 0}; // let OpenFHE pick
    cc->EvalBootstrapSetup(levelBudget, dim1, slots,
                           /*correctionFactor=*/0, /*precompute=*/true);

    return 1;
  } catch (const std::exception &e) {
    set_err(errOut, e.what());
    return 0;
  } catch (...) {
    set_err(errOut, "unknown exception in EvalBootstrapSetup");
    return 0;
  }
}

int CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc_ptr_to_sptr,
                                            const uint32_t *lb, int len,
                                            char **errOut) {
  if (errOut)
    *errOut = nullptr;
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    if (!cc) {
      if (errOut)
        set_err(errOut, "null CryptoContext");
      return 0;
    }
    std::vector<uint32_t> levelBudget;
    if (lb && len > 0)
      levelBudget.assign(lb, lb + len);
    else
      levelBudget = {4, 4};

    cc->EvalBootstrapSetup(levelBudget);
    return 1;
  } catch (const std::exception &e) {
    if (errOut)
      set_err(errOut, e.what());
    return 0;
  } catch (...) {
    if (errOut)
      set_err(errOut, "unknown exception");
    return 0;
  }
}

int CryptoContext_EvalBootstrapPrecompute(CryptoContextPtr cc_ptr_to_sptr,
                                          uint32_t slots, char **errOut) {
  try {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    if (!cc) {
      set_err(errOut, "null CryptoContext");
      return 0;
    }

    auto N = cc->GetRingDimension();
    if (slots == 0 || slots > N / 2)
      slots = (uint32_t)(N / 2);

    // std::fprintf(stderr, "[OpenFHE] Precompute: N=%llu slots=%u\n",
    //              (unsigned long long)N, (unsigned)slots);
    // std::fflush(stderr);

    cc->EvalBootstrapPrecompute(slots);

    // std::fprintf(stderr, "[OpenFHE] Precompute: ok\n");
    // std::fflush(stderr);
    return 1;
  } catch (const std::exception &e) {
    set_err(errOut, e.what());
    // std::fprintf(stderr, "[OpenFHE] Precompute exception: %s\n", e.what());
    // std::fflush(stderr);
    return 0;
  } catch (...) {
    set_err(errOut, "unknown exception in EvalBootstrapPrecompute");
    // std::fprintf(stderr, "[OpenFHE] Precompute unknown exception\n");
    // std::fflush(stderr);
    return 0;
  }
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

uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc_ptr_to_sptr) {
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  return cc->GetRingDimension(); // CKKS: N (power of two)
}

// BFV/BGV MakePackedPlaintext (Same underlying C++ call)
PlaintextPtr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                               int64_t *values, int len) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  std::vector<int64_t> vec(values, values + len);
  Plaintext pt_sptr = cc_sptr->MakePackedPlaintext(vec);
  auto *heap_sptr_ptr = new PlaintextSharedPtr(pt_sptr);
  return reinterpret_cast<PlaintextPtr>(heap_sptr_ptr);
}

// CKKS MakeCKKSPackedPlaintext (Simplified)
// # TODO support depth, level, etc
PlaintextPtr
CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                      double *values, int len) {
  auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
  std::vector<double> vec(values, values + len);
  Plaintext pt_sptr =
      cc_sptr->MakeCKKSPackedPlaintext(vec); // Calls the simple C++ overload
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
// Accessors and setters for KeyPair reconstruction
void *GetPublicKey(KeyPairPtr kp_raw_ptr) {
  auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
  if (!kp || !kp->publicKey)
    return nullptr;
  // Return a pointer to a *copy* of the shared_ptr, managed on heap
  auto *heap_sptr_ptr = new PublicKeySharedPtr(kp->publicKey);
  return reinterpret_cast<void *>(heap_sptr_ptr);
}
void *GetPrivateKey(KeyPairPtr kp_raw_ptr) {
  auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
  if (!kp || !kp->secretKey)
    return nullptr;
  // Return a pointer to a *copy* of the shared_ptr, managed on heap
  auto *heap_sptr_ptr = new PrivateKeySharedPtr(kp->secretKey);
  return reinterpret_cast<void *>(heap_sptr_ptr);
}
KeyPairPtr NewKeyPair() {
  return reinterpret_cast<KeyPairPtr>(new KeyPair<DCRTPoly>());
}
void SetPublicKey(KeyPairPtr kp_raw_ptr, void *pk_ptr_to_sptr) {
  auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
  auto &pk_sptr = GetPKSharedPtr(pk_ptr_to_sptr);
  kp->publicKey = pk_sptr;
  delete reinterpret_cast<PublicKeySharedPtr *>(
      pk_ptr_to_sptr); // Clean up the heap-allocated shared_ptr wrapper
}
void SetPrivateKey(KeyPairPtr kp_raw_ptr, void *sk_ptr_to_sptr) {
  auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
  auto &sk_sptr = GetSKSharedPtr(sk_ptr_to_sptr);
  kp->secretKey = sk_sptr;
  delete reinterpret_cast<PrivateKeySharedPtr *>(
      sk_ptr_to_sptr); // Clean up the heap-allocated shared_ptr wrapper
}

void DestroyKeyPair(KeyPairPtr kp_raw_ptr) {
  delete reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
}

// --- Plaintext ---
// BFV/BGV GetPackedValue
int Plaintext_GetPackedValueLength(PlaintextPtr pt_ptr_to_sptr) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  // Ensure the underlying PlaintextImpl has GetPackedValue()
  try {
    return pt_sptr->GetPackedValue().size();
  } catch (...) {
    // Handle cases where GetPackedValue might not be available (e.g., CKKS)
    return 0;
  }
}

int64_t Plaintext_GetPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  try {
    return pt_sptr->GetPackedValue()[i];
  } catch (...) {
    // TODO: return error
    return 0; // Or some error indicator
  }
}

// Depth helper: FHECKKSRNS::GetBootstrapDepth(levelBudget, skd)
uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist) {
  std::vector<uint32_t> lb;
  if (levelBudget && len > 0)
    lb.assign(levelBudget, levelBudget + len);
  else
    lb = {4, 4};
  auto skd = static_cast<SecretKeyDist>(secretKeyDist);
  return FHECKKSRNS::GetBootstrapDepth(lb, skd);
}

// CKKS GetRealPackedValue
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

void Plaintext_SetLength(PlaintextPtr pt_ptr_to_sptr, int len) {
  auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
  pt_sptr->SetLength(len);
}

void DestroyPlaintext(PlaintextPtr pt_ptr_to_sptr) {
  delete reinterpret_cast<PlaintextSharedPtr *>(pt_ptr_to_sptr);
}

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct_ptr_to_sptr) {
  delete reinterpret_cast<CiphertextSharedPtr *>(ct_ptr_to_sptr);
}

// -- Serialization ---
void FreeString(char *s) { delete[] s; }

// Helper to copy std::string to C string (caller must free using FreeString)
char *CopyStringToC(const std::string &s) {
  char *cstr = new char[s.length() + 1];
  std::strcpy(cstr, s.c_str());
  return cstr;
}

// CryptoContext Serialization
size_t SerializeCryptoContextToString(CryptoContextPtr cc_ptr_to_sptr,
                                      char **outString) {
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  std::stringstream ss;
  Serial::Serialize(cc, ss, SerType::JSON); // Using JSON for readability
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  return s.length();
}

CryptoContextPtr DeserializeCryptoContextFromString(const char *inString) {
  CryptoContext<DCRTPoly> cc;
  std::stringstream ss(inString);
  Serial::Deserialize(cc, ss, SerType::JSON);
  if (!cc)
    return nullptr; // Deserialization failed
  auto *heap_sptr_ptr = new CryptoContextSharedPtr(cc);
  return reinterpret_cast<CryptoContextPtr>(heap_sptr_ptr);
}

// PublicKey Serialization
size_t SerializePublicKeyToString(KeyPairPtr kp_raw_ptr, char **outString) {
  auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
  if (!kp || !kp->publicKey)
    return 0;
  std::stringstream ss;
  Serial::Serialize(kp->publicKey, ss, SerType::JSON);
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  return s.length();
}

KeyPairPtr DeserializePublicKeyFromString(const char *inString) {
  PublicKey<DCRTPoly> pk;
  std::stringstream ss(inString);
  Serial::Deserialize(pk, ss, SerType::JSON);
  if (!pk)
    return nullptr;
  KeyPairRawPtr kp = new KeyPair<DCRTPoly>();
  kp->publicKey = pk; // Assign deserialized key
  return reinterpret_cast<KeyPairPtr>(kp);
}

// PrivateKey Serialization
size_t SerializePrivateKeyToString(KeyPairPtr kp_raw_ptr, char **outString) {
  auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
  if (!kp || !kp->secretKey)
    return 0;
  std::stringstream ss;
  Serial::Serialize(kp->secretKey, ss, SerType::JSON);
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  return s.length();
}

KeyPairPtr DeserializePrivateKeyFromString(const char *inString) {
  PrivateKey<DCRTPoly> sk;
  std::stringstream ss(inString);
  Serial::Deserialize(sk, ss, SerType::JSON);
  if (!sk)
    return nullptr;
  KeyPairRawPtr kp = new KeyPair<DCRTPoly>();
  kp->secretKey = sk; // Assign deserialized key
  return reinterpret_cast<KeyPairPtr>(kp);
}

// EvalMultKey (Relinearization Key) Serialization
size_t SerializeEvalMultKeyToString(CryptoContextPtr cc_ptr_to_sptr,
                                    const char *keyId, char **outString) {
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  std::stringstream ss;
  // EvalMultKey is stored in the CryptoContext, identified by ID (usually sk
  // fingerprint)
  if (!cc->SerializeEvalMultKey(ss, SerType::JSON, std::string(keyId)))
    return 0;
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  return s.length();
}

void DeserializeEvalMultKeyFromString(CryptoContextPtr cc_ptr_to_sptr,
                                      const char *inString) {
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  std::stringstream ss(inString);
  cc->DeserializeEvalMultKey(ss, SerType::JSON);
}

// Ciphertext Serialization
size_t SerializeCiphertextToString(CiphertextPtr ct_ptr_to_sptr,
                                   char **outString) {
  auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);
  std::stringstream ss;
  Serial::Serialize(ct, ss, SerType::JSON);
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  return s.length();
}

CiphertextPtr DeserializeCiphertextFromString(const char *inString) {
  Ciphertext<DCRTPoly> ct;
  std::stringstream ss(inString);
  Serial::Deserialize(ct, ss, SerType::JSON);
  if (!ct)
    return nullptr;
  auto *heap_sptr_ptr = new CiphertextSharedPtr(ct);
  return reinterpret_cast<CiphertextPtr>(heap_sptr_ptr);
}

} // extern "C"
