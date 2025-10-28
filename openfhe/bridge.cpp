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

// --- PKE Error Handling (NEW) ---
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

// --- End of helpers ---

extern "C" {

// --- PKE Error Handling (NEW) ---
const char *PKE_LastError() { return g_pke_last_error_message.c_str(); }

// --- CCParams ---
// BFV
PKE_Err NewParamsBFV(ParamsBFVPtr *out){PKE_TRY{
    if (!out){set_last_error_pke_str("NewParamsBFV: null output pointer");
return PKE_ERR;
}
*out = new CCParams<CryptoContextBFVRNS>();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBFV_SetPlaintextModulus(ParamsBFVPtr p,
                                      uint64_t mod){PKE_TRY{if (!p){
    set_last_error_pke_str("ParamsBFV_SetPlaintextModulus: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)->SetPlaintextModulus(mod);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBFV_SetMultiplicativeDepth(ParamsBFVPtr p, int depth) {
  PKE_TRY {
    if (!p) {
      set_last_error_pke_str("ParamsBFV_SetMultiplicativeDepth: null params");
      return PKE_ERR;
    }
    reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p)
        ->SetMultiplicativeDepth(depth);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}
void DestroyParamsBFV(ParamsBFVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
}

// BGV
PKE_Err NewParamsBGV(ParamsBGVPtr *out){PKE_TRY{
    if (!out){set_last_error_pke_str("NewParamsBGV: null output pointer");
return PKE_ERR;
}
*out = new CCParams<CryptoContextBGVRNS>();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBGV_SetPlaintextModulus(ParamsBGVPtr p,
                                      uint64_t mod){PKE_TRY{if (!p){
    set_last_error_pke_str("ParamsBGV_SetPlaintextModulus: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)->SetPlaintextModulus(mod);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsBGV_SetMultiplicativeDepth(ParamsBGVPtr p, int depth) {
  PKE_TRY {
    if (!p) {
      set_last_error_pke_str("ParamsBGV_SetMultiplicativeDepth: null params");
      return PKE_ERR;
    }
    reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p)
        ->SetMultiplicativeDepth(depth);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}
void DestroyParamsBGV(ParamsBGVPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
}

// CKKS
PKE_Err NewParamsCKKS(ParamsCKKSPtr *out){PKE_TRY{
    if (!out){set_last_error_pke_str("NewParamsCKKS: null output pointer");
return PKE_ERR;
}
*out = new CCParams<CryptoContextCKKSRNS>();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetScalingModSize(ParamsCKKSPtr p, int modSize){PKE_TRY{
    if (!p){set_last_error_pke_str("ParamsCKKS_SetScalingModSize: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetScalingModSize(
    modSize);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetBatchSize(ParamsCKKSPtr p, int batchSize){PKE_TRY{
    if (!p){set_last_error_pke_str("ParamsCKKS_SetBatchSize: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetBatchSize(batchSize);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetMultiplicativeDepth(ParamsCKKSPtr p,
                                          int depth){PKE_TRY{if (!p){
    set_last_error_pke_str("ParamsCKKS_SetMultiplicativeDepth: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetMultiplicativeDepth(
    depth);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetSecurityLevel(ParamsCKKSPtr p,
                                    OFHESecurityLevel level){PKE_TRY{
    if (!p){set_last_error_pke_str("ParamsCKKS_SetSecurityLevel: null params");
return PKE_ERR;
}
auto params = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
params->SetSecurityLevel(static_cast<lbcrypto::SecurityLevel>(level));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetRingDim(ParamsCKKSPtr p, uint64_t ringDim){PKE_TRY{
    if (!p){set_last_error_pke_str("ParamsCKKS_SetRingDim: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetRingDim(ringDim);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetScalingTechnique(ParamsCKKSPtr p,
                                       int technique){PKE_TRY{if (!p){
    set_last_error_pke_str("ParamsCKKS_SetScalingTechnique: null params");
return PKE_ERR;
}
ScalingTechnique st;
switch (technique) {
case 0:
  st = lbcrypto::FIXEDMANUAL;
  break;
case 1:
  st = lbcrypto::FIXEDAUTO;
  break;
case 2:
  st = lbcrypto::FLEXIBLEAUTO;
  break;
case 3:
  st = lbcrypto::FLEXIBLEAUTOEXT;
  break;
case 6:
  st = lbcrypto::NORESCALE;
  break;
default:
  st = lbcrypto::INVALID_RS_TECHNIQUE;
}
reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetScalingTechnique(st);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetSecretKeyDist(ParamsCKKSPtr p,
                                    OFHESecretKeyDist dist){PKE_TRY{
    if (!p){set_last_error_pke_str("ParamsCKKS_SetSecretKeyDist: null params");
return PKE_ERR;
}
auto params = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
params->SetSecretKeyDist(static_cast<lbcrypto::SecretKeyDist>(dist));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetFirstModSize(ParamsCKKSPtr p, int modSize){PKE_TRY{
    if (!p){set_last_error_pke_str("ParamsCKKS_SetFirstModSize: null params");
return PKE_ERR;
}
reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetFirstModSize(modSize);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err ParamsCKKS_SetNumLargeDigits(ParamsCKKSPtr p, int numDigits) {
  PKE_TRY {
    if (!p) {
      set_last_error_pke_str("ParamsCKKS_SetNumLargeDigits: null params");
      return PKE_ERR;
    }
    reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p)->SetNumLargeDigits(
        numDigits);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}
void DestroyParamsCKKS(ParamsCKKSPtr p) {
  delete reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
}

// --- CryptoContext ---
PKE_Err NewCryptoContextBFV(ParamsBFVPtr p, CryptoContextPtr *out){
    PKE_TRY{if (!p){set_last_error_pke_str("NewCryptoContextBFV: null params");
return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("NewCryptoContextBFV: null output pointer");
  return PKE_ERR;
}
auto params_ptr = reinterpret_cast<CCParams<CryptoContextBFVRNS> *>(p);
CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
*out = reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err NewCryptoContextCKKS(ParamsCKKSPtr p, CryptoContextPtr *out){
    PKE_TRY{if (!p){set_last_error_pke_str("NewCryptoContextCKKS: null params");
return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("NewCryptoContextCKKS: null output pointer");
  return PKE_ERR;
}
auto params_ptr = reinterpret_cast<CCParams<CryptoContextCKKSRNS> *>(p);
CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
*out = reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err NewCryptoContextBGV(ParamsBGVPtr p, CryptoContextPtr *out){
    PKE_TRY{if (!p){set_last_error_pke_str("NewCryptoContextBGV: null params");
return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("NewCryptoContextBGV: null output pointer");
  return PKE_ERR;
}
auto params_ptr = reinterpret_cast<CCParams<CryptoContextBGVRNS> *>(p);
CryptoContext<DCRTPoly> cc_sptr = GenCryptoContext(*params_ptr);
*out = reinterpret_cast<CryptoContextPtr>(new CryptoContextSharedPtr(cc_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_Enable(CryptoContextPtr cc_ptr_to_sptr,
                             int feature){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_Enable: null context");
return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
if (feature & lbcrypto::PKE)
  cc_sptr->Enable(PKE);
if (feature & lbcrypto::KEYSWITCH)
  cc_sptr->Enable(KEYSWITCH);
if (feature & lbcrypto::LEVELEDSHE)
  cc_sptr->Enable(LEVELEDSHE);
if (feature & lbcrypto::ADVANCEDSHE)
  cc_sptr->Enable(ADVANCEDSHE);
if (feature & lbcrypto::FHE)
  cc_sptr->Enable(FHE);
// Add other features if needed (PRE, MULTIPARTY, etc.)
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_KeyGen(CryptoContextPtr cc_ptr_to_sptr,
                             KeyPairPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_KeyGen: null context");
return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_KeyGen: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
*out = new KeyPair<DCRTPoly>(cc_sptr->KeyGen());
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalMultKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                     KeyPairPtr keys_raw_ptr){
    PKE_TRY{if (!cc_ptr_to_sptr){
        set_last_error_pke_str("CryptoContext_EvalMultKeyGen: null context");
return PKE_ERR;
}
if (!keys_raw_ptr) {
  set_last_error_pke_str("CryptoContext_EvalMultKeyGen: null keypair");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
if (!kp_raw->secretKey) {
  set_last_error_pke_str(
      "CryptoContext_EvalMultKeyGen: keypair has no secret key");
  return PKE_ERR;
}
cc_sptr->EvalMultKeyGen(kp_raw->secretKey);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                       KeyPairPtr keys_raw_ptr,
                                       int32_t *indices,
                                       int len){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_EvalRotateKeyGen: null context");
return PKE_ERR;
}
if (!keys_raw_ptr) {
  set_last_error_pke_str("CryptoContext_EvalRotateKeyGen: null keypair");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
if (!kp_raw->secretKey) {
  set_last_error_pke_str(
      "CryptoContext_EvalRotateKeyGen: keypair has no secret key");
  return PKE_ERR;
}
if (len > 0 && !indices) {
  set_last_error_pke_str(
      "CryptoContext_EvalRotateKeyGen: non-zero length with null indices");
  return PKE_ERR;
}
std::vector<int32_t> vec(indices, indices + len);
cc_sptr->EvalRotateKeyGen(kp_raw->secretKey, vec);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

uint64_t CryptoContext_GetRingDimension(CryptoContextPtr cc_ptr_to_sptr) {
  // This is a simple getter, no error handling needed
  if (!cc_ptr_to_sptr)
    return 0;
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  return cc->GetRingDimension();
}

// BFV/BGV MakePackedPlaintext
PKE_Err CryptoContext_MakePackedPlaintext(
    CryptoContextPtr cc_ptr_to_sptr, int64_t *values, int len,
    PlaintextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_MakePackedPlaintext: null context");
return PKE_ERR;
}
if (len > 0 && !values) {
  set_last_error_pke_str(
      "CryptoContext_MakePackedPlaintext: non-zero length with null values");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str(
      "CryptoContext_MakePackedPlaintext: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
std::vector<int64_t> vec(values, values + len);
Plaintext pt_sptr = cc_sptr->MakePackedPlaintext(vec);
*out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

// CKKS MakeCKKSPackedPlaintext
PKE_Err CryptoContext_MakeCKKSPackedPlaintext(CryptoContextPtr cc_ptr_to_sptr,
                                              double *values, int len,
                                              PlaintextPtr *out){
    PKE_TRY{if (!cc_ptr_to_sptr){set_last_error_pke_str(
        "CryptoContext_MakeCKKSPackedPlaintext: null context");
return PKE_ERR;
}
if (len > 0 && !values) {
  set_last_error_pke_str("CryptoContext_MakeCKKSPackedPlaintext: non-zero "
                         "length with null values");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str(
      "CryptoContext_MakeCKKSPackedPlaintext: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
std::vector<double> vec(values, values + len);
Plaintext pt_sptr = cc_sptr->MakeCKKSPackedPlaintext(vec);
*out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_Rescale(CryptoContextPtr cc_ptr_to_sptr,
                              CiphertextPtr ct_ptr_to_sptr,
                              CiphertextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_Rescale: null context");
return PKE_ERR;
}
if (!ct_ptr_to_sptr) {
  set_last_error_pke_str("CryptoContext_Rescale: null ciphertext");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_Rescale: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->Rescale(ct_sptr);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_Encrypt(CryptoContextPtr cc_ptr_to_sptr,
                              KeyPairPtr keys_raw_ptr,
                              PlaintextPtr pt_ptr_to_sptr,
                              CiphertextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_Encrypt: null context");
return PKE_ERR;
}
if (!keys_raw_ptr) {
  set_last_error_pke_str("CryptoContext_Encrypt: null keypair");
  return PKE_ERR;
}
if (!pt_ptr_to_sptr) {
  set_last_error_pke_str("CryptoContext_Encrypt: null plaintext");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_Encrypt: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
if (!kp_raw->publicKey) {
  set_last_error_pke_str("CryptoContext_Encrypt: keypair has no public key");
  return PKE_ERR;
}
auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
Ciphertext<DCRTPoly> ct_sptr = cc_sptr->Encrypt(kp_raw->publicKey, pt_sptr);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(ct_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalAdd(CryptoContextPtr cc_ptr_to_sptr,
                              CiphertextPtr ct1_ptr_to_sptr,
                              CiphertextPtr ct2_ptr_to_sptr,
                              CiphertextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_EvalAdd: null context");
return PKE_ERR;
}
if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
  set_last_error_pke_str("CryptoContext_EvalAdd: null input ciphertext");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_EvalAdd: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalAdd(ct1_sptr, ct2_sptr);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalSub(CryptoContextPtr cc_ptr_to_sptr,
                              CiphertextPtr ct1_ptr_to_sptr,
                              CiphertextPtr ct2_ptr_to_sptr,
                              CiphertextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_EvalSub: null context");
return PKE_ERR;
}
if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
  set_last_error_pke_str("CryptoContext_EvalSub: null input ciphertext");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_EvalSub: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalSub(ct1_sptr, ct2_sptr);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalMult(CryptoContextPtr cc_ptr_to_sptr,
                               CiphertextPtr ct1_ptr_to_sptr,
                               CiphertextPtr ct2_ptr_to_sptr,
                               CiphertextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
    set_last_error_pke_str("CryptoContext_EvalMult: null context");
return PKE_ERR;
}
if (!ct1_ptr_to_sptr || !ct2_ptr_to_sptr) {
  set_last_error_pke_str("CryptoContext_EvalMult: null input ciphertext");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_EvalMult: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto &ct1_sptr = GetCTSharedPtr(ct1_ptr_to_sptr);
auto &ct2_sptr = GetCTSharedPtr(ct2_ptr_to_sptr);
Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalMult(ct1_sptr, ct2_sptr);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalRotate(CryptoContextPtr cc_ptr_to_sptr,
                                 CiphertextPtr ct_ptr_to_sptr, int32_t index,
                                 CiphertextPtr *out){
    PKE_TRY{if (!cc_ptr_to_sptr){
        set_last_error_pke_str("CryptoContext_EvalRotate: null context");
return PKE_ERR;
}
if (!ct_ptr_to_sptr) {
  set_last_error_pke_str("CryptoContext_EvalRotate: null ciphertext");
  return PKE_ERR;
}
if (!out) {
  set_last_error_pke_str("CryptoContext_EvalRotate: null output pointer");
  return PKE_ERR;
}
auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);
Ciphertext<DCRTPoly> result_ct_sptr = cc_sptr->EvalRotate(ct_sptr, index);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(result_ct_sptr));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_Decrypt(CryptoContextPtr cc_ptr_to_sptr,
                              KeyPairPtr keys_raw_ptr,
                              CiphertextPtr ct_ptr_to_sptr, PlaintextPtr *out) {
  PKE_TRY {
    if (!cc_ptr_to_sptr) {
      set_last_error_pke_str("CryptoContext_Decrypt: null context");
      return PKE_ERR;
    }
    if (!keys_raw_ptr) {
      set_last_error_pke_str("CryptoContext_Decrypt: null keypair");
      return PKE_ERR;
    }
    if (!ct_ptr_to_sptr) {
      set_last_error_pke_str("CryptoContext_Decrypt: null ciphertext");
      return PKE_ERR;
    }
    if (!out) {
      set_last_error_pke_str("CryptoContext_Decrypt: null output pointer");
      return PKE_ERR;
    }
    auto &cc_sptr = GetCCSharedPtr(cc_ptr_to_sptr);
    auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
    if (!kp_raw->secretKey) {
      set_last_error_pke_str(
          "CryptoContext_Decrypt: keypair has no secret key");
      return PKE_ERR;
    }
    auto &ct_sptr = GetCTSharedPtr(ct_ptr_to_sptr);

    Plaintext pt_res_sptr;
    DecryptResult result =
        cc_sptr->Decrypt(kp_raw->secretKey, ct_sptr, &pt_res_sptr);

    if (!result.isValid) {
      set_last_error_pke_str(
          "CryptoContext_Decrypt: decryption failed (isValid=false)");
      return PKE_ERR;
    }

    *out = reinterpret_cast<PlaintextPtr>(new PlaintextSharedPtr(pt_res_sptr));
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}

void DestroyCryptoContext(CryptoContextPtr cc_ptr_to_sptr) {
  delete reinterpret_cast<CryptoContextSharedPtr *>(cc_ptr_to_sptr);
}

// --- KeyPair ---
PKE_Err GetPublicKey(KeyPairPtr kp_raw_ptr, void **out_pk_sptr_wrapper){PKE_TRY{
    if (!kp_raw_ptr){set_last_error_pke_str("GetPublicKey: null keypair");
return PKE_ERR;
}
if (!out_pk_sptr_wrapper) {
  set_last_error_pke_str("GetPublicKey: null output pointer");
  return PKE_ERR;
}
auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
if (!kp || !kp->publicKey) {
  set_last_error_pke_str("GetPublicKey: keypair has no public key");
  return PKE_ERR;
}
// Return a pointer to a *copy* of the shared_ptr, managed on heap
auto *heap_sptr_ptr = new PublicKeySharedPtr(kp->publicKey);
*out_pk_sptr_wrapper = reinterpret_cast<void *>(heap_sptr_ptr);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err GetPrivateKey(KeyPairPtr kp_raw_ptr,
                      void **out_sk_sptr_wrapper){PKE_TRY{
    if (!kp_raw_ptr){set_last_error_pke_str("GetPrivateKey: null keypair");
return PKE_ERR;
}
if (!out_sk_sptr_wrapper) {
  set_last_error_pke_str("GetPrivateKey: null output pointer");
  return PKE_ERR;
}
auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
if (!kp || !kp->secretKey) {
  set_last_error_pke_str("GetPrivateKey: keypair has no secret key");
  return PKE_ERR;
}
// Return a pointer to a *copy* of the shared_ptr, managed on heap
auto *heap_sptr_ptr = new PrivateKeySharedPtr(kp->secretKey);
*out_sk_sptr_wrapper = reinterpret_cast<void *>(heap_sptr_ptr);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err NewKeyPair(KeyPairPtr *out){
    PKE_TRY{if (!out){set_last_error_pke_str("NewKeyPair: null output pointer");
return PKE_ERR;
}
*out = reinterpret_cast<KeyPairPtr>(new KeyPair<DCRTPoly>());
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err SetPublicKey(KeyPairPtr kp_raw_ptr, void *pk_ptr_to_sptr){PKE_TRY{
    if (!kp_raw_ptr){set_last_error_pke_str("SetPublicKey: null keypair");
return PKE_ERR;
}
if (!pk_ptr_to_sptr) {
  set_last_error_pke_str("SetPublicKey: null public key pointer");
  return PKE_ERR;
}
auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
auto &pk_sptr = GetPKSharedPtr(pk_ptr_to_sptr);
kp->publicKey = pk_sptr;
delete reinterpret_cast<PublicKeySharedPtr *>(
    pk_ptr_to_sptr); // Clean up the heap-allocated shared_ptr wrapper
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}
PKE_Err SetPrivateKey(KeyPairPtr kp_raw_ptr, void *sk_ptr_to_sptr) {
  PKE_TRY {
    if (!kp_raw_ptr) {
      set_last_error_pke_str("SetPrivateKey: null keypair");
      return PKE_ERR;
    }
    if (!sk_ptr_to_sptr) {
      set_last_error_pke_str("SetPrivateKey: null private key pointer");
      return PKE_ERR;
    }
    auto kp = reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
    auto &sk_sptr = GetSKSharedPtr(sk_ptr_to_sptr);
    kp->secretKey = sk_sptr;
    delete reinterpret_cast<PrivateKeySharedPtr *>(
        sk_ptr_to_sptr); // Clean up the heap-allocated shared_ptr wrapper
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}

void DestroyKeyPair(KeyPairPtr kp_raw_ptr) {
  delete reinterpret_cast<KeyPairRawPtr>(kp_raw_ptr);
}

// --- Plaintext ---
PKE_Err
Plaintext_GetPackedValueLength(PlaintextPtr pt_ptr_to_sptr,
                               int *out_len){PKE_TRY{if (!pt_ptr_to_sptr){
    set_last_error_pke_str("Plaintext_GetPackedValueLength: null plaintext");
return PKE_ERR;
}
if (!out_len) {
  set_last_error_pke_str("Plaintext_GetPackedValueLength: null output pointer");
  return PKE_ERR;
}
auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
*out_len = pt_sptr->GetPackedValue().size();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err Plaintext_GetPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                                   int64_t *out_val){
    PKE_TRY{if (!pt_ptr_to_sptr){
        set_last_error_pke_str("Plaintext_GetPackedValueAt: null plaintext");
return PKE_ERR;
}
if (!out_val) {
  set_last_error_pke_str("Plaintext_GetPackedValueAt: null output pointer");
  return PKE_ERR;
}
auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
// Add bounds check
if (i < 0 || (size_t)i >= pt_sptr->GetPackedValue().size()) {
  set_last_error_pke_str("Plaintext_GetPackedValueAt: index out of bounds");
  return PKE_ERR;
}
*out_val = pt_sptr->GetPackedValue()[i];
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

// Depth helper
uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist) {
  // This is a static helper, no error handling needed
  std::vector<uint32_t> lb;
  if (levelBudget && len > 0)
    lb.assign(levelBudget, levelBudget + len);
  else
    lb = {4, 4};
  auto skd = static_cast<SecretKeyDist>(secretKeyDist);
  return FHECKKSRNS::GetBootstrapDepth(lb, skd);
}

// CKKS GetRealPackedValue
PKE_Err Plaintext_GetRealPackedValueLength(PlaintextPtr pt_ptr_to_sptr,
                                           int *out_len){
    PKE_TRY{if (!pt_ptr_to_sptr){set_last_error_pke_str(
        "Plaintext_GetRealPackedValueLength: null plaintext");
return PKE_ERR;
}
if (!out_len) {
  set_last_error_pke_str(
      "Plaintext_GetRealPackedValueLength: null output pointer");
  return PKE_ERR;
}
auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
*out_len = pt_sptr->GetRealPackedValue().size();
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err
Plaintext_GetRealPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                               double *out_val){PKE_TRY{if (!pt_ptr_to_sptr){
    set_last_error_pke_str("Plaintext_GetRealPackedValueAt: null plaintext");
return PKE_ERR;
}
if (!out_val) {
  set_last_error_pke_str("Plaintext_GetRealPackedValueAt: null output pointer");
  return PKE_ERR;
}
auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
// Add bounds check
if (i < 0 || (size_t)i >= pt_sptr->GetRealPackedValue().size()) {
  set_last_error_pke_str("Plaintext_GetRealPackedValueAt: index out of bounds");
  return PKE_ERR;
}
*out_val = pt_sptr->GetRealPackedValue()[i];
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err Plaintext_SetLength(PlaintextPtr pt_ptr_to_sptr, int len) {
  PKE_TRY {
    if (!pt_ptr_to_sptr) {
      set_last_error_pke_str("Plaintext_SetLength: null plaintext");
      return PKE_ERR;
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    pt_sptr->SetLength(len);
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}

void DestroyPlaintext(PlaintextPtr pt_ptr_to_sptr) {
  delete reinterpret_cast<PlaintextSharedPtr *>(pt_ptr_to_sptr);
}

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct_ptr_to_sptr) {
  delete reinterpret_cast<CiphertextSharedPtr *>(ct_ptr_to_sptr);
}

// --- Bootstrapping (Refactored) ---
PKE_Err CryptoContext_EvalBootstrapSetup_Simple(CryptoContextPtr cc_ptr_to_sptr,
                                                const uint32_t *lb, int len){
    PKE_TRY{if (!cc_ptr_to_sptr){set_last_error_pke_str(
        "CryptoContext_EvalBootstrapSetup_Simple: null context");
return PKE_ERR;
}
auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
std::vector<uint32_t> levelBudget;
if (lb && len > 0)
  levelBudget.assign(lb, lb + len);
else
  levelBudget = {4, 4}; // Default

cc->EvalBootstrapSetup(levelBudget);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalBootstrapKeyGen(CryptoContextPtr cc_ptr_to_sptr,
                                          KeyPairPtr keys_raw_ptr,
                                          uint32_t slots){
    PKE_TRY{auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
if (!cc) {
  set_last_error_pke_str("CryptoContext_EvalBootstrapKeyGen: null context");
  return PKE_ERR;
}
auto kp_raw = reinterpret_cast<KeyPairRawPtr>(keys_raw_ptr);
if (!kp_raw || !kp_raw->secretKey) {
  set_last_error_pke_str(
      "CryptoContext_EvalBootstrapKeyGen: missing secret key");
  return PKE_ERR;
}

auto N = cc->GetRingDimension();
if (slots == 0 || slots > N / 2)
  slots = (uint32_t)(N / 2);

cc->EvalBootstrapKeyGen(kp_raw->secretKey, slots);
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

PKE_Err CryptoContext_EvalBootstrap(CryptoContextPtr cc_ptr_to_sptr,
                                    CiphertextPtr ct_ptr_to_sptr,
                                    CiphertextPtr *out) {
  PKE_TRY {
    auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
    auto &ct = GetCTSharedPtr(ct_ptr_to_sptr);
    if (!cc) {
      set_last_error_pke_str("CryptoContext_EvalBootstrap: null context");
      return PKE_ERR;
    }
    if (!ct) {
      set_last_error_pke_str("CryptoContext_EvalBootstrap: null ciphertext");
      return PKE_ERR;
    }
    if (!out) {
      set_last_error_pke_str(
          "CryptoContext_EvalBootstrap: null output pointer");
      return PKE_ERR;
    }

    auto out_ct = cc->EvalBootstrap(ct);
    *out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(out_ct));
    return PKE_OK;
  }
  PKE_CATCH_RETURN(PKE_ERR)
}

// -- Serialization (Unchanged) ---
void FreeString(char *s) {
  if (s) {
    free(s);
  }
}

// Helper to copy std::string to C string (caller must free using C.free or
// FreeString)
char *CopyStringToC(const std::string &s) {
  char *cstr = (char *)malloc(s.length() + 1);
  if (!cstr)
    return nullptr; // Handle malloc failure
  std::strcpy(cstr, s.c_str());
  return cstr;
}

// CryptoContext Serialization
size_t SerializeCryptoContextToString(CryptoContextPtr cc_ptr_to_sptr,
                                      char **outString) {
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  std::stringstream ss;
  Serial::Serialize(cc, ss, SerType::JSON);
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  if (!*outString)
    return 0; // Handle malloc failure
  return s.length();
}

CryptoContextPtr DeserializeCryptoContextFromString(const char *inString) {
  CryptoContext<DCRTPoly> cc;
  std::stringstream ss(inString);
  Serial::Deserialize(cc, ss, SerType::JSON);
  if (!cc)
    return nullptr;
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
  if (!*outString)
    return 0;
  return s.length();
}

KeyPairPtr DeserializePublicKeyFromString(const char *inString) {
  PublicKey<DCRTPoly> pk;
  std::stringstream ss(inString);
  Serial::Deserialize(pk, ss, SerType::JSON);
  if (!pk)
    return nullptr;
  KeyPairRawPtr kp = new KeyPair<DCRTPoly>();
  kp->publicKey = pk;
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
  if (!*outString)
    return 0;
  return s.length();
}

KeyPairPtr DeserializePrivateKeyFromString(const char *inString) {
  PrivateKey<DCRTPoly> sk;
  std::stringstream ss(inString);
  Serial::Deserialize(sk, ss, SerType::JSON);
  if (!sk)
    return nullptr;
  KeyPairRawPtr kp = new KeyPair<DCRTPoly>();
  kp->secretKey = sk;
  return reinterpret_cast<KeyPairPtr>(kp);
}

// EvalMultKey (Relinearization Key) Serialization
size_t SerializeEvalMultKeyToString(CryptoContextPtr cc_ptr_to_sptr,
                                    const char *keyId, char **outString) {
  auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
  std::stringstream ss;
  if (!cc->SerializeEvalMultKey(ss, SerType::JSON, std::string(keyId)))
    return 0;
  std::string s = ss.str();
  *outString = CopyStringToC(s);
  if (!*outString)
    return 0;
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
  if (!*outString)
    return 0;
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
