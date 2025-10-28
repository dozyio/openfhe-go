#include "ckks_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- CKKS Params Functions ---
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

// --- CKKS CryptoContext ---
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

// --- CKKS Plaintext ---
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

// --- CKKS Operations ---
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

// --- CKKS Bootstrapping ---
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
                                    CiphertextPtr *out){
    PKE_TRY{auto &cc = GetCCSharedPtr(cc_ptr_to_sptr);
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
  set_last_error_pke_str("CryptoContext_EvalBootstrap: null output pointer");
  return PKE_ERR;
}

auto out_ct = cc->EvalBootstrap(ct);
*out = reinterpret_cast<CiphertextPtr>(new CiphertextSharedPtr(out_ct));
return PKE_OK;
}
PKE_CATCH_RETURN(PKE_ERR)
}

uint32_t CKKS_GetBootstrapDepth(const uint32_t *levelBudget, int len,
                                int secretKeyDist) {
  // This is a static helper, no error handling needed
  std::vector<uint32_t> lb;
  if (levelBudget && len > 0)
    lb.assign(levelBudget, levelBudget + len);
  else
    lb = {4, 4};
  auto skd = static_cast<lbcrypto::SecretKeyDist>(secretKeyDist);
  return FHECKKSRNS::GetBootstrapDepth(lb, skd);
}

} // extern "C"
