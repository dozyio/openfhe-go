#include "pke_common_c.h"
#include "pke_helpers_c.h"

using namespace lbcrypto;

extern "C" {

// --- PKE Error Handling ---
const char *PKE_LastError() { return g_pke_last_error_message.c_str(); }

// --- Common CryptoContext Functions ---
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

void DestroyCryptoContext(CryptoContextPtr cc_ptr_to_sptr) {
  delete reinterpret_cast<CryptoContextSharedPtr *>(cc_ptr_to_sptr);
}

// --- Common Operations ---
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

PKE_Err CryptoContext_Decrypt(CryptoContextPtr cc_ptr_to_sptr,
                              KeyPairPtr keys_raw_ptr,
                              CiphertextPtr ct_ptr_to_sptr,
                              PlaintextPtr *out){PKE_TRY{if (!cc_ptr_to_sptr){
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
  set_last_error_pke_str("CryptoContext_Decrypt: keypair has no secret key");
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

PKE_Err Plaintext_GetRealPackedValueAt(PlaintextPtr pt_ptr_to_sptr, int i,
                                       double *out_val) {
  PKE_TRY {
    if (!pt_ptr_to_sptr) {
      set_last_error_pke_str("Plaintext_GetRealPackedValueAt: null plaintext");
      return PKE_ERR;
    }
    if (!out_val) {
      set_last_error_pke_str(
          "Plaintext_GetRealPackedValueAt: null output pointer");
      return PKE_ERR;
    }
    auto &pt_sptr = GetPTSharedPtr(pt_ptr_to_sptr);
    // Add bounds check
    if (i < 0 || (size_t)i >= pt_sptr->GetRealPackedValue().size()) {
      set_last_error_pke_str(
          "Plaintext_GetRealPackedValueAt: index out of bounds");
      return PKE_ERR;
    }
    *out_val = pt_sptr->GetRealPackedValue()[i];
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

// --- Serialization ---
void FreeString(char *s) {
  if (s) {
    free(s);
  }
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
