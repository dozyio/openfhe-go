#include "binfhe.h"
#include "binfhecontext.h"
#include <map>

// Maps to store objects by ID
std::map<BINFHE_CONTEXT_ID, lbcrypto::BinFHEContext> binFHEContexts;
std::map<BINFHE_SECRETKEY_ID, lbcrypto::LWEPrivateKey> binFHESecretKeys;
std::map<BINFHE_CIPHERTEXT_ID, lbcrypto::LWECiphertext> binFHECiphertexts;

// ID counters
BINFHE_CONTEXT_ID nextBinFHEContextId = 1;
BINFHE_SECRETKEY_ID nextBinFHESecretKeyId = 1;
BINFHE_CIPHERTEXT_ID nextBinFHECiphertextId = 1;

extern "C" {

BINFHE_CONTEXT_ID BinFHEContext_Create() {
  BINFHE_CONTEXT_ID id = nextBinFHEContextId++;
  binFHEContexts[id] = lbcrypto::BinFHEContext();
  return id;
}

void BinFHEContext_GenerateBinFHEContext(BINFHE_CONTEXT_ID id,
                                         BINFHE_PARAMSET_C paramset,
                                         BINFHE_METHOD_C method) {
  auto p = static_cast<lbcrypto::BINFHE_PARAMSET>(paramset);
  auto m = static_cast<lbcrypto::BINFHE_METHOD>(method);
  binFHEContexts.at(id).GenerateBinFHEContext(p, m);
}

BINFHE_SECRETKEY_ID BinFHEContext_KeyGen(BINFHE_CONTEXT_ID id) {
  BINFHE_SECRETKEY_ID skId = nextBinFHESecretKeyId++;
  binFHESecretKeys[skId] = binFHEContexts.at(id).KeyGen();
  return skId;
}

void BinFHEContext_BTKeyGen(BINFHE_CONTEXT_ID id, BINFHE_SECRETKEY_ID skId) {
  binFHEContexts.at(id).BTKeyGen(binFHESecretKeys.at(skId));
}

BINFHE_CIPHERTEXT_ID BinFHEContext_Encrypt(BINFHE_CONTEXT_ID id,
                                           BINFHE_SECRETKEY_ID skId,
                                           int message) {
  BINFHE_CIPHERTEXT_ID ctId = nextBinFHECiphertextId++;
  binFHECiphertexts[ctId] =
      binFHEContexts.at(id).Encrypt(binFHESecretKeys.at(skId), message);
  return ctId;
}

BINFHE_CIPHERTEXT_ID BinFHEContext_EvalBinGate(BINFHE_CONTEXT_ID id,
                                               BINFHE_GATE_C gate,
                                               BINFHE_CIPHERTEXT_ID ct1Id,
                                               BINFHE_CIPHERTEXT_ID ct2Id) {
  auto g = static_cast<lbcrypto::BINGATE>(gate);
  auto ct1 = binFHECiphertexts.at(ct1Id);
  auto ct2 = binFHECiphertexts.at(ct2Id);

  BINFHE_CIPHERTEXT_ID ctOutId = nextBinFHECiphertextId++;
  binFHECiphertexts[ctOutId] = binFHEContexts.at(id).EvalBinGate(g, ct1, ct2);
  return ctOutId;
}

BINFHE_CIPHERTEXT_ID BinFHEContext_Bootstrap(BINFHE_CONTEXT_ID id,
                                             BINFHE_CIPHERTEXT_ID ctId) {
  auto ct = binFHECiphertexts.at(ctId);
  BINFHE_CIPHERTEXT_ID ctOutId = nextBinFHECiphertextId++;
  binFHECiphertexts[ctOutId] = binFHEContexts.at(id).Bootstrap(ct);
  return ctOutId;
}

int BinFHEContext_Decrypt(BINFHE_CONTEXT_ID id, BINFHE_SECRETKEY_ID skId,
                          BINFHE_CIPHERTEXT_ID ctId) {
  lbcrypto::LWEPlaintext result;
  binFHEContexts.at(id).Decrypt(binFHESecretKeys.at(skId),
                                binFHECiphertexts.at(ctId), &result);
  return result;
}

// Memory management
void ReleaseBinFHEContext(BINFHE_CONTEXT_ID id) { binFHEContexts.erase(id); }
void ReleaseBinFHESecretKey(BINFHE_SECRETKEY_ID id) {
  binFHESecretKeys.erase(id);
}
void ReleaseBinFHECiphertext(BINFHE_CIPHERTEXT_ID id) {
  binFHECiphertexts.erase(id);
}

void ReleaseAllBinFHE() {
  binFHEContexts.clear();
  binFHESecretKeys.clear();
  binFHECiphertexts.clear();
}

} // extern "C"
