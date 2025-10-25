// bridge.cpp
#include "bridge.h"
#include "openfhe/pke/openfhe.h"

// We're using the DCRTPoly backend, which is standard
using namespace lbcrypto;

extern "C" {

// --- CCParams ---
ParamsPtr NewParamsBFVrns() {
    return new CCParams<CryptoContextBFVrns>();
}
void Params_SetPlaintextModulus(ParamsPtr p, uint64_t mod) {
    reinterpret_cast<CCParams<CryptoContextBFVrns>*>(p)->SetPlaintextModulus(mod);
}
void Params_SetMultiplicativeDepth(ParamsPtr p, int depth) {
    reinterpret_cast<CCParams<CryptoContextBFVrns>*>(p)->SetMultiplicativeDepth(depth);
}
void DestroyParams(ParamsPtr p) {
    delete reinterpret_cast<CCParams<CryptoContextBFVrns>*>(p);
}

// --- CryptoContext ---
CryptoContextPtr NewCryptoContext(ParamsPtr p) {
    auto params = reinterpret_cast<CCParams<CryptoContextBFVrns>*>(p);
    // GenCryptoContext returns by value, so we create a new heap-allocated object
    return new CryptoContext<DCRTPoly>(GenCryptoContext(*params));
}

void CryptoContext_Enable(CryptoContextPtr cc, int feature) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    if (feature == PKE_FEATURE) cc_obj->Enable(PKE);
    else if (feature == KEYSWITCH_FEATURE) cc_obj->Enable(KEYSWITCH);
    else if (feature == LEVELEDSHE_FEATURE) cc_obj->Enable(LEVELEDSHE);
}

KeyPairPtr CryptoContext_KeyGen(CryptoContextPtr cc) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    // KeyGen returns by value, so we create a new heap-allocated object
    return new KeyPair<DCRTPoly>(cc_obj->KeyGen());
}

void CryptoContext_EvalMultKeyGen(CryptoContextPtr cc, KeyPairPtr keys) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keys);
    cc_obj->EvalMultKeyGen(kp->secretKey);
}

void CryptoContext_EvalRotateKeyGen(CryptoContextPtr cc, KeyPairPtr keys, int* indices, int len) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keys);
    std::vector<int> vec(indices, indices + len);
    cc_obj->EvalRotateKeyGen(kp->secretKey, vec);
}

PlaintextPtr CryptoContext_MakePackedPlaintext(CryptoContextPtr cc, int64_t* values, int len) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    std::vector<int64_t> vec(values, values + len);
    // MakePackedPlaintext returns by value
    return new Plaintext(cc_obj->MakePackedPlaintext(vec));
}

CiphertextPtr CryptoContext_Encrypt(CryptoContextPtr cc, KeyPairPtr keys, PlaintextPtr pt) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keys);
    auto ptxt = reinterpret_cast<Plaintext*>(pt);
    // Encrypt returns by value
    return new Ciphertext<DCRTPoly>(cc_obj->Encrypt(kp->publicKey, *ptxt));
}

CiphertextPtr CryptoContext_EvalAdd(CryptoContextPtr cc, CiphertextPtr ct1, CiphertextPtr ct2) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto c1 = reinterpret_cast<Ciphertext<DCRTPoly>*>(ct1);
    auto c2 = reinterpret_cast<Ciphertext<DCRTPoly>*>(ct2);
    // EvalAdd returns by value
    return new Ciphertext<DCRTPoly>(cc_obj->EvalAdd(*c1, *c2));
}

CiphertextPtr CryptoContext_EvalMult(CryptoContextPtr cc, CiphertextPtr ct1, CiphertextPtr ct2) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto c1 = reinterpret_cast<Ciphertext<DCRTPoly>*>(ct1);
    auto c2 = reinterpret_cast<Ciphertext<DCRTPoly>*>(ct2);
    // EvalMult returns by value
    return new Ciphertext<DCRTPoly>(cc_obj->EvalMult(*c1, *c2));
}

CiphertextPtr CryptoContext_EvalRotate(CryptoContextPtr cc, CiphertextPtr ct, int index) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto c1 = reinterpret_cast<Ciphertext<DCRTPoly>*>(ct);
    // EvalRotate returns by value
    return new Ciphertext<DCRTPoly>(cc_obj->EvalRotate(*c1, index));
}

PlaintextPtr CryptoContext_Decrypt(CryptoContextPtr cc, KeyPairPtr keys, CiphertextPtr ct) {
    auto cc_obj = reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
    auto kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keys);
    auto ctxt = reinterpret_cast<Ciphertext<DCRTPoly>*>(ct);

    Plaintext pt_res; // Decrypt fills this
    cc_obj->Decrypt(kp->secretKey, *ctxt, &pt_res);
    return new Plaintext(pt_res); // Return a heap-allocated copy
}

void DestroyCryptoContext(CryptoContextPtr cc) {
    delete reinterpret_cast<CryptoContext<DCRTPoly>*>(cc);
}

// --- KeyPair ---
void DestroyKeyPair(KeyPairPtr kp) {
    delete reinterpret_cast<KeyPair<DCRTPoly>*>(kp);
}

// --- Plaintext ---
int Plaintext_GetPackedValueLength(PlaintextPtr pt) {
    auto ptxt = reinterpret_cast<Plaintext*>(pt);
    // GetPackedValue() returns a vector, we get its size.
    return ptxt->GetPackedValue().size();
}

int64_t Plaintext_GetPackedValueAt(PlaintextPtr pt, int i) {
    auto ptxt = reinterpret_cast<Plaintext*>(pt);
    // This is simple and safe, though not the most efficient.
    // It copies the vector and then accesses the element.
    return ptxt->GetPackedValue()[i];
}

void DestroyPlaintext(PlaintextPtr pt) {
    delete reinterpret_cast<Plaintext*>(pt);
}

// --- Ciphertext ---
void DestroyCiphertext(CiphertextPtr ct) {
    delete reinterpret_cast<Ciphertext<DCRTPoly>*>(ct);
}

} // extern "C"
