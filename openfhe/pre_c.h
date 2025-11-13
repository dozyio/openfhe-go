#ifndef PRE_C_H
#define PRE_C_H

#include "pke_common_c.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer for EvalKey (used for re-encryption keys)
typedef void *EvalKeyPtr;

// --- PRE (Proxy Re-Encryption) Functions ---

// ReKeyGen generates a re-encryption key from oldPrivateKey to newPublicKey
// This key allows transforming ciphertexts encrypted under oldPublicKey
// to ciphertexts encrypted under newPublicKey without decryption.
PKEErr CryptoContext_ReKeyGen(CryptoContextPtr cc, void *oldPrivateKey,
                              void *newPublicKey, EvalKeyPtr *out);

// ReEncrypt transforms a ciphertext encrypted under one key to be encrypted
// under another key using the re-encryption key from ReKeyGen.
PKEErr CryptoContext_ReEncrypt(CryptoContextPtr cc, CiphertextPtr ciphertext,
                               EvalKeyPtr evalKey, CiphertextPtr *out);

// --- EvalKey Management ---
void DestroyEvalKey(EvalKeyPtr ek);

#ifdef __cplusplus
}
#endif

#endif // PRE_C_H
