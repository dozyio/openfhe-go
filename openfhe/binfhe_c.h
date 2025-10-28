#ifndef BINFHE_H
#define BINFHE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque Handles
typedef void *BinFHEContextH;
typedef void *LWESecretKeyH;
typedef void *LWECiphertextH;

// Error Codes
typedef enum {
  BIN_OK = 0,
  BIN_ERR = 1 // Indicates an error occurred, check LastError
} BinErr;

typedef enum {
  BINFHE_PARAMSET_TOY = 0,
  BINFHE_PARAMSET_MEDIUM = 1,
  BINFHE_PARAMSET_STD128_AP = 2,
  BINFHE_PARAMSET_STD128 = 3,
  BINFHE_PARAMSET_STD128_3 = 4,
  BINFHE_PARAMSET_STD128_4 = 5,
  BINFHE_PARAMSET_STD128Q = 6,
  BINFHE_PARAMSET_STD128Q_3 = 7,
  BINFHE_PARAMSET_STD128Q_4 = 8,
  BINFHE_PARAMSET_STD192 = 9,
  BINFHE_PARAMSET_STD192_3 = 10,
  BINFHE_PARAMSET_STD192_4 = 11,
  BINFHE_PARAMSET_STD192Q = 12,
  BINFHE_PARAMSET_STD192Q_3 = 13,
  BINFHE_PARAMSET_STD192Q_4 = 14,
  BINFHE_PARAMSET_STD256 = 15,
  BINFHE_PARAMSET_STD256_3 = 16,
  BINFHE_PARAMSET_STD256_4 = 17,
  BINFHE_PARAMSET_STD256Q = 18,
  BINFHE_PARAMSET_STD256Q_3 = 19,
  BINFHE_PARAMSET_STD256Q_4 = 20,
  BINFHE_PARAMSET_STD128_LMKCDEY = 21,
  BINFHE_PARAMSET_STD128_3_LMKCDEY = 22,
  BINFHE_PARAMSET_STD128_4_LMKCDEY = 23,
  BINFHE_PARAMSET_STD128Q_LMKCDEY = 24,
  BINFHE_PARAMSET_STD128Q_3_LMKCDEY = 25,
  BINFHE_PARAMSET_STD128Q_4_LMKCDEY = 26,
  BINFHE_PARAMSET_STD192_LMKCDEY = 27,
  BINFHE_PARAMSET_STD192_3_LMKCDEY = 28,
  BINFHE_PARAMSET_STD192_4_LMKCDEY = 29,
  BINFHE_PARAMSET_STD192Q_LMKCDEY = 30,
  BINFHE_PARAMSET_STD192Q_3_LMKCDEY = 31,
  BINFHE_PARAMSET_STD192Q_4_LMKCDEY = 32,
  BINFHE_PARAMSET_STD256_LMKCDEY = 33,
  BINFHE_PARAMSET_STD256_3_LMKCDEY = 34,
  BINFHE_PARAMSET_STD256_4_LMKCDEY = 35,
  BINFHE_PARAMSET_STD256Q_LMKCDEY = 36,
  BINFHE_PARAMSET_STD256Q_3_LMKCDEY = 37,
  BINFHE_PARAMSET_STD256Q_4_LMKCDEY = 38,
  BINFHE_PARAMSET_LPF_STD128 = 39,
  BINFHE_PARAMSET_LPF_STD128Q = 40,
  BINFHE_PARAMSET_LPF_STD128_LMKCDEY = 41,
  BINFHE_PARAMSET_LPF_STD128Q_LMKCDEY = 42,
  BINFHE_PARAMSET_SIGNED_MOD_TEST = 43,

} BINFHE_PARAMSET_C;

typedef enum {
  BINFHE_METHOD_INVALID = 0,
  BINFHE_METHOD_AP = 1,
  BINFHE_METHOD_GINX = 2,
  BINFHE_METHOD_LMKCDEY = 3
} BINFHE_METHOD_C;

typedef enum {
  BINGATE_OR = 0,
  BINGATE_AND = 1,
  BINGATE_NOR = 2,
  BINGATE_NAND = 3,
  BINGATE_XOR = 4,
  BINGATE_XNOR = 5,
  BINGATE_MAJORITY = 6,
  BINGATE_AND3 = 7,
  BINGATE_OR3 = 8,
  BINGATE_AND4 = 9,
  BINGATE_OR4 = 10,
  BINGATE_XOR_FAST = 11,
  BINGATE_XNOR_FAST = 12,
  BINGATE_CMUX = 13
} BINFHE_GATE_C;

// --- Context ---
BinFHEContextH BinFHEContext_New();
void BinFHEContext_Delete(BinFHEContextH h);
BinErr BinFHEContext_Generate(BinFHEContextH h, BINFHE_PARAMSET_C paramset,
                              BINFHE_METHOD_C method);

// --- Keys ---
BinErr
BinFHEContext_KeyGen(BinFHEContextH h,
                     LWESecretKeyH *out); // Output param for new key handle
void LWESecretKey_Delete(LWESecretKeyH h);
BinErr BinFHEContext_BTKeyGen(BinFHEContextH h, LWESecretKeyH sk);

// --- Operations ---
BinErr BinFHEContext_Encrypt(BinFHEContextH h, LWESecretKeyH sk, int bit,
                             LWECiphertextH *out); // Output param
void LWECiphertext_Delete(LWECiphertextH h);
BinErr BinFHEContext_EvalBinGate(BinFHEContextH h, BINFHE_GATE_C gate,
                                 LWECiphertextH a, LWECiphertextH b,
                                 LWECiphertextH *out); // Output param
BinErr BinFHEContext_Bootstrap(BinFHEContextH h, LWECiphertextH in,
                               LWECiphertextH *out); // Output param
BinErr BinFHEContext_Decrypt(BinFHEContextH h, LWESecretKeyH sk,
                             LWECiphertextH ct, int *out_bit); // Output param

// --- Error Handling ---
const char *BinFHE_LastError(); // Get last error message (thread-local)

#ifdef __cplusplus
}
#endif

#endif // BINFHE_C_H
