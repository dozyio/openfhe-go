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
  BINFHE_OK_CODE = 0,
  BINFHE_ERR_CODE = 1 // Indicates an error occurred, check LastError
} BinFHEErrCode;

typedef struct {
  BinFHEErrCode code; // 0 for OK, non-zero for error (e.g., 1)
  char *msg; // Allocated error string if code != 0, NULL otherwise. Go side
             // MUST call FreeBin_ErrMsg on this if not NULL.
} BinFHEErr;

void FreeBinFHE_ErrMsg(char *msg);

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
BinFHEErr BinFHEContext_New(BinFHEContextH *out);
void BinFHEContext_Delete(BinFHEContextH h);
BinFHEErr BinFHEContext_Generate(BinFHEContextH h, BINFHE_PARAMSET_C paramset,
                                 BINFHE_METHOD_C method);

// --- Keys ---
BinFHEErr
BinFHEContext_KeyGen(BinFHEContextH h,
                     LWESecretKeyH *out); // Output param for new key handle
void LWESecretKey_Delete(LWESecretKeyH h);
BinFHEErr BinFHEContext_BTKeyGen(BinFHEContextH h, LWESecretKeyH sk);

// --- Operations ---
BinFHEErr BinFHEContext_Encrypt(BinFHEContextH h, LWESecretKeyH sk, int bit,
                                LWECiphertextH *out); // Output param
void LWECiphertext_Delete(LWECiphertextH h);
BinFHEErr BinFHEContext_EvalBinGate(BinFHEContextH h, BINFHE_GATE_C gate,
                                    LWECiphertextH a, LWECiphertextH b,
                                    LWECiphertextH *out); // Output param
BinFHEErr BinFHEContext_Bootstrap(BinFHEContextH h, LWECiphertextH in,
                                  LWECiphertextH *out); // Output param
BinFHEErr BinFHEContext_Decrypt(BinFHEContextH h, LWESecretKeyH sk,
                                LWECiphertextH ct,
                                int *out_bit); // Output param

// Decrypt with plaintext modulus
BinFHEErr BinFHEContext_DecryptModulus(BinFHEContextH h, LWESecretKeyH sk,
                                       LWECiphertextH ct, uint64_t p,
                                       uint64_t *out_val);

// Decrypt with plaintext modulus using LWEPrivateKey (from scheme switching)
// Note: We use void* to accept the LWEPrivateKeyPtr from schemeswitch_c.h
BinFHEErr BinFHEContext_DecryptModulusLWEKey(BinFHEContextH h, void *sk,
                                             LWECiphertextH ct, uint64_t p,
                                             uint64_t *out_val);

// --- Parameter Getters ---
BinFHEErr BinFHEContext_GetMaxPlaintextSpace(BinFHEContextH h, uint32_t *out);
BinFHEErr BinFHEContext_Getn(BinFHEContextH h, uint32_t *out);
BinFHEErr BinFHEContext_Getq(BinFHEContextH h, uint64_t *out);
BinFHEErr BinFHEContext_GetBeta(BinFHEContextH h, uint32_t *out);

// --- Advanced Operations ---
BinFHEErr BinFHEContext_EvalSign(BinFHEContextH h, LWECiphertextH ct,
                                 LWECiphertextH *out);
BinFHEErr BinFHEContext_EvalFloor(BinFHEContextH h, LWECiphertextH ct,
                                  uint32_t bits, LWECiphertextH *out);
BinFHEErr BinFHEContext_EvalNOT(BinFHEContextH h, LWECiphertextH ct,
                                LWECiphertextH *out);

// Note: LUT and arbitrary function evaluation require more complex types
// and will be added in a future enhancement if needed

#ifdef __cplusplus
}
#endif

#endif // BINFHE_C_H
