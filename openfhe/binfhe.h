#ifndef BINFHE_H
#define BINFHE_H

#ifdef __cplusplus
extern "C" {
#endif

// Opaque integer IDs for Go
typedef int BINFHE_CONTEXT_ID;
typedef int BINFHE_SECRETKEY_ID;
typedef int BINFHE_CIPHERTEXT_ID;

// BINFHE_PARAMSET (from binfhe-constants.h)
// TOY = 0, MEDIUM = 1, STD128_AP = 2, STD128 = 3, STD128_3 = 4, STD128_4 = 5,
// STD192 = 6, STD256 = 7, STD128_LMKCDEY = 8, STD192_LMKCDEY = 9,
// STD256_LMKCDEY = 10
typedef int BINFHE_PARAMSET_C;

// BINFHE_METHOD (from binfhe-constants.h)
// AP = 0, GINX = 1, LMKCDEY = 2
typedef int BINFHE_METHOD_C;

// BINGATE (from binfhe-constants.h)
// AND = 0, OR = 1, NAND = 2, NOR = 3, XOR = 4, XNOR = 5
typedef int BINFHE_GATE_C;

BINFHE_CONTEXT_ID BinFHEContext_Create();
void BinFHEContext_GenerateBinFHEContext(BINFHE_CONTEXT_ID id,
                                         BINFHE_PARAMSET_C paramset,
                                         BINFHE_METHOD_C method);
BINFHE_SECRETKEY_ID BinFHEContext_KeyGen(BINFHE_CONTEXT_ID id);
void BinFHEContext_BTKeyGen(BINFHE_CONTEXT_ID id, BINFHE_SECRETKEY_ID skId);
BINFHE_CIPHERTEXT_ID BinFHEContext_Encrypt(BINFHE_CONTEXT_ID id,
                                           BINFHE_SECRETKEY_ID skId,
                                           int message);
BINFHE_CIPHERTEXT_ID BinFHEContext_EvalBinGate(BINFHE_CONTEXT_ID id,
                                               BINFHE_GATE_C gate,
                                               BINFHE_CIPHERTEXT_ID ct1Id,
                                               BINFHE_CIPHERTEXT_ID ct2Id);
BINFHE_CIPHERTEXT_ID BinFHEContext_Bootstrap(BINFHE_CONTEXT_ID id,
                                             BINFHE_CIPHERTEXT_ID ctId);
int BinFHEContext_Decrypt(BINFHE_CONTEXT_ID id, BINFHE_SECRETKEY_ID skId,
                          BINFHE_CIPHERTEXT_ID ctId);

// Memory management
void ReleaseBinFHEContext(BINFHE_CONTEXT_ID id);
void ReleaseBinFHESecretKey(BINFHE_SECRETKEY_ID id);
void ReleaseBinFHECiphertext(BINFHE_CIPHERTEXT_ID id);
void ReleaseAllBinFHE();

#ifdef __cplusplus
}
#endif

#endif // BINFHE_H
