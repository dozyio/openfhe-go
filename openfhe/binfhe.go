package openfhe

// #cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/include -I${SRCDIR}/openfhe/include -I${SRCDIR}/openfhe/include/pke -I${SRCDIR}/openfhe/include/core -I${SRCDIR}/openfhe/include/binfhe -I${SRCDIR}/openfhe/include/core/include -I${SRCDIR}/openfhe/include/pke/include
// #include "binfhe.h"
import "C"

// BinFHEParamset maps to BINFHE_PARAMSET enum
type BinFHEParamset int

const (
	//  NAME                                // Description                                                     : Approximate Probability of Failure
	TOY                 BinFHEParamset = 0  // no security                                                     : 2^(-360)
	MEDIUM              BinFHEParamset = 1  // 108 bits of security for classical and 100 bits for quantum     : 2^(-70)
	STD128_AP           BinFHEParamset = 2  // more than 128 bits of security for classical computer attacks   : 2^(-50)
	STD128              BinFHEParamset = 3  // more than 128 bits of security for classical computer attacks   : 2^(-40)
	STD128_3            BinFHEParamset = 4  // STD128 for 3 binary inputs                                      : 2^(-50)
	STD128_4            BinFHEParamset = 5  // STD128 for 4 binary inputs                                      : 2^(-50)
	STD128Q             BinFHEParamset = 6  // more than 128 bits of security for quantum attacks              : 2^(-40)
	STD128Q_3           BinFHEParamset = 7  // STD128Q for 3 binary inputs                                     : 2^(-50)
	STD128Q_4           BinFHEParamset = 8  // STD128Q for 4 binary inputs                                     : 2^(-50)
	STD192              BinFHEParamset = 9  // more than 192 bits of security for classical computer attacks   : 2^(-40)
	STD192_3            BinFHEParamset = 10 // STD192 for 3 binary inputs                                      : 2^(-60)
	STD192_4            BinFHEParamset = 11 // STD192 for 4 binary inputs                                      : 2^(-70)
	STD192Q             BinFHEParamset = 12 // more than 192 bits of security for quantum attacks              : 2^(-80)
	STD192Q_3           BinFHEParamset = 13 // STD192Q for 3 binary inputs                                     : 2^(-80)
	STD192Q_4           BinFHEParamset = 14 // STD192Q for 4 binary inputs                                     : 2^(-50)
	STD256              BinFHEParamset = 15 // more than 256 bits of security for classical computer attacks   : 2^(-80)
	STD256_3            BinFHEParamset = 16 // STD256 for 3 binary inputs                                      : 2^(-70)
	STD256_4            BinFHEParamset = 17 // STD256 for 4 binary inputs                                      : 2^(-50)
	STD256Q             BinFHEParamset = 18 // more than 256 bits of security for quantum attacks              : 2^(-60)
	STD256Q_3           BinFHEParamset = 19 // STD256Q for 3 binary inputs                                     : 2^(-80)
	STD256Q_4           BinFHEParamset = 20 // STD256Q for 4 binary inputs                                     : 2^(-50)
	STD128_LMKCDEY      BinFHEParamset = 21 // STD128 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-55)
	STD128_3_LMKCDEY    BinFHEParamset = 22 // STD128_LMKCDEY for 3 binary inputs                              : 2^(-40)
	STD128_4_LMKCDEY    BinFHEParamset = 23 // STD128_LMKCDEY for 4 binary inputs                              : 2^(-60)
	STD128Q_LMKCDEY     BinFHEParamset = 24 // STD128Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-50)
	STD128Q_3_LMKCDEY   BinFHEParamset = 25 // STD128Q_LMKCDEY for 3 binary inputs                             : 2^(-45)
	STD128Q_4_LMKCDEY   BinFHEParamset = 26 // STD128Q_LMKCDEY for 4 binary inputs                             : 2^(-80)
	STD192_LMKCDEY      BinFHEParamset = 27 // STD192 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-60)
	STD192_3_LMKCDEY    BinFHEParamset = 28 // STD192_LMKCDEY for 3 binary inputs                              : 2^(-60)
	STD192_4_LMKCDEY    BinFHEParamset = 29 // STD192_LMKCDEY for 4 binary inputs                              : 2^(-70)
	STD192Q_LMKCDEY     BinFHEParamset = 30 // STD192Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-70)
	STD192Q_3_LMKCDEY   BinFHEParamset = 31 // STD192Q_LMKCDEY for 3 binary inputs                             : 2^(-55)
	STD192Q_4_LMKCDEY   BinFHEParamset = 32 // STD192Q_LMKCDEY for 4 binary inputs                             : 2^(-70)
	STD256_LMKCDEY      BinFHEParamset = 33 // STD256 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-50)
	STD256_3_LMKCDEY    BinFHEParamset = 34 // STD256_LMKCDEY for 3 binary inputs                              : 2^(-50)
	STD256_4_LMKCDEY    BinFHEParamset = 35 // STD256_LMKCDEY for 4 binary inputs                              : 2^(-60)
	STD256Q_LMKCDEY     BinFHEParamset = 36 // STD256Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-60)
	STD256Q_3_LMKCDEY   BinFHEParamset = 37 // STD256Q_LMKCDEY for 3 binary inputs                             : 2^(-50)
	STD256Q_4_LMKCDEY   BinFHEParamset = 38 // STD256Q_LMKCDEY for 4 binary inputs                             : 2^(-45)
	LPF_STD128          BinFHEParamset = 39 // STD128 configured with lower probability of failures            : 2^(-220)
	LPF_STD128Q         BinFHEParamset = 40 // STD128Q configured with lower probability of failures           : 2^(-75)
	LPF_STD128_LMKCDEY  BinFHEParamset = 41 // LPF_STD128 optimized for LMKCDEY                                : 2^(-120)
	LPF_STD128Q_LMKCDEY BinFHEParamset = 42 // LPF_STD128Q optimized for LMKCDEY                               : 2^(-120)
	SIGNED_MOD_TEST     BinFHEParamset = 43 // special parameter set for confirming the signed modular reduction in the accumulator updates works correctly : 2^(-40)
)

// BinFHEMethod maps to BINFHE_METHOD enum
type BinFHEMethod int

const (
	INVALID_METHOD BinFHEMethod = 0
	AP             BinFHEMethod = 1 // Ducas-Micciancio variant
	GINX           BinFHEMethod = 2 // Chillotti-Gama-Georgieva-Izabachene variant
	LMKCDEY        BinFHEMethod = 3 // Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo variant, ia.cr/2022/198
)

// BinFHEGate maps to BINGATE enum
type BinFHEGate int

const (
	OR        BinFHEGate = 0
	AND       BinFHEGate = 1
	NOR       BinFHEGate = 2
	NAND      BinFHEGate = 3
	XOR       BinFHEGate = 4
	XNOR      BinFHEGate = 5
	MAJORITY  BinFHEGate = 6
	AND3      BinFHEGate = 7
	OR3       BinFHEGate = 8
	AND4      BinFHEGate = 9
	OR4       BinFHEGate = 10
	XOR_FAST  BinFHEGate = 11
	XNOR_FAST BinFHEGate = 12
	CMUX      BinFHEGate = 13
)

// BinFHEContext is a Go wrapper for the C++ BinFHEContext
type BinFHEContext struct {
	id C.BINFHE_CONTEXT_ID
}

// BinFHESecretKey is a Go wrapper for the C++ LWEPrivateKey
type BinFHESecretKey struct {
	id C.BINFHE_SECRETKEY_ID
}

// BinFHECiphertext is a Go wrapper for the C++ LWECiphertext
type BinFHECiphertext struct {
	id C.BINFHE_CIPHERTEXT_ID
}

// NewBinFHEContext creates a new BinFHEContext.
func NewBinFHEContext() BinFHEContext {
	id := C.BinFHEContext_Create()
	ctx := BinFHEContext{id: id}
	releaseQueue = append(releaseQueue, ctx)
	return ctx
}

// GenerateBinFHEContext sets the parameters for the context.
func (cc *BinFHEContext) GenerateBinFHEContext(paramset BinFHEParamset, method BinFHEMethod) {
	C.BinFHEContext_GenerateBinFHEContext(cc.id, C.BINFHE_PARAMSET_C(paramset), C.BINFHE_METHOD_C(method))
}

// KeyGen generates a new secret key.
func (cc *BinFHEContext) KeyGen() BinFHESecretKey {
	id := C.BinFHEContext_KeyGen(cc.id)
	sk := BinFHESecretKey{id: id}
	releaseQueue = append(releaseQueue, sk)
	return sk
}

// BTKeyGen generates the bootstrapping keys.
func (cc *BinFHEContext) BTKeyGen(sk BinFHESecretKey) {
	C.BinFHEContext_BTKeyGen(cc.id, sk.id)
}

// Encrypt encrypts a single bit (0 or 1).
func (cc *BinFHEContext) Encrypt(sk BinFHESecretKey, message int) BinFHECiphertext {
	id := C.BinFHEContext_Encrypt(cc.id, sk.id, C.int(message))
	ct := BinFHECiphertext{id: id}
	releaseQueue = append(releaseQueue, ct)
	return ct
}

// EvalBinGate evaluates a binary homomorphic gate.
func (cc *BinFHEContext) EvalBinGate(gate BinFHEGate, ct1, ct2 BinFHECiphertext) BinFHECiphertext {
	id := C.BinFHEContext_EvalBinGate(cc.id, C.BINFHE_GATE_C(gate), ct1.id, ct2.id)
	ct := BinFHECiphertext{id: id}
	releaseQueue = append(releaseQueue, ct)
	return ct
}

// Bootstrap refreshes a ciphertext.
func (cc *BinFHEContext) Bootstrap(ct BinFHECiphertext) BinFHECiphertext {
	id := C.BinFHEContext_Bootstrap(cc.id, ct.id)
	newCt := BinFHECiphertext{id: id}
	releaseQueue = append(releaseQueue, newCt)
	return newCt
}

// Decrypt decrypts a ciphertext to a single bit (0 or 1).
func (cc *BinFHEContext) Decrypt(sk BinFHESecretKey, ct BinFHECiphertext) int {
	return int(C.BinFHEContext_Decrypt(cc.id, sk.id, ct.id))
}

// Release methods for memory management
func (cc BinFHEContext) Release() {
	C.ReleaseBinFHEContext(cc.id)
}

func (sk BinFHESecretKey) Release() {
	C.ReleaseBinFHESecretKey(sk.id)
}

func (ct BinFHECiphertext) Release() {
	C.ReleaseBinFHECiphertext(ct.id)
}
