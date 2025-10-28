package openfhe

// #cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/include -I${SRCDIR}/openfhe/include -I${SRCDIR}/openfhe/include/pke -I${SRCDIR}/openfhe/include/core -I${SRCDIR}/openfhe/include/binfhe -I${SRCDIR}/openfhe/include/core/include -I${SRCDIR}/openfhe/include/pke/include
// #include "binfhe_c.h"
import "C"

import (
	"errors"
	"fmt"
)

func lastBinFHEError() error {
	cErr := C.BinFHE_LastError()
	if cErr != nil {
		return errors.New(C.GoString(cErr))
	}
	return errors.New("unknown BinFHE C++ error") // Fallback
}

type BinFHEParamset C.BINFHE_PARAMSET_C

const (
	TOY                 BinFHEParamset = C.BINFHE_PARAMSET_TOY
	MEDIUM              BinFHEParamset = C.BINFHE_PARAMSET_MEDIUM
	STD128_AP           BinFHEParamset = C.BINFHE_PARAMSET_STD128_AP
	STD128              BinFHEParamset = C.BINFHE_PARAMSET_STD128
	STD128_3            BinFHEParamset = C.BINFHE_PARAMSET_STD128_3
	STD128_4            BinFHEParamset = C.BINFHE_PARAMSET_STD128_4
	STD128Q             BinFHEParamset = C.BINFHE_PARAMSET_STD128Q
	STD128Q_3           BinFHEParamset = C.BINFHE_PARAMSET_STD128Q_4
	STD128Q_4           BinFHEParamset = C.BINFHE_PARAMSET_STD128Q_3
	STD192              BinFHEParamset = C.BINFHE_PARAMSET_STD192
	STD192_3            BinFHEParamset = C.BINFHE_PARAMSET_STD192_3
	STD192_4            BinFHEParamset = C.BINFHE_PARAMSET_STD192_4
	STD192Q             BinFHEParamset = C.BINFHE_PARAMSET_STD192Q
	STD192Q_3           BinFHEParamset = C.BINFHE_PARAMSET_STD192Q_3
	STD192Q_4           BinFHEParamset = C.BINFHE_PARAMSET_STD192Q_4
	STD256              BinFHEParamset = C.BINFHE_PARAMSET_STD256
	STD256_3            BinFHEParamset = C.BINFHE_PARAMSET_STD256_3
	STD256_4            BinFHEParamset = C.BINFHE_PARAMSET_STD256_4
	STD256Q             BinFHEParamset = C.BINFHE_PARAMSET_STD256Q
	STD256Q_3           BinFHEParamset = C.BINFHE_PARAMSET_STD256_3
	STD256Q_4           BinFHEParamset = C.BINFHE_PARAMSET_STD256_4
	STD128_LMKCDEY      BinFHEParamset = C.BINFHE_PARAMSET_STD128_LMKCDEY
	STD128_3_LMKCDEY    BinFHEParamset = C.BINFHE_PARAMSET_STD128_3_LMKCDEY
	STD128_4_LMKCDEY    BinFHEParamset = C.BINFHE_PARAMSET_STD128_4_LMKCDEY
	STD128Q_LMKCDEY     BinFHEParamset = C.BINFHE_PARAMSET_STD128Q_LMKCDEY
	STD128Q_3_LMKCDEY   BinFHEParamset = C.BINFHE_PARAMSET_STD128Q_3_LMKCDEY
	STD128Q_4_LMKCDEY   BinFHEParamset = C.BINFHE_PARAMSET_STD128Q_4_LMKCDEY
	STD192_LMKCDEY      BinFHEParamset = C.BINFHE_PARAMSET_STD192_LMKCDEY
	STD192_3_LMKCDEY    BinFHEParamset = C.BINFHE_PARAMSET_STD192_3_LMKCDEY
	STD192_4_LMKCDEY    BinFHEParamset = C.BINFHE_PARAMSET_STD192_4_LMKCDEY
	STD192Q_LMKCDEY     BinFHEParamset = C.BINFHE_PARAMSET_STD192Q_LMKCDEY
	STD192Q_3_LMKCDEY   BinFHEParamset = C.BINFHE_PARAMSET_STD192Q_3_LMKCDEY
	STD192Q_4_LMKCDEY   BinFHEParamset = C.BINFHE_PARAMSET_STD192Q_4_LMKCDEY
	STD256_LMKCDEY      BinFHEParamset = C.BINFHE_PARAMSET_STD256_LMKCDEY
	STD256_3_LMKCDEY    BinFHEParamset = C.BINFHE_PARAMSET_STD256_3_LMKCDEY
	STD256_4_LMKCDEY    BinFHEParamset = C.BINFHE_PARAMSET_STD256_4_LMKCDEY
	STD256Q_LMKCDEY     BinFHEParamset = C.BINFHE_PARAMSET_STD256Q_LMKCDEY
	STD256Q_3_LMKCDEY   BinFHEParamset = C.BINFHE_PARAMSET_STD256Q_3_LMKCDEY
	STD256Q_4_LMKCDEY   BinFHEParamset = C.BINFHE_PARAMSET_STD256Q_4_LMKCDEY
	LPF_STD128          BinFHEParamset = C.BINFHE_PARAMSET_LPF_STD128
	LPF_STD128Q         BinFHEParamset = C.BINFHE_PARAMSET_LPF_STD128Q
	LPF_STD128_LMKCDEY  BinFHEParamset = C.BINFHE_PARAMSET_LPF_STD128_LMKCDEY
	LPF_STD128Q_LMKCDEY BinFHEParamset = C.BINFHE_PARAMSET_LPF_STD128Q_LMKCDEY
	SIGNED_MOD_TEST     BinFHEParamset = C.BINFHE_PARAMSET_SIGNED_MOD_TEST
)

type BinFHEMethod C.BINFHE_METHOD_C

const (
	INVALID_METHOD BinFHEMethod = C.BINFHE_METHOD_INVALID
	AP             BinFHEMethod = C.BINFHE_METHOD_AP
	GINX           BinFHEMethod = C.BINFHE_METHOD_GINX
	LMKCDEY        BinFHEMethod = C.BINFHE_METHOD_LMKCDEY
)

type BinFHEGate C.BINFHE_GATE_C

const (
	OR        BinFHEGate = C.BINGATE_OR
	AND       BinFHEGate = C.BINGATE_AND
	NOR       BinFHEGate = C.BINGATE_NOR
	NAND      BinFHEGate = C.BINGATE_NAND
	XOR       BinFHEGate = C.BINGATE_XOR
	XNOR      BinFHEGate = C.BINGATE_XNOR
	MAJORITY  BinFHEGate = C.BINGATE_MAJORITY
	AND3      BinFHEGate = C.BINGATE_AND3
	OR3       BinFHEGate = C.BINGATE_OR3
	AND4      BinFHEGate = C.BINGATE_AND4
	OR4       BinFHEGate = C.BINGATE_OR4
	XOR_FAST  BinFHEGate = C.BINGATE_XOR_FAST
	XNOR_FAST BinFHEGate = C.BINGATE_XNOR_FAST
	CMUX      BinFHEGate = C.BINGATE_CMUX
)

// --- Wrapper Structs (Use Handles) ---
type (
	BinFHEContext    struct{ h C.BinFHEContextH }
	BinFHESecretKey  struct{ h C.LWESecretKeyH }
	BinFHECiphertext struct{ h C.LWECiphertextH }
)

// --- Context ---
func NewBinFHEContext() (*BinFHEContext, error) {
	cH := C.BinFHEContext_New()
	if cH == nil {
		return nil, lastBinFHEError()
	}

	ctx := &BinFHEContext{h: cH}

	return ctx, nil
}

func (cc *BinFHEContext) Close() {
	if cc.h != nil {
		C.BinFHEContext_Delete(cc.h)
		cc.h = nil
	}
}

func (cc *BinFHEContext) Release() { cc.Close() }

func (cc *BinFHEContext) GenerateBinFHEContext(paramset BinFHEParamset, method BinFHEMethod) error {
	if cc.h == nil {
		return errors.New("BinFHEContext is closed or invalid")
	}

	res := C.BinFHEContext_Generate(cc.h, C.BINFHE_PARAMSET_C(paramset), C.BINFHE_METHOD_C(method))
	if res != C.BIN_OK {
		return lastBinFHEError()
	}

	return nil
}

// --- Keys ---
func (cc *BinFHEContext) KeyGen() (*BinFHESecretKey, error) {
	if cc.h == nil {
		return nil, errors.New("BinFHEContext is closed or invalid")
	}

	var skH C.LWESecretKeyH

	res := C.BinFHEContext_KeyGen(cc.h, &skH)
	if res != C.BIN_OK {
		return nil, lastBinFHEError()
	}

	if skH == nil { // Should not happen if BIN_OK, but check defensively
		return nil, fmt.Errorf("KeyGen returned OK but null handle")
	}

	sk := &BinFHESecretKey{h: skH}
	return sk, nil
}

func (sk *BinFHESecretKey) Close() {
	if sk.h != nil {
		C.LWESecretKey_Delete(sk.h)
		sk.h = nil
	}
}
func (sk *BinFHESecretKey) Release() { sk.Close() }

func (cc *BinFHEContext) BTKeyGen(sk *BinFHESecretKey) error {
	if cc.h == nil {
		return errors.New("BinFHEContext is closed or invalid")
	}

	if sk == nil || sk.h == nil {
		return errors.New("BinFHESecretKey is closed or invalid")
	}

	res := C.BinFHEContext_BTKeyGen(cc.h, sk.h)
	if res != C.BIN_OK {
		return lastBinFHEError()
	}

	return nil
}

// --- Operations ---
func (cc *BinFHEContext) Encrypt(sk *BinFHESecretKey, message int) (*BinFHECiphertext, error) {
	if cc.h == nil {
		return nil, errors.New("BinFHEContext is closed or invalid")
	}

	if sk == nil || sk.h == nil {
		return nil, errors.New("BinFHESecretKey is closed or invalid")
	}

	var ctH C.LWECiphertextH

	res := C.BinFHEContext_Encrypt(cc.h, sk.h, C.int(message), &ctH)
	if res != C.BIN_OK {
		return nil, lastBinFHEError()
	}

	if ctH == nil {
		return nil, fmt.Errorf("Encrypt returned OK but null handle")
	}

	ct := &BinFHECiphertext{h: ctH}

	return ct, nil
}

func (ct *BinFHECiphertext) Close() {
	if ct.h != nil {
		C.LWECiphertext_Delete(ct.h)
		ct.h = nil
	}
}
func (ct *BinFHECiphertext) Release() { ct.Close() }

func (cc *BinFHEContext) EvalBinGate(gate BinFHEGate, ct1, ct2 *BinFHECiphertext) (*BinFHECiphertext, error) {
	if cc.h == nil {
		return nil, errors.New("BinFHEContext is closed or invalid")
	}

	if ct1 == nil || ct1.h == nil {
		return nil, errors.New("first BinFHECiphertext is closed or invalid")
	}

	if ct2 == nil || ct2.h == nil {
		return nil, errors.New("second BinFHECiphertext is closed or invalid")
	}

	var ctOutH C.LWECiphertextH

	res := C.BinFHEContext_EvalBinGate(cc.h, C.BINFHE_GATE_C(gate), ct1.h, ct2.h, &ctOutH)
	if res != C.BIN_OK {
		return nil, lastBinFHEError()
	}

	if ctOutH == nil {
		return nil, fmt.Errorf("EvalBinGate returned OK but null handle")
	}

	ct := &BinFHECiphertext{h: ctOutH}
	return ct, nil
}

func (cc *BinFHEContext) Bootstrap(ctIn *BinFHECiphertext) (*BinFHECiphertext, error) {
	if cc.h == nil {
		return nil, errors.New("BinFHEContext is closed or invalid")
	}

	if ctIn == nil || ctIn.h == nil {
		return nil, errors.New("input BinFHECiphertext is closed or invalid")
	}

	var ctOutH C.LWECiphertextH

	res := C.BinFHEContext_Bootstrap(cc.h, ctIn.h, &ctOutH)
	if res != C.BIN_OK {
		return nil, lastBinFHEError()
	}

	if ctOutH == nil {
		return nil, fmt.Errorf("Bootstrap returned OK but null handle")
	}

	ct := &BinFHECiphertext{h: ctOutH}

	return ct, nil
}

func (cc *BinFHEContext) Decrypt(sk *BinFHESecretKey, ct *BinFHECiphertext) (int, error) {
	if cc.h == nil {
		return 0, errors.New("BinFHEContext is closed or invalid")
	}

	if sk == nil || sk.h == nil {
		return 0, errors.New("BinFHESecretKey is closed or invalid")
	}

	if ct == nil || ct.h == nil {
		return 0, errors.New("BinFHECiphertext is closed or invalid")
	}

	var resultBit C.int

	res := C.BinFHEContext_Decrypt(cc.h, sk.h, ct.h, &resultBit)
	if res != C.BIN_OK {
		return 0, lastBinFHEError()
	}

	return int(resultBit), nil
}
