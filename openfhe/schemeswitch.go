package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include <stdlib.h>
#include "schemeswitch_c.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// BinFHEParamSet represents security levels for BinFHE scheme
type BinFHEParamSet int

const (
	BinFHETOY       BinFHEParamSet = 0
	BinFHEMEDIUM    BinFHEParamSet = 1
	BinFHESTD128_AP BinFHEParamSet = 2
	BinFHESTD128    BinFHEParamSet = 3
	BinFHESTD128_3  BinFHEParamSet = 4
	BinFHESTD128_4  BinFHEParamSet = 5
	BinFHESTD128Q   BinFHEParamSet = 6
	BinFHESTD128Q_3 BinFHEParamSet = 7
	BinFHESTD128Q_4 BinFHEParamSet = 8
	BinFHESTD192    BinFHEParamSet = 9
	BinFHESTD192_3  BinFHEParamSet = 10
	BinFHESTD192_4  BinFHEParamSet = 11
	BinFHESTD192Q   BinFHEParamSet = 12
	BinFHESTD192Q_3 BinFHEParamSet = 13
	BinFHESTD192Q_4 BinFHEParamSet = 14
	BinFHESTD256    BinFHEParamSet = 15
	BinFHESTD256_3  BinFHEParamSet = 16
	BinFHESTD256_4  BinFHEParamSet = 17
	BinFHESTD256Q   BinFHEParamSet = 18
	BinFHESTD256Q_3 BinFHEParamSet = 19
	BinFHESTD256Q_4 BinFHEParamSet = 20
)

// SchSwchParams holds parameters for scheme switching
type SchSwchParams struct {
	ptr C.SchSwchParamsPtr
}

// LWEPrivateKey represents a private key for LWE/BinFHE operations
type LWEPrivateKey struct {
	ptr C.LWEPrivateKeyPtr
}

// LWECiphertext is an alias for BinFHECiphertext for scheme switching
type LWECiphertext = BinFHECiphertext

// --- SchSwchParams Functions ---

// NewSchSwchParams creates a new scheme switching parameters object
func NewSchSwchParams() (*SchSwchParams, error) {
	var pH C.SchSwchParamsPtr
	status := C.NewSchSwchParams(&pH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pH == nil {
		return nil, errors.New("NewSchSwchParams returned OK but null handle")
	}
	return &SchSwchParams{ptr: pH}, nil
}

// SetSecurityLevelCKKS sets the security level for the CKKS cryptocontext
func (p *SchSwchParams) SetSecurityLevelCKKS(level SecurityLevel) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	status := C.SchSwchParams_SetSecurityLevelCKKS(p.ptr, C.OFHESecurityLevel(level))
	return checkPKEErrorMsg(status)
}

// SetSecurityLevelFHEW sets the security level for the FHEW cryptocontext
func (p *SchSwchParams) SetSecurityLevelFHEW(level BinFHEParamSet) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	status := C.SchSwchParams_SetSecurityLevelFHEW(p.ptr, C.BinFHEParamSet(level))
	return checkPKEErrorMsg(status)
}

// SetNumSlotsCKKS sets the number of slots in CKKS encryption
func (p *SchSwchParams) SetNumSlotsCKKS(numSlots uint32) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	status := C.SchSwchParams_SetNumSlotsCKKS(p.ptr, C.uint32_t(numSlots))
	return checkPKEErrorMsg(status)
}

// SetNumValues sets the number of values to switch
func (p *SchSwchParams) SetNumValues(numValues uint32) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	status := C.SchSwchParams_SetNumValues(p.ptr, C.uint32_t(numValues))
	return checkPKEErrorMsg(status)
}

// SetCtxtModSizeFHEWLargePrec sets the ciphertext modulus size for FHEW in large precision
func (p *SchSwchParams) SetCtxtModSizeFHEWLargePrec(ctxtModSize uint32) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	status := C.SchSwchParams_SetCtxtModSizeFHEWLargePrec(p.ptr, C.uint32_t(ctxtModSize))
	return checkPKEErrorMsg(status)
}

// SetComputeArgmin enables/disables argmin computation
func (p *SchSwchParams) SetComputeArgmin(flag bool) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	cFlag := C.int(0)
	if flag {
		cFlag = C.int(1)
	}
	status := C.SchSwchParams_SetComputeArgmin(p.ptr, cFlag)
	return checkPKEErrorMsg(status)
}

// SetUseAltArgmin enables/disables alternative argmin mode
func (p *SchSwchParams) SetUseAltArgmin(flag bool) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	cFlag := C.int(0)
	if flag {
		cFlag = C.int(1)
	}
	status := C.SchSwchParams_SetUseAltArgmin(p.ptr, cFlag)
	return checkPKEErrorMsg(status)
}

// SetArbitraryFunctionEvaluation enables/disables arbitrary function evaluation
func (p *SchSwchParams) SetArbitraryFunctionEvaluation(flag bool) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	cFlag := C.int(0)
	if flag {
		cFlag = C.int(1)
	}
	status := C.SchSwchParams_SetArbitraryFunctionEvaluation(p.ptr, cFlag)
	return checkPKEErrorMsg(status)
}

// SetOneHotEncoding enables/disables one-hot encoding for argmin output
func (p *SchSwchParams) SetOneHotEncoding(flag bool) error {
	if p.ptr == nil {
		return errors.New("SchSwchParams is closed or invalid")
	}
	cFlag := C.int(0)
	if flag {
		cFlag = C.int(1)
	}
	status := C.SchSwchParams_SetOneHotEncoding(p.ptr, cFlag)
	return checkPKEErrorMsg(status)
}

// GetSecurityLevelCKKS returns the security level for CKKS
func (p *SchSwchParams) GetSecurityLevelCKKS() (SecurityLevel, error) {
	if p.ptr == nil {
		return 0, errors.New("SchSwchParams is closed or invalid")
	}
	var level C.OFHESecurityLevel
	status := C.SchSwchParams_GetSecurityLevelCKKS(p.ptr, &level)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return 0, err
	}
	return SecurityLevel(level), nil
}

// GetSecurityLevelFHEW returns the security level for FHEW
func (p *SchSwchParams) GetSecurityLevelFHEW() (BinFHEParamSet, error) {
	if p.ptr == nil {
		return 0, errors.New("SchSwchParams is closed or invalid")
	}
	var level C.BinFHEParamSet
	status := C.SchSwchParams_GetSecurityLevelFHEW(p.ptr, &level)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return 0, err
	}
	return BinFHEParamSet(level), nil
}

// GetNumSlotsCKKS returns the number of slots in CKKS
func (p *SchSwchParams) GetNumSlotsCKKS() (uint32, error) {
	if p.ptr == nil {
		return 0, errors.New("SchSwchParams is closed or invalid")
	}
	var numSlots C.uint32_t
	status := C.SchSwchParams_GetNumSlotsCKKS(p.ptr, &numSlots)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return 0, err
	}
	return uint32(numSlots), nil
}

// GetNumValues returns the number of values
func (p *SchSwchParams) GetNumValues() (uint32, error) {
	if p.ptr == nil {
		return 0, errors.New("SchSwchParams is closed or invalid")
	}
	var numValues C.uint32_t
	status := C.SchSwchParams_GetNumValues(p.ptr, &numValues)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return 0, err
	}
	return uint32(numValues), nil
}

// Close frees the underlying C++ SchSwchParams object
func (p *SchSwchParams) Close() {
	if p.ptr != nil {
		C.DestroySchSwchParams(p.ptr)
		p.ptr = nil
	}
}

// --- LWEPrivateKey Functions ---

// Close frees the underlying C++ LWEPrivateKey object
func (k *LWEPrivateKey) Close() {
	if k.ptr != nil {
		C.DestroyLWEPrivateKey(k.ptr)
		k.ptr = nil
	}
}

// --- CryptoContext Scheme Switching Methods ---

// EvalCKKStoFHEWSetup performs setup for CKKS to FHEW scheme switching
func (cc *CryptoContext) EvalCKKStoFHEWSetup(params *SchSwchParams) (*LWEPrivateKey, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if params == nil || params.ptr == nil {
		return nil, errors.New("SchSwchParams is closed or invalid")
	}

	var keyH C.LWEPrivateKeyPtr
	status := C.CryptoContext_EvalCKKStoFHEWSetup(cc.ptr, params.ptr, &keyH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if keyH == nil {
		return nil, errors.New("EvalCKKStoFHEWSetup returned OK but null handle")
	}

	return &LWEPrivateKey{ptr: keyH}, nil
}

// EvalCKKStoFHEWKeyGen generates keys for CKKS to FHEW scheme switching
func (cc *CryptoContext) EvalCKKStoFHEWKeyGen(keys *KeyPair, lwesk *LWEPrivateKey) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if lwesk == nil || lwesk.ptr == nil {
		return errors.New("LWEPrivateKey is closed or invalid")
	}

	status := C.CryptoContext_EvalCKKStoFHEWKeyGen(cc.ptr, keys.ptr, lwesk.ptr)
	return checkPKEErrorMsg(status)
}

// EvalCKKStoFHEWPrecompute performs precomputation for CKKS to FHEW switching
func (cc *CryptoContext) EvalCKKStoFHEWPrecompute(scale float64) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}

	status := C.CryptoContext_EvalCKKStoFHEWPrecompute(cc.ptr, C.double(scale))
	return checkPKEErrorMsg(status)
}

// EvalCKKStoFHEW transforms a CKKS ciphertext to FHEW ciphertexts
func (cc *CryptoContext) EvalCKKStoFHEW(ct *Ciphertext, numValues uint32) ([]*LWECiphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}

	var outArray *C.LWECiphertextH
	var outLen C.int

	status := C.CryptoContext_EvalCKKStoFHEW(cc.ptr, ct.ptr, C.uint32_t(numValues), &outArray, &outLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	// Convert C array to Go slice
	length := int(outLen)
	if length == 0 {
		return []*LWECiphertext{}, nil
	}

	// Create slice from C array
	cArray := unsafe.Slice(outArray, length)
	result := make([]*LWECiphertext, length)
	for i := 0; i < length; i++ {
		result[i] = &LWECiphertext{h: cArray[i]}
	}

	// Free the array (but not the individual elements)
	C.free(unsafe.Pointer(outArray))

	return result, nil
}

// EvalFHEWtoCKKSSetup performs setup for FHEW to CKKS scheme switching
func (cc *CryptoContext) EvalFHEWtoCKKSSetup(ccLWE *BinFHEContext, numSlots, logQ uint32) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if ccLWE == nil || ccLWE.h == nil {
		return errors.New("BinFHEContext is closed or invalid")
	}

	status := C.CryptoContext_EvalFHEWtoCKKSSetup(cc.ptr, ccLWE.h, C.uint32_t(numSlots), C.uint32_t(logQ))
	return checkPKEErrorMsg(status)
}

// EvalFHEWtoCKKSKeyGen generates keys for FHEW to CKKS scheme switching
func (cc *CryptoContext) EvalFHEWtoCKKSKeyGen(keys *KeyPair, lwesk *LWEPrivateKey) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if lwesk == nil || lwesk.ptr == nil {
		return errors.New("LWEPrivateKey is closed or invalid")
	}

	status := C.CryptoContext_EvalFHEWtoCKKSKeyGen(cc.ptr, keys.ptr, lwesk.ptr)
	return checkPKEErrorMsg(status)
}

// EvalFHEWtoCKKS transforms FHEW ciphertexts to a CKKS ciphertext
func (cc *CryptoContext) EvalFHEWtoCKKS(lweCts []*LWECiphertext, numSlots, p uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if len(lweCts) == 0 {
		return nil, errors.New("LWE ciphertext array is empty")
	}

	// Convert Go slice to C array
	cArray := make([]C.LWECiphertextH, len(lweCts))
	for i, ct := range lweCts {
		if ct == nil || ct.h == nil {
			return nil, errors.New("LWE ciphertext is closed or invalid")
		}
		cArray[i] = ct.h
	}

	var outH C.CiphertextPtr
	status := C.CryptoContext_EvalFHEWtoCKKS(cc.ptr, &cArray[0], C.int(len(cArray)),
		C.uint32_t(numSlots), C.uint32_t(p), &outH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if outH == nil {
		return nil, errors.New("EvalFHEWtoCKKS returned OK but null handle")
	}

	return &Ciphertext{ptr: outH}, nil
}

// EvalFHEWtoCKKSExt transforms FHEW ciphertexts to CKKS with extended control
func (cc *CryptoContext) EvalFHEWtoCKKSExt(lweCts []*LWECiphertext, numSlots, p uint32,
	pmin, pmax float64,
) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if len(lweCts) == 0 {
		return nil, errors.New("LWE ciphertext array is empty")
	}

	// Convert Go slice to C array
	cArray := make([]C.LWECiphertextH, len(lweCts))
	for i, ct := range lweCts {
		if ct == nil || ct.h == nil {
			return nil, errors.New("LWE ciphertext is closed or invalid")
		}
		cArray[i] = ct.h
	}

	var outH C.CiphertextPtr
	status := C.CryptoContext_EvalFHEWtoCKKSExt(cc.ptr, &cArray[0], C.int(len(cArray)),
		C.uint32_t(numSlots), C.uint32_t(p), C.double(pmin), C.double(pmax), &outH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if outH == nil {
		return nil, errors.New("EvalFHEWtoCKKSExt returned OK but null handle")
	}

	return &Ciphertext{ptr: outH}, nil
}

// EvalSchemeSwitchingSetup performs setup for bidirectional scheme switching
func (cc *CryptoContext) EvalSchemeSwitchingSetup(params *SchSwchParams) (*LWEPrivateKey, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if params == nil || params.ptr == nil {
		return nil, errors.New("SchSwchParams is closed or invalid")
	}

	var keyH C.LWEPrivateKeyPtr
	status := C.CryptoContext_EvalSchemeSwitchingSetup(cc.ptr, params.ptr, &keyH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if keyH == nil {
		return nil, errors.New("EvalSchemeSwitchingSetup returned OK but null handle")
	}

	return &LWEPrivateKey{ptr: keyH}, nil
}

// EvalSchemeSwitchingKeyGen generates keys for bidirectional scheme switching
func (cc *CryptoContext) EvalSchemeSwitchingKeyGen(keys *KeyPair, lwesk *LWEPrivateKey) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if lwesk == nil || lwesk.ptr == nil {
		return errors.New("LWEPrivateKey is closed or invalid")
	}

	status := C.CryptoContext_EvalSchemeSwitchingKeyGen(cc.ptr, keys.ptr, lwesk.ptr)
	return checkPKEErrorMsg(status)
}

// GetBinCCForSchemeSwitch retrieves the BinFHE context used for scheme switching
// Note: The returned BinFHEContext is owned by the CKKS CryptoContext and should NOT be closed.
// It will be automatically cleaned up when the CryptoContext is closed.
func (cc *CryptoContext) GetBinCCForSchemeSwitch() (*BinFHEContext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}

	var binCCH C.BinFHEContextH
	status := C.CryptoContext_GetBinCCForSchemeSwitch(cc.ptr, &binCCH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if binCCH == nil {
		return nil, errors.New("GetBinCCForSchemeSwitch returned OK but null handle")
	}

	return &BinFHEContext{h: binCCH}, nil
}

// EvalCompareSwitchPrecompute performs precomputation for comparison via scheme switching
func (cc *CryptoContext) EvalCompareSwitchPrecompute(pLWE uint32, scaleSign float64) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}

	status := C.CryptoContext_EvalCompareSwitchPrecompute(cc.ptr, C.uint32_t(pLWE), C.double(scaleSign))
	return checkPKEErrorMsg(status)
}

// --- Helper Methods for LWEPrivateKey ---

// DecryptLWECiphertext decrypts an LWE ciphertext using the LWEPrivateKey from scheme switching
// This is a convenience method that calls the BinFHE context's decrypt function
func (lwesk *LWEPrivateKey) DecryptLWECiphertext(ccLWE *BinFHEContext, ct *LWECiphertext, p uint64) (uint64, error) {
	if lwesk == nil || lwesk.ptr == nil {
		return 0, errors.New("LWEPrivateKey is closed or invalid")
	}
	if ccLWE == nil || ccLWE.h == nil {
		return 0, errors.New("BinFHEContext is closed or invalid")
	}
	if ct == nil || ct.h == nil {
		return 0, errors.New("LWECiphertext is closed or invalid")
	}

	var result C.uint64_t
	// Convert LWEPrivateKeyPtr to unsafe.Pointer for void* parameter
	status := C.BinFHEContext_DecryptModulusLWEKey(ccLWE.h, unsafe.Pointer(lwesk.ptr), ct.h, C.uint64_t(p), &result)
	err := checkBinFHEErrorMsg(status)
	if err != nil {
		return 0, err
	}

	return uint64(result), nil
}
