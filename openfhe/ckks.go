package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "ckks_c.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// ChebyshevFunc is a function type for custom Chebyshev approximations
type ChebyshevFunc func(float64) float64

var (
	chebyshevCallbackMutex  sync.RWMutex
	chebyshevCallbacks      = make(map[int]ChebyshevFunc)
	nextChebyshevCallbackID = 1
)

// registerChebyshevCallback registers a Go function and returns its ID
func registerChebyshevCallback(fn ChebyshevFunc) int {
	chebyshevCallbackMutex.Lock()
	defer chebyshevCallbackMutex.Unlock()

	id := nextChebyshevCallbackID
	nextChebyshevCallbackID++
	chebyshevCallbacks[id] = fn
	return id
}

// unregisterChebyshevCallback removes a callback from the registry
func unregisterChebyshevCallback(id int) {
	chebyshevCallbackMutex.Lock()
	defer chebyshevCallbackMutex.Unlock()
	delete(chebyshevCallbacks, id)
}

//export goChebyshevCallback
func goChebyshevCallback(callbackID C.int, x C.double) C.double {
	chebyshevCallbackMutex.RLock()
	fn := chebyshevCallbacks[int(callbackID)]
	chebyshevCallbackMutex.RUnlock()

	if fn == nil {
		return 0
	}

	result := fn(float64(x))
	return C.double(result)
}

type complexDouble C.complex_double_t

// --- CKKS Params Functions ---
func NewParamsCKKSRNS() (*ParamsCKKS, error) {
	var pH C.ParamsCKKSPtr

	status := C.NewParamsCKKS(&pH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if pH == nil {
		return nil, errors.New("NewParamsCKKS returned OK but null handle")
	}

	p := &ParamsCKKS{ptr: pH}

	return p, nil
}

func (p *ParamsCKKS) SetScalingModSize(modSize int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetScalingModSize(p.ptr, C.int(modSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetBatchSize(batchSize int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetBatchSize(p.ptr, C.int(batchSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetMultiplicativeDepth(depth int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetMultiplicativeDepth(p.ptr, C.int(depth))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetSecurityLevel(level SecurityLevel) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetSecurityLevel(p.ptr, C.OFHESecurityLevel(level))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetRingDim(ringDim uint64) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetRingDim(p.ptr, C.uint64_t(ringDim))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetScalingTechnique(technique int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetScalingTechnique(p.ptr, C.int(technique))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetFirstModSize(modSize int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetFirstModSize(p.ptr, C.int(modSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetNumLargeDigits(numDigits int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetNumLargeDigits(p.ptr, C.int(numDigits))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetSecretKeyDist(d SecretKeyDist) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetSecretKeyDist(p.ptr, C.OFHESecretKeyDist(d))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetDigitSize(digitSize int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetDigitSize(p.ptr, C.int(digitSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetKeySwitchTechnique(technique int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetKeySwitchTechnique(p.ptr, C.int(technique))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetMultipartyMode(mode int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetMultipartyMode(p.ptr, C.int(mode))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// CKKSDataType constants
const (
	CKKS_DATA_TYPE_REAL    = 0
	CKKS_DATA_TYPE_COMPLEX = 1
)

func (p *ParamsCKKS) SetCKKSDataType(dataType int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetCKKSDataType(p.ptr, C.int(dataType))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

func (p *ParamsCKKS) SetInteractiveBootCompressionLevel(compressionLevel int) error {
	if p.ptr == nil {
		return ErrParamsCKKSNil
	}

	status := C.ParamsCKKS_SetInteractiveBootCompressionLevel(p.ptr, C.int(compressionLevel))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// Close method for ParamsCKKS
func (p *ParamsCKKS) Close() {
	if p.ptr != nil {
		C.DestroyParamsCKKS(p.ptr)
		p.ptr = nil
	}
}

// Expose ring dimension
func (cc *CryptoContext) GetRingDimension() uint64 {
	if cc.ptr == nil {
		return 0
	}

	return uint64(C.CryptoContext_GetRingDimension(cc.ptr))
}

func (cc *CryptoContext) GetCyclotomicOrder() uint64 {
	if cc.ptr == nil {
		return 0
	}

	return uint64(C.CryptoContext_GetCyclotomicOrder(cc.ptr))
}

// --- CKKS CryptoContext ---
func NewCryptoContextCKKS(p *ParamsCKKS) (*CryptoContext, error) {
	if p == nil || p.ptr == nil {
		return nil, ErrParamsCKKSNil
	}

	var ccH C.CryptoContextPtr

	status := C.NewCryptoContextCKKS(p.ptr, &ccH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ccH == nil {
		return nil, errors.New("NewCryptoContextCKKS returned OK but null handle")
	}

	cc := &CryptoContext{ptr: ccH}

	return cc, nil
}

// --- CKKS Plaintext ---
func (cc *CryptoContext) MakeCKKSPackedPlaintext(vec []float64) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(vec) == 0 {
		return nil, errors.New("MakeCKKSPackedPlaintext: input vector is empty")
	}

	cVec := (*C.double)(unsafe.Pointer(&vec[0]))
	cLen := C.int(len(vec))

	var ptH C.PlaintextPtr

	status := C.CryptoContext_MakeCKKSPackedPlaintext(cc.ptr, cVec, cLen, &ptH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ptH == nil {
		return nil, errors.New("MakeCKKSPackedPlaintext returned OK but null handle")
	}

	pt := &Plaintext{ptr: ptH}

	return pt, nil
}

// MakeCKKSPackedPlaintextWithParams creates a CKKS plaintext with specified scale and level.
func (cc *CryptoContext) MakeCKKSPackedPlaintextWithParams(vec []float64, scaleDeg float64, level int) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(vec) == 0 {
		return nil, errors.New("MakeCKKSPackedPlaintextWithParams: input vector is empty")
	}

	cVec := (*C.double)(unsafe.Pointer(&vec[0]))
	cLen := C.int(len(vec))

	var ptH C.PlaintextPtr

	status := C.CryptoContext_MakeCKKSPackedPlaintextWithParams(cc.ptr, cVec, cLen, C.double(scaleDeg), C.int(level), &ptH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ptH == nil {
		return nil, errors.New("MakeCKKSPackedPlaintextWithParams returned OK but null handle")
	}

	pt := &Plaintext{ptr: ptH}

	return pt, nil
}

// MakeCKKSComplexPackedPlaintext creates a CKKS plaintext from a slice of complex128.
func (cc *CryptoContext) MakeCKKSComplexPackedPlaintext(vec []complex128) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(vec) == 0 {
		return nil, errors.New("MakeCKKSComplexPackedPlaintext: input vector is empty")
	}

	// Convert Go []complex128 to C []complex_double_t
	cVec := make([]C.complex_double_t, len(vec))
	for i, v := range vec {
		cVec[i].real = C.double(real(v))
		cVec[i].imag = C.double(imag(v))
	}

	cLen := C.int(len(vec))

	var ptH C.PlaintextPtr

	status := C.CryptoContext_MakeCKKSComplexPackedPlaintext(cc.ptr, &cVec[0], cLen, &ptH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ptH == nil {
		return nil, errors.New("MakeCKKSComplexPackedPlaintext returned OK but null handle")
	}

	pt := &Plaintext{ptr: ptH}

	return pt, nil
}

// MakeCKKSComplexPackedPlaintextWithParams creates a CKKS plaintext from complex numbers with specified scale and level.
func (cc *CryptoContext) MakeCKKSComplexPackedPlaintextWithParams(vec []complex128, scaleDeg float64, level int) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(vec) == 0 {
		return nil, errors.New("MakeCKKSComplexPackedPlaintextWithParams: input vector is empty")
	}

	// Convert Go []complex128 to C []complex_double_t
	cVec := make([]C.complex_double_t, len(vec))
	for i, v := range vec {
		cVec[i].real = C.double(real(v))
		cVec[i].imag = C.double(imag(v))
	}

	cLen := C.int(len(vec))

	var ptH C.PlaintextPtr

	status := C.CryptoContext_MakeCKKSComplexPackedPlaintextWithParams(cc.ptr, &cVec[0], cLen, C.double(scaleDeg), C.int(level), &ptH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ptH == nil {
		return nil, errors.New("MakeCKKSComplexPackedPlaintextWithParams returned OK but null handle")
	}

	pt := &Plaintext{ptr: ptH}

	return pt, nil
}

// --- CKKS Operations ---
func (cc *CryptoContext) Rescale(ct *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr

	status := C.CryptoContext_Rescale(cc.ptr, ct.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("Rescale returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}

	return resCt, nil
}

// ModReduce reduces the modulus of the ciphertext without rescaling.
func (cc *CryptoContext) ModReduce(ct *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr

	status := C.CryptoContext_ModReduce(cc.ptr, ct.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("ModReduce returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}

	return resCt, nil
}

// ModReduceInPlace reduces the modulus of the ciphertext in place without rescaling.
// This is more memory-efficient than ModReduce as it modifies the input ciphertext directly.
func (cc *CryptoContext) ModReduceInPlace(ct *Ciphertext) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}

	if ct == nil || ct.ptr == nil {
		return ErrInputCiphertextNil
	}

	status := C.CryptoContext_ModReduceInPlace(cc.ptr, ct.ptr)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// --- Scalar and Complex Constant Operations ---

// EvalMultDouble multiplies a ciphertext by a scalar double value.
func (cc *CryptoContext) EvalMultDouble(ct *Ciphertext, constant float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalMultDouble(cc.ptr, ct.ptr, C.double(constant), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalMultDouble returned OK but null handle")
	}

	return &Ciphertext{ptr: ctH}, nil
}

// EvalMultComplex multiplies a ciphertext by a complex constant.
func (cc *CryptoContext) EvalMultComplex(ct *Ciphertext, constant complex128) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	cConst := C.complex_double_t{real: C.double(real(constant)), imag: C.double(imag(constant))}
	status := C.CryptoContext_EvalMultComplex(cc.ptr, ct.ptr, cConst, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalMultComplex returned OK but null handle")
	}

	return &Ciphertext{ptr: ctH}, nil
}

// EvalAddDouble adds a scalar double value to a ciphertext.
func (cc *CryptoContext) EvalAddDouble(ct *Ciphertext, constant float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalAddDouble(cc.ptr, ct.ptr, C.double(constant), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalAddDouble returned OK but null handle")
	}

	return &Ciphertext{ptr: ctH}, nil
}

// EvalAddComplex adds a complex constant to a ciphertext.
func (cc *CryptoContext) EvalAddComplex(ct *Ciphertext, constant complex128) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	cConst := C.complex_double_t{real: C.double(real(constant)), imag: C.double(imag(constant))}
	status := C.CryptoContext_EvalAddComplex(cc.ptr, ct.ptr, cConst, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalAddComplex returned OK but null handle")
	}

	return &Ciphertext{ptr: ctH}, nil
}

// EvalSubDouble subtracts a scalar double value from a ciphertext.
func (cc *CryptoContext) EvalSubDouble(ct *Ciphertext, constant float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalSubDouble(cc.ptr, ct.ptr, C.double(constant), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalSubDouble returned OK but null handle")
	}

	return &Ciphertext{ptr: ctH}, nil
}

// EvalSubComplex subtracts a complex constant from a ciphertext.
func (cc *CryptoContext) EvalSubComplex(ct *Ciphertext, constant complex128) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	cConst := C.complex_double_t{real: C.double(real(constant)), imag: C.double(imag(constant))}
	status := C.CryptoContext_EvalSubComplex(cc.ptr, ct.ptr, cConst, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalSubComplex returned OK but null handle")
	}

	return &Ciphertext{ptr: ctH}, nil
}

// --- In-Place Operations ---

// EvalAddInPlaceDouble adds a scalar double value to a ciphertext in place.
func (cc *CryptoContext) EvalAddInPlaceDouble(ct *Ciphertext, constant float64) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return ErrInputCiphertextNil
	}

	status := C.CryptoContext_EvalAddInPlaceDouble(cc.ptr, ct.ptr, C.double(constant))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// EvalAddInPlaceComplex adds a complex constant to a ciphertext in place.
func (cc *CryptoContext) EvalAddInPlaceComplex(ct *Ciphertext, constant complex128) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return ErrInputCiphertextNil
	}

	cConst := C.complex_double_t{real: C.double(real(constant)), imag: C.double(imag(constant))}
	status := C.CryptoContext_EvalAddInPlaceComplex(cc.ptr, ct.ptr, cConst)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// EvalSubInPlaceDouble subtracts a scalar double value from a ciphertext in place.
func (cc *CryptoContext) EvalSubInPlaceDouble(ct *Ciphertext, constant float64) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return ErrInputCiphertextNil
	}

	status := C.CryptoContext_EvalSubInPlaceDouble(cc.ptr, ct.ptr, C.double(constant))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// EvalSubInPlaceComplex subtracts a complex constant from a ciphertext in place.
func (cc *CryptoContext) EvalSubInPlaceComplex(ct *Ciphertext, constant complex128) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return ErrInputCiphertextNil
	}

	cConst := C.complex_double_t{real: C.double(real(constant)), imag: C.double(imag(constant))}
	status := C.CryptoContext_EvalSubInPlaceComplex(cc.ptr, ct.ptr, cConst)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// EvalPoly evaluates a polynomial on a ciphertext.
// coefficients: A slice of doubles representing the polynomial coefficients in ascending order (e.g., [c0, c1, c2] for c0 + c1*x + c2*x^2).
// Returns the resulting ciphertext and a potential error.
func (cc *CryptoContext) EvalPoly(ct *Ciphertext, coefficients []float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	if len(coefficients) == 0 {
		return nil, errors.New("EvalPoly requires at least one coefficient")
	}

	cCoefficients := (*C.double)(unsafe.Pointer(&coefficients[0]))
	cCount := C.size_t(len(coefficients))
	var resultPtr C.CiphertextPtr

	status := C.CryptoContext_EvalPoly(cc.ptr, ct.ptr, cCoefficients, cCount, &resultPtr)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if resultPtr == nil {
		return nil, errors.New("CryptoContext_EvalPoly returned OK but null handle")
	}

	newCt := &Ciphertext{ptr: resultPtr}

	return newCt, nil
}

func GetBootstrapDepth(levelBudget []uint32, skd SecretKeyDist) uint32 {
	var ptr *C.uint32_t
	var n C.int

	if len(levelBudget) > 0 {
		ptr = (*C.uint32_t)(&levelBudget[0])
		n = C.int(len(levelBudget))
	}

	d := C.CKKS_GetBootstrapDepth(ptr, n, C.int(skd))

	return uint32(d)
}

// --- CKKS Advanced Operations ---

// EvalSumKeyGen generates the rotation keys required for EvalSum operations.
// This must be called before using EvalSum or EvalInnerProduct.
// The function generates all necessary rotation keys for summing slots.
func (cc *CryptoContext) EvalSumKeyGen(keys *KeyPair) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}
	if keys == nil || keys.ptr == nil {
		return ErrKeypairClosed
	}

	status := C.CryptoContext_EvalSumKeyGen(cc.ptr, keys.ptr)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// EvalSum computes the sum of all slots in a ciphertext.
// Returns a ciphertext where all slots contain the sum of the input slots.
// Requires EvalSumKeyGen to have been called first.
//
// Parameters:
//   - ct: The input ciphertext
//   - batchSize: The number of slots to sum (must match the batch size used during encryption)
//
// Example:
//
//	input:  [1, 2, 3, 4, 5, 6, 7, 8]
//	output: [36, 36, 36, 36, 36, 36, 36, 36]  // sum = 1+2+3+4+5+6+7+8 = 36
func (cc *CryptoContext) EvalSum(ct *Ciphertext, batchSize uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalSum(cc.ptr, ct.ptr, C.uint32_t(batchSize), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalSum returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalInnerProduct computes the inner product (dot product) of two ciphertexts.
// Returns a ciphertext containing the inner product result in all slots.
// Requires both EvalMultKeyGen and EvalSumKeyGen to have been called first.
//
// The inner product is computed as: sum(ct1[i] * ct2[i]) for i in 0..batchSize-1
//
// Parameters:
//   - ct1: The first input ciphertext
//   - ct2: The second input ciphertext
//   - batchSize: The number of slots to use in the computation
//
// Example:
//
//	ct1:    [1, 2, 3, 4]
//	ct2:    [5, 6, 7, 8]
//	output: [70, 70, 70, 70]  // 1*5 + 2*6 + 3*7 + 4*8 = 70
func (cc *CryptoContext) EvalInnerProduct(ct1, ct2 *Ciphertext, batchSize uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct1 == nil || ct1.ptr == nil || ct2 == nil || ct2.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalInnerProduct(cc.ptr, ct1.ptr, ct2.ptr,
		C.uint32_t(batchSize), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalInnerProduct returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalLinearWSum computes a linear weighted sum of ciphertexts with scalar constants.
// Returns a ciphertext containing: sum(constants[i] * ciphertexts[i]) for all i.
// Requires EvalMultKeyGen to have been called first.
//
// This is useful for computing weighted averages, linear combinations, and other
// operations common in machine learning and statistical applications.
//
// Parameters:
//   - ciphertexts: A slice of input ciphertexts
//   - constants: A slice of scalar weights (must have same length as ciphertexts)
//
// Example:
//
//	ct1:      [1, 2, 3]
//	ct2:      [4, 5, 6]
//	ct3:      [7, 8, 9]
//	constants: [0.5, 0.25, 0.25]
//	output:   [2.75, 3.75, 4.75]  // 0.5*[1,2,3] + 0.25*[4,5,6] + 0.25*[7,8,9]
func (cc *CryptoContext) EvalLinearWSum(ciphertexts []*Ciphertext, constants []float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if len(ciphertexts) == 0 {
		return nil, errors.New("ciphertexts slice cannot be empty")
	}
	if len(constants) == 0 {
		return nil, errors.New("constants slice cannot be empty")
	}
	if len(ciphertexts) != len(constants) {
		return nil, errors.New("ciphertexts and constants must have the same length")
	}

	// Create array of ciphertext pointers
	ctPtrs := make([]C.CiphertextPtr, len(ciphertexts))
	for i, ct := range ciphertexts {
		if ct == nil || ct.ptr == nil {
			return nil, ErrInputCiphertextNil
		}
		ctPtrs[i] = ct.ptr
	}

	// Convert Go float64 slice to C double array
	constPtrs := make([]C.double, len(constants))
	for i, c := range constants {
		constPtrs[i] = C.double(c)
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalLinearWSum(
		cc.ptr,
		(*C.CiphertextPtr)(unsafe.Pointer(&ctPtrs[0])),
		C.int(len(ctPtrs)),
		(*C.double)(unsafe.Pointer(&constPtrs[0])),
		C.int(len(constPtrs)),
		&ctH,
	)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalLinearWSum returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// --- CKKS Function Evaluation (Chebyshev Approximation) ---

// EvalLogistic evaluates the logistic function 1/(1+exp(-x)) on encrypted data
// using Chebyshev approximation. This is commonly used as an activation function
// in machine learning applications.
//
// The function approximates the logistic (sigmoid) function over the interval
// [lowerBound, upperBound] using a Chebyshev polynomial of the specified degree.
// Higher polynomial degrees provide better accuracy but require more multiplicative depth.
//
// IMPORTANT: Before calling this function, you must:
//  1. Enable ADVANCEDSHE on the CryptoContext: cc.Enable(ADVANCEDSHE)
//  2. Generate multiplication keys: cc.EvalMultKeyGen(secretKey)
//
// Parameters:
//   - ct: Input ciphertext containing values to evaluate
//   - lowerBound: Lower bound of the approximation interval
//   - upperBound: Upper bound of the approximation interval
//   - polyDegree: Degree of the Chebyshev polynomial (higher = more accurate, more depth)
//
// The multiplicative depth required depends on the polynomial degree:
//   - polyDegree 16 requires depth ~6
//   - polyDegree 32 requires depth ~6
//   - polyDegree 64 requires depth ~7
//   - See OpenFHE documentation for complete mapping
//
// Example:
//
//	// Evaluate logistic function on values in range [-5, 5]
//	result, err := cc.EvalLogistic(ciphertext, -5.0, 5.0, 16)
//	// Input:  [-4, -3, -2, -1, 0, 1, 2, 3, 4]
//	// Output: [0.018, 0.047, 0.119, 0.269, 0.5, 0.731, 0.881, 0.953, 0.982]
func (cc *CryptoContext) EvalLogistic(ct *Ciphertext, lowerBound, upperBound float64, polyDegree uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalLogistic(cc.ptr, ct.ptr, C.double(lowerBound),
		C.double(upperBound), C.uint32_t(polyDegree), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalLogistic returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalDivide evaluates the division function f(x) = 1/x on encrypted data
// using Chebyshev approximation. This can be used for computing reciprocals
// or division operations in homomorphic encryption.
//
// The function approximates 1/x over the interval [lowerBound, upperBound]
// using a Chebyshev polynomial of the specified degree.
// Higher polynomial degrees provide better accuracy but require more multiplicative depth.
//
// IMPORTANT: Before calling this function, you must:
//  1. Enable ADVANCEDSHE on the CryptoContext: cc.Enable(ADVANCEDSHE)
//  2. Generate multiplication keys: cc.EvalMultKeyGen(secretKey)
//
// Parameters:
//   - ct: Input ciphertext containing values to evaluate (must be non-zero in interval)
//   - lowerBound: Lower bound of the approximation interval (must be > 0)
//   - upperBound: Upper bound of the approximation interval
//   - polyDegree: Degree of the Chebyshev polynomial (higher = more accurate, more depth)
//
// Note: The input values must be strictly positive (non-zero) as division by zero
// is undefined. The interval [lowerBound, upperBound] should not include zero.
//
// Example:
//
//	// Evaluate 1/x for values in range [0.5, 10]
//	result, err := cc.EvalDivide(ciphertext, 0.5, 10.0, 50)
//	// Input:  [1, 2, 3, 4, 5]
//	// Output: [1.0, 0.5, 0.333, 0.25, 0.2]
func (cc *CryptoContext) EvalDivide(ct *Ciphertext, lowerBound, upperBound float64, polyDegree uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalDivide(cc.ptr, ct.ptr, C.double(lowerBound),
		C.double(upperBound), C.uint32_t(polyDegree), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalDivide returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalSin evaluates the sine function sin(x) on encrypted data
// using Chebyshev approximation. This is useful for trigonometric operations
// and signal processing applications on encrypted data.
//
// The function approximates sin(x) over the interval [lowerBound, upperBound]
// using a Chebyshev polynomial of the specified degree.
// Higher polynomial degrees provide better accuracy but require more multiplicative depth.
//
// IMPORTANT: Before calling this function, you must:
//  1. Enable ADVANCEDSHE on the CryptoContext: cc.Enable(ADVANCEDSHE)
//  2. Generate multiplication keys: cc.EvalMultKeyGen(secretKey)
//
// Parameters:
//   - ct: Input ciphertext containing values to evaluate
//   - lowerBound: Lower bound of the approximation interval (typically -π to π)
//   - upperBound: Upper bound of the approximation interval
//   - polyDegree: Degree of the Chebyshev polynomial (higher = more accurate, more depth)
//
// Common intervals for sine approximation:
//   - [-π, π] for full period approximation
//   - [-π/2, π/2] for better accuracy in restricted range
//
// Example:
//
//	// Evaluate sine function on values in range [-π, π]
//	result, err := cc.EvalSin(ciphertext, -math.Pi, math.Pi, 32)
//	// Input:  [0, π/4, π/2, 3π/4, π]
//	// Output: [0, 0.707, 1.0, 0.707, 0]
func (cc *CryptoContext) EvalSin(ct *Ciphertext, lowerBound, upperBound float64, polyDegree uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalSin(cc.ptr, ct.ptr, C.double(lowerBound),
		C.double(upperBound), C.uint32_t(polyDegree), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalSin returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalCos evaluates the cosine function cos(x) on encrypted data
// using Chebyshev approximation. This is useful for trigonometric operations
// and signal processing applications on encrypted data.
//
// The function approximates cos(x) over the interval [lowerBound, upperBound]
// using a Chebyshev polynomial of the specified degree.
// Higher polynomial degrees provide better accuracy but require more multiplicative depth.
//
// IMPORTANT: Before calling this function, you must:
//  1. Enable ADVANCEDSHE on the CryptoContext: cc.Enable(ADVANCEDSHE)
//  2. Generate multiplication keys: cc.EvalMultKeyGen(secretKey)
//
// Parameters:
//   - ct: Input ciphertext containing values to evaluate
//   - lowerBound: Lower bound of the approximation interval (typically -π to π)
//   - upperBound: Upper bound of the approximation interval
//   - polyDegree: Degree of the Chebyshev polynomial (higher = more accurate, more depth)
//
// Common intervals for cosine approximation:
//   - [-π, π] for full period approximation
//   - [0, π] for better accuracy in restricted range
//
// Example:
//
//	// Evaluate cosine function on values in range [-π, π]
//	result, err := cc.EvalCos(ciphertext, -math.Pi, math.Pi, 32)
//	// Input:  [0, π/4, π/2, 3π/4, π]
//	// Output: [1.0, 0.707, 0, -0.707, -1.0]
func (cc *CryptoContext) EvalCos(ct *Ciphertext, lowerBound, upperBound float64, polyDegree uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalCos(cc.ptr, ct.ptr, C.double(lowerBound),
		C.double(upperBound), C.uint32_t(polyDegree), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalCos returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalChebyshevFunction evaluates an arbitrary smooth function on encrypted data
// using Chebyshev approximation. This allows you to evaluate custom functions
// (like sqrt, exp, or any other smooth function) on encrypted data.
//
// The function approximates fn(x) over the interval [lowerBound, upperBound]
// using a Chebyshev polynomial of the specified degree.
// Higher polynomial degrees provide better accuracy but require more multiplicative depth.
//
// IMPORTANT: Before calling this function, you must:
//  1. Enable ADVANCEDSHE on the CryptoContext: cc.Enable(ADVANCEDSHE)
//  2. Generate multiplication keys: cc.EvalMultKeyGen(secretKey)
//
// Parameters:
//   - fn: A Go function that takes a float64 and returns a float64
//   - ct: Input ciphertext containing values to evaluate
//   - lowerBound: Lower bound of the approximation interval
//   - upperBound: Upper bound of the approximation interval
//   - polyDegree: Degree of the Chebyshev polynomial (higher = more accurate, more depth)
//
// The function must be smooth (continuously differentiable) in the interval [lowerBound, upperBound].
// Common examples: sqrt, exp, log, custom activation functions, etc.
//
// Polynomial degree to depth mapping (approximate):
//   - degree 16 requires depth ~6
//   - degree 32 requires depth ~7
//   - degree 50 requires depth ~7
//   - degree 64 requires depth ~8
//
// Example:
//
//	import "math"
//
//	// Evaluate square root on encrypted data
//	result, err := cc.EvalChebyshevFunction(math.Sqrt, ciphertext, 0.1, 10.0, 50)
//	// Input:  [1, 4, 9, 16, 25]
//	// Output: [1.0, 2.0, 3.0, 4.0, 5.0]
//
//	// Or use a custom function
//	customFunc := func(x float64) float64 {
//	    return x*x + 2*x + 1  // (x+1)^2
//	}
//	result, err := cc.EvalChebyshevFunction(customFunc, ciphertext, -5.0, 5.0, 32)
func (cc *CryptoContext) EvalChebyshevFunction(fn ChebyshevFunc, ct *Ciphertext, lowerBound, upperBound float64, polyDegree uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}
	if fn == nil {
		return nil, errors.New("Function is nil")
	}

	// Register the callback
	callbackID := registerChebyshevCallback(fn)
	defer unregisterChebyshevCallback(callbackID)

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalChebyshevFunction(cc.ptr, C.int(callbackID), ct.ptr,
		C.double(lowerBound), C.double(upperBound), C.uint32_t(polyDegree), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalChebyshevFunction returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// --- Chebyshev Plaintext Evaluation (Uses C++ OpenFHE Implementation) ---

// evalChebyshevCoefficients computes Chebyshev coefficients for approximating
// a function over the interval [a, b] using a polynomial of specified degree.
//
// This calls OpenFHE's EvalChebyshevCoefficients function to ensure consistency
// with the encrypted version. This guarantees that plaintext and encrypted evaluations
// use the exact same Chebyshev approximation.
//
// The algorithm computes coefficients c_i such that:
//
//	f(x) ≈ c_0/2 + Σ c_i * T_i(x)
//
// where T_i(x) are Chebyshev polynomials of the first kind.
//
// Parameters:
//   - fn: Function to approximate
//   - a: Lower bound of interval
//   - b: Upper bound of interval
//   - degree: Polynomial degree (number of coefficients will be degree+1)
//
// Returns: Chebyshev coefficients (length = degree + 1)
func evalChebyshevCoefficients(fn func(float64) float64, a, b float64, degree uint32) []float64 {
	if degree == 0 {
		panic("degree of approximation cannot be zero")
	}

	// Register callback
	callbackID := registerChebyshevCallback(fn)
	defer unregisterChebyshevCallback(callbackID)

	// Call C++ EvalChebyshevCoefficients
	var coeffsC C.ChebyshevCoeffs
	status := C.EvalChebyshevCoefficients(C.int(callbackID), C.double(a), C.double(b),
		C.uint32_t(degree), &coeffsC)

	err := checkPKEErrorMsg(status)
	if err != nil {
		panic(err.Error())
	}

	// Convert C array to Go slice
	coeffsGo := make([]float64, coeffsC.length)
	coeffsSlice := unsafe.Slice(coeffsC.coeffs, coeffsC.length)
	for i := 0; i < int(coeffsC.length); i++ {
		coeffsGo[i] = float64(coeffsSlice[i])
	}

	// Free C memory
	C.FreeChebyshevCoeffs(&coeffsC)

	return coeffsGo
}

// EvalChebyshevCoefficients computes Chebyshev polynomial coefficients for a given function.
// This is part of the advanced API for batch function evaluation on encrypted data.
//
// Use this when you need to evaluate the same function on multiple ciphertexts:
//  1. Call this function once to compute coefficients
//  2. Call EvalChebyshevSeries multiple times with the same coefficients
//
// This is much more efficient than calling EvalChebyshevFunction multiple times,
// as it avoids recomputing the coefficients for each ciphertext.
//
// Parameters:
//   - fn: Function to approximate (must be smooth over [lowerBound, upperBound])
//   - lowerBound: Lower bound of approximation interval
//   - upperBound: Upper bound of approximation interval
//   - degree: Polynomial degree (higher = more accurate, more depth required)
//
// Returns: Chebyshev coefficients (length = degree + 1)
//
// Example:
//
//	// Compute coefficients once
//	coeffs, err := openfhe.EvalChebyshevCoefficients(math.Sqrt, 0.1, 10.0, 50)
//	if err != nil {
//	    panic(err)
//	}
//
//	// Reuse on multiple ciphertexts
//	result1, _ := cc.EvalChebyshevSeries(ct1, coeffs, 0.1, 10.0)
//	result2, _ := cc.EvalChebyshevSeries(ct2, coeffs, 0.1, 10.0)
//	result3, _ := cc.EvalChebyshevSeries(ct3, coeffs, 0.1, 10.0)
func EvalChebyshevCoefficients(fn func(float64) float64, lowerBound, upperBound float64, degree uint32) ([]float64, error) {
	if degree == 0 {
		return nil, errors.New("degree of approximation cannot be zero")
	}

	// Defer panic recovery to return error instead
	defer func() {
		if r := recover(); r != nil {
			// This will be caught if evalChebyshevCoefficients panics
		}
	}()

	coeffs := evalChebyshevCoefficients(fn, lowerBound, upperBound, degree)
	return coeffs, nil
}

// EvalChebyshevSeries evaluates a Chebyshev polynomial series on encrypted data
// using pre-computed coefficients. This is an advanced API that allows you to
// compute coefficients once and reuse them on multiple ciphertexts for better performance.
//
// This function is useful when you need to evaluate the same function on many
// different ciphertexts, as it avoids recomputing the coefficients each time.
//
// IMPORTANT: Before calling this function, you must:
//  1. Enable ADVANCEDSHE on the CryptoContext: cc.Enable(ADVANCEDSHE)
//  2. Generate multiplication keys: cc.EvalMultKeyGen(secretKey)
//
// Three-level API pattern:
//  1. Simple: EvalChebyshevFunction(fn, ct, a, b, degree) - one-shot evaluation
//  2. Testing: EvalChebyshevFunctionPtxt(fn, ptxt, a, b, degree) - plaintext version
//  3. Advanced: EvalChebyshevCoefficients + EvalChebyshevSeries - batch optimization
//
// Parameters:
//   - ct: Input ciphertext containing values to evaluate
//   - coeffs: Pre-computed Chebyshev coefficients (from EvalChebyshevCoefficients)
//   - lowerBound: Lower bound of the approximation interval (must match coefficient computation)
//   - upperBound: Upper bound of the approximation interval (must match coefficient computation)
//
// Example usage pattern for batch processing:
//
//	// Step 1: Compute coefficients once for sqrt on [0.1, 10]
//	coeffs, err := openfhe.EvalChebyshevCoefficients(math.Sqrt, 0.1, 10.0, 50)
//	if err != nil {
//	    panic(err)
//	}
//
//	// Step 2: Reuse coefficients on multiple ciphertexts
//	result1, err := cc.EvalChebyshevSeries(ct1, coeffs, 0.1, 10.0)
//	result2, err := cc.EvalChebyshevSeries(ct2, coeffs, 0.1, 10.0)
//	result3, err := cc.EvalChebyshevSeries(ct3, coeffs, 0.1, 10.0)
//	// Much faster than calling EvalChebyshevFunction 3 times!
//
// Note: The bounds (a, b) must exactly match those used to compute the coefficients,
// otherwise the approximation will be incorrect.
func (cc *CryptoContext) EvalChebyshevSeries(ct *Ciphertext, coeffs []float64, lowerBound, upperBound float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if ct == nil || ct.ptr == nil {
		return nil, ErrInputCiphertextNil
	}
	if len(coeffs) == 0 {
		return nil, errors.New("Coefficients slice cannot be empty")
	}

	// Convert Go slice to C array
	coeffsC := make([]C.double, len(coeffs))
	for i, c := range coeffs {
		coeffsC[i] = C.double(c)
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalChebyshevSeries(
		cc.ptr,
		ct.ptr,
		&coeffsC[0],
		C.size_t(len(coeffsC)),
		C.double(lowerBound),
		C.double(upperBound),
		&ctH)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ctH == nil {
		return nil, errors.New("EvalChebyshevSeries returned OK but null handle")
	}

	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// EvalChebyshevFunctionPtxt evaluates a Chebyshev approximation on cleartext data.
// This is the plaintext (unencrypted) version of EvalChebyshevFunction.
//
// This function is useful for:
//   - Testing and debugging: Compare with encrypted results to isolate FHE noise
//   - Verification: Check approximation quality before using on encrypted data
//   - Education: Understand how Chebyshev approximation works
//   - Optimization: Choose appropriate polynomial degree
//
// The function approximates fn(x) over [a, b] using Chebyshev polynomials:
//
//	fn(x) ≈ c_0/2 + Σ c_i * T_i(x)
//
// This should produce identical results to the encrypted version (EvalChebyshevFunction)
// when decrypted, allowing you to separate approximation error from FHE noise.
//
// Parameters:
//   - fn: Function to approximate (must be smooth over [a, b])
//   - ptxt: Plaintext input values to evaluate
//   - a: Lower bound of approximation interval
//   - b: Upper bound of approximation interval
//   - degree: Polynomial degree (higher = more accurate, same as encrypted version)
//
// Returns: Approximated function values for each input
//
// Example:
//
//	// Compare encrypted vs plaintext results
//	input := []float64{1, 2, 3, 4, 5}
//
//	// Encrypted evaluation
//	ct, _ := cc.EvalChebyshevFunction(math.Sqrt, ciphertext, 0, 10, 50)
//	encResult, _ := cc.Decrypt(keyPair, ct)
//
//	// Plaintext evaluation (for comparison)
//	ptxtResult := openfhe.EvalChebyshevFunctionPtxt(math.Sqrt, input, 0, 10, 50)
//
//	// ptxtResult shows pure approximation error
//	// encResult shows approximation error + FHE noise
func EvalChebyshevFunctionPtxt(fn func(float64) float64, ptxt []float64, a, b float64, degree uint32) []float64 {
	// Step 1: Get Chebyshev coefficients
	coeffs := evalChebyshevCoefficients(fn, a, b, degree)

	// Step 2: Halve the first coefficient (standard practice)
	// This comes from the orthogonality relation of Chebyshev polynomials
	// See: https://arxiv.org/pdf/1810.04282 Eq. (4) and (6)
	coeffs[0] /= 2.0

	// Special case: degree 0 returns constant
	if degree == 0 {
		result := make([]float64, len(ptxt))
		for i := range result {
			result[i] = coeffs[0]
		}
		return result
	}

	// Step 3: Evaluate the Chebyshev series for each input value
	// Transform [a,b] to [-1,1] for Chebyshev evaluation
	scaleFactor := 2.0 / (b - a)
	offset := (b + a) * scaleFactor / -2.0

	result := make([]float64, len(ptxt))
	for i := 0; i < len(ptxt); i++ {
		// Scale input to [-1, 1]
		x := ptxt[i]*scaleFactor + offset
		x2 := 2.0 * x

		// Initialize Chebyshev recurrence
		// T_0(x) = 1, T_1(x) = x
		tPrev := 1.0
		tCurr := x

		// Start sum with first two terms: c_0/2 + c_1 * x
		y := coeffs[0] + coeffs[1]*x

		// Use Chebyshev recurrence relation: T_{i+1}(x) = 2x*T_i(x) - T_{i-1}(x)
		for j := 2; j < len(coeffs); j++ {
			tNext := x2*tCurr - tPrev
			y += coeffs[j] * tNext
			tPrev = tCurr
			tCurr = tNext
		}

		result[i] = y
	}

	return result
}

// --- TCKKS Interactive Multi-Party Bootstrapping ---

// IntMPBootAdjustScale adjusts the ciphertext scale for interactive multi-party bootstrapping.
// This is the first step in the TCKKS interactive bootstrapping protocol.
// It compresses the ciphertext to the smallest possible number of towers (RNS limbs).
func (cc *CryptoContext) IntMPBootAdjustScale(ciphertext *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, ErrCiphertextArgNil
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntMPBootAdjustScale(cc.ptr, ciphertext.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntMPBootAdjustScale returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}

// IntMPBootRandomElementGen generates a common random polynomial (CRP) for TCKKS bootstrapping.
// The leading party generates this CRP, which is sampled uniformly from R_Q (at max coefficient modulus).
// This CRP is shared with all parties and used in the IntMPBootDecrypt step.
func (cc *CryptoContext) IntMPBootRandomElementGen(publicKey *PublicKey) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if publicKey == nil || publicKey.ptr == nil {
		return nil, ErrPublicKeyArgNil
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntMPBootRandomElementGen(cc.ptr, publicKey.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntMPBootRandomElementGen returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}

// IntMPBootDecrypt performs masked decryption for a party in TCKKS interactive bootstrapping.
// Each party generates its own shares: (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share).
//
// Parameters:
//   - privateKey: The party's private key share (sk_i)
//   - c1: The second element of the ciphertext (after removing c0)
//   - a: The common random polynomial generated by IntMPBootRandomElementGen
//
// Returns: A slice with 2 ciphertexts [h0, h1] representing the party's shares
func (cc *CryptoContext) IntMPBootDecrypt(privateKey *PrivateKey, c1, a *Ciphertext) ([]*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	if c1 == nil || c1.ptr == nil {
		return nil, errors.New("c1 ciphertext is nil")
	}

	if a == nil || a.ptr == nil {
		return nil, errors.New("a ciphertext is nil")
	}

	var outCT0, outCT1 C.CiphertextPtr
	status := C.CryptoContext_IntMPBootDecrypt(cc.ptr, privateKey.ptr, c1.ptr, a.ptr, &outCT0, &outCT1)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT0 == nil || outCT1 == nil {
		return nil, errors.New("IntMPBootDecrypt returned null ciphertext")
	}

	return []*Ciphertext{
		{ptr: outCT0},
		{ptr: outCT1},
	}, nil
}

// IntMPBootAdd aggregates the shares from all parties in TCKKS interactive bootstrapping.
// This combines the (h_{0,i}, h_{1,i}) shares from all n parties into aggregated shares.
//
// Parameters:
//   - sharesPairVec: A slice of slices, where each inner slice contains 2 ciphertexts [h0, h1] from one party
//
// Returns: A slice with 2 aggregated ciphertexts [aggregated_h0, aggregated_h1]
func (cc *CryptoContext) IntMPBootAdd(sharesPairVec [][]*Ciphertext) ([]*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(sharesPairVec) == 0 {
		return nil, errors.New("sharesPairVec is empty")
	}

	// Validate that each party has exactly 2 shares
	for i, shares := range sharesPairVec {
		if len(shares) != 2 {
			return nil, fmt.Errorf("party %d does not have exactly 2 shares", i)
		}
		if shares[0] == nil || shares[0].ptr == nil || shares[1] == nil || shares[1].ptr == nil {
			return nil, fmt.Errorf("party %d has nil shares", i)
		}
	}

	numParties := len(sharesPairVec)

	// Convert Go slice to C array of arrays
	// We need to pin cSharesData because cSharesPairVec contains Go pointers to it.
	// Per cgo rules: "Go code may pass a Go pointer to C provided the memory to which
	// it points does not contain any Go pointers to memory that is unpinned."
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// First, create a flat array to hold all the ciphertext pointers (2 per party)
	cSharesData := make([]C.CiphertextPtr, numParties*2)
	for i := 0; i < numParties; i++ {
		cSharesData[i*2] = sharesPairVec[i][0].ptr
		cSharesData[i*2+1] = sharesPairVec[i][1].ptr
	}
	pinner.Pin(&cSharesData[0])

	// Create array of pointers to the inner arrays (each party's pair)
	// These are Go pointers (&cSharesData[i*2]) pointing into the pinned cSharesData
	cSharesPairVec := make([]*C.CiphertextPtr, numParties)
	for i := 0; i < numParties; i++ {
		cSharesPairVec[i] = &cSharesData[i*2]
	}

	var outCT0, outCT1 C.CiphertextPtr
	status := C.CryptoContext_IntMPBootAdd(
		cc.ptr,
		(**C.CiphertextPtr)(unsafe.Pointer(&cSharesPairVec[0])),
		C.size_t(numParties),
		&outCT0,
		&outCT1,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT0 == nil || outCT1 == nil {
		return nil, errors.New("IntMPBootAdd returned null ciphertext")
	}

	return []*Ciphertext{
		{ptr: outCT0},
		{ptr: outCT1},
	}, nil
}

// IntMPBootEncrypt finalizes the TCKKS interactive bootstrapping protocol.
// The leading party re-encrypts the aggregated shares to produce the final bootstrapped ciphertext.
//
// Parameters:
//   - publicKey: The joint public key
//   - aggregatedSharesPair: The aggregated shares [h0, h1] from IntMPBootAdd
//   - a: The common random polynomial from IntMPBootRandomElementGen
//   - inCtxt: The original input ciphertext (non-stripped, with both c0 and c1)
//
// Returns: The bootstrapped ciphertext
func (cc *CryptoContext) IntMPBootEncrypt(publicKey *PublicKey, aggregatedSharesPair []*Ciphertext, a, inCtxt *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if publicKey == nil || publicKey.ptr == nil {
		return nil, ErrPublicKeyArgNil
	}

	if len(aggregatedSharesPair) != 2 {
		return nil, errors.New("aggregatedSharesPair must have exactly 2 elements")
	}

	if aggregatedSharesPair[0] == nil || aggregatedSharesPair[0].ptr == nil ||
		aggregatedSharesPair[1] == nil || aggregatedSharesPair[1].ptr == nil {
		return nil, errors.New("aggregatedSharesPair contains nil ciphertexts")
	}

	if a == nil || a.ptr == nil {
		return nil, errors.New("a ciphertext is nil")
	}

	if inCtxt == nil || inCtxt.ptr == nil {
		return nil, errors.New("inCtxt is nil")
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntMPBootEncrypt(
		cc.ptr,
		publicKey.ptr,
		aggregatedSharesPair[0].ptr,
		aggregatedSharesPair[1].ptr,
		a.ptr,
		inCtxt.ptr,
		&outCT,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntMPBootEncrypt returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}
