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
	"unsafe"
)

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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
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
		return errors.New("ParamsCKKS is closed or invalid")
	}

	status := C.ParamsCKKS_SetKeySwitchTechnique(p.ptr, C.int(technique))
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

// --- CKKS CryptoContext ---
func NewCryptoContextCKKS(p *ParamsCKKS) (*CryptoContext, error) {
	if p == nil || p.ptr == nil {
		return nil, errors.New("ParamsCKKS is closed or invalid")
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
		return nil, errors.New("CryptoContext is closed or invalid")
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

// MakeCKKSComplexPackedPlaintext creates a CKKS plaintext from a slice of complex128.
func (cc *CryptoContext) MakeCKKSComplexPackedPlaintext(vec []complex128) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
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

// --- CKKS Operations ---
func (cc *CryptoContext) Rescale(ct *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}

	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
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
		return nil, errors.New("CryptoContext is closed or invalid")
	}

	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
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

// EvalPoly evaluates a polynomial on a ciphertext.
// coefficients: A slice of doubles representing the polynomial coefficients in ascending order (e.g., [c0, c1, c2] for c0 + c1*x + c2*x^2).
// Returns the resulting ciphertext and a potential error.
func (cc *CryptoContext) EvalPoly(ct *Ciphertext, coefficients []float64) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}

	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
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
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
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
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
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
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct1 == nil || ct1.ptr == nil || ct2 == nil || ct2.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
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
