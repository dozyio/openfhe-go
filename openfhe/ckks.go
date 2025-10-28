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
	if status != PKE_OK {
		return nil, lastPKEError()
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
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetBatchSize(batchSize int) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetBatchSize(p.ptr, C.int(batchSize))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetMultiplicativeDepth(depth int) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetMultiplicativeDepth(p.ptr, C.int(depth))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetSecurityLevel(level SecurityLevel) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetSecurityLevel(p.ptr, C.OFHESecurityLevel(level))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetRingDim(ringDim uint64) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetRingDim(p.ptr, C.uint64_t(ringDim))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetScalingTechnique(technique int) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetScalingTechnique(p.ptr, C.int(technique))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetFirstModSize(modSize int) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetFirstModSize(p.ptr, C.int(modSize))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetNumLargeDigits(numDigits int) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetNumLargeDigits(p.ptr, C.int(numDigits))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsCKKS) SetSecretKeyDist(d SecretKeyDist) error {
	if p.ptr == nil {
		return errors.New("ParamsCKKS is closed or invalid")
	}
	status := C.ParamsCKKS_SetSecretKeyDist(p.ptr, C.OFHESecretKeyDist(d))
	if status != PKE_OK {
		return lastPKEError()
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
	if status != PKE_OK {
		return nil, lastPKEError()
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
	if status != PKE_OK {
		return nil, lastPKEError()
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
	if status != PKE_OK {
		return nil, lastPKEError()
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
	if status != PKE_OK {
		return nil, lastPKEError()
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
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	if ctH == nil {
		return nil, errors.New("ModReduce returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
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
