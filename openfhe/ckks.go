package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a -lc++ -lm
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// --- CKKS Params Functions ---
func NewParamsCKKSRNS() *ParamsCKKS {
	p := &ParamsCKKS{ptr: C.NewParamsCKKS()}
	runtime.SetFinalizer(p, func(obj *ParamsCKKS) {
		C.DestroyParamsCKKS(obj.ptr)
	})
	return p
}

func (p *ParamsCKKS) SetScalingModSize(modSize int) {
	C.ParamsCKKS_SetScalingModSize(p.ptr, C.int(modSize))
}

func (p *ParamsCKKS) SetBatchSize(batchSize int) {
	C.ParamsCKKS_SetBatchSize(p.ptr, C.int(batchSize))
}

func (p *ParamsCKKS) SetMultiplicativeDepth(depth int) {
	C.ParamsCKKS_SetMultiplicativeDepth(p.ptr, C.int(depth))
}

func (p *ParamsCKKS) SetSecurityLevel(level SecurityLevel) {
	C.ParamsCKKS_SetSecurityLevel(p.ptr, C.OFHESecurityLevel(level))
}

func (p *ParamsCKKS) SetRingDim(ringDim uint64) {
	C.ParamsCKKS_SetRingDim(p.ptr, C.uint64_t(ringDim))
}

func (p *ParamsCKKS) SetScalingTechnique(technique int) {
	C.ParamsCKKS_SetScalingTechnique(p.ptr, C.int(technique))
}

func (p *ParamsCKKS) SetFirstModSize(modSize int) {
	C.ParamsCKKS_SetFirstModSize(p.ptr, C.int(modSize))
}

func (p *ParamsCKKS) SetNumLargeDigits(numDigits int) {
	C.ParamsCKKS_SetNumLargeDigits(p.ptr, C.int(numDigits))
}

func (p *ParamsCKKS) SetSecretKeyDist(d SecretKeyDist) {
	C.ParamsCKKS_SetSecretKeyDist(p.ptr, C.OFHESecretKeyDist(d))
}

// Expose ring dimension
func (cc *CryptoContext) GetRingDimension() uint64 {
	return uint64(C.CryptoContext_GetRingDimension(cc.ptr))
}

// --- CKKS CryptoContext ---
func NewCryptoContextCKKS(p *ParamsCKKS) *CryptoContext {
	cc := &CryptoContext{ptr: C.NewCryptoContextCKKS(p.ptr)}
	runtime.SetFinalizer(cc, func(obj *CryptoContext) {
		C.DestroyCryptoContext(obj.ptr)
	})
	return cc
}

// --- CKKS Plaintext ---
func (cc *CryptoContext) MakeCKKSPackedPlaintext(vec []float64) *Plaintext {
	if len(vec) == 0 {
		return nil
	}
	cVec := (*C.double)(unsafe.Pointer(&vec[0]))
	cLen := C.int(len(vec))
	// pt := &Plaintext{ptr: C.CryptoContext_MakeCKKSPackedPlaintext(cc.ptr, cVec, cLen, 1, 0, 0)}
	pt := &Plaintext{ptr: C.CryptoContext_MakeCKKSPackedPlaintext(cc.ptr, cVec, cLen)} // NEW 3-argument call
	runtime.SetFinalizer(pt, func(obj *Plaintext) {
		C.DestroyPlaintext(obj.ptr)
	})
	return pt
}

func (pt *Plaintext) GetRealPackedValue() []float64 {
	length := int(C.Plaintext_GetRealPackedValueLength(pt.ptr))
	if length == 0 {
		return nil
	}
	goSlice := make([]float64, length)
	for i := 0; i < length; i++ {
		goSlice[i] = float64(C.Plaintext_GetRealPackedValueAt(pt.ptr, C.int(i)))
	}
	return goSlice
}

// --- CKKS Operations ---
func (cc *CryptoContext) Rescale(ct *Ciphertext) *Ciphertext {
	resCt := &Ciphertext{ptr: C.CryptoContext_Rescale(cc.ptr, ct.ptr)}
	runtime.SetFinalizer(resCt, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return resCt
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

func (cc *CryptoContext) EvalBootstrapSetupSimple(levelBudget []uint32) error {
	var ptr *C.uint32_t
	var n C.int
	if len(levelBudget) > 0 {
		ptr = (*C.uint32_t)(unsafe.Pointer(&levelBudget[0]))
		n = C.int(len(levelBudget))
	}

	var cerr *C.char
	ok := C.CryptoContext_EvalBootstrapSetup_Simple(cc.ptr, ptr, n, &cerr)
	if ok == 0 {
		if cerr != nil {
			msg := C.GoString(cerr)
			C.FreeString(cerr) // free C-side string
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("EvalBootstrapSetupSimple failed")
	}
	return nil
}
