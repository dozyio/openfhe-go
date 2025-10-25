package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a -lc++ -lm
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// --- BFV Params Functions ---
func NewParamsBFVrns() *ParamsBFV {
	p := &ParamsBFV{ptr: C.NewParamsBFV()}
	runtime.SetFinalizer(p, func(obj *ParamsBFV) { C.DestroyParamsBFV(obj.ptr) })
	return p
}

func (p *ParamsBFV) SetPlaintextModulus(mod uint64) {
	C.ParamsBFV_SetPlaintextModulus(p.ptr, C.uint64_t(mod))
}

func (p *ParamsBFV) SetMultiplicativeDepth(depth int) {
	C.ParamsBFV_SetMultiplicativeDepth(p.ptr, C.int(depth))
}

// --- BFV CryptoContext ---
func NewCryptoContextBFV(p *ParamsBFV) *CryptoContext {
	cc := &CryptoContext{ptr: C.NewCryptoContextBFV(p.ptr)}
	runtime.SetFinalizer(cc, func(obj *CryptoContext) {
		C.DestroyCryptoContext(obj.ptr)
	})
	return cc
}

// --- BFV Plaintext ---
func (cc *CryptoContext) MakePackedPlaintext(vec []int64) *Plaintext {
	if len(vec) == 0 {
		return nil
	}
	cVec := (*C.int64_t)(unsafe.Pointer(&vec[0]))
	cLen := C.int(len(vec))
	pt := &Plaintext{ptr: C.CryptoContext_MakePackedPlaintext(cc.ptr, cVec, cLen)}
	runtime.SetFinalizer(pt, func(obj *Plaintext) {
		C.DestroyPlaintext(obj.ptr)
	})
	return pt
}

func (pt *Plaintext) GetPackedValue() []int64 {
	length := int(C.Plaintext_GetPackedValueLength(pt.ptr))
	if length == 0 {
		return nil
	}
	goSlice := make([]int64, length)
	for i := 0; i < length; i++ {
		goSlice[i] = int64(C.Plaintext_GetPackedValueAt(pt.ptr, C.int(i)))
	}
	return goSlice
}
