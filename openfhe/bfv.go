package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// --- BFV Params Functions ---
func NewParamsBFVrns() (*ParamsBFV, error) {
	var pH C.ParamsBFVPtr
	status := C.NewParamsBFV(&pH)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	if pH == nil {
		return nil, errors.New("NewParamsBFV returned OK but null handle")
	}
	p := &ParamsBFV{ptr: pH}
	return p, nil
}

func (p *ParamsBFV) SetPlaintextModulus(mod uint64) error {
	if p.ptr == nil {
		return errors.New("ParamsBFV is closed or invalid")
	}
	status := C.ParamsBFV_SetPlaintextModulus(p.ptr, C.uint64_t(mod))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsBFV) SetMultiplicativeDepth(depth int) error {
	if p.ptr == nil {
		return errors.New("ParamsBFV is closed or invalid")
	}
	status := C.ParamsBFV_SetMultiplicativeDepth(p.ptr, C.int(depth))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsBFV) Close() {
	if p.ptr != nil {
		C.DestroyParamsBFV(p.ptr)
		p.ptr = nil
	}
}

// --- BFV CryptoContext ---
func NewCryptoContextBFV(p *ParamsBFV) (*CryptoContext, error) {
	if p == nil || p.ptr == nil {
		return nil, errors.New("ParamsBFV is closed or invalid")
	}
	var ccH C.CryptoContextPtr
	status := C.NewCryptoContextBFV(p.ptr, &ccH)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	if ccH == nil {
		return nil, errors.New("NewCryptoContextBFV returned OK but null handle")
	}
	cc := &CryptoContext{ptr: ccH}
	return cc, nil
}

// --- BFV Plaintext ---
func (cc *CryptoContext) MakePackedPlaintext(vec []int64) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if len(vec) == 0 {
		// Or return error? For now, match old behavior.
		// Let's return error, it's safer.
		return nil, errors.New("MakePackedPlaintext: input vector is empty")
	}
	cVec := (*C.int64_t)(unsafe.Pointer(&vec[0]))
	cLen := C.int(len(vec))
	var ptH C.PlaintextPtr
	status := C.CryptoContext_MakePackedPlaintext(cc.ptr, cVec, cLen, &ptH)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	if ptH == nil {
		return nil, errors.New("MakePackedPlaintext returned OK but null handle")
	}
	pt := &Plaintext{ptr: ptH}
	return pt, nil
}

func (pt *Plaintext) GetPackedValue() ([]int64, error) { // CHANGED signature
	if pt.ptr == nil {
		return nil, errors.New("Plaintext is closed or invalid")
	}
	var lengthC C.int
	status := C.Plaintext_GetPackedValueLength(pt.ptr, &lengthC)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	length := int(lengthC)
	if length == 0 {
		return nil, nil // Empty vector
	}
	goSlice := make([]int64, length)
	for i := 0; i < length; i++ {
		var valC C.int64_t
		status = C.Plaintext_GetPackedValueAt(pt.ptr, C.int(i), &valC)
		if status != PKE_OK {
			return nil, lastPKEError()
		}
		goSlice[i] = int64(valC)
	}
	return goSlice, nil
}
