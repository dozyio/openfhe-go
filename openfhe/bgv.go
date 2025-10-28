package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "bgv_c.h"
*/
import "C"
import "errors"

// --- BGV Params Type ---
// Opaque struct to hold the C pointer for BGV Params
type ParamsBGV struct {
	ptr C.ParamsBGVPtr
}

// --- BGV Params Functions ---
func NewParamsBGVrns() (*ParamsBGV, error) {
	var pH C.ParamsBGVPtr
	status := C.NewParamsBGV(&pH)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	if pH == nil {
		return nil, errors.New("NewParamsBGV returned OK but null handle")
	}
	p := &ParamsBGV{ptr: pH}
	return p, nil
}

func (p *ParamsBGV) SetPlaintextModulus(mod uint64) error {
	if p.ptr == nil {
		return errors.New("ParamsBGV is closed or invalid")
	}
	status := C.ParamsBGV_SetPlaintextModulus(p.ptr, C.uint64_t(mod))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

func (p *ParamsBGV) SetMultiplicativeDepth(depth int) error {
	if p.ptr == nil {
		return errors.New("ParamsBGV is closed or invalid")
	}
	status := C.ParamsBGV_SetMultiplicativeDepth(p.ptr, C.int(depth))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

// Close method for ParamsBGV
func (p *ParamsBGV) Close() {
	if p.ptr != nil {
		C.DestroyParamsBGV(p.ptr)
		p.ptr = nil
	}
}

// --- BGV CryptoContext ---
func NewCryptoContextBGV(p *ParamsBGV) (*CryptoContext, error) {
	if p == nil || p.ptr == nil {
		return nil, errors.New("ParamsBGV is closed or invalid")
	}
	var ccH C.CryptoContextPtr
	status := C.NewCryptoContextBGV(p.ptr, &ccH)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	if ccH == nil {
		return nil, errors.New("NewCryptoContextBGV returned OK but null handle")
	}
	cc := &CryptoContext{ptr: ccH}
	return cc, nil
}
