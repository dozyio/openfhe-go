package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "bridge.h"
*/
import "C"

// --- BGV Params Type ---
// Opaque struct to hold the C pointer for BGV Params
type ParamsBGV struct {
	ptr C.ParamsBGVPtr
}

// --- BGV Params Functions ---
func NewParamsBGVrns() *ParamsBGV {
	p := &ParamsBGV{ptr: C.NewParamsBGV()}
	return p
}

func (p *ParamsBGV) SetPlaintextModulus(mod uint64) {
	C.ParamsBGV_SetPlaintextModulus(p.ptr, C.uint64_t(mod))
}

func (p *ParamsBGV) SetMultiplicativeDepth(depth int) {
	C.ParamsBGV_SetMultiplicativeDepth(p.ptr, C.int(depth))
}

// Release method for ParamsBGV
func (p *ParamsBGV) Release() {
	if p.ptr != nil {
		C.DestroyParamsBGV(p.ptr)
		p.ptr = nil
	}
}

// --- BGV CryptoContext ---
func NewCryptoContextBGV(p *ParamsBGV) *CryptoContext {
	cc := &CryptoContext{ptr: C.NewCryptoContextBGV(p.ptr)}
	return cc
}

// --- BGV Plaintext ---
// Note: MakePackedPlaintext and GetPackedValue are already defined in bfv.go and common.go
// We only need the BGV-specific SetLength method added to the Plaintext type.

// This method should be added to the existing Plaintext type, likely in common.go or a new plaintext.go
// For now, let's put it here, but ideally it integrates with the existing Plaintext struct.
func (pt *Plaintext) SetLength(len int) {
	C.Plaintext_SetLength(pt.ptr, C.int(len))
}
