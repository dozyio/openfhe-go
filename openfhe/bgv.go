package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "bgv_c.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// --- BGV Params Type ---
// Opaque struct to hold the C pointer for BGV Params
type ParamsBGV struct {
	ptr C.ParamsBGVPtr
}

// --- BGV Params Functions ---
func NewParamsBGVrns() (*ParamsBGV, error) {
	var pH C.ParamsBGVPtr
	status := C.NewParamsBGV(&pH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pH == nil {
		return nil, errors.New("NewParamsBGV returned OK but null handle")
	}
	p := &ParamsBGV{ptr: pH}
	return p, nil
}

func (p *ParamsBGV) SetPlaintextModulus(mod uint64) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetPlaintextModulus(p.ptr, C.uint64_t(mod))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetMultiplicativeDepth(depth int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetMultiplicativeDepth(p.ptr, C.int(depth))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetScalingTechnique(technique int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetScalingTechnique(p.ptr, C.int(technique))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetSecurityLevel(level SecurityLevel) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetSecurityLevel(p.ptr, C.OFHESecurityLevel(level))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetDigitSize(digitSize int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetDigitSize(p.ptr, C.int(digitSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetMultipartyMode(mode int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetMultipartyMode(p.ptr, C.int(mode))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetPREMode(mode int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetPREMode(p.ptr, C.int(mode))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetPRENumHops(numHops uint32) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetPRENumHops(p.ptr, C.uint32_t(numHops))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetStatisticalSecurity(statSec uint32) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetStatisticalSecurity(p.ptr, C.uint32_t(statSec))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetNumAdversarialQueries(numQueries uint32) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetNumAdversarialQueries(p.ptr, C.uint32_t(numQueries))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetRingDim(ringDim uint32) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetRingDim(p.ptr, C.uint32_t(ringDim))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetKeySwitchTechnique(technique int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetKeySwitchTechnique(p.ptr, C.int(technique))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetScalingModSize(modSize int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetScalingModSize(p.ptr, C.int(modSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (p *ParamsBGV) SetFirstModSize(modSize int) error {
	if p.ptr == nil {
		return ErrParamsBGVNil
	}
	status := C.ParamsBGV_SetFirstModSize(p.ptr, C.int(modSize))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
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
		return nil, ErrParamsBGVNil
	}
	var ccH C.CryptoContextPtr
	status := C.NewCryptoContextBGV(p.ptr, &ccH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ccH == nil {
		return nil, errors.New("NewCryptoContextBGV returned OK but null handle")
	}
	cc := &CryptoContext{ptr: ccH}
	return cc, nil
}

// MakeCoefPackedPlaintext creates a plaintext from coefficient-packed integer values.
// This is used for BGV/BFV schemes when working in coefficient representation.
func (cc *CryptoContext) MakeCoefPackedPlaintext(values []int64) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}
	if len(values) == 0 {
		return nil, errors.New("values slice is empty")
	}

	var ptH C.PlaintextPtr
	status := C.CryptoContext_MakeCoefPackedPlaintext(
		cc.ptr,
		(*C.int64_t)(unsafe.Pointer(&values[0])),
		C.int(len(values)),
		&ptH,
	)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if ptH == nil {
		return nil, errors.New("MakeCoefPackedPlaintext returned OK but null handle")
	}

	pt := &Plaintext{ptr: ptH}
	return pt, nil
}
