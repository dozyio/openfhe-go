package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include <stdlib.h>
#include "pke_common_c.h"
#include "ckks_c.h"
#include "bgv_c.h"
*/
import "C"

import (
	"unsafe"
)

func (pt *Plaintext) GetPackedValue() ([]int64, error) {
	if pt.ptr == nil {
		return nil, ErrPlaintextNil
	}

	var cValues *C.int64_t
	var cLen C.int

	status := C.Plaintext_GetPackedValueBulk(pt.ptr, &cValues, &cLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	length := int(cLen)
	if length == 0 || cValues == nil {
		return []int64{}, nil
	}

	cSlice := unsafe.Slice(cValues, length)
	goSlice := make([]int64, length)
	for i := 0; i < length; i++ {
		goSlice[i] = int64(cSlice[i])
	}

	// Free the C-allocated memory
	C.free(unsafe.Pointer(cValues))

	return goSlice, nil
}

func (pt *Plaintext) GetRealPackedValue() ([]float64, error) {
	if pt.ptr == nil {
		return nil, ErrPlaintextNil
	}

	var cValues *C.double
	var cLen C.int

	status := C.Plaintext_GetRealPackedValueBulk(pt.ptr, &cValues, &cLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	length := int(cLen)
	if length == 0 || cValues == nil {
		return []float64{}, nil
	}

	cSlice := unsafe.Slice(cValues, length)
	goSlice := make([]float64, length)
	for i := 0; i < length; i++ {
		goSlice[i] = float64(cSlice[i])
	}

	// Free the C-allocated memory
	C.free(unsafe.Pointer(cValues))

	return goSlice, nil
}

func (pt *Plaintext) GetComplexPackedValue() ([]complex128, error) {
	if pt.ptr == nil {
		return nil, ErrPlaintextNil
	}

	var cValues *C.complex_double_t
	var cLen C.int

	status := C.Plaintext_GetComplexPackedValueBulk(pt.ptr, &cValues, &cLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	length := int(cLen)
	if length == 0 || cValues == nil {
		return []complex128{}, nil
	}

	cSlice := unsafe.Slice(cValues, length)
	goSlice := make([]complex128, length)
	for i := 0; i < length; i++ {
		goSlice[i] = complex(float64(cSlice[i].real), float64(cSlice[i].imag))
	}

	// Free the C-allocated memory
	C.free(unsafe.Pointer(cValues))

	return goSlice, nil
}

func (pt *Plaintext) GetCoefPackedValue() ([]int64, error) {
	if pt.ptr == nil {
		return nil, ErrPlaintextNil
	}

	var cValues *C.int64_t
	var cLen C.int

	status := C.Plaintext_GetCoefPackedValue(pt.ptr, &cValues, &cLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	length := int(cLen)
	if length == 0 || cValues == nil {
		return []int64{}, nil
	}

	cSlice := unsafe.Slice(cValues, length)
	goSlice := make([]int64, length)
	for i := 0; i < length; i++ {
		goSlice[i] = int64(cSlice[i])
	}

	// Free the C-allocated memory
	C.free(unsafe.Pointer(cValues))

	return goSlice, nil
}

func (pt *Plaintext) SetLength(len int) error {
	if pt.ptr == nil {
		return ErrPlaintextNil
	}

	status := C.Plaintext_SetLength(pt.ptr, C.int(len))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}

	return nil
}

// GetLength returns the length of the plaintext.
// Returns 0 if the plaintext is invalid.
func (pt *Plaintext) GetLength() int {
	if pt == nil || pt.ptr == nil {
		return 0
	}
	return int(C.Plaintext_GetLength(pt.ptr))
}

// GetLevel returns the level (depth) of the plaintext.
// Returns 0 if the plaintext is invalid.
func (pt *Plaintext) GetLevel() int {
	if pt == nil || pt.ptr == nil {
		return 0
	}
	return int(C.Plaintext_GetLevel(pt.ptr))
}

// GetSlots returns the number of slots in the plaintext.
// Returns 0 if the plaintext is invalid.
func (pt *Plaintext) GetSlots() uint32 {
	if pt == nil || pt.ptr == nil {
		return 0
	}
	return uint32(C.Plaintext_GetSlots(pt.ptr))
}

// GetScalingFactor returns the scaling factor of the plaintext (CKKS scheme).
// Returns 0.0 if the plaintext is invalid.
func (pt *Plaintext) GetScalingFactor() float64 {
	if pt == nil || pt.ptr == nil {
		return 0.0
	}
	return float64(C.Plaintext_GetScalingFactor(pt.ptr))
}

// SetScalingFactor sets the scaling factor of the plaintext (CKKS scheme).
// Does nothing if the plaintext is invalid.
func (pt *Plaintext) SetScalingFactor(scalingFactor float64) {
	if pt == nil || pt.ptr == nil {
		return
	}
	C.Plaintext_SetScalingFactor(pt.ptr, C.double(scalingFactor))
}

// GetEncodingType returns the encoding type of the plaintext.
// Returns -1 if the plaintext is invalid.
func (pt *Plaintext) GetEncodingType() int {
	if pt == nil || pt.ptr == nil {
		return -1
	}
	return int(C.Plaintext_GetEncodingType(pt.ptr))
}

// Close frees the underlying C++ Plaintext object.
func (pt *Plaintext) Close() {
	if pt.ptr != nil {
		C.DestroyPlaintext(pt.ptr)
		pt.ptr = nil
	}
}
