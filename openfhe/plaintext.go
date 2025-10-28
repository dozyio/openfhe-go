package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "pke_common_c.h"
#include "ckks_c.h"
#include "bgv_c.h"
*/
import "C"

import (
	"errors"
)

func (pt *Plaintext) GetPackedValue() ([]int64, error) {
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

func (pt *Plaintext) GetRealPackedValue() ([]float64, error) {
	if pt.ptr == nil {
		return nil, errors.New("Plaintext is closed or invalid")
	}
	var lengthC C.int
	status := C.Plaintext_GetRealPackedValueLength(pt.ptr, &lengthC)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	length := int(lengthC)
	if length == 0 {
		return nil, nil // Empty vector
	}
	goSlice := make([]float64, length)
	for i := 0; i < length; i++ {
		var valC C.double
		status = C.Plaintext_GetRealPackedValueAt(pt.ptr, C.int(i), &valC)
		if status != PKE_OK {
			return nil, lastPKEError()
		}
		goSlice[i] = float64(valC)
	}
	return goSlice, nil
}

func (pt *Plaintext) GetComplexPackedValue() ([]complex128, error) {
	if pt.ptr == nil {
		return nil, errors.New("Plaintext is closed or invalid")
	}
	var lengthC C.int
	status := C.Plaintext_GetComplexPackedValueLength(pt.ptr, &lengthC)
	if status != PKE_OK {
		return nil, lastPKEError()
	}
	length := int(lengthC)
	if length == 0 {
		return nil, nil // Empty vector
	}
	goSlice := make([]complex128, length)
	var valC C.complex_double_t
	for i := 0; i < length; i++ {
		status = C.Plaintext_GetComplexPackedValueAt(pt.ptr, C.int(i), &valC)
		if status != PKE_OK {
			return nil, lastPKEError()
		}
		goSlice[i] = complex(float64(valC.real), float64(valC.imag))
	}
	return goSlice, nil
}

func (pt *Plaintext) SetLength(len int) error {
	if pt.ptr == nil {
		return errors.New("Plaintext is closed or invalid")
	}
	status := C.Plaintext_SetLength(pt.ptr, C.int(len))
	if status != PKE_OK {
		return lastPKEError()
	}
	return nil
}

// Close frees the underlying C++ Plaintext object.
func (pt *Plaintext) Close() {
	if pt.ptr != nil {
		C.DestroyPlaintext(pt.ptr)
		pt.ptr = nil
	}
}
