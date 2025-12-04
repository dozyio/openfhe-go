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
	"errors"
	"unsafe"
)

func (pt *Plaintext) GetPackedValue() ([]int64, error) {
	if pt.ptr == nil {
		return nil, errors.New("Plaintext is closed or invalid")
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
		return nil, errors.New("Plaintext is closed or invalid")
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
		return nil, errors.New("Plaintext is closed or invalid")
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
		return nil, errors.New("Plaintext is closed or invalid")
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
		return errors.New("Plaintext is closed or invalid")
	}

	status := C.Plaintext_SetLength(pt.ptr, C.int(len))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
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
