package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include "minmax_c.h"
#include "pke_common_c.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// MinMaxResult holds the result of min/max operations via scheme switching.
// It contains two ciphertexts: one for the min/max value and one for its index (argmin/argmax).
//
// By default, the Index ciphertext contains a one-hot encoded vector where the position
// with value 1.0 indicates the argmin/argmax index. Use GetArgminIndex or GetArgmaxIndex
// helper methods to extract the index, or set SchSwchParams.SetOneHotEncoding(false) to
// get the index directly as a single value.
type MinMaxResult struct {
	Value *Ciphertext // The minimum or maximum value
	Index *Ciphertext // The argmin or argmax index (one-hot encoded by default)
}

// Close frees the underlying C++ objects for both ciphertexts.
// This should be called when the result is no longer needed.
func (r *MinMaxResult) Close() {
	if r.Value != nil {
		r.Value.Close()
		r.Value = nil
	}
	if r.Index != nil {
		r.Index.Close()
		r.Index = nil
	}
}

// GetIndexFromOneHot decrypts and extracts the index from a one-hot encoded Index ciphertext.
// This is a convenience method that handles the common case where SetOneHotEncoding(true) is used (default).
//
// Parameters:
//   - cc: CryptoContext for decryption
//   - keys: KeyPair for decryption
//   - numValues: Number of values that were compared (length of one-hot vector)
//
// Returns:
//   - index: The position where the one-hot vector has value 1.0
//   - error: An error if decryption fails or no index found
//
// Example:
//
//	result, _ := cc.EvalMinSchemeSwitching(ct, keys, 8, 8)
//	defer result.Close()
//	argminIndex, _ := result.GetIndexFromOneHot(cc, keys, 8)
//	fmt.Printf("Argmin is at index: %d\n", argminIndex)
func (r *MinMaxResult) GetIndexFromOneHot(cc *CryptoContext, keys *KeyPair, numValues uint32) (int, error) {
	if r.Index == nil {
		return -1, errors.New("Index ciphertext is nil")
	}

	// Decrypt the one-hot encoded index
	indexPt, err := cc.Decrypt(keys, r.Index)
	if err != nil {
		return -1, err
	}
	defer indexPt.Close()

	indexPt.SetLength(int(numValues))
	indexValues, err := indexPt.GetRealPackedValue()
	if err != nil {
		return -1, err
	}

	// Find the index with value 1.0 in the one-hot vector
	for i := 0; i < int(numValues); i++ {
		// Use a tolerance for floating-point comparison
		if indexValues[i] > 0.5 { // Any value > 0.5 is considered as 1
			return i, nil
		}
	}

	return -1, errors.New("no index found in one-hot vector (all values are 0)")
}

// EvalMinSchemeSwitching finds the minimum value and its index (argmin) from the first numValues
// packed in a CKKS ciphertext using scheme switching to FHEW and back.
//
// This function switches from CKKS (approximate arithmetic) to FHEW (exact boolean operations)
// to perform exact comparisons, then switches back to CKKS with the result.
//
// Prerequisites:
//   - CKKS context must be created
//   - SCHEMESWITCH feature must be enabled: cc.Enable(openfhe.SCHEMESWITCH)
//   - Scheme switching must be set up: cc.EvalSchemeSwitchingSetup() and EvalSchemeSwitchingKeyGen()
//
// Parameters:
//   - ciphertext: CKKS ciphertext containing the values to compare
//   - keys: KeyPair with the public key used for operations
//   - numValues: Number of values to extract and compare (must be power of 2)
//   - numSlots: Number of slots in the output ciphertexts
//
// Returns:
//   - *MinMaxResult: Contains Value (minimum) and Index (argmin)
//   - error: An error if the operation fails
//
// Example:
//
//	// After setting up CKKS and scheme switching...
//	data := []float64{5.2, 3.1, 7.8, 2.9}
//	pt, _ := cc.MakeCKKSPackedPlaintext(data)
//	ct, _ := cc.Encrypt(keys, pt)
//
//	result, _ := cc.EvalMinSchemeSwitching(ct, keys, 4, 4)
//	defer result.Close()
//
//	minPt, _ := cc.Decrypt(keys, result.Value)  // Should be ~2.9
//	argminPt, _ := cc.Decrypt(keys, result.Index) // Should be ~3
func (cc *CryptoContext) EvalMinSchemeSwitching(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
) (*MinMaxResult, error) {
	return cc.EvalMinSchemeSwitchingExt(ciphertext, keys, numValues, numSlots, 0, 1.0)
}

// EvalMinSchemeSwitchingExt is the extended version of EvalMinSchemeSwitching with all parameters.
//
// Parameters:
//   - ciphertext: CKKS ciphertext containing the values to compare
//   - keys: KeyPair with the public key
//   - numValues: Number of values to compare (must be power of 2)
//   - numSlots: Number of slots in output ciphertexts
//   - pLWE: Target plaintext modulus for FHEW ciphertexts (0 = use default)
//   - scaleSign: Scaling factor when switching to FHEW (1.0 = no scaling)
//
// Returns:
//   - *MinMaxResult: Contains Value (minimum) and Index (argmin)
//   - error: An error if the operation fails
func (cc *CryptoContext) EvalMinSchemeSwitchingExt(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
	pLWE uint32,
	scaleSign float64,
) (*MinMaxResult, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}

	// Get public key from KeyPair
	var pk unsafe.Pointer
	status := C.GetPublicKey(keys.ptr, &pk)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.New("KeyPair has no public key")
	}

	var valuePtr C.CiphertextPtr
	var indexPtr C.CiphertextPtr

	status = C.CryptoContext_EvalMinSchemeSwitching(
		cc.ptr,
		ciphertext.ptr,
		pk,
		C.uint32_t(numValues),
		C.uint32_t(numSlots),
		C.uint32_t(pLWE),
		C.double(scaleSign),
		&valuePtr,
		&indexPtr,
	)

	err = checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if valuePtr == nil || indexPtr == nil {
		return nil, errors.New("EvalMinSchemeSwitching returned OK but null handle(s)")
	}

	return &MinMaxResult{
		Value: &Ciphertext{ptr: valuePtr},
		Index: &Ciphertext{ptr: indexPtr},
	}, nil
}

// EvalMinSchemeSwitchingAlt is an alternative version of EvalMinSchemeSwitching that uses
// more FHEW operations for higher precision, but is slower than the standard version.
//
// Parameters are the same as EvalMinSchemeSwitching.
//
// Returns:
//   - *MinMaxResult: Contains Value (minimum) and Index (argmin)
//   - error: An error if the operation fails
func (cc *CryptoContext) EvalMinSchemeSwitchingAlt(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
) (*MinMaxResult, error) {
	return cc.EvalMinSchemeSwitchingAltExt(ciphertext, keys, numValues, numSlots, 0, 1.0)
}

// EvalMinSchemeSwitchingAltExt is the extended version with all parameters.
func (cc *CryptoContext) EvalMinSchemeSwitchingAltExt(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
	pLWE uint32,
	scaleSign float64,
) (*MinMaxResult, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}

	var pk unsafe.Pointer
	status := C.GetPublicKey(keys.ptr, &pk)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.New("KeyPair has no public key")
	}

	var valuePtr C.CiphertextPtr
	var indexPtr C.CiphertextPtr

	status = C.CryptoContext_EvalMinSchemeSwitchingAlt(
		cc.ptr,
		ciphertext.ptr,
		pk,
		C.uint32_t(numValues),
		C.uint32_t(numSlots),
		C.uint32_t(pLWE),
		C.double(scaleSign),
		&valuePtr,
		&indexPtr,
	)

	err = checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if valuePtr == nil || indexPtr == nil {
		return nil, errors.New("EvalMinSchemeSwitchingAlt returned OK but null handle(s)")
	}

	return &MinMaxResult{
		Value: &Ciphertext{ptr: valuePtr},
		Index: &Ciphertext{ptr: indexPtr},
	}, nil
}

// EvalMaxSchemeSwitching finds the maximum value and its index (argmax) from the first numValues
// packed in a CKKS ciphertext using scheme switching to FHEW and back.
//
// This function switches from CKKS (approximate arithmetic) to FHEW (exact boolean operations)
// to perform exact comparisons, then switches back to CKKS with the result.
//
// Prerequisites and parameters are the same as EvalMinSchemeSwitching.
//
// Returns:
//   - *MinMaxResult: Contains Value (maximum) and Index (argmax)
//   - error: An error if the operation fails
//
// Example:
//
//	result, _ := cc.EvalMaxSchemeSwitching(ct, keys, 4, 4)
//	defer result.Close()
//
//	maxPt, _ := cc.Decrypt(keys, result.Value)  // Should be ~7.8
//	argmaxPt, _ := cc.Decrypt(keys, result.Index) // Should be ~2
func (cc *CryptoContext) EvalMaxSchemeSwitching(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
) (*MinMaxResult, error) {
	return cc.EvalMaxSchemeSwitchingExt(ciphertext, keys, numValues, numSlots, 0, 1.0)
}

// EvalMaxSchemeSwitchingExt is the extended version of EvalMaxSchemeSwitching with all parameters.
func (cc *CryptoContext) EvalMaxSchemeSwitchingExt(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
	pLWE uint32,
	scaleSign float64,
) (*MinMaxResult, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}

	var pk unsafe.Pointer
	status := C.GetPublicKey(keys.ptr, &pk)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.New("KeyPair has no public key")
	}

	var valuePtr C.CiphertextPtr
	var indexPtr C.CiphertextPtr

	status = C.CryptoContext_EvalMaxSchemeSwitching(
		cc.ptr,
		ciphertext.ptr,
		pk,
		C.uint32_t(numValues),
		C.uint32_t(numSlots),
		C.uint32_t(pLWE),
		C.double(scaleSign),
		&valuePtr,
		&indexPtr,
	)

	err = checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if valuePtr == nil || indexPtr == nil {
		return nil, errors.New("EvalMaxSchemeSwitching returned OK but null handle(s)")
	}

	return &MinMaxResult{
		Value: &Ciphertext{ptr: valuePtr},
		Index: &Ciphertext{ptr: indexPtr},
	}, nil
}

// EvalMaxSchemeSwitchingAlt is an alternative version of EvalMaxSchemeSwitching that uses
// more FHEW operations for higher precision, but is slower than the standard version.
//
// Parameters are the same as EvalMaxSchemeSwitching.
//
// Returns:
//   - *MinMaxResult: Contains Value (maximum) and Index (argmax)
//   - error: An error if the operation fails
func (cc *CryptoContext) EvalMaxSchemeSwitchingAlt(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
) (*MinMaxResult, error) {
	return cc.EvalMaxSchemeSwitchingAltExt(ciphertext, keys, numValues, numSlots, 0, 1.0)
}

// EvalMaxSchemeSwitchingAltExt is the extended version with all parameters.
func (cc *CryptoContext) EvalMaxSchemeSwitchingAltExt(
	ciphertext *Ciphertext,
	keys *KeyPair,
	numValues uint32,
	numSlots uint32,
	pLWE uint32,
	scaleSign float64,
) (*MinMaxResult, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}

	var pk unsafe.Pointer
	status := C.GetPublicKey(keys.ptr, &pk)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.New("KeyPair has no public key")
	}

	var valuePtr C.CiphertextPtr
	var indexPtr C.CiphertextPtr

	status = C.CryptoContext_EvalMaxSchemeSwitchingAlt(
		cc.ptr,
		ciphertext.ptr,
		pk,
		C.uint32_t(numValues),
		C.uint32_t(numSlots),
		C.uint32_t(pLWE),
		C.double(scaleSign),
		&valuePtr,
		&indexPtr,
	)

	err = checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if valuePtr == nil || indexPtr == nil {
		return nil, errors.New("EvalMaxSchemeSwitchingAlt returned OK but null handle(s)")
	}

	return &MinMaxResult{
		Value: &Ciphertext{ptr: valuePtr},
		Index: &Ciphertext{ptr: indexPtr},
	}, nil
}
