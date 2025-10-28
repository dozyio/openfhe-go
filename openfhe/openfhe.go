package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Interface for objects that need C++ memory released
type Releasable interface {
	Release()
}

// --- Feature Flags ---
const (
	PKE          = 0x01 // 1
	KEYSWITCH    = 0x02 // 2
	PRE          = 0x04 // 4
	LEVELEDSHE   = 0x08 // 8
	ADVANCEDSHE  = 0x10 // 16
	MULTIPARTY   = 0x20 // 32
	FHE          = 0x40 // 64
	SCHEMESWITCH = 0x80 // 128
)

// --- Scaling Techniques ---
const (
	FIXEDMANUAL            = 0
	FIXEDAUTO              = 1
	FLEXIBLEAUTO           = 2
	FLEXIBLEAUTOEXT        = 3
	COMPOSITESCALINGAUTO   = 4
	COMPOSITESCALINGMANUAL = 5
	NORESCALE              = 6
	INVALID_RS_TECHNIQUE   = 7
)

// --- Common CryptoContext Methods ---
func (cc *CryptoContext) Enable(feature int) {
	C.CryptoContext_Enable(cc.ptr, C.int(feature))
}

func (cc *CryptoContext) KeyGen() *KeyPair {
	kp := &KeyPair{ptr: C.CryptoContext_KeyGen(cc.ptr)}
	return kp
}

func (cc *CryptoContext) EvalMultKeyGen(keys *KeyPair) {
	C.CryptoContext_EvalMultKeyGen(cc.ptr, keys.ptr)
}

func (cc *CryptoContext) EvalRotateKeyGen(keys *KeyPair, indices []int32) {
	if len(indices) == 0 {
		return
	}
	cIndices := (*C.int32_t)(unsafe.Pointer(&indices[0]))
	cLen := C.int(len(indices))
	C.CryptoContext_EvalRotateKeyGen(cc.ptr, keys.ptr, cIndices, cLen)
}

func (cc *CryptoContext) Encrypt(keys *KeyPair, pt *Plaintext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_Encrypt(cc.ptr, keys.ptr, pt.ptr)}
	return ct
}

func (cc *CryptoContext) Decrypt(keys *KeyPair, ct *Ciphertext) *Plaintext {
	pt := &Plaintext{ptr: C.CryptoContext_Decrypt(cc.ptr, keys.ptr, ct.ptr)}
	if pt.ptr == nil {
		// Decrypt can fail and return null
		return nil
	}
	return pt
}

// --- Common Homomorphic Operations ---
func (cc *CryptoContext) EvalAdd(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalAdd(cc.ptr, ct1.ptr, ct2.ptr)}
	return ct
}

func (cc *CryptoContext) EvalSub(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalSub(cc.ptr, ct1.ptr, ct2.ptr)}
	return ct
}

func (cc *CryptoContext) EvalMult(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalMult(cc.ptr, ct1.ptr, ct2.ptr)}
	return ct
}

func (cc *CryptoContext) EvalRotate(ct *Ciphertext, index int32) *Ciphertext {
	resCt := &Ciphertext{ptr: C.CryptoContext_EvalRotate(cc.ptr, ct.ptr, C.int32_t(index))}
	return resCt
}

// --- CKKS Bootstrapping ---
func (cc *CryptoContext) EvalBootstrapKeyGen(keys *KeyPair, slots uint32) error {
	var cErr *C.char
	ok := C.CryptoContext_EvalBootstrapKeyGen(cc.ptr, keys.ptr, C.uint32_t(slots), &cErr)
	if ok == 1 {
		return nil
	}
	defer func() {
		if cErr != nil {
			C.free(unsafe.Pointer(cErr))
		}
	}()
	if cErr != nil {
		return fmt.Errorf("%s", C.GoString(cErr))
	}
	return fmt.Errorf("EvalBootstrapKeyGen failed")
}

func (cc *CryptoContext) EvalBootstrap(ct *Ciphertext) (*Ciphertext, error) {
	var cErr *C.char
	out := C.CryptoContext_EvalBootstrap(cc.ptr, ct.ptr, &cErr)
	if out != nil {
		res := &Ciphertext{ptr: out}
		return res, nil
	}
	defer func() {
		if cErr != nil {
			C.free(unsafe.Pointer(cErr))
		}
	}()
	if cErr != nil {
		return nil, fmt.Errorf("%s", C.GoString(cErr))
	}
	return nil, fmt.Errorf("EvalBootstrap failed")
}

func (cc *CryptoContext) EvalBootstrapSetup(slots uint32) error {
	var cErr *C.char
	ok := C.CryptoContext_EvalBootstrapSetup(cc.ptr, C.uint32_t(slots), &cErr)
	if ok == 1 {
		return nil
	}
	defer func() {
		if cErr != nil {
			C.free(unsafe.Pointer(cErr))
		}
	}()
	if cErr != nil {
		return fmt.Errorf("%s", C.GoString(cErr))
	}
	return fmt.Errorf("EvalBootstrapSetup failed")
}

func (cc *CryptoContext) EvalBootstrapPrecompute(slots uint32) error {
	var cErr *C.char
	ok := C.CryptoContext_EvalBootstrapPrecompute(cc.ptr, C.uint32_t(slots), &cErr)
	if ok == 1 {
		return nil
	}
	defer func() {
		if cErr != nil {
			C.free(unsafe.Pointer(cErr))
		}
	}()
	if cErr != nil {
		return fmt.Errorf("%s", C.GoString(cErr))
	}
	return fmt.Errorf("EvalBootstrapPrecompute failed")
}

// --- Global Cleanup ---

// Cleanup releases all C++ objects created by the wrapper.
// Call this function typically via `defer openfhe.Cleanup()` at the start of main.
func Cleanup() {
	fmt.Println("TODO!!! Running OpenFHE Global Cleanup...") // Optional: for debugging

	// Call C++ functions to clear internal object maps
	// C.ReleaseAllBinFHE()
	// C.ReleaseAllPKE()

	fmt.Println("OpenFHE Global Cleanup finished.") // Optional
}

// --- Release Methods for Go Wrappers ---

// Release frees the underlying C++ CryptoContext object.
// Call this manually if you need fine-grained control, otherwise rely on Cleanup().
func (cc *CryptoContext) Release() {
	if cc.ptr != nil {
		// fmt.Println("Releasing CryptoContext:", cc.ptr) // Debug
		C.DestroyCryptoContext(cc.ptr)
		cc.ptr = nil // Prevent double-free
	}
}

// Release frees the underlying C++ Plaintext object.
func (pt *Plaintext) Release() {
	if pt.ptr != nil {
		// fmt.Println("Releasing Plaintext:", pt.ptr) // Debug
		C.DestroyPlaintext(pt.ptr)
		pt.ptr = nil
	}
}

// Release frees the underlying C++ KeyPair object.
func (kp *KeyPair) Release() {
	if kp.ptr != nil {
		// fmt.Println("Releasing KeyPair:", kp.ptr) // Debug
		C.DestroyKeyPair(kp.ptr)
		kp.ptr = nil
	}
}

// Release frees the underlying C++ Ciphertext object.
func (ct *Ciphertext) Release() {
	if ct.ptr != nil {
		// fmt.Println("Releasing Ciphertext:", ct.ptr) // Debug
		C.DestroyCiphertext(ct.ptr)
		ct.ptr = nil
	}
}

// Note: Ensure BinFHE types have Release methods defined in binfhe.go
// Note: Ensure Params types have Release methods defined in respective files (bfv.go, bgv.go, ckks.go)
