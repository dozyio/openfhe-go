// main.go
package main

import (
	"fmt"
	"runtime"
	"unsafe"
)

/*
#cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/openfhe_install/include/openfhe -I${SRCDIR}/openfhe_install/include/openfhe/core -I${SRCDIR}/openfhe_install/include/openfhe/pke -I${SRCDIR}/openfhe_install/include/openfhe/binfhe -I${SRCDIR}/openfhe_install/include/openfhe/cereal
#cgo LDFLAGS: ${SRCDIR}/openfhe_install/lib/libOPENFHEpke_static.a ${SRCDIR}/openfhe_install/lib/libOPENFHEcore_static.a ${SRCDIR}/openfhe_install/lib/libOPENFHEbinfhe_static.a -lstdc++ -lm
#include "bridge.h"
*/
import "C"

// --- Go Structs ---
// These structs wrap the opaque C pointers.

type (
	Params        struct{ ptr C.ParamsPtr }
	CryptoContext struct{ ptr C.CryptoContextPtr }
	KeyPair       struct{ ptr C.KeyPairPtr }
	Plaintext     struct{ ptr C.PlaintextPtr }
	Ciphertext    struct{ ptr C.CiphertextPtr }
)

// --- Enums ---
const (
	PKE        = C.PKE_FEATURE
	KEYSWITCH  = C.KEYSWITCH_FEATURE
	LEVELEDSHE = C.LEVELEDSHE_FEATURE
)

// --- CCParams Methods ---

func NewParamsBFVrns() *Params {
	// 1. Create the C++ object
	p := &Params{ptr: C.NewParamsBFVrns()}
	// 2. Set a finalizer to auto-delete the C++ object when Go's GC collects it
	runtime.SetFinalizer(p, func(obj *Params) {
		C.DestroyParams(obj.ptr)
	})
	return p
}

func (p *Params) SetPlaintextModulus(mod uint64) {
	C.Params_SetPlaintextModulus(p.ptr, C.uint64_t(mod))
}

func (p *Params) SetMultiplicativeDepth(depth int) {
	C.Params_SetMultiplicativeDepth(p.ptr, C.int(depth))
}

// --- CryptoContext Methods ---

func NewCryptoContext(p *Params) *CryptoContext {
	cc := &CryptoContext{ptr: C.NewCryptoContext(p.ptr)}
	runtime.SetFinalizer(cc, func(obj *CryptoContext) {
		C.DestroyCryptoContext(obj.ptr)
	})
	return cc
}

func (cc *CryptoContext) Enable(feature int) {
	C.CryptoContext_Enable(cc.ptr, C.int(feature))
}

func (cc *CryptoContext) KeyGen() *KeyPair {
	kp := &KeyPair{ptr: C.CryptoContext_KeyGen(cc.ptr)}
	runtime.SetFinalizer(kp, func(obj *KeyPair) {
		C.DestroyKeyPair(obj.ptr)
	})
	return kp
}

func (cc *CryptoContext) EvalMultKeyGen(keys *KeyPair) {
	C.CryptoContext_EvalMultKeyGen(cc.ptr, keys.ptr)
}

func (cc *CryptoContext) EvalRotateKeyGen(keys *KeyPair, indices []int) {
	if len(indices) == 0 {
		return
	}
	// Get a C-style pointer to the first element of the Go slice
	cIndices := (*C.int)(unsafe.Pointer(&indices[0]))
	cLen := C.int(len(indices))
	C.CryptoContext_EvalRotateKeyGen(cc.ptr, keys.ptr, cIndices, cLen)
}

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

func (cc *CryptoContext) Encrypt(keys *KeyPair, pt *Plaintext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_Encrypt(cc.ptr, keys.ptr, pt.ptr)}
	runtime.SetFinalizer(ct, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return ct
}

func (cc *CryptoContext) EvalAdd(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalAdd(cc.ptr, ct1.ptr, ct2.ptr)}
	runtime.SetFinalizer(ct, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return ct
}

func (cc *CryptoContext) EvalMult(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalMult(cc.ptr, ct1.ptr, ct2.ptr)}
	runtime.SetFinalizer(ct, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return ct
}

func (cc *CryptoContext) EvalRotate(ct *Ciphertext, index int) *Ciphertext {
	resCt := &Ciphertext{ptr: C.CryptoContext_EvalRotate(cc.ptr, ct.ptr, C.int(index))}
	runtime.SetFinalizer(resCt, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return resCt
}

func (cc *CryptoContext) Decrypt(keys *KeyPair, ct *Ciphertext) *Plaintext {
	pt := &Plaintext{ptr: C.CryptoContext_Decrypt(cc.ptr, keys.ptr, ct.ptr)}
	runtime.SetFinalizer(pt, func(obj *Plaintext) {
		C.DestroyPlaintext(obj.ptr)
	})
	return pt
}

// --- Plaintext Methods ---

func (pt *Plaintext) GetPackedValue() []int64 {
	// We use our C-API accessors to safely copy the data from C++ to Go
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

// This helper function truncates the vector for printing
func truncateVector(vec []int64, maxLen int) []int64 {
	if len(vec) > maxLen {
		return vec[:maxLen]
	}
	return vec
}

// --- main() ---
// This is the Go equivalent of the Python script

func main() {
	fmt.Println("--- Go simple-integers example starting ---")

	// 1. Set up parameters
	parameters := NewParamsBFVrns()
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	fmt.Println("Parameters set.")

	// 2. Generate CryptoContext
	cc := NewCryptoContext(parameters)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	fmt.Println("CryptoContext generated.")

	// 3. Key Generation
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	cc.EvalRotateKeyGen(keys, []int{1, -2})
	fmt.Println("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	fmt.Printf("Plaintext: %v\n", truncateVector(vectorOfInts, 12))
	fmt.Println("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add := cc.EvalAdd(ciphertext, ciphertext)
	ciphertext_mul := cc.EvalMult(ciphertext, ciphertext)
	ciphertext_rot1 := cc.EvalRotate(ciphertext, 1)
	ciphertext_rot2 := cc.EvalRotate(ciphertext, -2)
	fmt.Println("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add := cc.Decrypt(keys, ciphertext_add)
	plaintext_dec_mul := cc.Decrypt(keys, ciphertext_mul)
	plaintext_dec_rot1 := cc.Decrypt(keys, ciphertext_rot1)
	plaintext_dec_rot2 := cc.Decrypt(keys, ciphertext_rot2)
	fmt.Println("Decryption complete.")

	// 7. Print results
	fmt.Println("\n--- Results ---")
	fmt.Printf("Original vector:        %v\n", truncateVector(vectorOfInts, 12))
	fmt.Printf("Decrypted Add (v+v):    %v\n", truncateVector(plaintext_dec_add.GetPackedValue(), 12))
	fmt.Printf("Decrypted Mult (v*v):   %v\n", truncateVector(plaintext_dec_mul.GetPackedValue(), 12))
	fmt.Printf("Decrypted Rotate(v, 1): %v\n", truncateVector(plaintext_dec_rot1.GetPackedValue(), 12))
	fmt.Printf("Decrypted Rotate(v,-2): %v\n", truncateVector(plaintext_dec_rot2.GetPackedValue(), 12))
}
