package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a -lc++ -lm
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// --- Common CryptoContext Methods ---
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
	runtime.SetFinalizer(ct, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return ct
}

func (cc *CryptoContext) Decrypt(keys *KeyPair, ct *Ciphertext) *Plaintext {
	pt := &Plaintext{ptr: C.CryptoContext_Decrypt(cc.ptr, keys.ptr, ct.ptr)}
	if pt.ptr == nil {
		// Decrypt can fail and return null
		return nil
	}
	runtime.SetFinalizer(pt, func(obj *Plaintext) {
		C.DestroyPlaintext(obj.ptr)
	})
	return pt
}

// --- Common Homomorphic Operations ---
func (cc *CryptoContext) EvalAdd(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalAdd(cc.ptr, ct1.ptr, ct2.ptr)}
	runtime.SetFinalizer(ct, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return ct
}

func (cc *CryptoContext) EvalSub(ct1, ct2 *Ciphertext) *Ciphertext {
	ct := &Ciphertext{ptr: C.CryptoContext_EvalSub(cc.ptr, ct1.ptr, ct2.ptr)}
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

func (cc *CryptoContext) EvalRotate(ct *Ciphertext, index int32) *Ciphertext {
	resCt := &Ciphertext{ptr: C.CryptoContext_EvalRotate(cc.ptr, ct.ptr, C.int32_t(index))}
	runtime.SetFinalizer(resCt, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return resCt
}
