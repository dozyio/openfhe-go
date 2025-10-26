package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// --- CryptoContext Serialization ---

func SerializeCryptoContextToString(cc *CryptoContext) (string, error) {
	var cStr *C.char
	size := C.SerializeCryptoContextToString(cc.ptr, &cStr)
	if size == 0 || cStr == nil {
		return "", fmt.Errorf("cryptocontext serialization failed")
	}
	goStr := C.GoStringN(cStr, C.int(size))
	C.FreeString(cStr) // Free memory allocated by C++
	return goStr, nil
}

func DeserializeCryptoContextFromString(s string) *CryptoContext {
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))

	ccPtr := C.DeserializeCryptoContextFromString(cStr)
	if ccPtr == nil {
		return nil // Indicate failure
	}

	cc := &CryptoContext{ptr: ccPtr}
	runtime.SetFinalizer(cc, func(obj *CryptoContext) {
		C.DestroyCryptoContext(obj.ptr)
	})
	return cc
}

// --- PublicKey Serialization ---

func SerializePublicKeyToString(kp *KeyPair) (string, error) {
	var cStr *C.char
	size := C.SerializePublicKeyToString(kp.ptr, &cStr)
	if size == 0 || cStr == nil {
		return "", fmt.Errorf("public key serialization failed")
	}
	goStr := C.GoStringN(cStr, C.int(size))
	C.FreeString(cStr)
	return goStr, nil
}

// DeserializePublicKeyFromString returns a *new* KeyPair containing *only* the public key.
func DeserializePublicKeyFromString(s string) *KeyPair {
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))

	kpPtr := C.DeserializePublicKeyFromString(cStr)
	if kpPtr == nil {
		return nil
	}

	kp := &KeyPair{ptr: kpPtr}
	runtime.SetFinalizer(kp, func(obj *KeyPair) {
		C.DestroyKeyPair(obj.ptr)
	})
	return kp
}

// --- PrivateKey Serialization ---

func SerializePrivateKeyToString(kp *KeyPair) (string, error) {
	var cStr *C.char
	size := C.SerializePrivateKeyToString(kp.ptr, &cStr)
	if size == 0 || cStr == nil {
		return "", fmt.Errorf("private key serialization failed")
	}
	goStr := C.GoStringN(cStr, C.int(size))
	C.FreeString(cStr)
	return goStr, nil
}

// DeserializePrivateKeyFromString returns a *new* KeyPair containing *only* the private key.
func DeserializePrivateKeyFromString(s string) *KeyPair {
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))

	kpPtr := C.DeserializePrivateKeyFromString(cStr)
	if kpPtr == nil {
		return nil
	}

	kp := &KeyPair{ptr: kpPtr}
	runtime.SetFinalizer(kp, func(obj *KeyPair) {
		C.DestroyKeyPair(obj.ptr)
	})
	return kp
}

// --- EvalMultKey Serialization ---

// SerializeEvalMultKeyToString serializes the relin/evalmult keys stored *within* the CryptoContext.
// Assumes EvalMultKeyGen has been called. The keyId is typically the secret key ID.
func SerializeEvalMultKeyToString(cc *CryptoContext, keyId string) (string, error) {
	cKeyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(cKeyId))

	var cStr *C.char
	size := C.SerializeEvalMultKeyToString(cc.ptr, cKeyId, &cStr)
	if size == 0 || cStr == nil {
		return "", fmt.Errorf("eval mult key serialization failed (keyId: %s)", keyId)
	}
	goStr := C.GoStringN(cStr, C.int(size))
	C.FreeString(cStr)
	return goStr, nil
}

// DeserializeEvalMultKeyFromString loads the relin/evalmult keys *into* the provided CryptoContext.
func DeserializeEvalMultKeyFromString(cc *CryptoContext, s string) error {
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))

	C.DeserializeEvalMultKeyFromString(cc.ptr, cStr)
	// NOTE: C++ side doesn't easily return error status here. Assume success if no crash.
	return nil
}

// --- Ciphertext Serialization ---

func SerializeCiphertextToString(ct *Ciphertext) (string, error) {
	var cStr *C.char
	size := C.SerializeCiphertextToString(ct.ptr, &cStr)
	if size == 0 || cStr == nil {
		return "", fmt.Errorf("ciphertext serialization failed")
	}
	goStr := C.GoStringN(cStr, C.int(size))
	C.FreeString(cStr)
	return goStr, nil
}

func DeserializeCiphertextFromString(s string) *Ciphertext {
	cStr := C.CString(s)
	defer C.free(unsafe.Pointer(cStr))

	ctPtr := C.DeserializeCiphertextFromString(cStr)
	if ctPtr == nil {
		return nil
	}

	ct := &Ciphertext{ptr: ctPtr}
	runtime.SetFinalizer(ct, func(obj *Ciphertext) {
		C.DestroyCiphertext(obj.ptr)
	})
	return ct
}

// --- Helper for KeyPair Reconstruction ---

// NewKeyPair creates an empty KeyPair struct. Useful for combining deserialized keys.
func NewKeyPair() *KeyPair {
	kp := &KeyPair{ptr: C.NewKeyPair()}
	runtime.SetFinalizer(kp, func(obj *KeyPair) {
		C.DestroyKeyPair(obj.ptr)
	})
	return kp
}

// GetPublicKey extracts the public key part from a KeyPair.
// Returns a temporary pointer managed by Go's garbage collector.
func (kp *KeyPair) GetPublicKey() unsafe.Pointer {
	pkPtr := C.GetPublicKey(kp.ptr)
	if pkPtr == nil {
		return nil
	}
	// No finalizer needed here as SetPublicKey should consume this pointer
	return pkPtr
}

// GetPrivateKey extracts the private key part from a KeyPair.
// Returns a temporary pointer managed by Go's garbage collector.
func (kp *KeyPair) GetPrivateKey() unsafe.Pointer {
	skPtr := C.GetPrivateKey(kp.ptr)
	if skPtr == nil {
		return nil
	}
	// No finalizer needed here as SetPrivateKey should consume this pointer
	return skPtr
}

// SetPublicKey sets the public key part of an existing KeyPair.
// It takes the temporary pointer returned by GetPublicKey or a deserialization.
func (kp *KeyPair) SetPublicKey(pkPtr unsafe.Pointer) {
	if pkPtr != nil {
		C.SetPublicKey(kp.ptr, pkPtr)
	}
}

// SetPrivateKey sets the private key part of an existing KeyPair.
// It takes the temporary pointer returned by GetPrivateKey or a deserialization.
func (kp *KeyPair) SetPrivateKey(skPtr unsafe.Pointer) {
	if skPtr != nil {
		C.SetPrivateKey(kp.ptr, skPtr)
	}
}
