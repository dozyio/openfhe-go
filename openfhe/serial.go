package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdlib.h>
#include "pke_common_c.h"
*/
import "C"

import (
	"errors"
	"fmt"
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
	// No finalizer
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
	// No finalizer
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
	// No finalizer
	return ct
}

// --- Helper for KeyPair Reconstruction ---

// NewKeyPair creates an empty KeyPair struct. Useful for combining deserialized keys.
func NewKeyPair() (*KeyPair, error) {
	var kpH C.KeyPairPtr
	status := C.NewKeyPair(&kpH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if kpH == nil {
		return nil, errors.New("NewKeyPair returned OK but null handle")
	}
	kp := &KeyPair{ptr: kpH}
	return kp, nil
}

// GetPublicKey extracts the public key part from a KeyPair.
func (kp *KeyPair) GetPublicKey() (unsafe.Pointer, error) {
	if kp.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}
	var pkH unsafe.Pointer
	status := C.GetPublicKey(kp.ptr, &pkH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if pkH == nil {
		return nil, errors.New("GetPublicKey returned OK but null handle")
	}
	return pkH, nil
}

// GetPrivateKey extracts the private key part from a KeyPair.
func (kp *KeyPair) GetPrivateKey() (unsafe.Pointer, error) {
	if kp.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}
	var skH unsafe.Pointer
	status := C.GetPrivateKey(kp.ptr, &skH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if skH == nil {
		return nil, errors.New("GetPrivateKey returned OK but null handle")
	}
	return skH, nil
}

// SetPublicKey sets the public key part of an existing KeyPair.
// It takes the temporary pointer returned by GetPublicKey or a deserialization.
func (kp *KeyPair) SetPublicKey(pkPtr unsafe.Pointer) error { // ADDED error
	if kp.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if pkPtr == nil {
		return errors.New("Input public key pointer is nil")
	}
	status := C.SetPublicKey(kp.ptr, pkPtr)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

// SetPrivateKey sets the private key part of an existing KeyPair.
// It takes the temporary pointer returned by GetPrivateKey or a deserialization.
func (kp *KeyPair) SetPrivateKey(skPtr unsafe.Pointer) error { // ADDED error
	if kp.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if skPtr == nil {
		return errors.New("Input private key pointer is nil")
	}
	status := C.SetPrivateKey(kp.ptr, skPtr)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}
