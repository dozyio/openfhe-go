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

func SerializeCryptoContextToBytes(cc *CryptoContext) ([]byte, error) {
	var cBytes *C.char
	size := C.SerializeCryptoContextToBytes(cc.ptr, &cBytes)
	if size == 0 || cBytes == nil {
		return nil, fmt.Errorf("cryptocontext serialization failed")
	}
	goBytes := C.GoBytes(unsafe.Pointer(cBytes), C.int(size))
	C.FreeString(cBytes) // Free memory allocated by C++
	return goBytes, nil
}

func DeserializeCryptoContextFromBytes(data []byte) *CryptoContext {
	if len(data) == 0 {
		return nil // Indicate failure
	}
	cData := (*C.char)(unsafe.Pointer(&data[0]))
	cLen := C.int(len(data))

	ccPtr := C.DeserializeCryptoContextFromBytes(cData, cLen)
	if ccPtr == nil {
		return nil // Indicate failure
	}

	cc := &CryptoContext{ptr: ccPtr}
	return cc
}

// --- PublicKey Serialization ---

func SerializePublicKeyToBytes(kp *KeyPair) ([]byte, error) {
	var cBytes *C.char
	size := C.SerializePublicKeyToBytes(kp.ptr, &cBytes)
	if size == 0 || cBytes == nil {
		return nil, fmt.Errorf("public key serialization failed")
	}
	goBytes := C.GoBytes(unsafe.Pointer(cBytes), C.int(size))
	C.FreeString(cBytes)
	return goBytes, nil
}

// DeserializePublicKeyFromBytes returns a *new* KeyPair containing *only* the public key.
func DeserializePublicKeyFromBytes(data []byte) *KeyPair {
	if len(data) == 0 {
		return nil // Indicate failure
	}
	cData := (*C.char)(unsafe.Pointer(&data[0]))
	cLen := C.int(len(data))

	kpPtr := C.DeserializePublicKeyFromBytes(cData, cLen)
	if kpPtr == nil {
		return nil
	}

	kp := &KeyPair{ptr: kpPtr}
	return kp
}

// --- PrivateKey Serialization ---

func SerializePrivateKeyToBytes(kp *KeyPair) ([]byte, error) {
	var cBytes *C.char
	size := C.SerializePrivateKeyToBytes(kp.ptr, &cBytes)
	if size == 0 || cBytes == nil {
		return nil, fmt.Errorf("private key serialization failed")
	}
	goBytes := C.GoBytes(unsafe.Pointer(cBytes), C.int(size))
	C.FreeString(cBytes)
	return goBytes, nil
}

// DeserializePrivateKeyFromBytes returns a *new* KeyPair containing *only* the private key.
func DeserializePrivateKeyFromBytes(data []byte) *KeyPair {
	if len(data) == 0 {
		return nil
	}
	cData := (*C.char)(unsafe.Pointer(&data[0]))
	cLen := C.int(len(data))
	kpPtr := C.DeserializePrivateKeyFromBytes(cData, cLen)
	if kpPtr == nil {
		return nil
	}
	kp := &KeyPair{ptr: kpPtr}
	return kp
}

// --- EvalMultKey Serialization ---

// SerializeEvalMultKeyToBytes serializes the relin/evalmult keys stored *within* the CryptoContext.
func SerializeEvalMultKeyToBytes(cc *CryptoContext, keyId string) ([]byte, error) {
	cKeyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(cKeyId))

	var cBytes *C.char
	size := C.SerializeEvalMultKeyToBytes(cc.ptr, cKeyId, &cBytes)
	if size == 0 || cBytes == nil {
		return nil, fmt.Errorf("eval mult key serialization failed (keyId: %s)", keyId)
	}
	goBytes := C.GoBytes(unsafe.Pointer(cBytes), C.int(size))
	C.FreeString(cBytes)
	return goBytes, nil
}

// DeserializeEvalMultKeyFromBytes loads the relin/evalmult keys *into* the provided CryptoContext.
func DeserializeEvalMultKeyFromBytes(cc *CryptoContext, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot deserialize eval mult key from empty data")
	}
	cData := (*C.char)(unsafe.Pointer(&data[0]))
	cLen := C.int(len(data))

	C.DeserializeEvalMultKeyFromBytes(cc.ptr, cData, cLen)
	// NOTE: C++ side doesn't easily return error status here.
	// The C++ side now catches exceptions, so we assume success if no crash.
	return nil
}

// --- Ciphertext Serialization ---

func SerializeCiphertextToBytes(ct *Ciphertext) ([]byte, error) {
	var cBytes *C.char
	size := C.SerializeCiphertextToBytes(ct.ptr, &cBytes)
	if size == 0 || cBytes == nil {
		return nil, fmt.Errorf("ciphertext serialization failed")
	}
	goBytes := C.GoBytes(unsafe.Pointer(cBytes), C.int(size))
	C.FreeString(cBytes)
	return goBytes, nil
}

func DeserializeCiphertextFromBytes(data []byte) *Ciphertext {
	if len(data) == 0 {
		return nil // Indicate failure
	}
	cData := (*C.char)(unsafe.Pointer(&data[0]))
	cLen := C.int(len(data))

	ctPtr := C.DeserializeCiphertextFromBytes(cData, cLen)
	if ctPtr == nil {
		return nil
	}

	ct := &Ciphertext{ptr: ctPtr}
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
