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

// --- Multiparty Key Types ---

// PrivateKey wraps an OpenFHE private key (used in multiparty operations)
type PrivateKey struct {
	ptr C.PrivateKeyPtr
}

// PublicKey wraps an OpenFHE public key (used in multiparty operations)
type PublicKey struct {
	ptr C.PublicKeyPtr
}

// EvalKeyMap wraps an OpenFHE evaluation key map (used in multiparty eval key generation)
type EvalKeyMap struct {
	ptr C.EvalKeyMapPtr
}

// Close releases the C++ resources for PrivateKey
func (sk *PrivateKey) Close() {
	if sk.ptr != nil {
		C.DestroyPrivateKey(sk.ptr)
		sk.ptr = nil
	}
}

// Close releases the C++ resources for PublicKey
func (pk *PublicKey) Close() {
	if pk.ptr != nil {
		C.DestroyPublicKey(pk.ptr)
		pk.ptr = nil
	}
}

// Close releases the C++ resources for EvalKeyMap
func (ekm *EvalKeyMap) Close() {
	if ekm.ptr != nil {
		C.DestroyEvalKeyMap(ekm.ptr)
		ekm.ptr = nil
	}
}

// --- Helper Functions ---

// GetKeyTag returns the key tag associated with this private key
func (sk *PrivateKey) GetKeyTag() (string, error) {
	if sk.ptr == nil {
		return "", ErrPrivateKeyNil
	}

	var cKeyTag *C.char
	status := C.PrivateKey_GetKeyTag(sk.ptr, &cKeyTag)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return "", err
	}

	if cKeyTag == nil {
		return "", ErrNullString
	}

	keyTag := C.GoString(cKeyTag)
	C.free(unsafe.Pointer(cKeyTag))
	return keyTag, nil
}

// GetKeyTag returns the key tag associated with this public key
func (pk *PublicKey) GetKeyTag() (string, error) {
	if pk.ptr == nil {
		return "", ErrPublicKeyNil
	}

	var cKeyTag *C.char
	status := C.PublicKey_GetKeyTag(pk.ptr, &cKeyTag)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return "", err
	}

	if cKeyTag == nil {
		return "", ErrNullString
	}

	keyTag := C.GoString(cKeyTag)
	C.free(unsafe.Pointer(cKeyTag))
	return keyTag, nil
}

// --- Multiparty Key Generation ---

// MultipartyKeyGen generates a keypair from a vector of private keys (additive secret sharing)
func (cc *CryptoContext) MultipartyKeyGen(privateKeys []*PrivateKey) (*KeyPair, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(privateKeys) == 0 {
		return nil, ErrEmptySlice
	}

	// Convert Go slice to C array
	cPrivateKeys := make([]C.PrivateKeyPtr, len(privateKeys))
	for i, sk := range privateKeys {
		if sk == nil || sk.ptr == nil {
			return nil, fmt.Errorf("private key at index %d is nil", i)
		}
		cPrivateKeys[i] = sk.ptr
	}

	var outKP C.KeyPairPtr
	status := C.CryptoContext_MultipartyKeyGen_FromPrivateKeys(
		cc.ptr,
		&cPrivateKeys[0],
		C.size_t(len(cPrivateKeys)),
		&outKP,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outKP == nil {
		return nil, errors.New("MultipartyKeyGen returned null keypair")
	}

	return &KeyPair{ptr: outKP}, nil
}

// MultipartyKeyGenFromPublicKey generates a keypair that is compatible with an existing public key
func (cc *CryptoContext) MultipartyKeyGenFromPublicKey(publicKey *PublicKey, makeSparse bool, fresh bool) (*KeyPair, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if publicKey == nil || publicKey.ptr == nil {
		return nil, ErrPublicKeyArgNil
	}

	var outKP C.KeyPairPtr
	var cMakeSparse, cFresh C.int
	if makeSparse {
		cMakeSparse = 1
	}
	if fresh {
		cFresh = 1
	}

	status := C.CryptoContext_MultipartyKeyGen_FromPublicKey(
		cc.ptr,
		publicKey.ptr,
		cMakeSparse,
		cFresh,
		&outKP,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outKP == nil {
		return nil, errors.New("MultipartyKeyGenFromPublicKey returned null keypair")
	}

	return &KeyPair{ptr: outKP}, nil
}

// --- Multiparty Decryption ---

// MultipartyDecryptLead performs partial decryption by the lead party
func (cc *CryptoContext) MultipartyDecryptLead(ciphertexts []*Ciphertext, privateKey *PrivateKey) ([]*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(ciphertexts) == 0 {
		return nil, ErrEmptySlice
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	// Convert Go slice to C array
	cCiphertexts := make([]C.CiphertextPtr, len(ciphertexts))
	for i, ct := range ciphertexts {
		if ct == nil || ct.ptr == nil {
			return nil, fmt.Errorf("ciphertext at index %d is nil", i)
		}
		cCiphertexts[i] = ct.ptr
	}

	// Allocate output array
	cPartials := make([]C.CiphertextPtr, len(ciphertexts))

	status := C.CryptoContext_MultipartyDecryptLead(
		cc.ptr,
		&cCiphertexts[0],
		C.size_t(len(cCiphertexts)),
		privateKey.ptr,
		&cPartials[0],
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	// Convert C array back to Go slice
	partials := make([]*Ciphertext, len(cPartials))
	for i, cPtr := range cPartials {
		if cPtr == nil {
			return nil, fmt.Errorf("MultipartyDecryptLead returned null ciphertext at index %d", i)
		}
		partials[i] = &Ciphertext{ptr: cPtr}
	}

	return partials, nil
}

// MultipartyDecryptMain performs partial decryption by a main party (non-lead)
func (cc *CryptoContext) MultipartyDecryptMain(ciphertexts []*Ciphertext, privateKey *PrivateKey) ([]*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(ciphertexts) == 0 {
		return nil, ErrEmptySlice
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	// Convert Go slice to C array
	cCiphertexts := make([]C.CiphertextPtr, len(ciphertexts))
	for i, ct := range ciphertexts {
		if ct == nil || ct.ptr == nil {
			return nil, fmt.Errorf("ciphertext at index %d is nil", i)
		}
		cCiphertexts[i] = ct.ptr
	}

	// Allocate output array
	cPartials := make([]C.CiphertextPtr, len(ciphertexts))

	status := C.CryptoContext_MultipartyDecryptMain(
		cc.ptr,
		&cCiphertexts[0],
		C.size_t(len(cCiphertexts)),
		privateKey.ptr,
		&cPartials[0],
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	// Convert C array back to Go slice
	partials := make([]*Ciphertext, len(cPartials))
	for i, cPtr := range cPartials {
		if cPtr == nil {
			return nil, fmt.Errorf("MultipartyDecryptMain returned null ciphertext at index %d", i)
		}
		partials[i] = &Ciphertext{ptr: cPtr}
	}

	return partials, nil
}

// MultipartyDecryptFusion fuses partial decryptions from all parties into the final plaintext
func (cc *CryptoContext) MultipartyDecryptFusion(partialCiphertexts []*Ciphertext) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if len(partialCiphertexts) == 0 {
		return nil, ErrEmptySlice
	}

	// Convert Go slice to C array
	cPartials := make([]C.CiphertextPtr, len(partialCiphertexts))
	for i, ct := range partialCiphertexts {
		if ct == nil || ct.ptr == nil {
			return nil, fmt.Errorf("partial ciphertext at index %d is nil", i)
		}
		cPartials[i] = ct.ptr
	}

	var outPT C.PlaintextPtr
	status := C.CryptoContext_MultipartyDecryptFusion(
		cc.ptr,
		&cPartials[0],
		C.size_t(len(cPartials)),
		&outPT,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outPT == nil {
		return nil, errors.New("MultipartyDecryptFusion returned null plaintext")
	}

	return &Plaintext{ptr: outPT}, nil
}

// --- Multiparty Evaluation Key Generation ---

// KeySwitchGen generates a key switching key from old to new private key
// This is the base function used before MultiKeySwitchGen in multiparty workflows
func (cc *CryptoContext) KeySwitchGen(oldPrivateKey, newPrivateKey *PrivateKey) (*EvalKey, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if oldPrivateKey == nil || oldPrivateKey.ptr == nil {
		return nil, errors.New("oldPrivateKey is nil")
	}

	if newPrivateKey == nil || newPrivateKey.ptr == nil {
		return nil, errors.New("newPrivateKey is nil")
	}

	var outEK C.EvalKeyPtr
	status := C.CryptoContext_KeySwitchGen(
		cc.ptr,
		oldPrivateKey.ptr,
		newPrivateKey.ptr,
		&outEK,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEK == nil {
		return nil, errors.New("KeySwitchGen returned null eval key")
	}

	return &EvalKey{ptr: outEK}, nil
}

// InsertEvalMultKey inserts evaluation mult keys into the crypto context
func (cc *CryptoContext) InsertEvalMultKey(evalKeys []*EvalKey) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}

	if len(evalKeys) == 0 {
		return errors.New("evalKeys slice is empty")
	}

	// Convert Go slice to C array
	cEvalKeys := make([]C.EvalKeyPtr, len(evalKeys))
	for i, ek := range evalKeys {
		if ek == nil || ek.ptr == nil {
			return fmt.Errorf("eval key at index %d is nil", i)
		}
		cEvalKeys[i] = ek.ptr
	}

	status := C.CryptoContext_InsertEvalMultKey(
		cc.ptr,
		&cEvalKeys[0],
		C.size_t(len(cEvalKeys)),
	)

	return checkPKEErrorMsg(status)
}

// InsertEvalSumKey inserts evaluation sum keys into the crypto context
func (cc *CryptoContext) InsertEvalSumKey(evalKeyMap *EvalKeyMap) error {
	if cc.ptr == nil {
		return ErrContextClosed
	}

	if evalKeyMap == nil || evalKeyMap.ptr == nil {
		return errors.New("evalKeyMap is nil")
	}

	status := C.CryptoContext_InsertEvalSumKey(cc.ptr, evalKeyMap.ptr)
	return checkPKEErrorMsg(status)
}

// MultiKeySwitchGen generates a multiparty key switching key
func (cc *CryptoContext) MultiKeySwitchGen(oldPrivateKey, newPrivateKey *PrivateKey, evalKey *EvalKey) (*EvalKey, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if oldPrivateKey == nil || oldPrivateKey.ptr == nil {
		return nil, errors.New("oldPrivateKey is nil")
	}

	if newPrivateKey == nil || newPrivateKey.ptr == nil {
		return nil, errors.New("newPrivateKey is nil")
	}

	if evalKey == nil || evalKey.ptr == nil {
		return nil, ErrEvalKeyArgNil
	}

	var outEK C.EvalKeyPtr
	status := C.CryptoContext_MultiKeySwitchGen(
		cc.ptr,
		oldPrivateKey.ptr,
		newPrivateKey.ptr,
		evalKey.ptr,
		&outEK,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEK == nil {
		return nil, errors.New("MultiKeySwitchGen returned null eval key")
	}

	return &EvalKey{ptr: outEK}, nil
}

// MultiEvalSumKeyGen generates a multiparty evaluation sum key
func (cc *CryptoContext) MultiEvalSumKeyGen(privateKey *PrivateKey, evalKeyMap *EvalKeyMap, keyTag string) (*EvalKeyMap, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	var ekmPtr C.EvalKeyMapPtr
	if evalKeyMap != nil {
		ekmPtr = evalKeyMap.ptr
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEKM C.EvalKeyMapPtr
	status := C.CryptoContext_MultiEvalSumKeyGen(
		cc.ptr,
		privateKey.ptr,
		ekmPtr,
		cKeyTag,
		&outEKM,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEKM == nil {
		return nil, errors.New("MultiEvalSumKeyGen returned null eval key map")
	}

	return &EvalKeyMap{ptr: outEKM}, nil
}

// MultiEvalAtIndexKeyGen generates multiparty evaluation keys for rotation at specific indices
func (cc *CryptoContext) MultiEvalAtIndexKeyGen(privateKey *PrivateKey, evalKeyMap *EvalKeyMap, indices []int32, keyTag string) (*EvalKeyMap, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	if len(indices) == 0 {
		return nil, errors.New("indices slice is empty")
	}

	var ekmPtr C.EvalKeyMapPtr
	if evalKeyMap != nil {
		ekmPtr = evalKeyMap.ptr
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEKM C.EvalKeyMapPtr
	status := C.CryptoContext_MultiEvalAtIndexKeyGen(
		cc.ptr,
		privateKey.ptr,
		ekmPtr,
		(*C.int32_t)(unsafe.Pointer(&indices[0])),
		C.size_t(len(indices)),
		cKeyTag,
		&outEKM,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEKM == nil {
		return nil, errors.New("MultiEvalAtIndexKeyGen returned null eval key map")
	}

	return &EvalKeyMap{ptr: outEKM}, nil
}

// MultiMultEvalKey transforms a joint evaluation key for multiparty multiplication
func (cc *CryptoContext) MultiMultEvalKey(privateKey *PrivateKey, evalKey *EvalKey, keyTag string) (*EvalKey, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	if evalKey == nil || evalKey.ptr == nil {
		return nil, ErrEvalKeyArgNil
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEK C.EvalKeyPtr
	status := C.CryptoContext_MultiMultEvalKey(
		cc.ptr,
		privateKey.ptr,
		evalKey.ptr,
		cKeyTag,
		&outEK,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEK == nil {
		return nil, errors.New("MultiMultEvalKey returned null eval key")
	}

	return &EvalKey{ptr: outEK}, nil
}

// --- Key Aggregation Functions ---

// MultiAddPubKeys aggregates two public keys
func (cc *CryptoContext) MultiAddPubKeys(pk1, pk2 *PublicKey, keyTag string) (*PublicKey, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if pk1 == nil || pk1.ptr == nil {
		return nil, errors.New("pk1 is nil")
	}

	if pk2 == nil || pk2.ptr == nil {
		return nil, errors.New("pk2 is nil")
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outPK C.PublicKeyPtr
	status := C.CryptoContext_MultiAddPubKeys(
		cc.ptr,
		pk1.ptr,
		pk2.ptr,
		cKeyTag,
		&outPK,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outPK == nil {
		return nil, errors.New("MultiAddPubKeys returned null public key")
	}

	return &PublicKey{ptr: outPK}, nil
}

// MultiAddEvalKeys aggregates two evaluation keys
func (cc *CryptoContext) MultiAddEvalKeys(ek1, ek2 *EvalKey, keyTag string) (*EvalKey, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ek1 == nil || ek1.ptr == nil {
		return nil, errors.New("ek1 is nil")
	}

	if ek2 == nil || ek2.ptr == nil {
		return nil, errors.New("ek2 is nil")
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEK C.EvalKeyPtr
	status := C.CryptoContext_MultiAddEvalKeys(
		cc.ptr,
		ek1.ptr,
		ek2.ptr,
		cKeyTag,
		&outEK,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEK == nil {
		return nil, errors.New("MultiAddEvalKeys returned null eval key")
	}

	return &EvalKey{ptr: outEK}, nil
}

// MultiAddEvalMultKeys aggregates two multiplication evaluation keys
func (cc *CryptoContext) MultiAddEvalMultKeys(ek1, ek2 *EvalKey, keyTag string) (*EvalKey, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ek1 == nil || ek1.ptr == nil {
		return nil, errors.New("ek1 is nil")
	}

	if ek2 == nil || ek2.ptr == nil {
		return nil, errors.New("ek2 is nil")
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEK C.EvalKeyPtr
	status := C.CryptoContext_MultiAddEvalMultKeys(
		cc.ptr,
		ek1.ptr,
		ek2.ptr,
		cKeyTag,
		&outEK,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEK == nil {
		return nil, errors.New("MultiAddEvalMultKeys returned null eval key")
	}

	return &EvalKey{ptr: outEK}, nil
}

// MultiAddEvalSumKeys aggregates two evaluation sum key maps
func (cc *CryptoContext) MultiAddEvalSumKeys(ekm1, ekm2 *EvalKeyMap, keyTag string) (*EvalKeyMap, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ekm1 == nil || ekm1.ptr == nil {
		return nil, errors.New("ekm1 is nil")
	}

	if ekm2 == nil || ekm2.ptr == nil {
		return nil, errors.New("ekm2 is nil")
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEKM C.EvalKeyMapPtr
	status := C.CryptoContext_MultiAddEvalSumKeys(
		cc.ptr,
		ekm1.ptr,
		ekm2.ptr,
		cKeyTag,
		&outEKM,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEKM == nil {
		return nil, errors.New("MultiAddEvalSumKeys returned null eval key map")
	}

	return &EvalKeyMap{ptr: outEKM}, nil
}

// MultiAddEvalAutomorphismKeys aggregates two evaluation automorphism key maps
func (cc *CryptoContext) MultiAddEvalAutomorphismKeys(ekm1, ekm2 *EvalKeyMap, keyTag string) (*EvalKeyMap, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ekm1 == nil || ekm1.ptr == nil {
		return nil, errors.New("ekm1 is nil")
	}

	if ekm2 == nil || ekm2.ptr == nil {
		return nil, errors.New("ekm2 is nil")
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outEKM C.EvalKeyMapPtr
	status := C.CryptoContext_MultiAddEvalAutomorphismKeys(
		cc.ptr,
		ekm1.ptr,
		ekm2.ptr,
		cKeyTag,
		&outEKM,
	)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outEKM == nil {
		return nil, errors.New("MultiAddEvalAutomorphismKeys returned null eval key map")
	}

	return &EvalKeyMap{ptr: outEKM}, nil
}

// --- Interactive Bootstrapping Functions ---

// IntBootAdjustScale adjusts the ciphertext scale for interactive bootstrapping.
// This is the first step in the 2-party interactive bootstrapping protocol.
// It reduces the ciphertext to two towers (RNS limbs).
func (cc *CryptoContext) IntBootAdjustScale(ciphertext *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, ErrCiphertextArgNil
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntBootAdjustScale(cc.ptr, ciphertext.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntBootAdjustScale returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}

// IntBootDecrypt performs masked decryption for interactive bootstrapping.
// For the server (lead party): c0 = b + a*s0
// For the client (main party): c1 = a*s1
// This is the second step in the 2-party interactive bootstrapping protocol.
func (cc *CryptoContext) IntBootDecrypt(privateKey *PrivateKey, ciphertext *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if privateKey == nil || privateKey.ptr == nil {
		return nil, ErrPrivateKeyArgNil
	}

	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, ErrCiphertextArgNil
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntBootDecrypt(cc.ptr, privateKey.ptr, ciphertext.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntBootDecrypt returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}

// IntBootEncrypt encrypts the masked decryption result from the client.
// This encrypts the result of IntBootDecrypt (c1 = a*s1) using the client's public key.
// This is the third step in the 2-party interactive bootstrapping protocol (client-side).
func (cc *CryptoContext) IntBootEncrypt(publicKey *PublicKey, ciphertext *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if publicKey == nil || publicKey.ptr == nil {
		return nil, ErrPublicKeyArgNil
	}

	if ciphertext == nil || ciphertext.ptr == nil {
		return nil, ErrCiphertextArgNil
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntBootEncrypt(cc.ptr, publicKey.ptr, ciphertext.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntBootEncrypt returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}

// IntBootAdd adds the encrypted masked decryption to the server's masked decryption.
// Computes: Enc(c1) + c0
// This is the final step in the 2-party interactive bootstrapping protocol (server-side).
func (cc *CryptoContext) IntBootAdd(ciphertext1, ciphertext2 *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, ErrContextClosed
	}

	if ciphertext1 == nil || ciphertext1.ptr == nil {
		return nil, errors.New("ciphertext1 is nil")
	}

	if ciphertext2 == nil || ciphertext2.ptr == nil {
		return nil, errors.New("ciphertext2 is nil")
	}

	var outCT C.CiphertextPtr
	status := C.CryptoContext_IntBootAdd(cc.ptr, ciphertext1.ptr, ciphertext2.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("IntBootAdd returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}
