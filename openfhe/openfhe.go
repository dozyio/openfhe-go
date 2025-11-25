package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#include <stdint.h>
#include <stdlib.h>
#include "pke_common_c.h"
#include "ckks_c.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Interface for objects that need C++ memory released
type Closeable interface {
	Close()
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

// --- Key Switch Techniques ---
const (
	INVALID_KS_TECH = 0
	BV              = 1
	HYBRID          = 2
)

// --- Multiparty Modes ---
const (
	INVALID_MULTIPARTY_MODE   = 0
	FIXED_NOISE_MULTIPARTY    = 1
	NOISE_FLOODING_MULTIPARTY = 2
)

// --- Proxy Re-Encryption Modes ---
const (
	NOT_SET            = 0
	INDCPA             = 1
	FIXED_NOISE_HRA    = 2
	NOISE_FLOODING_HRA = 3
)

// --- Interactive Bootstrapping Compression Levels ---
const (
	COMPACT = 2 // More efficient with stronger security assumption
	SLACK   = 3 // Less efficient with weaker security assumption (default, more secure)
)

// --- Common CryptoContext Methods ---
func (cc *CryptoContext) Enable(feature int) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	status := C.CryptoContext_Enable(cc.ptr, C.int(feature))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CryptoContext) KeyGen() (*KeyPair, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	var kpH C.KeyPairPtr
	status := C.CryptoContext_KeyGen(cc.ptr, &kpH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if kpH == nil {
		return nil, errors.New("KeyGen returned OK but null handle")
	}

	kp := &KeyPair{ptr: kpH}

	return kp, nil
}

func (cc *CryptoContext) EvalMultKeyGen(keys *KeyPair) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	status := C.CryptoContext_EvalMultKeyGen(cc.ptr, keys.ptr)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CryptoContext) EvalRotateKeyGen(keys *KeyPair, indices []int32) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if len(indices) == 0 {
		return nil // Nothing to do
	}
	cIndices := (*C.int32_t)(unsafe.Pointer(&indices[0]))
	cLen := C.int(len(indices))
	status := C.CryptoContext_EvalRotateKeyGen(cc.ptr, keys.ptr, cIndices, cLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CryptoContext) EvalAutomorphismKeyGen(keys *KeyPair, indices []uint32) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	if len(indices) == 0 {
		return nil // Nothing to do
	}
	cIndices := (*C.uint32_t)(unsafe.Pointer(&indices[0]))
	cLen := C.int(len(indices))
	status := C.CryptoContext_EvalAutomorphismKeyGen(cc.ptr, keys.ptr, cIndices, cLen)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CryptoContext) GetEvalAutomorphismKeyMap(keyTag string) *EvalKeyMap {
	if cc.ptr == nil {
		return nil
	}
	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	mapPtr := C.CryptoContext_GetEvalAutomorphismKeyMap(cc.ptr, cKeyTag)
	if mapPtr == nil {
		return nil
	}

	return &EvalKeyMap{ptr: mapPtr}
}

func (cc *CryptoContext) Encrypt(keys *KeyPair, pt *Plaintext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}
	if pt == nil || pt.ptr == nil {
		return nil, errors.New("Plaintext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_Encrypt(cc.ptr, keys.ptr, pt.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("Encrypt returned OK but null handle")
	}
	ct := &Ciphertext{ptr: ctH}
	return ct, nil
}

func (cc *CryptoContext) Decrypt(keys *KeyPair, ct *Ciphertext) (*Plaintext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return nil, errors.New("KeyPair is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}
	var ptH C.PlaintextPtr
	status := C.CryptoContext_Decrypt(cc.ptr, keys.ptr, ct.ptr, &ptH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ptH == nil {
		// Decrypt can fail and return null
		return nil, errors.New("Decrypt returned OK but null handle (decryption failure)")
	}
	pt := &Plaintext{ptr: ptH}
	return pt, nil
}

// --- Common Homomorphic Operations ---
func (cc *CryptoContext) EvalAdd(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct1 == nil || ct1.ptr == nil || ct2 == nil || ct2.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalAdd(cc.ptr, ct1.ptr, ct2.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalAdd returned OK but null handle")
	}
	ct := &Ciphertext{ptr: ctH}
	return ct, nil
}

func (cc *CryptoContext) EvalSub(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct1 == nil || ct1.ptr == nil || ct2 == nil || ct2.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalSub(cc.ptr, ct1.ptr, ct2.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalSub returned OK but null handle")
	}
	ct := &Ciphertext{ptr: ctH}
	return ct, nil
}

func (cc *CryptoContext) EvalMult(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct1 == nil || ct1.ptr == nil || ct2 == nil || ct2.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalMult(cc.ptr, ct1.ptr, ct2.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalMult returned OK but null handle")
	}
	ct := &Ciphertext{ptr: ctH}
	return ct, nil
}

func (cc *CryptoContext) EvalAddPlain(ct *Ciphertext, pt *Plaintext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	if pt == nil || pt.ptr == nil {
		return nil, errors.New("Input Plaintext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalAddPlain(cc.ptr, ct.ptr, pt.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalAddPlain returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

func (cc *CryptoContext) EvalSubPlain(ct *Ciphertext, pt *Plaintext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	if pt == nil || pt.ptr == nil {
		return nil, errors.New("Input Plaintext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalSubPlain(cc.ptr, ct.ptr, pt.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalSubPlain returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

func (cc *CryptoContext) EvalMultPlain(ct *Ciphertext, pt *Plaintext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	if pt == nil || pt.ptr == nil {
		return nil, errors.New("Input Plaintext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalMultPlain(cc.ptr, ct.ptr, pt.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalMultPlain returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

func (cc *CryptoContext) EvalRotate(ct *Ciphertext, index int32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalRotate(cc.ptr, ct.ptr, C.int32_t(index), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalRotate returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

func (cc *CryptoContext) EvalAutomorphism(ct *Ciphertext, index uint32, evalKeyMap *EvalKeyMap) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	if evalKeyMap == nil || evalKeyMap.ptr == nil {
		return nil, errors.New("EvalKeyMap is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalAutomorphism(cc.ptr, ct.ptr, C.uint32_t(index), evalKeyMap.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalAutomorphism returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

func (cc *CryptoContext) EvalMerge(ciphertexts []*Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if len(ciphertexts) == 0 {
		return nil, errors.New("ciphertext array is empty")
	}

	// Convert Go slice to C array
	cCts := make([]C.CiphertextPtr, len(ciphertexts))
	for i, ct := range ciphertexts {
		if ct == nil || ct.ptr == nil {
			return nil, errors.New("Ciphertext in array is closed or invalid")
		}
		cCts[i] = ct.ptr
	}

	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalMerge(cc.ptr, &cCts[0], C.int(len(ciphertexts)), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalMerge returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

// FastRotationPrecompute holds precomputed values for fast rotation
type FastRotationPrecompute struct {
	ptr unsafe.Pointer
}

func (cc *CryptoContext) EvalFastRotationPrecompute(ct *Ciphertext) (*FastRotationPrecompute, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var precompH unsafe.Pointer
	status := C.CryptoContext_EvalFastRotationPrecompute(cc.ptr, ct.ptr, &precompH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if precompH == nil {
		return nil, errors.New("EvalFastRotationPrecompute returned OK but null handle")
	}
	precomp := &FastRotationPrecompute{ptr: precompH}
	return precomp, nil
}

func (cc *CryptoContext) EvalFastRotation(ct *Ciphertext, index int32, m uint32, precomp *FastRotationPrecompute) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	if precomp == nil || precomp.ptr == nil {
		return nil, errors.New("FastRotationPrecompute is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalFastRotation(cc.ptr, ct.ptr, C.int32_t(index), C.uint32_t(m), precomp.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalFastRotation returned OK but null handle")
	}
	resCt := &Ciphertext{ptr: ctH}
	return resCt, nil
}

func (p *FastRotationPrecompute) Close() {
	if p.ptr != nil {
		C.DestroyFastRotationPrecompute(p.ptr)
		p.ptr = nil
	}
}

// GetNativeInt returns the native integer size in bits (64 or 128)
func GetNativeInt() int {
	return int(C.GetNativeInt())
}

// --- CKKS Bootstrapping ---
func (cc *CryptoContext) EvalBootstrapKeyGen(keys *KeyPair, slots uint32) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if keys == nil || keys.ptr == nil {
		return errors.New("KeyPair is closed or invalid")
	}
	status := C.CryptoContext_EvalBootstrapKeyGen(cc.ptr, keys.ptr, C.uint32_t(slots))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CryptoContext) EvalBootstrap(ct *Ciphertext) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalBootstrap(cc.ptr, ct.ptr, &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalBootstrap returned OK but null handle")
	}
	res := &Ciphertext{ptr: ctH}
	return res, nil
}

// EvalBootstrapWithIterations performs iterative bootstrapping with specified number of iterations and precision.
// numIterations: number of bootstrapping iterations (typically 1 or 2)
// precision: measured precision from first iteration (set to 0 if unknown)
func (cc *CryptoContext) EvalBootstrapWithIterations(ct *Ciphertext, numIterations, precision uint32) (*Ciphertext, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}
	if ct == nil || ct.ptr == nil {
		return nil, errors.New("Input Ciphertext is closed or invalid")
	}
	var ctH C.CiphertextPtr
	status := C.CryptoContext_EvalBootstrapWithIterations(cc.ptr, ct.ptr, C.uint32_t(numIterations), C.uint32_t(precision), &ctH)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}
	if ctH == nil {
		return nil, errors.New("EvalBootstrapWithIterations returned OK but null handle")
	}
	res := &Ciphertext{ptr: ctH}
	return res, nil
}

func (cc *CryptoContext) EvalBootstrapSetupSimple(levelBudget []uint32) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	var ptr *C.uint32_t
	var n C.int
	if len(levelBudget) > 0 {
		ptr = (*C.uint32_t)(unsafe.Pointer(&levelBudget[0]))
		n = C.int(len(levelBudget))
	}

	status := C.CryptoContext_EvalBootstrapSetup_Simple(cc.ptr, ptr, n)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

// EvalBootstrapSetup performs precomputations for bootstrapping with full control over parameters.
// levelBudget: budget for levels used in bootstrapping
// bsgsDim: BSGS dimensions for baby-step giant-step algorithm (pass nil or empty for defaults)
// numSlots: number of slots to use for bootstrapping
func (cc *CryptoContext) EvalBootstrapSetup(levelBudget []uint32, bsgsDim []uint32, numSlots uint32) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}

	var lbPtr *C.uint32_t
	var lbLen C.int
	if len(levelBudget) > 0 {
		lbPtr = (*C.uint32_t)(unsafe.Pointer(&levelBudget[0]))
		lbLen = C.int(len(levelBudget))
	}

	var bsgsPtr *C.uint32_t
	var bsgsLen C.int
	if len(bsgsDim) > 0 {
		bsgsPtr = (*C.uint32_t)(unsafe.Pointer(&bsgsDim[0]))
		bsgsLen = C.int(len(bsgsDim))
	}

	status := C.CryptoContext_EvalBootstrapSetup(cc.ptr, lbPtr, lbLen, bsgsPtr, bsgsLen, C.uint32_t(numSlots))
	err := checkPKEErrorMsg(status)
	if err != nil {
		return err
	}
	return nil
}

// func (cc *CryptoContext) EvalBootstrapSetup(slots uint32) error {
// 	var cErr *C.char
// 	ok := C.CryptoContext_EvalBootstrapSetup(cc.ptr, C.uint32_t(slots), &cErr)
// 	if ok == 1 {
// 		return nil
// 	}
// 	defer func() {
// 		if cErr != nil {
// 			C.free(unsafe.Pointer(cErr))
// 		}
// 	}()
// 	if cErr != nil {
// 		return fmt.Errorf("%s", C.GoString(cErr))
// 	}
// 	return fmt.Errorf("EvalBootstrapSetup failed")
// }
//
// func (cc *CryptoContext) EvalBootstrapPrecompute(slots uint32) error {
// 	var cErr *C.char
// 	ok := C.CryptoContext_EvalBootstrapPrecompute(cc.ptr, C.uint32_t(slots), &cErr)
// 	if ok == 1 {
// 		return nil
// 	}
// 	defer func() {
// 		if cErr != nil {
// 			C.free(unsafe.Pointer(cErr))
// 		}
// 	}()
// 	if cErr != nil {
// 		return fmt.Errorf("%s", C.GoString(cErr))
// 	}
// 	return fmt.Errorf("EvalBootstrapPrecompute failed")
// }

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

func (ct *Ciphertext) GetLevel() (int, bool) {
	if ct.ptr == nil {
		return -1, false // Indicate invalid state
	}
	level := C.Ciphertext_GetLevel(ct.ptr)
	if level == -1 {
		return -1, false
	}

	return int(level), true
}

func (ct *Ciphertext) GetNoiseScaleDeg() uint32 {
	if ct.ptr == nil {
		return 0
	}
	return uint32(C.Ciphertext_GetNoiseScaleDeg(ct.ptr))
}

func (ct *Ciphertext) GetKeyTag() (string, error) {
	if ct.ptr == nil {
		return "", errors.New("Ciphertext is closed or invalid")
	}

	var cKeyTag *C.char
	status := C.Ciphertext_GetKeyTag(ct.ptr, &cKeyTag)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return "", err
	}

	if cKeyTag == nil {
		return "", errors.New("GetKeyTag returned null string")
	}
	defer C.free(unsafe.Pointer(cKeyTag))

	return C.GoString(cKeyTag), nil
}

func (cc *CryptoContext) GetParameterElementString() (string, error) {
	fmt.Println("Go: Calling GetParameterElementString...")
	if cc.ptr == nil {
		return "", errors.New("CryptoContext is closed or invalid")
	}
	var cStr *C.char
	status := C.CryptoContext_GetParameterElementString(cc.ptr, &cStr)
	err := checkPKEErrorMsg(status) // Check for errors returned by the C function
	if err != nil {
		if cStr != nil {
			C.FreeString(cStr)
		} // Free if allocated before error
		return "", fmt.Errorf("GetParameterElementString failed in C++: %w", err)
	}
	if cStr == nil {
		// Should not happen if status is OK, but check defensively
		return "", fmt.Errorf("GetParameterElementString returned OK but null string")
	}
	goStr := C.GoString(cStr)
	C.FreeString(cStr) // Use FreeString which calls C.free
	fmt.Printf("Go: Parameter Element String: %s\n", goStr)
	return goStr, nil
}

// --- Release Methods for Go Wrappers ---

// Close frees the underlying C++ CryptoContext object.
func (cc *CryptoContext) Close() {
	if cc.ptr != nil {
		C.DestroyCryptoContext(cc.ptr)
		cc.ptr = nil
	}
}

// Close frees the underlying C++ KeyPair object.
func (kp *KeyPair) Close() {
	if kp.ptr != nil {
		C.DestroyKeyPair(kp.ptr)
		kp.ptr = nil
	}
}

// Close frees the underlying C++ Ciphertext object.
func (ct *Ciphertext) Close() {
	if ct.ptr != nil {
		// fmt.Println("Releasing Ciphertext:", ct.ptr) // Debug
		C.DestroyCiphertext(ct.ptr)
		ct.ptr = nil
	}
}

// Clone creates a deep copy of the ciphertext.
// This is useful for interactive bootstrapping when you need to manipulate
// ciphertext elements independently.
func (ct *Ciphertext) Clone() (*Ciphertext, error) {
	if ct.ptr == nil {
		return nil, errors.New("Ciphertext is closed or invalid")
	}

	var outCT C.CiphertextPtr
	status := C.Ciphertext_Clone(ct.ptr, &outCT)

	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outCT == nil {
		return nil, errors.New("Clone returned null ciphertext")
	}

	return &Ciphertext{ptr: outCT}, nil
}

// GetNumElements returns the number of ring elements in the ciphertext.
// For a fresh ciphertext, this is typically 2 (c0, c1).
func (ct *Ciphertext) GetNumElements() (int, error) {
	if ct.ptr == nil {
		return 0, errors.New("Ciphertext is closed or invalid")
	}

	numElements := C.Ciphertext_GetNumElements(ct.ptr)
	return int(numElements), nil
}

// SetElementAtIndex keeps only the element at the specified index,
// discarding all other elements. This is used in interactive bootstrapping
// to extract specific ciphertext components.
// For example, SetElementAtIndex(1) extracts just the second element (c1 = a*s).
func (ct *Ciphertext) SetElementAtIndex(index int) error {
	if ct.ptr == nil {
		return errors.New("Ciphertext is closed or invalid")
	}

	status := C.Ciphertext_SetElementAtIndex(ct.ptr, C.size_t(index))
	return checkPKEErrorMsg(status)
}

// EvalSumKeyGen generates evaluation keys for summation operations.
// This must be called before using MultiEvalSumKeyGen in multiparty scenarios.
func (cc *CryptoContext) EvalSumKeyGenPrivate(privateKey *PrivateKey, publicKey *PublicKey) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if privateKey == nil || privateKey.ptr == nil {
		return errors.New("privateKey is nil or closed")
	}

	var pkPtr C.PublicKeyPtr
	if publicKey != nil {
		pkPtr = publicKey.ptr
	}

	status := C.CryptoContext_EvalSumKeyGenPrivate(cc.ptr, privateKey.ptr, pkPtr)
	return checkPKEErrorMsg(status)
}

// EvalAtIndexKeyGen generates evaluation keys for rotation at specific indices.
// This must be called before using MultiEvalAtIndexKeyGen in multiparty scenarios.
func (cc *CryptoContext) EvalAtIndexKeyGenPrivate(privateKey *PrivateKey, indices []int32, publicKey *PublicKey) error {
	if cc.ptr == nil {
		return errors.New("CryptoContext is closed or invalid")
	}
	if privateKey == nil || privateKey.ptr == nil {
		return errors.New("privateKey is nil or closed")
	}
	if len(indices) == 0 {
		return errors.New("indices slice is empty")
	}

	var pkPtr C.PublicKeyPtr
	if publicKey != nil {
		pkPtr = publicKey.ptr
	}

	status := C.CryptoContext_EvalAtIndexKeyGenPrivate(
		cc.ptr,
		privateKey.ptr,
		(*C.int32_t)(unsafe.Pointer(&indices[0])),
		C.size_t(len(indices)),
		pkPtr,
	)
	return checkPKEErrorMsg(status)
}

// GetEvalSumKeyMap retrieves the evaluation sum key map from the context.
// Used after EvalSumKeyGen to get the key map for multiparty scenarios.
func (cc *CryptoContext) GetEvalSumKeyMap(keyTag string) (*EvalKeyMap, error) {
	if cc.ptr == nil {
		return nil, errors.New("CryptoContext is closed or invalid")
	}

	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var outKeyMap C.EvalKeyMapPtr
	status := C.CryptoContext_GetEvalSumKeyMap(cc.ptr, cKeyTag, &outKeyMap)
	err := checkPKEErrorMsg(status)
	if err != nil {
		return nil, err
	}

	if outKeyMap == nil {
		return nil, errors.New("GetEvalSumKeyMap returned null")
	}

	return &EvalKeyMap{ptr: outKeyMap}, nil
}
