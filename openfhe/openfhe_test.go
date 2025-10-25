package openfhe

/*
#cgo CPPFLAGS: -I${SRCDIR}/../openfhe-install/include/openfhe -I${SRCDIR}/../openfhe-install/include/openfhe/core -I${SRCDIR}/../openfhe-install/include/openfhe/pke -I${SRCDIR}/../openfhe-install/include/openfhe/binfhe -I${SRCDIR}/../openfhe-install/include/openfhe/cereal
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: ${SRCDIR}/../openfhe-install/lib/libOPENFHEpke_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEcore_static.a ${SRCDIR}/../openfhe-install/lib/libOPENFHEbinfhe_static.a -lc++ -lm
#include <stdint.h>
#include "bridge.h"
*/
import (
	"math"
	"testing"
)

// Helper to check if two int64 slices are equal
func slicesEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Helper to check if two float64 slices are approximately equal
func slicesApproxEqual(a, b []float64, tolerance float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if math.Abs(v-b[i]) > tolerance {
			return false
		}
	}
	return true
}

func TestSimpleIntegers(t *testing.T) {
	t.Log("--- Go simple-integers (BFV) test starting ---")

	// 1. Set up parameters
	parameters := NewParamsBFVrns()
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	t.Log("Parameters set.")

	// 2. Generate CryptoContext
	cc := NewCryptoContextBFV(parameters)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	t.Log("CryptoContext generated.")

	// 3. Key Generation
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	cc.EvalRotateKeyGen(keys, []int32{1, -2})
	t.Log("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := cc.MakePackedPlaintext(vectorOfInts)
	ciphertext := cc.Encrypt(keys, plaintext)
	t.Log("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add := cc.EvalAdd(ciphertext, ciphertext)
	ciphertext_mul := cc.EvalMult(ciphertext, ciphertext)
	ciphertext_rot1 := cc.EvalRotate(ciphertext, 1)
	ciphertext_rot2 := cc.EvalRotate(ciphertext, -2)
	t.Log("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add := cc.Decrypt(keys, ciphertext_add)
	plaintext_dec_mul := cc.Decrypt(keys, ciphertext_mul)
	plaintext_dec_rot1 := cc.Decrypt(keys, ciphertext_rot1)
	plaintext_dec_rot2 := cc.Decrypt(keys, ciphertext_rot2)
	t.Log("Decryption complete.")

	// 7. Check results
	// Note: We only check the first 12 slots, as the rest are 0s
	addExpected := []int64{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24}
	mulExpected := []int64{1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144}
	rot1Expected := []int64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0}
	rot2Expected := []int64{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10} // Corrected based on your last run

	if !slicesEqual(plaintext_dec_add.GetPackedValue()[:12], addExpected) {
		t.Errorf("Add failed. Expected %v, Got %v", addExpected, plaintext_dec_add.GetPackedValue()[:12])
	}
	if !slicesEqual(plaintext_dec_mul.GetPackedValue()[:12], mulExpected) {
		t.Errorf("Mult failed. Expected %v, Got %v", mulExpected, plaintext_dec_mul.GetPackedValue()[:12])
	}
	if !slicesEqual(plaintext_dec_rot1.GetPackedValue()[:12], rot1Expected) {
		t.Errorf("Rotate 1 failed. Expected %v, Got %v", rot1Expected, plaintext_dec_rot1.GetPackedValue()[:12])
	}
	if !slicesEqual(plaintext_dec_rot2.GetPackedValue()[:12], rot2Expected) {
		t.Errorf("Rotate -2 failed. Expected %v, Got %v", rot2Expected, plaintext_dec_rot2.GetPackedValue()[:12])
	}
}

func TestSimpleRealNumbers(t *testing.T) {
	t.Log("--- Go simple-real-numbers (CKKS) test starting ---")

	// 1. Set up parameters
	scalingModSize := 50
	batchSize := 8
	multDepth := 1

	parameters := NewParamsCKKSRNS()
	parameters.SetMultiplicativeDepth(multDepth)
	parameters.SetScalingModSize(scalingModSize)
	parameters.SetBatchSize(batchSize)
	t.Log("Parameters set.")

	// 2. Generate CryptoContext
	cc := NewCryptoContextCKKS(parameters)
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	t.Log("CryptoContext generated.")

	// 3. Key Generation
	keys := cc.KeyGen()
	cc.EvalMultKeyGen(keys)
	t.Log("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfDoubles := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	plaintext := cc.MakeCKKSPackedPlaintext(vectorOfDoubles)
	ciphertext := cc.Encrypt(keys, plaintext)
	t.Log("Encryption complete.")

	// 5. Homomorphic Operations
	ciphertext_add := cc.EvalAdd(ciphertext, ciphertext)
	ciphertext_sub := cc.EvalSub(ciphertext, ciphertext)
	ciphertext_mul := cc.EvalMult(ciphertext, ciphertext)
	ciphertext_mul_rescaled := cc.Rescale(ciphertext_mul)
	t.Log("Homomorphic operations complete.")

	// 6. Decryption
	plaintext_dec_add := cc.Decrypt(keys, ciphertext_add)
	plaintext_dec_sub := cc.Decrypt(keys, ciphertext_sub)
	plaintext_dec_mul := cc.Decrypt(keys, ciphertext_mul_rescaled)
	t.Log("Decryption complete.")

	// 7. Check results
	addExpected := []float64{2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0}
	subExpected := []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}
	mulExpected := []float64{1.0, 4.0, 9.0, 16.0, 25.0, 36.0, 49.0, 64.0}
	tolerance := 0.0001 // CKKS is approximate

	if !slicesApproxEqual(plaintext_dec_add.GetRealPackedValue()[:batchSize], addExpected, tolerance) {
		t.Errorf("Add failed. Expected ~%v, Got %v", addExpected, plaintext_dec_add.GetRealPackedValue()[:batchSize])
	}
	if !slicesApproxEqual(plaintext_dec_sub.GetRealPackedValue()[:batchSize], subExpected, tolerance) {
		t.Errorf("Sub failed. Expected ~%v, Got %v", subExpected, plaintext_dec_sub.GetRealPackedValue()[:batchSize])
	}
	if !slicesApproxEqual(plaintext_dec_mul.GetRealPackedValue()[:batchSize], mulExpected, tolerance) {
		t.Errorf("Mult failed. Expected ~%v, Got %v", mulExpected, plaintext_dec_mul.GetRealPackedValue()[:batchSize])
	}
}

func TestSimpleIntegersBGVrns(t *testing.T) {
	t.Log("--- Go simple-integers-bgvrns test starting ---")

	// 1. Set CryptoContext Parameters
	parameters := NewParamsBGVrns() // Use BGV Params
	parameters.SetPlaintextModulus(65537)
	parameters.SetMultiplicativeDepth(2)
	t.Log("Parameters set.")

	// 2. Generate CryptoContext
	cc := NewCryptoContextBGV(parameters) // Use BGV Context constructor
	cc.Enable(PKE)
	cc.Enable(KEYSWITCH)
	cc.Enable(LEVELEDSHE)
	t.Log("CryptoContext generated.")

	// 3. Key Generation
	keyPair := cc.KeyGen()
	cc.EvalMultKeyGen(keyPair)
	// Rotation keys needed for this test
	rotationIndices := []int32{1, 2, -1, -2}
	cc.EvalRotateKeyGen(keyPair, rotationIndices)
	t.Log("Keys generated.")

	// 4. Encoding and Encryption
	vectorOfInts1 := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext1 := cc.MakePackedPlaintext(vectorOfInts1)

	vectorOfInts2 := []int64{3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext2 := cc.MakePackedPlaintext(vectorOfInts2)

	vectorOfInts3 := []int64{1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext3 := cc.MakePackedPlaintext(vectorOfInts3)

	ciphertext1 := cc.Encrypt(keyPair, plaintext1)
	ciphertext2 := cc.Encrypt(keyPair, plaintext2)
	ciphertext3 := cc.Encrypt(keyPair, plaintext3)
	t.Log("Encryption complete.")

	// 5. Evaluation
	ciphertextAdd12 := cc.EvalAdd(ciphertext1, ciphertext2)
	ciphertextAddResult := cc.EvalAdd(ciphertextAdd12, ciphertext3)

	ciphertextMult12 := cc.EvalMult(ciphertext1, ciphertext2)
	ciphertextMultResult := cc.EvalMult(ciphertextMult12, ciphertext3)

	ciphertextRot1 := cc.EvalRotate(ciphertext1, 1)
	ciphertextRot2 := cc.EvalRotate(ciphertext1, 2)
	ciphertextRotNeg1 := cc.EvalRotate(ciphertext1, -1)
	ciphertextRotNeg2 := cc.EvalRotate(ciphertext1, -2)
	t.Log("Homomorphic operations complete.")

	// 6. Decryption
	plaintextAddResult := cc.Decrypt(keyPair, ciphertextAddResult)
	plaintextMultResult := cc.Decrypt(keyPair, ciphertextMultResult)
	plaintextRot1 := cc.Decrypt(keyPair, ciphertextRot1)
	plaintextRot2 := cc.Decrypt(keyPair, ciphertextRot2)
	plaintextRotNeg1 := cc.Decrypt(keyPair, ciphertextRotNeg1)
	plaintextRotNeg2 := cc.Decrypt(keyPair, ciphertextRotNeg2)
	t.Log("Decryption complete.")

	// 7. Check results
	vecLen := len(vectorOfInts1)
	// Calculate expected values
	addExpected := make([]int64, vecLen)
	mulExpected := make([]int64, vecLen)
	rot1Expected := make([]int64, vecLen)
	rot2Expected := make([]int64, vecLen)
	rotNeg1Expected := make([]int64, vecLen)
	rotNeg2Expected := make([]int64, vecLen)

	ptMod := int64(65537) // Plaintext modulus used

	// Correctly calculate expected addition and multiplication
	for i := 0; i < vecLen; i++ {
		addExpected[i] = (vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i]) % ptMod
		mulExpected[i] = (vectorOfInts1[i] * vectorOfInts2[i] * vectorOfInts3[i]) % ptMod
	}

	// Calculate expected rotations (handle wrap-around/zero padding) - keep corrected logic from previous step
	// Rotate(1) - Left shift by 1
	for i := 0; i < vecLen-1; i++ {
		rot1Expected[i] = vectorOfInts1[i+1]
	}
	rot1Expected[vecLen-1] = 0 // Zero padding

	// Rotate(2) - Left shift by 2
	for i := 0; i < vecLen-2; i++ {
		rot2Expected[i] = vectorOfInts1[i+2]
	}
	rot2Expected[vecLen-2], rot2Expected[vecLen-1] = 0, 0 // Zero padding

	// Rotate(-1) - Right shift by 1
	rotNeg1Expected[0] = 0 // Zero padding
	for i := 1; i < vecLen; i++ {
		rotNeg1Expected[i] = vectorOfInts1[i-1]
	}

	// Rotate(-2) - Right shift by 2
	rotNeg2Expected[0], rotNeg2Expected[1] = 0, 0 // Zero padding
	for i := 2; i < vecLen; i++ {
		rotNeg2Expected[i] = vectorOfInts1[i-2]
	}

	// Set length before comparison
	plaintextRot1.SetLength(vecLen)
	plaintextRot2.SetLength(vecLen)
	plaintextRotNeg1.SetLength(vecLen)
	plaintextRotNeg2.SetLength(vecLen)

	if !slicesEqual(plaintextAddResult.GetPackedValue()[:vecLen], addExpected) {
		t.Errorf("BGV Add failed. Expected %v, Got %v", addExpected, plaintextAddResult.GetPackedValue()[:vecLen])
	}
	if !slicesEqual(plaintextAddResult.GetPackedValue()[:vecLen], addExpected) {
		t.Errorf("BGV Add failed. Expected %v, Got %v", addExpected, plaintextAddResult.GetPackedValue()[:vecLen])
	}
	if !slicesEqual(plaintextMultResult.GetPackedValue()[:vecLen], mulExpected) {
		t.Errorf("BGV Mult failed. Expected %v, Got %v", mulExpected, plaintextMultResult.GetPackedValue()[:vecLen])
	}
	if !slicesEqual(plaintextRot1.GetPackedValue(), rot1Expected) {
		t.Errorf("BGV Rotate(1) failed. Expected %v, Got %v", rot1Expected, plaintextRot1.GetPackedValue())
	}
	if !slicesEqual(plaintextRot2.GetPackedValue(), rot2Expected) {
		t.Errorf("BGV Rotate(2) failed. Expected %v, Got %v", rot2Expected, plaintextRot2.GetPackedValue())
	}
	if !slicesEqual(plaintextRotNeg1.GetPackedValue(), rotNeg1Expected) {
		t.Errorf("BGV Rotate(-1) failed. Expected %v, Got %v", rotNeg1Expected, plaintextRotNeg1.GetPackedValue())
	}
	if !slicesEqual(plaintextRotNeg2.GetPackedValue(), rotNeg2Expected) {
		t.Errorf("BGV Rotate(-2) failed. Expected %v, Got %v", rotNeg2Expected, plaintextRotNeg2.GetPackedValue())
	}
}
