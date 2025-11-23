package openfhe

import (
	"math"
	"testing"
)

func setupCKKSBootstrapContext(t *testing.T) (*CryptoContext, *KeyPair, uint32) {
	t.Helper()

	levelBudget := []uint32{4, 4}
	secretKeyDist := SecretKeyUniformTernary

	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close() // Params can be closed after CC is created

	mustT(t, params.SetSecretKeyDist(secretKeyDist), "SetSecretKeyDist")
	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel") // critical for small N
	mustT(t, params.SetRingDim(uint64(1<<12)), "SetRingDim")           // N=4096 (slots=N/2)
	mustT(t, params.SetScalingTechnique(FLEXIBLEAUTO), "SetScalingTechnique")
	mustT(t, params.SetScalingModSize(59), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	// depth = levelsAfter + GetBootstrapDepth(levelBudget, skd)
	levelsAfter := uint32(10)
	bootDepth := GetBootstrapDepth(levelBudget, secretKeyDist)
	mustT(t, params.SetMultiplicativeDepth(int(levelsAfter+bootDepth)), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")
	mustT(t, cc.Enable(FHE), "Enable FHE")

	N := cc.GetRingDimension()
	if N != 1<<12 {
		t.Fatalf("unexpected ring dimension: got %d, want %d", N, 1<<12)
	}
	slots := uint32(N / 2)

	// Setup -> keys -> bootstrap keys
	mustT(t, cc.EvalBootstrapSetupSimple(levelBudget), "EvalBootstrapSetupSimple")

	kp, err := cc.KeyGen()
	mustT(t, err, "KeyGen")

	mustT(t, cc.EvalMultKeyGen(kp), "EvalMultKeyGen")
	// Rotation keys not strictly required for this simple test, but safe to omit/add as desired.

	mustT(t, cc.EvalBootstrapKeyGen(kp, slots), "EvalBootstrapKeyGen")

	return cc, kp, slots // Caller is responsible for Closing cc and kp
}

// Test 1: Bootstrap a ciphertext without prior arithmetic.
func TestCKKSBootstrap_SimpleRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CKKS bootstrapping test in -short mode")
	}

	cc, kp, _ := setupCKKSBootstrapContext(t)
	defer cc.Close()
	defer kp.Close()

	in := []float64{0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0}
	pt, err := cc.MakeCKKSPackedPlaintext(in)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	mustT(t, pt.SetLength(len(in)), "SetLength")

	ct, err := cc.Encrypt(kp, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	ctB, err := cc.EvalBootstrap(ct)
	mustT(t, err, "EvalBootstrap")
	defer ctB.Close()

	ptOut, err := cc.Decrypt(kp, ctB)
	mustT(t, err, "Decrypt")
	defer ptOut.Close()

	mustT(t, ptOut.SetLength(len(in)), "SetLength")
	got, err := ptOut.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	tol := 0.02
	if !slicesApproxEqual(got[:len(in)], in, tol) {
		t.Fatalf("CKKS bootstrap roundtrip mismatch.\nwant ~%v\ngot  %v", in, got[:len(in)])
	}
}

// Test 2: Burn levels (v -> v^8 via three squarings) then bootstrap.
func TestCKKSBootstrap_AfterArithmetic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CKKS bootstrapping test in -short mode")
	}

	cc, kp, _ := setupCKKSBootstrapContext(t)
	defer cc.Close()
	defer kp.Close()

	in := []float64{0.25, 0.5, 0.75, 1.0, 2.0}
	want := make([]float64, len(in))
	for i, v := range in {
		want[i] = math.Pow(v, 8) // what we’ll compute via squarings
	}

	pt, err := cc.MakeCKKSPackedPlaintext(in)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	mustT(t, pt.SetLength(len(in)), "SetLength")
	ct, err := cc.Encrypt(kp, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// v -> v^2 -> v^4 -> v^8, with rescale after each mult
	ct1, err := cc.EvalMult(ct, ct)
	mustT(t, err, "EvalMult ct1")
	defer ct1.Close()
	ct1_r, err := cc.Rescale(ct1)
	mustT(t, err, "Rescale ct1_r")
	defer ct1_r.Close()

	ct2, err := cc.EvalMult(ct1_r, ct1_r)
	mustT(t, err, "EvalMult ct2")
	defer ct2.Close()
	ct2_r, err := cc.Rescale(ct2)
	mustT(t, err, "Rescale ct2_r")
	defer ct2_r.Close()

	ct3, err := cc.EvalMult(ct2_r, ct2_r)
	mustT(t, err, "EvalMult ct3")
	defer ct3.Close()
	ct3_r, err := cc.Rescale(ct3)
	mustT(t, err, "Rescale ct3_r")
	defer ct3_r.Close()

	ctB, err := cc.EvalBootstrap(ct3_r)
	mustT(t, err, "EvalBootstrap")
	defer ctB.Close()

	ptOut, err := cc.Decrypt(kp, ctB)
	mustT(t, err, "Decrypt")
	defer ptOut.Close()

	mustT(t, ptOut.SetLength(len(in)), "SetLength")
	got, err := ptOut.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	tol := 0.02 // bootstrapping is approximate; loosen if needed
	if !slicesApproxEqual(got[:len(want)], want, tol) {
		t.Fatalf("CKKS bootstrap after arithmetic mismatch.\nwant ~%v\ngot  %v", want, got[:len(want)])
	}
}

// Test 3: EvalSum - basic functionality
func TestCKKS_EvalSum(t *testing.T) {
	// Setup
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(8), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	// Generate sum keys
	mustT(t, cc.EvalSumKeyGen(keys), "EvalSumKeyGen")

	// Create test vector
	batchSize := uint32(8)
	input := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}
	expectedSum := 36.0 // Sum of 1+2+...+8

	pt, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// Perform sum
	ctSum, err := cc.EvalSum(ct, batchSize)
	mustT(t, err, "EvalSum")
	defer ctSum.Close()

	// Decrypt and verify
	ptResult, err := cc.Decrypt(keys, ctSum)
	mustT(t, err, "Decrypt")
	defer ptResult.Close()

	result, err := ptResult.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// All slots should contain the sum
	tolerance := 0.01
	for i := 0; i < len(input); i++ {
		if math.Abs(result[i]-expectedSum) > tolerance {
			t.Errorf("Slot %d: expected %.6f, got %.6f", i, expectedSum, result[i])
		}
	}
}

// Test 4: EvalSum - small batch size
func TestCKKS_EvalSum_SmallBatch(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(4), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	mustT(t, cc.EvalSumKeyGen(keys), "EvalSumKeyGen")

	batchSize := uint32(4)
	input := []float64{10.5, 20.5, 30.5, 40.5}
	expectedSum := 102.0 // 10.5 + 20.5 + 30.5 + 40.5

	pt, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	ctSum, err := cc.EvalSum(ct, batchSize)
	mustT(t, err, "EvalSum")
	defer ctSum.Close()

	ptResult, err := cc.Decrypt(keys, ctSum)
	mustT(t, err, "Decrypt")
	defer ptResult.Close()

	result, err := ptResult.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	tolerance := 0.01
	if math.Abs(result[0]-expectedSum) > tolerance {
		t.Errorf("Expected sum %.6f, got %.6f", expectedSum, result[0])
	}
}

// Test 5: EvalInnerProduct - basic functionality
func TestCKKS_EvalInnerProduct(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(4), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	// Generate required keys
	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	mustT(t, cc.EvalSumKeyGen(keys), "EvalSumKeyGen")

	// Create test vectors
	batchSize := uint32(4)
	vec1 := []float64{1.0, 2.0, 3.0, 4.0}
	vec2 := []float64{5.0, 6.0, 7.0, 8.0}
	expectedIP := 1.0*5.0 + 2.0*6.0 + 3.0*7.0 + 4.0*8.0 // = 70.0

	pt1, err := cc.MakeCKKSPackedPlaintext(vec1)
	mustT(t, err, "MakeCKKSPackedPlaintext 1")
	defer pt1.Close()

	pt2, err := cc.MakeCKKSPackedPlaintext(vec2)
	mustT(t, err, "MakeCKKSPackedPlaintext 2")
	defer pt2.Close()

	ct1, err := cc.Encrypt(keys, pt1)
	mustT(t, err, "Encrypt 1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(keys, pt2)
	mustT(t, err, "Encrypt 2")
	defer ct2.Close()

	// Compute inner product
	ctIP, err := cc.EvalInnerProduct(ct1, ct2, batchSize)
	mustT(t, err, "EvalInnerProduct")
	defer ctIP.Close()

	// Decrypt and verify
	ptResult, err := cc.Decrypt(keys, ctIP)
	mustT(t, err, "Decrypt")
	defer ptResult.Close()

	result, err := ptResult.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// All slots should contain inner product
	tolerance := 0.01
	if math.Abs(result[0]-expectedIP) > tolerance {
		t.Errorf("Expected inner product %.6f, got %.6f", expectedIP, result[0])
	}
}

// Test 6: EvalInnerProduct - orthogonal vectors
func TestCKKS_EvalInnerProduct_Orthogonal(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(4), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")
	mustT(t, cc.EvalSumKeyGen(keys), "EvalSumKeyGen")

	// Orthogonal vectors: [1, 1, 0, 0] and [0, 0, 1, 1]
	batchSize := uint32(4)
	vec1 := []float64{1.0, 1.0, 0.0, 0.0}
	vec2 := []float64{0.0, 0.0, 1.0, 1.0}
	expectedIP := 0.0 // Orthogonal vectors

	pt1, err := cc.MakeCKKSPackedPlaintext(vec1)
	mustT(t, err, "MakeCKKSPackedPlaintext 1")
	defer pt1.Close()

	pt2, err := cc.MakeCKKSPackedPlaintext(vec2)
	mustT(t, err, "MakeCKKSPackedPlaintext 2")
	defer pt2.Close()

	ct1, err := cc.Encrypt(keys, pt1)
	mustT(t, err, "Encrypt 1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(keys, pt2)
	mustT(t, err, "Encrypt 2")
	defer ct2.Close()

	ctIP, err := cc.EvalInnerProduct(ct1, ct2, batchSize)
	mustT(t, err, "EvalInnerProduct")
	defer ctIP.Close()

	ptResult, err := cc.Decrypt(keys, ctIP)
	mustT(t, err, "Decrypt")
	defer ptResult.Close()

	result, err := ptResult.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	tolerance := 0.01
	if math.Abs(result[0]-expectedIP) > tolerance {
		t.Errorf("Expected inner product %.6f, got %.6f", expectedIP, result[0])
	}
}

// Test 7: EvalSum error handling - missing key generation
func TestCKKS_EvalSum_MissingKeyGen(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(4), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	// Intentionally skip EvalSumKeyGen

	input := []float64{1.0, 2.0, 3.0, 4.0}
	pt, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer pt.Close()

	ct, err := cc.Encrypt(keys, pt)
	mustT(t, err, "Encrypt")
	defer ct.Close()

	// This should fail because we didn't generate sum keys
	_, err = cc.EvalSum(ct, 4)
	if err == nil {
		t.Error("Expected error when calling EvalSum without EvalSumKeyGen, got nil")
	}
}

// Test 8: Error handling - closed context
func TestCKKS_EvalSum_ClosedContext(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(4), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	cc.Close() // Close the context

	ct := &Ciphertext{}
	_, err = cc.EvalSum(ct, 8)
	if err == nil {
		t.Error("Expected error with closed context")
	}
	if err.Error() != "CryptoContext is closed or invalid" {
		t.Errorf("Expected 'CryptoContext is closed or invalid', got %v", err)
	}
}

// Test 9: Error handling - null ciphertext
func TestCKKS_EvalSum_NullCiphertext(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(5), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetBatchSize(4), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	_, err = cc.EvalSum(nil, 4)
	if err == nil {
		t.Error("Expected error with null ciphertext")
	}
}

// --- Function Evaluation Tests ---

// TestCKKS_EvalLogistic tests the logistic function evaluation using Chebyshev approximation
func TestCKKS_EvalLogistic(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	// Settings based on the C++ example
	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	polyDegree := uint32(16)
	multDepth := 6
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	input := []float64{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	lowerBound := -5.0
	upperBound := 5.0
	result, err := cc.EvalLogistic(ciphertext, lowerBound, upperBound, polyDegree)
	mustT(t, err, "EvalLogistic")
	defer result.Close()

	plaintextDec, err := cc.Decrypt(keyPair, result)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	mustT(t, plaintextDec.SetLength(len(input)), "SetLength")
	finalResult, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// Expected output from the C++ example
	expectedOutput := []float64{0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011}

	// Check results with tolerance
	tolerance := 0.01
	for i := 0; i < len(input); i++ {
		diff := math.Abs(finalResult[i] - expectedOutput[i])
		if diff > tolerance {
			t.Errorf("Result mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expectedOutput[i], finalResult[i], diff)
		}
	}
}

// TestCKKS_EvalLogistic_ErrorCases tests error handling
func TestCKKS_EvalLogistic_ErrorCases(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(6), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Test with null ciphertext
	_, err = cc.EvalLogistic(nil, -5.0, 5.0, 16)
	if err == nil {
		t.Error("Expected error with null ciphertext")
	}

	// Test with closed context
	cc.Close()
	keyPair, _ := cc.KeyGen()
	if keyPair != nil {
		defer keyPair.Close()
	}
	_, err = cc.EvalLogistic(nil, -5.0, 5.0, 16)
	if err == nil {
		t.Error("Expected error with closed context")
	}
}

// TestCKKS_EvalSin tests the sine function evaluation using Chebyshev approximation
func TestCKKS_EvalSin(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	polyDegree := uint32(32)
	multDepth := 7
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Test values: 0, π/4, π/2, 3π/4, π
	input := []float64{0, math.Pi / 4, math.Pi / 2, 3 * math.Pi / 4, math.Pi}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	lowerBound := -math.Pi
	upperBound := math.Pi
	result, err := cc.EvalSin(ciphertext, lowerBound, upperBound, polyDegree)
	mustT(t, err, "EvalSin")
	defer result.Close()

	plaintextDec, err := cc.Decrypt(keyPair, result)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	mustT(t, plaintextDec.SetLength(len(input)), "SetLength")
	finalResult, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// Expected: sin(0)=0, sin(π/4)≈0.707, sin(π/2)=1, sin(3π/4)≈0.707, sin(π)≈0
	expectedOutput := []float64{0.0, 0.707107, 1.0, 0.707107, 0.0}

	tolerance := 0.01
	for i := 0; i < len(input); i++ {
		diff := math.Abs(finalResult[i] - expectedOutput[i])
		if diff > tolerance {
			t.Errorf("Sin result mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expectedOutput[i], finalResult[i], diff)
		}
	}
}

// TestCKKS_EvalCos tests the cosine function evaluation using Chebyshev approximation
func TestCKKS_EvalCos(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	polyDegree := uint32(32)
	multDepth := 7
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Test values: 0, π/4, π/2, 3π/4, π
	input := []float64{0, math.Pi / 4, math.Pi / 2, 3 * math.Pi / 4, math.Pi}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	lowerBound := -math.Pi
	upperBound := math.Pi
	result, err := cc.EvalCos(ciphertext, lowerBound, upperBound, polyDegree)
	mustT(t, err, "EvalCos")
	defer result.Close()

	plaintextDec, err := cc.Decrypt(keyPair, result)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	mustT(t, plaintextDec.SetLength(len(input)), "SetLength")
	finalResult, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// Expected: cos(0)=1, cos(π/4)≈0.707, cos(π/2)=0, cos(3π/4)≈-0.707, cos(π)=-1
	expectedOutput := []float64{1.0, 0.707107, 0.0, -0.707107, -1.0}

	tolerance := 0.01
	for i := 0; i < len(input); i++ {
		diff := math.Abs(finalResult[i] - expectedOutput[i])
		if diff > tolerance {
			t.Errorf("Cos result mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expectedOutput[i], finalResult[i], diff)
		}
	}
}

// TestCKKS_EvalChebyshevFunction tests custom function evaluation with sqrt
func TestCKKS_EvalChebyshevFunction(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	polyDegree := uint32(50)
	multDepth := 7
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Test sqrt function
	input := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	lowerBound := 0.0
	upperBound := 10.0

	// Use math.Sqrt as the custom function
	result, err := cc.EvalChebyshevFunction(math.Sqrt, ciphertext, lowerBound, upperBound, polyDegree)
	mustT(t, err, "EvalChebyshevFunction")
	defer result.Close()

	plaintextDec, err := cc.Decrypt(keyPair, result)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	mustT(t, plaintextDec.SetLength(len(input)), "SetLength")
	finalResult, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// Expected: sqrt(1)=1, sqrt(2)≈1.414, sqrt(3)≈1.732, sqrt(4)=2, etc.
	expectedOutput := []float64{1.0, 1.414213, 1.732050, 2.0, 2.236067, 2.449489, 2.645751, 2.828427, 3.0}

	tolerance := 0.01
	for i := 0; i < len(input); i++ {
		diff := math.Abs(finalResult[i] - expectedOutput[i])
		if diff > tolerance {
			t.Errorf("Sqrt result mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expectedOutput[i], finalResult[i], diff)
		}
	}
}

// TestCKKS_EvalChebyshevFunction_CustomFunc tests with a custom polynomial function
func TestCKKS_EvalChebyshevFunction_CustomFunc(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	polyDegree := uint32(16)
	multDepth := 6
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Test custom function: f(x) = x^2 + 1
	customFunc := func(x float64) float64 {
		return x*x + 1.0
	}

	input := []float64{1, 2, 3, 4, 5}
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	lowerBound := 0.0
	upperBound := 6.0

	result, err := cc.EvalChebyshevFunction(customFunc, ciphertext, lowerBound, upperBound, polyDegree)
	mustT(t, err, "EvalChebyshevFunction")
	defer result.Close()

	plaintextDec, err := cc.Decrypt(keyPair, result)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	mustT(t, plaintextDec.SetLength(len(input)), "SetLength")
	finalResult, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// Expected: f(1)=2, f(2)=5, f(3)=10, f(4)=17, f(5)=26
	expectedOutput := []float64{2.0, 5.0, 10.0, 17.0, 26.0}

	tolerance := 0.1
	for i := 0; i < len(input); i++ {
		diff := math.Abs(finalResult[i] - expectedOutput[i])
		if diff > tolerance {
			t.Errorf("Custom function result mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expectedOutput[i], finalResult[i], diff)
		}
	}
}

// --- Plaintext Chebyshev Function Tests ---

// TestEvalChebyshevFunctionPtxt_Sqrt tests plaintext Chebyshev approximation for sqrt
func TestEvalChebyshevFunctionPtxt_Sqrt(t *testing.T) {
	input := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9}
	lowerBound := 0.0
	upperBound := 10.0
	degree := uint32(50)

	result := EvalChebyshevFunctionPtxt(math.Sqrt, input, lowerBound, upperBound, degree)

	// Expected: sqrt(1)=1, sqrt(2)≈1.414, sqrt(3)≈1.732, etc.
	expected := []float64{1.0, 1.414213, 1.732050, 2.0, 2.236067, 2.449489, 2.645751, 2.828427, 3.0}

	tolerance := 0.001 // Should be very accurate with degree 50
	for i := 0; i < len(input); i++ {
		diff := math.Abs(result[i] - expected[i])
		if diff > tolerance {
			t.Errorf("Sqrt approximation mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected[i], result[i], diff)
		}
	}
}

// TestEvalChebyshevFunctionPtxt_Logistic tests plaintext Chebyshev approximation for logistic
func TestEvalChebyshevFunctionPtxt_Logistic(t *testing.T) {
	logistic := func(x float64) float64 {
		return 1.0 / (1.0 + math.Exp(-x))
	}

	input := []float64{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0}
	lowerBound := -5.0
	upperBound := 5.0
	degree := uint32(16)

	result := EvalChebyshevFunctionPtxt(logistic, input, lowerBound, upperBound, degree)

	expected := []float64{0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011}

	tolerance := 0.001
	for i := 0; i < len(input); i++ {
		diff := math.Abs(result[i] - expected[i])
		if diff > tolerance {
			t.Errorf("Logistic approximation mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected[i], result[i], diff)
		}
	}
}

// TestEvalChebyshevFunctionPtxt_Sin tests plaintext Chebyshev approximation for sine
func TestEvalChebyshevFunctionPtxt_Sin(t *testing.T) {
	input := []float64{0, math.Pi / 6, math.Pi / 4, math.Pi / 3, math.Pi / 2}
	lowerBound := -math.Pi
	upperBound := math.Pi
	degree := uint32(32)

	result := EvalChebyshevFunctionPtxt(math.Sin, input, lowerBound, upperBound, degree)

	// Expected: sin(0)=0, sin(π/6)=0.5, sin(π/4)≈0.707, sin(π/3)≈0.866, sin(π/2)=1
	expected := []float64{0.0, 0.5, 0.707107, 0.866025, 1.0}

	tolerance := 0.001
	for i := 0; i < len(input); i++ {
		diff := math.Abs(result[i] - expected[i])
		if diff > tolerance {
			t.Errorf("Sin approximation mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected[i], result[i], diff)
		}
	}
}

// TestEvalChebyshevFunctionPtxt_CustomPolynomial tests with a simple polynomial
func TestEvalChebyshevFunctionPtxt_CustomPolynomial(t *testing.T) {
	// f(x) = x^2 + 2x + 1 = (x+1)^2
	customFunc := func(x float64) float64 {
		return x*x + 2*x + 1
	}

	input := []float64{0, 1, 2, 3, 4, 5}
	lowerBound := -1.0
	upperBound := 6.0
	degree := uint32(16)

	result := EvalChebyshevFunctionPtxt(customFunc, input, lowerBound, upperBound, degree)

	// Expected: (0+1)^2=1, (1+1)^2=4, (2+1)^2=9, (3+1)^2=16, (4+1)^2=25, (5+1)^2=36
	expected := []float64{1.0, 4.0, 9.0, 16.0, 25.0, 36.0}

	tolerance := 0.01 // Polynomial should be very accurate
	for i := 0; i < len(input); i++ {
		diff := math.Abs(result[i] - expected[i])
		if diff > tolerance {
			t.Errorf("Polynomial approximation mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected[i], result[i], diff)
		}
	}
}

// TestEvalChebyshevFunctionPtxt_MatchesEncrypted compares plaintext and encrypted results
func TestEvalChebyshevFunctionPtxt_MatchesEncrypted(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	polyDegree := uint32(32)
	multDepth := 7
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Test data
	input := []float64{1, 4, 9, 16, 25}
	lowerBound := 0.0
	upperBound := 30.0

	// Encrypted evaluation
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	ctResult, err := cc.EvalChebyshevFunction(math.Sqrt, ciphertext, lowerBound, upperBound, polyDegree)
	mustT(t, err, "EvalChebyshevFunction")
	defer ctResult.Close()

	plaintextDec, err := cc.Decrypt(keyPair, ctResult)
	mustT(t, err, "Decrypt")
	defer plaintextDec.Close()

	mustT(t, plaintextDec.SetLength(len(input)), "SetLength")
	encryptedResult, err := plaintextDec.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue")

	// Plaintext evaluation
	plaintextResult := EvalChebyshevFunctionPtxt(math.Sqrt, input, lowerBound, upperBound, polyDegree)

	// Results should match closely (within FHE noise tolerance)
	tolerance := 0.01
	for i := 0; i < len(input); i++ {
		diff := math.Abs(encryptedResult[i] - plaintextResult[i])
		if diff > tolerance {
			t.Errorf("Encrypted vs plaintext mismatch at index %d: encrypted=%.6f, plaintext=%.6f (diff: %.6f)",
				i, encryptedResult[i], plaintextResult[i], diff)
		}
	}
}

// TestEvalChebyshevSeries_BatchProcessing tests the advanced API for batch processing
func TestEvalChebyshevSeries_BatchProcessing(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	multDepth := 7
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Compute coefficients once for sqrt on [0.1, 10]
	lowerBound := 0.1
	upperBound := 10.0
	degree := uint32(50)
	coeffs, err := EvalChebyshevCoefficients(math.Sqrt, lowerBound, upperBound, degree)
	mustT(t, err, "EvalChebyshevCoefficients")

	// Test data - multiple batches
	batch1 := []float64{1, 4, 9}
	batch2 := []float64{0.5, 2, 6.25}
	batch3 := []float64{0.25, 1, 2.25}

	// Encrypt all batches
	pt1, err := cc.MakeCKKSPackedPlaintext(batch1)
	mustT(t, err, "MakeCKKSPackedPlaintext batch1")
	defer pt1.Close()

	ct1, err := cc.Encrypt(keyPair, pt1)
	mustT(t, err, "Encrypt batch1")
	defer ct1.Close()

	pt2, err := cc.MakeCKKSPackedPlaintext(batch2)
	mustT(t, err, "MakeCKKSPackedPlaintext batch2")
	defer pt2.Close()

	ct2, err := cc.Encrypt(keyPair, pt2)
	mustT(t, err, "Encrypt batch2")
	defer ct2.Close()

	pt3, err := cc.MakeCKKSPackedPlaintext(batch3)
	mustT(t, err, "MakeCKKSPackedPlaintext batch3")
	defer pt3.Close()

	ct3, err := cc.Encrypt(keyPair, pt3)
	mustT(t, err, "Encrypt batch3")
	defer ct3.Close()

	// Use EvalChebyshevSeries with the same coefficients on all batches
	result1, err := cc.EvalChebyshevSeries(ct1, coeffs, lowerBound, upperBound)
	mustT(t, err, "EvalChebyshevSeries batch1")
	defer result1.Close()

	result2, err := cc.EvalChebyshevSeries(ct2, coeffs, lowerBound, upperBound)
	mustT(t, err, "EvalChebyshevSeries batch2")
	defer result2.Close()

	result3, err := cc.EvalChebyshevSeries(ct3, coeffs, lowerBound, upperBound)
	mustT(t, err, "EvalChebyshevSeries batch3")
	defer result3.Close()

	// Decrypt and verify results
	ptDec1, err := cc.Decrypt(keyPair, result1)
	mustT(t, err, "Decrypt result1")
	defer ptDec1.Close()

	mustT(t, ptDec1.SetLength(len(batch1)), "SetLength batch1")
	decResult1, err := ptDec1.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue batch1")

	ptDec2, err := cc.Decrypt(keyPair, result2)
	mustT(t, err, "Decrypt result2")
	defer ptDec2.Close()

	mustT(t, ptDec2.SetLength(len(batch2)), "SetLength batch2")
	decResult2, err := ptDec2.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue batch2")

	ptDec3, err := cc.Decrypt(keyPair, result3)
	mustT(t, err, "Decrypt result3")
	defer ptDec3.Close()

	mustT(t, ptDec3.SetLength(len(batch3)), "SetLength batch3")
	decResult3, err := ptDec3.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue batch3")

	// Verify batch1: sqrt([1, 4, 9]) = [1, 2, 3]
	expected1 := []float64{1.0, 2.0, 3.0}
	tolerance := 0.01
	for i := 0; i < len(expected1); i++ {
		diff := math.Abs(decResult1[i] - expected1[i])
		if diff > tolerance {
			t.Errorf("Batch1 mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected1[i], decResult1[i], diff)
		}
	}

	// Verify batch2: sqrt([0.5, 2, 6.25]) ≈ [0.707, 1.414, 2.5]
	expected2 := []float64{0.707107, 1.414214, 2.5}
	for i := 0; i < len(expected2); i++ {
		diff := math.Abs(decResult2[i] - expected2[i])
		if diff > tolerance {
			t.Errorf("Batch2 mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected2[i], decResult2[i], diff)
		}
	}

	// Verify batch3: sqrt([0.25, 1, 2.25]) = [0.5, 1, 1.5]
	expected3 := []float64{0.5, 1.0, 1.5}
	for i := 0; i < len(expected3); i++ {
		diff := math.Abs(decResult3[i] - expected3[i])
		if diff > tolerance {
			t.Errorf("Batch3 mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected3[i], decResult3[i], diff)
		}
	}
}

// TestEvalChebyshevSeries_MatchesEvalFunction verifies that EvalChebyshevSeries
// produces the same results as EvalChebyshevFunction
func TestEvalChebyshevSeries_MatchesEvalFunction(t *testing.T) {
	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetSecurityLevel(HEStdNotSet), "SetSecurityLevel")
	mustT(t, params.SetRingDim(1<<10), "SetRingDim")
	mustT(t, params.SetScalingModSize(50), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(60), "SetFirstModSize")

	multDepth := 7
	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")

	keyPair, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keyPair.Close()

	mustT(t, cc.EvalMultKeyGen(keyPair), "EvalMultKeyGen")

	// Test data
	input := []float64{1, 4, 9, 16, 25}
	lowerBound := 0.1
	upperBound := 30.0
	degree := uint32(50)

	// Encrypt input
	plaintext, err := cc.MakeCKKSPackedPlaintext(input)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ct1, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt ct1")
	defer ct1.Close()

	ct2, err := cc.Encrypt(keyPair, plaintext)
	mustT(t, err, "Encrypt ct2")
	defer ct2.Close()

	// Method 1: Use EvalChebyshevFunction (one-shot)
	result1, err := cc.EvalChebyshevFunction(math.Sqrt, ct1, lowerBound, upperBound, degree)
	mustT(t, err, "EvalChebyshevFunction")
	defer result1.Close()

	// Method 2: Use EvalChebyshevSeries (with pre-computed coefficients)
	coeffs, err := EvalChebyshevCoefficients(math.Sqrt, lowerBound, upperBound, degree)
	mustT(t, err, "EvalChebyshevCoefficients")
	result2, err := cc.EvalChebyshevSeries(ct2, coeffs, lowerBound, upperBound)
	mustT(t, err, "EvalChebyshevSeries")
	defer result2.Close()

	// Decrypt both results
	ptDec1, err := cc.Decrypt(keyPair, result1)
	mustT(t, err, "Decrypt result1")
	defer ptDec1.Close()

	mustT(t, ptDec1.SetLength(len(input)), "SetLength result1")
	decResult1, err := ptDec1.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue result1")

	ptDec2, err := cc.Decrypt(keyPair, result2)
	mustT(t, err, "Decrypt result2")
	defer ptDec2.Close()

	mustT(t, ptDec2.SetLength(len(input)), "SetLength result2")
	decResult2, err := ptDec2.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue result2")

	// Both methods should produce identical results
	tolerance := 0.0001 // Very tight tolerance since they should be identical
	for i := 0; i < len(input); i++ {
		diff := math.Abs(decResult1[i] - decResult2[i])
		if diff > tolerance {
			t.Errorf("Method mismatch at index %d: EvalFunction=%.6f, EvalSeries=%.6f (diff: %.6f)",
				i, decResult1[i], decResult2[i], diff)
		}
	}

	// Also verify actual correctness: sqrt([1, 4, 9, 16, 25]) = [1, 2, 3, 4, 5]
	expected := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	tolerance = 0.01
	for i := 0; i < len(expected); i++ {
		diff := math.Abs(decResult2[i] - expected[i])
		if diff > tolerance {
			t.Errorf("Result mismatch at index %d: expected %.6f, got %.6f (diff: %.6f)",
				i, expected[i], decResult2[i], diff)
		}
	}
}
