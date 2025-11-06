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
