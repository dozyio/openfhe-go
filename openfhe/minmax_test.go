package openfhe

import (
	"math"
	"testing"
)

// TestEvalMinSchemeSwitching tests finding minimum value and argmin
func TestEvalMinSchemeSwitching(t *testing.T) {
	t.Helper()

	// Setup CKKS parameters for scheme switching
	scaleModSize := 50
	firstModSize := 60
	ringDim := uint64(65536) // HE standard compliant
	slots := uint32(16)
	numValues := uint32(16)

	// Depth: 13 for FHEW to CKKS, log2(numValues) for argmin
	multDepth := 9 + 3 + 1 + int(math.Log2(float64(numValues)))

	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(scaleModSize), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(firstModSize), "SetFirstModSize")
	mustT(t, params.SetRingDim(ringDim), "SetRingDim")
	mustT(t, params.SetBatchSize(int(slots)), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")
	mustT(t, cc.Enable(SCHEMESWITCH), "Enable SCHEMESWITCH")

	// Generate keys
	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	// Generate EvalMult keys
	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Setup scheme switching - use bidirectional setup for min/max operations
	swParams, err := NewSchSwchParams()
	mustT(t, err, "NewSchSwchParams")
	mustT(t, swParams.SetSecurityLevelCKKS(HEStdNotSet), "SetSecurityLevelCKKS") // Disable security for testing
	mustT(t, swParams.SetSecurityLevelFHEW(BinFHETOY), "SetSecurityLevelFHEW")   // Use TOY parameters for speed
	mustT(t, swParams.SetNumSlotsCKKS(slots), "SetNumSlotsCKKS")
	mustT(t, swParams.SetNumValues(numValues), "SetNumValues")
	mustT(t, swParams.SetComputeArgmin(true), "SetComputeArgmin") // Enable argmin computation
	mustT(t, swParams.SetCtxtModSizeFHEWLargePrec(25), "SetCtxtModSizeFHEWLargePrec")
	defer swParams.Close()

	// Bidirectional scheme switching setup (includes bootstrapping key generation)
	lwesk, err := cc.EvalSchemeSwitchingSetup(swParams)
	mustT(t, err, "EvalSchemeSwitchingSetup")
	defer lwesk.Close()

	mustT(t, cc.EvalSchemeSwitchingKeyGen(keys, lwesk), "EvalSchemeSwitchingKeyGen")

	// Get FHEW context and compute parameters for comparison precomputation
	ccLWE, err := cc.GetBinCCForSchemeSwitch()
	mustT(t, err, "GetBinCCForSchemeSwitch")

	// Use large precision for comparisons
	modulus_LWE := uint32(1 << 25) // logQ_ccLWE = 25
	beta, err := ccLWE.GetBeta()
	mustT(t, err, "GetBeta")
	pLWE := modulus_LWE / (2 * beta)
	scaleSign := 512.0

	mustT(t, cc.EvalCompareSwitchPrecompute(pLWE, scaleSign), "EvalCompareSwitchPrecompute")

	// Create test data
	data := []float64{5.2, 3.1, 7.8, 2.9, 6.0, 1.5, 4.3, 8.1,
		3.7, 5.9, 2.2, 7.4, 6.8, 4.9, 3.3, 5.5}
	expectedMin := 1.5
	expectedArgmin := 5

	plaintext, err := cc.MakeCKKSPackedPlaintext(data)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Find minimum
	t.Logf("Finding minimum of %d values...", numValues)
	result, err := cc.EvalMinSchemeSwitching(ciphertext, keys, numValues, slots)
	mustT(t, err, "EvalMinSchemeSwitching")
	defer result.Close()

	// Decrypt minimum value
	minPt, err := cc.Decrypt(keys, result.Value)
	mustT(t, err, "Decrypt min value")
	defer minPt.Close()

	minPt.SetLength(1)
	minValues, err := minPt.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue for min")

	const tolerance = 0.1
	if math.Abs(minValues[0]-expectedMin) > tolerance {
		t.Errorf("Min value mismatch: expected %.2f, got %.2f (diff %.4f)",
			expectedMin, minValues[0], math.Abs(minValues[0]-expectedMin))
	} else {
		t.Logf("✓ Min value correct: %.2f", minValues[0])
	}

	// Extract argmin index from one-hot encoded result
	argminIndex, err := result.GetIndexFromOneHot(cc, keys, numValues)
	mustT(t, err, "GetIndexFromOneHot")

	if argminIndex != expectedArgmin {
		t.Errorf("Argmin index mismatch: expected %d, got %d", expectedArgmin, argminIndex)
	} else {
		t.Logf("✓ Argmin index correct: %d", argminIndex)
	}
}

// TestEvalMaxSchemeSwitching tests finding maximum value and argmax
func TestEvalMaxSchemeSwitching(t *testing.T) {
	t.Helper()

	// Setup CKKS parameters
	scaleModSize := 50
	firstModSize := 60
	ringDim := uint64(65536) // HE standard compliant
	slots := uint32(8)
	numValues := uint32(8)

	multDepth := 9 + 3 + 1 + int(math.Log2(float64(numValues)))

	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(scaleModSize), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(firstModSize), "SetFirstModSize")
	mustT(t, params.SetRingDim(ringDim), "SetRingDim")
	mustT(t, params.SetBatchSize(int(slots)), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")
	mustT(t, cc.Enable(SCHEMESWITCH), "Enable SCHEMESWITCH")

	// Generate keys
	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Setup scheme switching - use bidirectional setup for min/max operations
	swParams, err := NewSchSwchParams()
	mustT(t, err, "NewSchSwchParams")
	mustT(t, swParams.SetSecurityLevelCKKS(HEStdNotSet), "SetSecurityLevelCKKS") // Disable security for testing
	mustT(t, swParams.SetSecurityLevelFHEW(BinFHETOY), "SetSecurityLevelFHEW")   // Use TOY parameters for speed
	mustT(t, swParams.SetNumSlotsCKKS(slots), "SetNumSlotsCKKS")
	mustT(t, swParams.SetNumValues(numValues), "SetNumValues")
	mustT(t, swParams.SetComputeArgmin(true), "SetComputeArgmin") // Enable argmin computation
	mustT(t, swParams.SetCtxtModSizeFHEWLargePrec(25), "SetCtxtModSizeFHEWLargePrec")
	defer swParams.Close()

	// Bidirectional scheme switching setup (includes bootstrapping key generation)
	lwesk, err := cc.EvalSchemeSwitchingSetup(swParams)
	mustT(t, err, "EvalSchemeSwitchingSetup")
	defer lwesk.Close()

	mustT(t, cc.EvalSchemeSwitchingKeyGen(keys, lwesk), "EvalSchemeSwitchingKeyGen")

	// Get FHEW context and compute parameters for comparison precomputation
	ccLWE, err := cc.GetBinCCForSchemeSwitch()
	mustT(t, err, "GetBinCCForSchemeSwitch")

	// Use large precision for comparisons
	modulus_LWE := uint32(1 << 25) // logQ_ccLWE = 25
	beta, err := ccLWE.GetBeta()
	mustT(t, err, "GetBeta")
	pLWE := modulus_LWE / (2 * beta)
	scaleSign := 512.0

	mustT(t, cc.EvalCompareSwitchPrecompute(pLWE, scaleSign), "EvalCompareSwitchPrecompute")

	// Create test data
	data := []float64{5.2, 3.1, 7.8, 2.9, 6.0, 9.5, 4.3, 8.1}
	expectedMax := 9.5
	expectedArgmax := 5

	plaintext, err := cc.MakeCKKSPackedPlaintext(data)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Find maximum
	t.Logf("Finding maximum of %d values...", numValues)
	result, err := cc.EvalMaxSchemeSwitching(ciphertext, keys, numValues, slots)
	mustT(t, err, "EvalMaxSchemeSwitching")
	defer result.Close()

	// Decrypt maximum value
	maxPt, err := cc.Decrypt(keys, result.Value)
	mustT(t, err, "Decrypt max value")
	defer maxPt.Close()

	maxPt.SetLength(1)
	maxValues, err := maxPt.GetRealPackedValue()
	mustT(t, err, "GetRealPackedValue for max")

	const tolerance = 0.1
	if math.Abs(maxValues[0]-expectedMax) > tolerance {
		t.Errorf("Max value mismatch: expected %.2f, got %.2f (diff %.4f)",
			expectedMax, maxValues[0], math.Abs(maxValues[0]-expectedMax))
	} else {
		t.Logf("✓ Max value correct: %.2f", maxValues[0])
	}

	// Extract argmax index from one-hot encoded result
	argmaxIndex, err := result.GetIndexFromOneHot(cc, keys, numValues)
	mustT(t, err, "GetIndexFromOneHot")

	if argmaxIndex != expectedArgmax {
		t.Errorf("Argmax index mismatch: expected %d, got %d", expectedArgmax, argmaxIndex)
	} else {
		t.Logf("✓ Argmax index correct: %d", argmaxIndex)
	}
}

// TestEvalMinMaxSmallDataset tests with a smaller power-of-2 dataset
func TestEvalMinMaxSmallDataset(t *testing.T) {
	t.Helper()

	// Setup for 4 values
	scaleModSize := 50
	firstModSize := 60
	ringDim := uint64(65536) // HE standard compliant
	slots := uint32(4)
	numValues := uint32(4)

	multDepth := 9 + 3 + 1 + int(math.Log2(float64(numValues)))

	params, err := NewParamsCKKSRNS()
	mustT(t, err, "NewParamsCKKSRNS")
	defer params.Close()

	mustT(t, params.SetMultiplicativeDepth(multDepth), "SetMultiplicativeDepth")
	mustT(t, params.SetScalingModSize(scaleModSize), "SetScalingModSize")
	mustT(t, params.SetFirstModSize(firstModSize), "SetFirstModSize")
	mustT(t, params.SetRingDim(ringDim), "SetRingDim")
	mustT(t, params.SetBatchSize(int(slots)), "SetBatchSize")

	cc, err := NewCryptoContextCKKS(params)
	mustT(t, err, "NewCryptoContextCKKS")
	defer cc.Close()

	// Enable features
	mustT(t, cc.Enable(PKE), "Enable PKE")
	mustT(t, cc.Enable(KEYSWITCH), "Enable KEYSWITCH")
	mustT(t, cc.Enable(LEVELEDSHE), "Enable LEVELEDSHE")
	mustT(t, cc.Enable(ADVANCEDSHE), "Enable ADVANCEDSHE")
	mustT(t, cc.Enable(SCHEMESWITCH), "Enable SCHEMESWITCH")

	keys, err := cc.KeyGen()
	mustT(t, err, "KeyGen")
	defer keys.Close()

	mustT(t, cc.EvalMultKeyGen(keys), "EvalMultKeyGen")

	// Setup scheme switching - use bidirectional setup for min/max operations
	swParams, err := NewSchSwchParams()
	mustT(t, err, "NewSchSwchParams")
	mustT(t, swParams.SetSecurityLevelCKKS(HEStdNotSet), "SetSecurityLevelCKKS") // Disable security for testing
	mustT(t, swParams.SetSecurityLevelFHEW(BinFHETOY), "SetSecurityLevelFHEW")   // Use TOY parameters for speed
	mustT(t, swParams.SetNumSlotsCKKS(slots), "SetNumSlotsCKKS")
	mustT(t, swParams.SetNumValues(numValues), "SetNumValues")
	mustT(t, swParams.SetComputeArgmin(true), "SetComputeArgmin") // Enable argmin computation
	mustT(t, swParams.SetCtxtModSizeFHEWLargePrec(25), "SetCtxtModSizeFHEWLargePrec")
	defer swParams.Close()

	// Bidirectional scheme switching setup (includes bootstrapping key generation)
	lwesk, err := cc.EvalSchemeSwitchingSetup(swParams)
	mustT(t, err, "EvalSchemeSwitchingSetup")
	defer lwesk.Close()

	mustT(t, cc.EvalSchemeSwitchingKeyGen(keys, lwesk), "EvalSchemeSwitchingKeyGen")

	// Get FHEW context and compute parameters for comparison precomputation
	ccLWE, err := cc.GetBinCCForSchemeSwitch()
	mustT(t, err, "GetBinCCForSchemeSwitch")

	// Use large precision for comparisons
	modulus_LWE := uint32(1 << 25) // logQ_ccLWE = 25
	beta, err := ccLWE.GetBeta()
	mustT(t, err, "GetBeta")
	pLWE := modulus_LWE / (2 * beta)
	scaleSign := 512.0

	mustT(t, cc.EvalCompareSwitchPrecompute(pLWE, scaleSign), "EvalCompareSwitchPrecompute")

	// Test data: [10.5, 3.2, 15.7, 7.1]
	data := []float64{10.5, 3.2, 15.7, 7.1}

	plaintext, err := cc.MakeCKKSPackedPlaintext(data)
	mustT(t, err, "MakeCKKSPackedPlaintext")
	defer plaintext.Close()

	ciphertext, err := cc.Encrypt(keys, plaintext)
	mustT(t, err, "Encrypt")
	defer ciphertext.Close()

	// Test minimum
	minResult, err := cc.EvalMinSchemeSwitching(ciphertext, keys, numValues, slots)
	mustT(t, err, "EvalMinSchemeSwitching")
	defer minResult.Close()

	minPt, err := cc.Decrypt(keys, minResult.Value)
	mustT(t, err, "Decrypt min")
	defer minPt.Close()
	minPt.SetLength(1)
	minVals, _ := minPt.GetRealPackedValue()
	t.Logf("Min value: %.2f (expected 3.2)", minVals[0])

	// Test maximum
	maxResult, err := cc.EvalMaxSchemeSwitching(ciphertext, keys, numValues, slots)
	mustT(t, err, "EvalMaxSchemeSwitching")
	defer maxResult.Close()

	maxPt, err := cc.Decrypt(keys, maxResult.Value)
	mustT(t, err, "Decrypt max")
	defer maxPt.Close()
	maxPt.SetLength(1)
	maxVals, _ := maxPt.GetRealPackedValue()
	t.Logf("Max value: %.2f (expected 15.7)", maxVals[0])
}
